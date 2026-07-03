//! runbox core — run one command isolated (bubblewrap), measure its work as a
//! load-independent instruction count (perf), enforce limits, report a
//! structured result.
//!
//! Boundary: this engine runs ONE command. Everything above it — compile steps,
//! test tiers, checkers, verdict mapping (AC/WA/TLE/...) — belongs to the caller
//! (a judge, autograder, or execution backend). runbox knows nothing about
//! problems or queues.
//!
//! Isolation reuses bubblewrap: a fresh net/pid/user/ipc/mount namespace,
//! /usr read-only, the work box at /box.
//! Measurement: a `perf_event_open` counter for retired user-space instructions
//! is attached to the bwrap child with `inherit=1`, so it follows the whole
//! subtree across bwrap's new PID namespace. Peak RSS and CPU time come from a
//! per-run cgroup v2 (memory.peak / cpu.stat) with memory.max + swap.max=0
//! caps and atomic cgroup.kill teardown; wait4 rusage is the fallback when no
//! cgroup is available (per-process only — the JSON `accounting` field says
//! which one you got).
//! Supervision is event-driven, no polling: the parent sleeps in poll(2) on a
//! pidfd with the wall deadline as timeout, and the instruction limit is a
//! PMU tripwire — overflow at the budget SIGKILLs the run in-kernel.
//!
//! Note: because we count from the bwrap child's exec, a small, roughly-constant
//! bwrap-setup offset is included in `instructions`. It is stable run-to-run and
//! cancels in limit comparisons; removing it entirely wants native namespaces.

pub mod cgroup;
pub mod seccomp;

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::raw::{c_int, c_void};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const BWRAP: &str = "/usr/bin/bwrap";

/// memory.max headroom over the caller's limit: a run between 1.0x and 1.25x
/// is measured (and correctly flagged over-limit by the caller comparing
/// peak_kb to its limit) instead of OOM-killed at the boundary.
const MEM_CAP_NUM: u64 = 5;
const MEM_CAP_DEN: u64 = 4;

/// Resource limits and the instruction budget for one run.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Wall-clock safety timeout — only catches hangs that burn no instructions.
    pub wall_ms: u64,
    /// Kill once retired instructions exceed this (the load-invariant TLE path).
    pub insn_limit: Option<u64>,
    /// RLIMIT_CPU seconds — a coarse backstop if perf is unavailable.
    pub cpu_seconds: u64,
    /// Memory limit (the MLE verdict threshold). With a cgroup this becomes
    /// memory.max at 1.25x (subtree-wide, real RSS); without one it falls
    /// back to per-process RLIMIT_AS at 1.0x.
    pub mem_kb: Option<u64>,
    pub max_procs: u64,
    pub max_output_bytes: u64,
    pub max_open_files: u64,
    /// Pin the run to one CPU (cgroup cpuset — kernel-enforced, tree-wide).
    /// Serializes multi-threaded payloads; tightens the insn backstop
    /// to single-core burn rate. Assign each concurrent worker its own core.
    pub pin_cpu: Option<u32>,
    /// Fail the run instead of degrading when perf can't count instructions.
    /// Judges should set this: a degraded run can't produce a fair verdict.
    pub require_insn: bool,
    /// Fail the run instead of degrading when no per-run cgroup is available.
    pub require_cgroup: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            wall_ms: 10_000,
            insn_limit: None,
            cpu_seconds: 10,
            mem_kb: None,
            max_procs: 4096, // NPROC is per-uid; tight values break bwrap's clone()
            max_output_bytes: 8 * 1024 * 1024,
            max_open_files: 64,
            pin_cpu: None,
            require_insn: false,
            require_cgroup: false,
        }
    }
}

/// How `/proc` is presented inside the sandbox.
///
/// A bind of the host `/proc` leaks every host PID (and its cmdline) into the
/// sandbox even though the process is in its own PID namespace, because
/// procfs shows the tasks of the namespace the *mount* was created in. A
/// fresh procfs (bwrap `--proc`) shows only the sandbox's own tree — the
/// correct isolation — but the kernel refuses to mount one when the existing
/// `/proc` has locked child mounts (the masked `/proc/*` a hardened container
/// runtime like Docker adds), the `mount_too_revealing` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProcMode {
    /// Probe for a fresh procfs and use it; fall back to a read-only bind
    /// (with a warning) where the kernel forbids it. The right default:
    /// secure on bare metal / VMs, still works in hardened containers.
    #[default]
    Auto,
    /// Always mount a fresh procfs (`--proc`). bwrap fails loudly if the
    /// environment forbids it.
    Fresh,
    /// Always bind the host `/proc` read-only. Skips the probe; use when you
    /// know you are in a masked-procfs container and accept the PID leak.
    Bind,
}

/// How the sandbox is wired: the work box, whether it's writable (compile step),
/// and where the three standard streams come from / go.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Work dir bind-mounted at /box. `None` disables bwrap (direct exec) — for
    /// measuring on a host without bwrap, not for untrusted code.
    pub box_dir: Option<PathBuf>,
    pub writable: bool,
    /// Extra mounts layered on the base /usr view: (src, dst, writable).
    pub extra_binds: Vec<(String, String, bool)>,
    /// Prepared cgroup dir for per-run children (overrides RUNBOX_CGROUP_DIR
    /// and the self-service vacate dance).
    pub cgroup_dir: Option<PathBuf>,
    /// Load the seccomp denylist (src/seccomp.rs) into the sandbox. Default
    /// true; only rides on bwrap, so `--no-isolate` runs never get a filter.
    pub seccomp: bool,
    /// How `/proc` is exposed to the sandbox. See [`ProcMode`].
    pub proc_mode: ProcMode,
    pub stdin: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}

impl Default for SandboxSpec {
    fn default() -> Self {
        SandboxSpec {
            box_dir: None,
            writable: false,
            extra_binds: Vec::new(),
            cgroup_dir: None,
            seccomp: true,
            proc_mode: ProcMode::default(),
            stdin: PathBuf::from("/dev/null"),
            stdout: PathBuf::from("/dev/stdout"),
            stderr: PathBuf::from("/dev/stderr"),
        }
    }
}

/// Outcome of one measured execution.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    /// The wall-clock safety timeout fired (a genuine hang).
    pub timed_out: bool,
    /// Why runbox killed the process, if it did: "instructions" | "wall".
    pub killed: Option<&'static str>,
    /// Retired user-space instructions — low-variance, load-invariant virtual
    /// time. `None` if perf couldn't open (paranoid setting / no PMU).
    pub instructions: Option<u64>,
    pub cpu_ms: u64,
    pub wall_ms: u128,
    pub peak_kb: i64,
    /// Where cpu_ms/peak_kb came from: "cgroup" (subtree-accurate), "cpu-only"
    /// (cgroup cpu, per-process rusage memory), or "rusage" (per-process only
    /// — multi-process runs are under-accounted).
    pub accounting: &'static str,
}

impl RunResult {
    /// Stable JSON line — the CLI contract callers parse (docs/CONTRACT.md).
    pub fn to_json(&self) -> String {
        fn opt_i(v: Option<i32>) -> String {
            v.map_or("null".into(), |x| x.to_string())
        }
        let insns = self
            .instructions
            .map_or("null".to_string(), |x| x.to_string());
        let killed = self
            .killed
            .map_or("null".to_string(), |s| format!("\"{s}\""));
        // "degraded" shouts what a null `instructions` only whispers: no perf,
        // so any verdict from this run is time-based and load-dependent.
        let measurement = if self.instructions.is_some() {
            "full"
        } else {
            "degraded"
        };
        format!(
            "{{\"exit_code\":{},\"signal\":{},\"timed_out\":{},\"killed\":{},\
\"instructions\":{},\"measurement\":\"{}\",\"accounting\":\"{}\",\
\"cpu_ms\":{},\"wall_ms\":{},\"peak_kb\":{}}}",
            opt_i(self.exit_code),
            opt_i(self.signal),
            self.timed_out,
            killed,
            insns,
            measurement,
            self.accounting,
            self.cpu_ms,
            self.wall_ms,
            self.peak_kb,
        )
    }
}

// --- perf_event_attr, hand-rolled (VER1 layout, 72 bytes) -------------------
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    r#type: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
}

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const DISABLED: u64 = 1 << 0;
const INHERIT: u64 = 1 << 1;
const EXCLUDE_KERNEL: u64 = 1 << 5;
const EXCLUDE_HV: u64 = 1 << 6;
const ENABLE_ON_EXEC: u64 = 1 << 12;
const PERF_SAMPLE_IP: u64 = 1;

// fcntl owner ABI (asm-generic); the libc crate doesn't export these.
const F_SETSIG: c_int = 10;
const F_SETOWN_EX: c_int = 15;
const F_OWNER_PGRP: c_int = 2;
#[repr(C)]
struct FOwnerEx {
    r#type: c_int,
    pid: libc::pid_t,
}

/// Fixed supervisor tick when pidfd_open is unavailable (pre-5.3 kernels).
const NO_PIDFD_TICK: Duration = Duration::from_millis(5);

/// Minimum backstop sleep; caps the re-check rate near the limit.
const BACKSTOP_FLOOR: Duration = Duration::from_millis(1);

/// Per-core retirement ceiling for backstop sizing (a 2024 desktop core
/// measures ~14G/s on a plain interpreter loop).
const PEAK_INSN_RATE_PER_CORE: u64 = 16_000_000_000;

/// Longest sleep such that even every core at peak rate could not burn the
/// remaining budget before the next aggregate read — forking can't outrun it.
fn backstop_timeout(remaining_insns: u64, cores: u64) -> Duration {
    let rate = cores.max(1).saturating_mul(PEAK_INSN_RATE_PER_CORE);
    let ns = remaining_insns as u128 * 1_000_000_000 / rate as u128;
    Duration::from_nanos(ns.min(u64::MAX as u128) as u64).max(BACKSTOP_FLOOR)
}

/// Pollable child-exit fd (Linux 5.3+).
fn pidfd_open(pid: libc::pid_t) -> Option<c_int> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    (fd >= 0).then_some(fd as c_int)
}

/// Open a retired-instruction counter for `pid`'s subtree (inherit=1, enabled
/// at exec). With `kill_at`, the counter is also a tripwire: PMU overflow at
/// the budget SIGKILLs the run's process group in-kernel — the same
/// sample_period + fasync mechanism sio2jail uses, delivering SIGKILL
/// directly instead of SIGIO to a supervisor handler. read() stays the
/// aggregate tree count.
///
/// The period is per-task, so a forking payload can exceed the aggregate
/// budget untripped, and a setsid() escapee leaves the signalled group; the
/// backstop read covers both. poll() can't replace the signal: the kernel
/// forbids the ring-buffer mmap on inherited task events.
fn perf_open_instructions(pid: libc::pid_t, kill_at: Option<u64>) -> io::Result<c_int> {
    let open = |period: u64| -> io::Result<c_int> {
        let mut attr = PerfEventAttr {
            r#type: PERF_TYPE_HARDWARE,
            config: PERF_COUNT_HW_INSTRUCTIONS,
            flags: DISABLED | INHERIT | EXCLUDE_KERNEL | EXCLUDE_HV | ENABLE_ON_EXEC,
            sample_period_or_freq: period,
            ..Default::default()
        };
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        if period > 0 {
            attr.sample_type = PERF_SAMPLE_IP;
            attr.wakeup_events = 1;
        }
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr as *const c_void,
                pid,
                -1i32,
                -1i32,
                0u64,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as c_int)
    };
    if let Some(limit) = kill_at.filter(|&l| l > 0) {
        if let Ok(fd) = open(limit) {
            // Best-effort: if refused, the backstop still enforces.
            unsafe {
                let own = FOwnerEx {
                    r#type: F_OWNER_PGRP,
                    pid, // the child setsid()s before exec, so pgid == pid
                };
                if libc::fcntl(fd, F_SETOWN_EX, &own) == 0
                    && libc::fcntl(fd, F_SETSIG, libc::SIGKILL) == 0
                {
                    libc::fcntl(fd, libc::F_SETFL, libc::O_ASYNC);
                }
            }
            return Ok(fd);
        }
        // Some PMUs refuse sampling but allow counting; degrade to count-only.
    }
    open(0)
}

fn read_counter(fd: c_int) -> Option<u64> {
    let mut count: u64 = 0;
    let n = unsafe { libc::read(fd, &mut count as *mut u64 as *mut c_void, 8) };
    (n == 8).then_some(count)
}

/// Can this environment mount a *fresh* procfs, the way bwrap `--proc` will?
///
/// True on bare metal and clean namespaces; false inside a hardened container
/// whose `/proc` has locked masking mounts (the kernel's
/// `mount_too_revealing` check refuses a new, less-restricted procfs). We
/// can't read this reliably from `/proc/self/mountinfo` — whether a submount
/// is *locked* isn't exposed there — so we probe it directly, exactly the way
/// bwrap does: in a throwaway child, enter a new user + PID + mount namespace
/// (unshare(CLONE_NEWUSER) grants full caps there; a PID namespace is
/// required to mount procfs), then attempt the mount. The child tree exits
/// immediately and is reaped here, so nothing leaks into the real run.
fn fresh_proc_available() -> bool {
    match unsafe { libc::fork() } {
        -1 => false, // can't probe → caller falls back to the always-safe bind
        0 => {
            // child: async-signal-safe syscalls only, then _exit.
            let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
            if unsafe { libc::unshare(flags) } != 0 {
                unsafe { libc::_exit(2) }; // no unpriv userns → bwrap won't run either
            }
            // The proc mount must be done from *inside* the new PID namespace,
            // which only children entered by the CLONE_NEWPID unshare are.
            match unsafe { libc::fork() } {
                -1 => unsafe { libc::_exit(2) },
                0 => unsafe {
                    // Don't let our probe mount propagate back to the host.
                    libc::mount(
                        c"none".as_ptr(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    );
                    let rc = libc::mount(
                        c"proc".as_ptr(),
                        c"/proc".as_ptr(),
                        c"proc".as_ptr(),
                        0,
                        std::ptr::null(),
                    );
                    libc::_exit(if rc == 0 { 0 } else { 1 });
                },
                gpid => {
                    let mut st: c_int = 0;
                    unsafe { libc::waitpid(gpid, &mut st, 0) };
                    let code = if libc::WIFEXITED(st) {
                        libc::WEXITSTATUS(st)
                    } else {
                        3
                    };
                    unsafe { libc::_exit(code) };
                }
            }
        }
        pid => {
            let mut st: c_int = 0;
            unsafe { libc::waitpid(pid, &mut st, 0) };
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
        }
    }
}

/// Build the full argv to exec: bwrap-wrapped when a box is given, else raw.
/// `seccomp_fd` is a memfd holding the compiled filter, inherited across the
/// exec for bwrap's `--seccomp FD` (loaded last, so it never constrains
/// bwrap's own sandbox setup — only the payload subtree). `fresh_proc` picks
/// between a fresh procfs (`--proc`, hides host PIDs) and a read-only bind of
/// the host `/proc` (leaks them, but always mountable) — see [`ProcMode`].
#[rustfmt::skip] // the bwrap argv reads as a table of (flag, args) rows
fn build_command(
    argv: &[String],
    spec: &SandboxSpec,
    seccomp_fd: Option<RawFd>,
    fresh_proc: bool,
) -> Vec<String> {
    let Some(box_dir) = &spec.box_dir else {
        return argv.to_vec();
    };
    let box_bind = if spec.writable { "--bind" } else { "--ro-bind" };
    let box_str = box_dir.to_string_lossy().into_owned();
    let proc_args: &[&str] = if fresh_proc {
        &["--proc", "/proc"]
    } else {
        &["--ro-bind", "/proc", "/proc"]
    };
    let mut cmd: Vec<String> = [
        BWRAP, "--unshare-all", "--die-with-parent",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/bin", "/bin",
    ]
    .iter()
    .chain(proc_args)
    .chain([
        "--dev-bind", "/dev/null", "/dev/null",
        "--dev-bind", "/dev/zero", "/dev/zero",
        "--dev-bind", "/dev/urandom", "/dev/urandom",
        "--dev-bind", "/dev/random", "/dev/random",
    ].iter())
    .map(|s| s.to_string())
    .collect();
    if let Some(fd) = seccomp_fd {
        cmd.extend(["--seccomp".to_string(), fd.to_string()]);
    }
    cmd.extend([box_bind.to_string(), box_str, "/box".to_string()]);
    for (src, dst, rw) in &spec.extra_binds {
        let flag = if *rw { "--bind" } else { "--ro-bind" };
        cmd.extend([flag.to_string(), src.clone(), dst.clone()]);
    }
    cmd.extend(
        [
            "--tmpfs", "/tmp", "--chdir", "/box", "--clearenv",
            "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
            "--setenv", "HOME", "/tmp",
            "--setenv", "PYTHONPYCACHEPREFIX", "/tmp/pycache",
            // Hash randomization dominates Python's run-to-run instruction
            // variance (docs/BENCHMARK.md, Result 4) — pinning it trades
            // hash-DoS hardening for measurement fairness, like fixed-seed judges.
            "--setenv", "PYTHONHASHSEED", "0",
            "--setenv", "TMPDIR", "/tmp",
            "--",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    cmd.extend(argv.iter().cloned());
    cmd
}

/// Resolve a stream path to a raw fd. For `/dev/std{in,out,err}` we inherit the
/// existing fd (0/1/2) rather than open the path: opening those with O_TRUNC
/// would truncate whatever the caller redirected them to (its own log). The
/// bool is `owned` — whether the parent must close it afterwards.
fn resolve_fd(path: &Path, std_fd: RawFd, write: bool) -> io::Result<(RawFd, bool)> {
    let s = path.to_string_lossy();
    let std_path = match std_fd {
        0 => "/dev/stdin",
        1 => "/dev/stdout",
        2 => "/dev/stderr",
        _ => "",
    };
    if s == std_path {
        return Ok((std_fd, false)); // inherit; do not O_TRUNC, do not close
    }
    let c = CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let (flags, mode) = if write {
        (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644)
    } else {
        (libc::O_RDONLY, 0)
    };
    let fd = unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fd, true))
}

fn set_rlimit(res: c_int, soft: u64, hard: u64) {
    let lim = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // `as _`: glibc types the resource as __rlimit_resource_t, musl as c_int.
    unsafe {
        libc::setrlimit(res as _, &lim);
    }
}

/// Run `argv[0]` with the given isolation and limits, measuring its work.
pub fn run(argv: &[String], spec: &SandboxSpec, limits: &Limits) -> io::Result<RunResult> {
    assert!(!argv.is_empty(), "argv must contain at least the program");
    // The filter memfd rides into the child's exec (bwrap reads it by fd
    // number); OwnedFd closes the parent's copy on every path after fork.
    let seccomp_fd: Option<OwnedFd> = match (&spec.box_dir, spec.seccomp) {
        (Some(_), true) => Some(seccomp::install_fd()?),
        _ => None,
    };
    // Resolve how /proc is presented (only relevant when bwrap is in play).
    let fresh_proc = spec.box_dir.is_some()
        && match spec.proc_mode {
            ProcMode::Fresh => true,
            ProcMode::Bind => false,
            ProcMode::Auto => {
                let ok = fresh_proc_available();
                if !ok {
                    eprintln!(
                        "runbox: warning: cannot mount a fresh /proc here (hardened \
                         container?); binding host /proc read-only — sandboxed code \
                         can see host PIDs. Pass --proc-bind to silence, or fix the \
                         container's /proc masking."
                    );
                }
                ok
            }
        };
    let cmd = build_command(
        argv,
        spec,
        seccomp_fd.as_ref().map(|f| f.as_raw_fd()),
        fresh_proc,
    );

    // Per-run cgroup: subtree-wide CPU/RSS accounting, a real memory cap, and
    // atomic kill. Degrades loudly to per-process rusage + RLIMIT_AS.
    let mut cg = match cgroup::setup(spec.cgroup_dir.as_deref())
        .and_then(|base| cgroup::RunCgroup::create(&base))
    {
        Ok(c) => Some(c),
        Err(e) if limits.require_cgroup => {
            return Err(io::Error::new(
                e.kind(),
                format!("cgroup accounting required but unavailable: {e}"),
            ));
        }
        Err(e) => {
            eprintln!(
                "runbox: warning: no per-run cgroup ({e}); cpu_ms/peak_kb degrade \
                 to per-process rusage and the memory cap to RLIMIT_AS"
            );
            None
        }
    };
    if let Some(c) = &cg {
        if let Some(kb) = limits.mem_kb {
            c.set_memory_max(kb.saturating_mul(MEM_CAP_NUM) / MEM_CAP_DEN);
        }
        c.set_pids_max(limits.max_procs);
    }
    // Only a *confirmed* pin lets the backstop assume single-core burn rate.
    let pinned = match (limits.pin_cpu, &cg) {
        (Some(cpu), Some(c)) => match c.set_cpus(cpu) {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "runbox: warning: cpu pinning failed ({e}); running unpinned \
                     (needs the cpuset controller delegated)"
                );
                false
            }
        },
        (Some(_), None) => {
            eprintln!("runbox: warning: cpu pinning needs a cgroup; running unpinned");
            false
        }
        _ => false,
    };
    let cg_memory = cg.as_ref().is_some_and(|c| c.has_memory());
    if limits.require_cgroup && !cg_memory {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroup accounting required but the memory controller is not \
             delegated (peak RSS / memory cap would be per-process only)",
        ));
    }

    // Marshal C argv before fork (no allocation after fork).
    let c_args: Vec<CString> = cmd
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argv contains NUL"))?;
    let mut c_argv: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    c_argv.push(std::ptr::null());

    // Resolve the three streams in the parent so failures surface before fork.
    let (fd_in, own_in) = resolve_fd(&spec.stdin, 0, false)?;
    let (fd_out, own_out) = resolve_fd(&spec.stdout, 1, true)?;
    let (fd_err, own_err) = resolve_fd(&spec.stderr, 2, true)?;

    let mut sync = [0 as c_int; 2];
    if unsafe { libc::pipe(sync.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (sync_r, sync_w) = (sync[0], sync[1]);

    // Snapshot limits for the child (no struct access across fork).
    let cpu_seconds = limits.cpu_seconds;
    // RLIMIT_AS (virtual address space) wildly over-counts real RSS; when the
    // cgroup caps real RSS we drop the rlimit entirely (Python parity).
    let mem_kb = if cg_memory { None } else { limits.mem_kb };
    let max_procs = limits.max_procs;
    let max_output = limits.max_output_bytes;
    let max_files = limits.max_open_files;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        // ---- child: async-signal-safe calls only ----
        unsafe {
            libc::close(sync_w);
            libc::dup2(fd_in, 0);
            libc::dup2(fd_out, 1);
            libc::dup2(fd_err, 2);
            // Close the originals we opened (now duplicated onto 0/1/2) so they
            // don't leak into the sandboxed program.
            if own_in && fd_in > 2 {
                libc::close(fd_in);
            }
            if own_out && fd_out > 2 {
                libc::close(fd_out);
            }
            if own_err && fd_err > 2 {
                libc::close(fd_err);
            }
            libc::setsid(); // own process group so killpg reaches the whole run
            set_rlimit(libc::RLIMIT_CPU as c_int, cpu_seconds, cpu_seconds + 1);
            if let Some(kb) = mem_kb {
                let b = kb.saturating_mul(1024);
                set_rlimit(libc::RLIMIT_AS as c_int, b, b);
            }
            set_rlimit(libc::RLIMIT_NPROC as c_int, max_procs, max_procs);
            set_rlimit(libc::RLIMIT_FSIZE as c_int, max_output, max_output);
            set_rlimit(libc::RLIMIT_NOFILE as c_int, max_files, max_files);
            // Block until the parent attaches perf, then exec.
            let mut b = [0u8; 1];
            libc::read(sync_r, b.as_mut_ptr() as *mut c_void, 1);
            libc::close(sync_r);
            libc::execvp(c_argv[0], c_argv.as_ptr());
            libc::_exit(127);
        }
    }

    // ---- parent ----
    // The child owns its inherited copy of the seccomp memfd; drop ours.
    drop(seccomp_fd);
    unsafe {
        libc::close(sync_r);
        if own_in {
            libc::close(fd_in);
        }
        if own_out {
            libc::close(fd_out);
        }
        if own_err {
            libc::close(fd_err);
        }
    }

    // Enroll the child while it's parked on the sync pipe, so the whole
    // subtree (across bwrap's new PID namespace) is accounted from exec.
    if let Some(c) = &cg {
        if let Err(e) = c.add_pid(pid) {
            if limits.require_cgroup {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    let mut st: c_int = 0;
                    libc::waitpid(pid, &mut st, 0);
                    libc::close(sync_w);
                }
                return Err(io::Error::new(
                    e.kind(),
                    format!("cgroup accounting required but enrollment failed: {e}"),
                ));
            }
            eprintln!(
                "runbox: warning: cgroup enrollment failed ({e}); accounting \
                 degrades to per-process rusage"
            );
            cg = None;
        }
    }

    // The child is still parked on the sync pipe here, so on a required-perf
    // failure we can kill it before it ever execs the payload.
    let perf_fd = match perf_open_instructions(pid, limits.insn_limit) {
        Ok(fd) => Some(fd),
        Err(e) if limits.require_insn => {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                let mut st: c_int = 0;
                libc::waitpid(pid, &mut st, 0);
                libc::close(sync_w);
            }
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "instruction counting required but perf_event_open failed: {e} \
                     (needs kernel.perf_event_paranoid <= 2, a real PMU, and a \
                     container seccomp policy that allows perf_event_open)"
                ),
            ));
        }
        Err(e) => {
            eprintln!(
                "runbox: warning: perf_event_open failed ({e}); instruction \
                 counting disabled, measurement degraded to CPU/wall time"
            );
            None
        }
    };

    let start = Instant::now();
    let deadline = start + Duration::from_millis(limits.wall_ms);
    unsafe {
        let go = [1u8; 1];
        libc::write(sync_w, go.as_ptr() as *const c_void, 1);
        libc::close(sync_w);
    }

    let kill = || {
        // cgroup.kill first: atomic subtree SIGKILL, immune to fork bombs and
        // setsid escapes; killpg is the fallback (and covers --no-isolate).
        if let Some(c) = &cg {
            c.kill_all();
        }
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    };

    let mut status: c_int = 0;
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let mut killed: Option<&'static str> = None;
    let mut timed_out = false;

    // Event-driven supervision: block in poll(2) on the pidfd (readable at
    // child exit), wall deadline as the timeout. The tripwire kills single-
    // task overruns in-kernel; the backstop read covers multi-process ones.
    let pidfd = pidfd_open(pid);
    let cores = if pinned {
        1
    } else {
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as u64
    };

    loop {
        let w = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut ru) };
        if w == pid {
            break; // exited on its own, or tripwired (attributed below)
        }
        if w < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut backstop: Option<Duration> = None;
        if let (Some(fd), Some(limit)) = (perf_fd, limits.insn_limit) {
            match read_counter(fd) {
                Some(c) if c > limit => {
                    killed = Some("instructions");
                    kill();
                    unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
                    break;
                }
                Some(c) => backstop = Some(backstop_timeout(limit - c, cores)),
                None => backstop = Some(NO_PIDFD_TICK), // unreadable: fixed tick
            }
        }
        let now = Instant::now();
        if now >= deadline {
            killed = Some("wall");
            timed_out = true;
            kill();
            unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
            break;
        }
        let mut timeout = deadline - now;
        if let Some(b) = backstop {
            timeout = timeout.min(b);
        }
        match pidfd {
            Some(fd) => {
                // +1: poll() truncates to whole ms; rounding down would busy-
                // spin just short of the deadline. Any wake re-runs the checks.
                let ms = (timeout.as_millis() + 1).min(c_int::MAX as u128) as c_int;
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, ms) };
            }
            None => std::thread::sleep(timeout.min(NO_PIDFD_TICK)),
        }
    }
    let wall_ms = start.elapsed().as_millis();

    let instructions = perf_fd.and_then(read_counter);
    if let Some(fd) = perf_fd {
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = pidfd {
        unsafe { libc::close(fd) };
    }

    // A tripwire kill looks like a plain SIGKILL exit; attribute it.
    if killed.is_none() && libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL {
        if let (Some(c), Some(l)) = (instructions, limits.insn_limit) {
            if c > l {
                killed = Some("instructions");
            }
        }
    }

    // Read cgroup metrics before drop tears the cgroup down; fall back to
    // wait4 rusage (per-process only) where the cgroup can't answer.
    let (cg_cpu, cg_peak) = cg
        .as_ref()
        .map_or((None, None), |c| (c.cpu_ms(), c.peak_kb()));
    drop(cg);
    let rusage_cpu = (ru.ru_utime.tv_sec as u64 * 1000 + ru.ru_utime.tv_usec as u64 / 1000)
        + (ru.ru_stime.tv_sec as u64 * 1000 + ru.ru_stime.tv_usec as u64 / 1000);
    let accounting = match (cg_cpu.is_some(), cg_peak.is_some()) {
        (true, true) => "cgroup",
        (true, false) => "cpu-only",
        _ => "rusage",
    };

    let (exit_code, signal) = if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    };

    Ok(RunResult {
        exit_code,
        signal,
        timed_out,
        killed,
        instructions,
        cpu_ms: cg_cpu.unwrap_or(rusage_cpu),
        wall_ms,
        peak_kb: cg_peak.unwrap_or(ru.ru_maxrss),
        accounting,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_full() -> RunResult {
        RunResult {
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            killed: None,
            instructions: Some(1_140_561_942),
            cpu_ms: 116,
            wall_ms: 117,
            peak_kb: 5864,
            accounting: "cgroup",
        }
    }

    #[test]
    fn json_full_measurement() {
        assert_eq!(
            result_full().to_json(),
            "{\"exit_code\":0,\"signal\":null,\"timed_out\":false,\"killed\":null,\
             \"instructions\":1140561942,\"measurement\":\"full\",\"accounting\":\"cgroup\",\
             \"cpu_ms\":116,\"wall_ms\":117,\"peak_kb\":5864}"
        );
    }

    #[test]
    fn json_degraded_when_no_instructions() {
        let r = RunResult {
            instructions: None,
            accounting: "rusage",
            ..result_full()
        };
        let j = r.to_json();
        assert!(j.contains("\"instructions\":null"));
        assert!(j.contains("\"measurement\":\"degraded\""));
        assert!(j.contains("\"accounting\":\"rusage\""));
    }

    #[test]
    fn json_signal_kill() {
        let r = RunResult {
            exit_code: None,
            signal: Some(9),
            killed: Some("instructions"),
            ..result_full()
        };
        let j = r.to_json();
        assert!(j.contains("\"exit_code\":null"));
        assert!(j.contains("\"signal\":9"));
        assert!(j.contains("\"killed\":\"instructions\""));
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn build_command_no_box_is_passthrough() {
        let argv = args(&["python3", "m.py"]);
        assert_eq!(
            build_command(&argv, &SandboxSpec::default(), None, true),
            argv
        );
    }

    #[test]
    fn build_command_wraps_with_bwrap() {
        let spec = SandboxSpec {
            box_dir: Some(PathBuf::from("/tmp/box")),
            ..Default::default()
        };
        let cmd = build_command(&args(&["python3", "m.py"]), &spec, None, true);
        assert_eq!(cmd[0], BWRAP);
        // Read-only box by default; payload argv comes after the terminator.
        let ro = cmd
            .windows(3)
            .any(|w| w == args(&["--ro-bind", "/tmp/box", "/box"]));
        assert!(ro, "box should be ro-bound at /box: {cmd:?}");
        let sep = cmd.iter().rposition(|a| a == "--").unwrap();
        assert_eq!(&cmd[sep + 1..], &args(&["python3", "m.py"])[..]);
    }

    #[test]
    fn build_command_writable_and_extra_binds() {
        let spec = SandboxSpec {
            box_dir: Some(PathBuf::from("/tmp/box")),
            writable: true,
            extra_binds: vec![("/opt/jdk".into(), "/opt/jdk".into(), false)],
            ..Default::default()
        };
        let cmd = build_command(&args(&["javac", "M.java"]), &spec, None, true);
        assert!(cmd
            .windows(3)
            .any(|w| w == args(&["--bind", "/tmp/box", "/box"])));
        assert!(cmd
            .windows(3)
            .any(|w| w == args(&["--ro-bind", "/opt/jdk", "/opt/jdk"])));
    }

    #[test]
    fn build_command_seccomp_fd_wiring() {
        let spec = SandboxSpec {
            box_dir: Some(PathBuf::from("/tmp/box")),
            ..Default::default()
        };
        let with = build_command(&args(&["./a.out"]), &spec, Some(7), true);
        assert!(with.windows(2).any(|w| w == args(&["--seccomp", "7"])));
        let without = build_command(&args(&["./a.out"]), &spec, None, true);
        assert!(!without.iter().any(|a| a == "--seccomp"));
    }

    #[test]
    fn build_command_proc_mode_toggles_mount() {
        let spec = SandboxSpec {
            box_dir: Some(PathBuf::from("/tmp/box")),
            ..Default::default()
        };
        let fresh = build_command(&args(&["./a.out"]), &spec, None, true);
        assert!(fresh.windows(2).any(|w| w == args(&["--proc", "/proc"])));
        assert!(!fresh
            .windows(3)
            .any(|w| w == args(&["--ro-bind", "/proc", "/proc"])));

        let bind = build_command(&args(&["./a.out"]), &spec, None, false);
        assert!(bind
            .windows(3)
            .any(|w| w == args(&["--ro-bind", "/proc", "/proc"])));
        assert!(!bind.iter().any(|a| a == "--proc"));
    }

    #[test]
    fn backstop_scales_with_headroom() {
        // one peak-core-second of headroom on 1 core -> 1s sleep
        assert_eq!(
            backstop_timeout(PEAK_INSN_RATE_PER_CORE, 1),
            Duration::from_secs(1)
        );
        // ten cores burn ten times faster -> a tenth of the sleep
        assert_eq!(
            backstop_timeout(PEAK_INSN_RATE_PER_CORE, 10),
            Duration::from_millis(100)
        );
        // near-exhausted budgets floor at 1ms rather than busy-spinning
        assert_eq!(backstop_timeout(0, 16), BACKSTOP_FLOOR);
        assert_eq!(backstop_timeout(1, 16), BACKSTOP_FLOOR);
        // a failed sysconf (cores=0) must not divide by zero
        assert_eq!(
            backstop_timeout(PEAK_INSN_RATE_PER_CORE, 0),
            Duration::from_secs(1)
        );
    }
}
