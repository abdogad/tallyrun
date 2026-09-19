//! Runs one command inside bubblewrap, counts the user-space instructions it
//! retires, enforces its limits and returns a [`RunResult`].
//!
//! The crate handles a single command. Compile steps, test cases, checkers
//! and verdicts (AC/WA/TLE...) belong to the caller.
//!
//! Isolation is bubblewrap with fresh namespaces, a read-only /usr and the
//! work dir at /box. The instruction counter is a perf event opened on the
//! bwrap child with `inherit=1`, so it keeps counting across bwrap's PID
//! namespace and every process the payload forks. CPU time and peak RSS come
//! from a per-run cgroup v2 (cpu.stat, memory.peak), which also provides the
//! memory cap and `cgroup.kill`. Without a cgroup they fall back to wait4
//! rusage, which sees a single process; the JSON `accounting` field says
//! which source was used.
//!
//! The supervisor sleeps in poll(2) on a pidfd, with the wall deadline as the
//! timeout. The PMU enforces the instruction limit itself: the counter
//! overflows at the budget and the kernel SIGKILLs the process group. The CPU
//! budget is checked against cpu.stat for the whole tree. That catches
//! kernel-mode work, which the instruction counter leaves out, and work
//! spread over short-lived processes, which never adds up under a
//! per-process RLIMIT_CPU.
//!
//! Counting starts at the bwrap child's exec, so `instructions` includes
//! bwrap's own setup. That offset is small and stable from run to run.
//! Removing it would take native namespaces instead of bwrap.

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

/// memory.max is 1.25x the caller's limit. A run that peaks between 1.0x and
/// 1.25x gets measured instead of OOM-killed, and the caller still sees
/// peak_kb over its limit.
const MEM_CAP_NUM: u64 = 5;
const MEM_CAP_DEN: u64 = 4;

/// Resource limits and the instruction budget for one run.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Wall-clock timeout, for hangs that burn no instructions.
    pub wall_ms: u64,
    /// Kill once retired instructions exceed this. Unlike CPU time, the count
    /// doesn't depend on machine load.
    pub insn_limit: Option<u64>,
    /// CPU budget in seconds. With a cgroup it covers the whole tree
    /// (cpu.stat, reported as `killed:"cpu"`), so it also catches kernel-mode
    /// work, which the instruction counter leaves out. RLIMIT_CPU is set on
    /// each process as well, and is the only CPU limit without a cgroup.
    pub cpu_seconds: u64,
    /// Memory limit in KiB (the MLE threshold). With a cgroup it becomes
    /// memory.max at 1.25x, on real RSS for the whole tree. Without one it is
    /// RLIMIT_AS at 1.0x on each process.
    pub mem_kb: Option<u64>,
    pub max_procs: u64,
    pub max_output_bytes: u64,
    pub max_open_files: u64,
    /// Pin the whole run to one CPU with the cgroup cpuset, which the payload
    /// can't undo. Threads then share that core, and the instruction backstop
    /// can assume one core's burn rate. Give each concurrent worker its own
    /// CPU.
    pub pin_cpu: Option<u32>,
    /// Fail instead of degrading when perf can't count instructions. Judges
    /// should set this, since a degraded run can't give a fair verdict.
    pub require_insn: bool,
    /// Fail instead of degrading when no per-run cgroup is available.
    pub require_cgroup: bool,
    /// Also count cache misses, TLB misses and branch mispredictions
    /// ([`EXTRA_COUNTERS`]), for cost models that need more than instructions.
    pub extra_counters: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            wall_ms: 10_000,
            insn_limit: None,
            cpu_seconds: 10,
            mem_kb: None,
            max_procs: 4096, // RLIMIT_NPROC counts per uid; a tight value breaks bwrap's clone()
            max_output_bytes: 8 * 1024 * 1024,
            max_open_files: 64,
            pin_cpu: None,
            require_insn: false,
            require_cgroup: false,
            extra_counters: false,
        }
    }
}

/// How `/proc` appears inside the sandbox.
///
/// procfs lists the tasks of the PID namespace it was mounted in, so binding
/// the host `/proc` shows every host PID and command line to the sandbox,
/// even though the sandbox has its own PID namespace. A fresh procfs (bwrap
/// `--proc`) shows only the sandbox's tree. The kernel refuses to mount one
/// when the existing `/proc` has locked submounts, such as the masked
/// `/proc/*` paths Docker adds (the `mount_too_revealing` check).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProcMode {
    /// Mount a fresh procfs if a probe says the kernel allows it; otherwise
    /// bind the host `/proc` read-only and print a warning. Host PIDs stay
    /// hidden on bare metal and VMs, and hardened containers still work.
    #[default]
    Auto,
    /// Always mount a fresh procfs. bwrap fails if the kernel refuses.
    Fresh,
    /// Always bind the host `/proc` read-only and skip the probe. For
    /// masked-procfs containers, at the cost of showing host PIDs.
    Bind,
}

/// The sandbox layout and where the payload's standard streams point.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Work dir, mounted at /box. `None` skips bwrap and runs the command
    /// directly on the host, which is only for trusted code.
    pub box_dir: Option<PathBuf>,
    pub writable: bool,
    /// Extra mounts as (src, dst, writable).
    pub extra_binds: Vec<(String, String, bool)>,
    /// A prepared cgroup directory to create run cgroups in. Takes precedence
    /// over TALLYRUN_CGROUP_DIR and the automatic setup in [`cgroup::setup`].
    pub cgroup_dir: Option<PathBuf>,
    /// Load the [`seccomp`] denylist. bwrap installs it, so runs without a
    /// box never get a filter.
    pub seccomp: bool,
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
            // tallyrun's own stdout carries the JSON result, so the payload's
            // output is discarded unless the caller names a file.
            stdout: PathBuf::from("/dev/null"),
            stderr: PathBuf::from("/dev/stderr"),
        }
    }
}

/// One extra hardware counter's total over the process tree.
#[derive(Debug, Clone, PartialEq)]
pub struct Counter {
    pub name: &'static str,
    pub count: u64,
    /// time_running / time_enabled, as for `RunResult::instructions_running`.
    pub running: f64,
}

/// Outcome of one measured execution.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    /// The wall-clock timeout fired.
    pub timed_out: bool,
    /// Why tallyrun killed the process, if it did:
    /// "instructions" | "cpu" | "wall".
    pub killed: Option<&'static str>,
    /// Retired user-space instructions for the whole tree. `None` if perf
    /// couldn't open a counter (perf_event_paranoid too high, or no PMU).
    pub instructions: Option<u64>,
    pub cpu_ms: u64,
    pub wall_ms: u128,
    pub peak_kb: i64,
    /// Microsecond versions of `cpu_ms` (plus its user/system split) and
    /// `wall_ms`. Truncating to 1 ms is already a 5% error on a 20 ms run.
    pub cpu_us: u64,
    pub cpu_user_us: u64,
    pub cpu_sys_us: u64,
    pub wall_us: u128,
    /// Fraction of the run the instruction counter was on the PMU
    /// (time_running / time_enabled). Below 1.0 the kernel was sharing the
    /// PMU with other perf users and `instructions` is too low.
    pub instructions_running: Option<f64>,
    /// Extra hardware counters, in [`EXTRA_COUNTERS`] order; only those the
    /// PMU accepted. Empty unless `Limits::extra_counters`.
    pub counters: Vec<Counter>,
    /// Where cpu_ms/peak_kb came from: "cgroup" (whole tree), "cpu-only"
    /// (cgroup CPU, rusage memory), or "rusage" (one process, so multi-process
    /// runs are under-counted).
    pub accounting: &'static str,
}

impl RunResult {
    /// The JSON line the CLI prints. Its fields are a stable contract
    /// (docs/CONTRACT.md).
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
        // Redundant with a null `instructions`, but harder to overlook: without
        // perf, any verdict from this run rests on load-dependent time.
        let measurement = if self.instructions.is_some() {
            "full"
        } else {
            "degraded"
        };
        let running = self
            .instructions_running
            .map_or("null".to_string(), |r| format!("{r:.6}"));
        let counters = if self.counters.is_empty() {
            String::new()
        } else {
            let items: Vec<String> = self
                .counters
                .iter()
                .map(|c| {
                    format!(
                        "\"{}\":{{\"count\":{},\"running\":{:.6}}}",
                        c.name, c.count, c.running
                    )
                })
                .collect();
            format!(",\"counters\":{{{}}}", items.join(","))
        };
        format!(
            "{{\"exit_code\":{},\"signal\":{},\"timed_out\":{},\"killed\":{},\
\"instructions\":{},\"measurement\":\"{}\",\"accounting\":\"{}\",\
\"cpu_ms\":{},\"wall_ms\":{},\"peak_kb\":{},\
\"cpu_us\":{},\"cpu_user_us\":{},\"cpu_sys_us\":{},\"wall_us\":{},\
\"instructions_running\":{}{}}}",
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
            self.cpu_us,
            self.cpu_user_us,
            self.cpu_sys_us,
            self.wall_us,
            running,
            counters,
        )
    }
}

/// perf_event_attr, written out up to config2 (the 72-byte VER1 layout).
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
const PERF_TYPE_HW_CACHE: u32 = 3;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
// hw_cache config: cache id | (op << 8) | (result << 16)
const HW_CACHE_L1D_READ_MISS: u64 = 1 << 16;
const HW_CACHE_DTLB_READ_MISS: u64 = 3 | (1 << 16);
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;

/// The counters `--extra-counters` adds, user space only like instructions.
/// There are four so that, with instructions and the NMI watchdog, they fit a
/// six-counter PMU without multiplexing. `cache_misses` is the vendor's
/// generic event: last-level cache on Intel, L2 on AMD Zen.
pub const EXTRA_COUNTERS: [(&str, u32, u64); 4] = [
    (
        "l1d_read_misses",
        PERF_TYPE_HW_CACHE,
        HW_CACHE_L1D_READ_MISS,
    ),
    (
        "cache_misses",
        PERF_TYPE_HARDWARE,
        PERF_COUNT_HW_CACHE_MISSES,
    ),
    (
        "dtlb_read_misses",
        PERF_TYPE_HW_CACHE,
        HW_CACHE_DTLB_READ_MISS,
    ),
    (
        "branch_misses",
        PERF_TYPE_HARDWARE,
        PERF_COUNT_HW_BRANCH_MISSES,
    ),
];
const DISABLED: u64 = 1 << 0;
const INHERIT: u64 = 1 << 1;
const EXCLUDE_KERNEL: u64 = 1 << 5;
const EXCLUDE_HV: u64 = 1 << 6;
const ENABLE_ON_EXEC: u64 = 1 << 12;
const PERF_SAMPLE_IP: u64 = 1;

// fcntl owner constants from asm-generic; the libc crate doesn't export them.
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

/// The most instructions one core can retire per second, used to size the
/// backstop sleep. It has to cover the fastest code: a high-ILP compiled loop
/// on a 2026 desktop core (~6 GHz, IPC 5-6) retires 30-35G/s, against ~14G/s
/// for an interpreter loop. Sized for the interpreter, a forking compiled
/// payload could overshoot between reads on fast machines. Setting it too
/// high only costs extra wakeups near the budget.
const PEAK_INSN_RATE_PER_CORE: u64 = 40_000_000_000;

/// The longest sleep in which every core at peak rate still couldn't burn
/// the remaining budget, so forking can't outrun the next read.
fn backstop_timeout(remaining_insns: u64, cores: u64) -> Duration {
    let rate = cores.max(1).saturating_mul(PEAK_INSN_RATE_PER_CORE);
    let ns = remaining_insns as u128 * 1_000_000_000 / rate as u128;
    Duration::from_nanos(ns.min(u64::MAX as u128) as u64).max(BACKSTOP_FLOOR)
}

/// The same for the CPU budget: the tree uses at most `cores` ms of CPU per
/// ms of wall time, so after sleeping `remaining / cores` the next cpu.stat
/// read can find the budget exceeded by a few core-milliseconds at most.
fn cpu_backstop_timeout(remaining_ms: u64, cores: u64) -> Duration {
    Duration::from_millis(remaining_ms / cores.max(1)).max(BACKSTOP_FLOOR)
}

/// Pollable child-exit fd (Linux 5.3+).
fn pidfd_open(pid: libc::pid_t) -> Option<c_int> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    (fd >= 0).then_some(fd as c_int)
}

/// Open a retired-instruction counter on `pid` and its descendants
/// (inherit=1), enabled at exec. With `kill_at`, overflowing the budget makes
/// the kernel SIGKILL the run's process group. sio2jail uses the same
/// sample_period + fasync setup, but gets a SIGIO in its supervisor instead.
/// read() still returns the total for the whole tree.
///
/// The sample period counts per task, so forked children can exceed the
/// budget together without any one of them tripping it, and a child that
/// calls setsid() leaves the signalled group. The backstop read catches both.
/// poll() can't stand in for the signal because the kernel won't mmap a ring
/// buffer for an inherited event.
fn perf_open_instructions(pid: libc::pid_t, kill_at: Option<u64>) -> io::Result<c_int> {
    let open = |period: u64| -> io::Result<c_int> {
        let mut attr = PerfEventAttr {
            r#type: PERF_TYPE_HARDWARE,
            config: PERF_COUNT_HW_INSTRUCTIONS,
            flags: DISABLED | INHERIT | EXCLUDE_KERNEL | EXCLUDE_HV | ENABLE_ON_EXEC,
            read_format: PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
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
            // If fcntl fails, the backstop read still enforces the limit.
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

/// A counting-only, user-space counter for `pid`'s subtree, enabled at exec.
fn perf_open_counter(pid: libc::pid_t, r#type: u32, config: u64) -> Option<c_int> {
    let attr = PerfEventAttr {
        r#type,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config,
        flags: DISABLED | INHERIT | EXCLUDE_KERNEL | EXCLUDE_HV | ENABLE_ON_EXEC,
        read_format: PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
        ..Default::default()
    };
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
    (fd >= 0).then_some(fd as c_int)
}

/// (count, time_enabled, time_running) of a counter opened with both
/// PERF_FORMAT_TOTAL_TIME_* flags.
fn read_counter_times(fd: c_int) -> Option<(u64, u64, u64)> {
    let mut buf = [0u64; 3];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, 24) };
    (n == 24).then_some((buf[0], buf[1], buf[2]))
}

fn read_counter(fd: c_int) -> Option<u64> {
    read_counter_times(fd).map(|(count, _, _)| count)
}

fn running_fraction(enabled: u64, running: u64) -> Option<f64> {
    (enabled > 0).then(|| running as f64 / enabled as f64)
}

/// Whether a fresh procfs can be mounted here, the way bwrap `--proc` does.
///
/// A hardened container whose `/proc` has locked masking mounts refuses it
/// (the kernel's `mount_too_revealing` check). mountinfo doesn't show which
/// submounts are locked, so this tries the mount the way bwrap would: a
/// throwaway child unshares a user namespace (for the capabilities), a PID
/// namespace (procfs needs one) and a mount namespace, then forks a process
/// into the new PID namespace to attempt the mount. Both exit right away and
/// are reaped here.
fn fresh_proc_available() -> bool {
    match unsafe { libc::fork() } {
        -1 => false, // can't probe, so fall back to the bind
        0 => {
            // Child: async-signal-safe calls only, then _exit.
            let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
            if unsafe { libc::unshare(flags) } != 0 {
                unsafe { libc::_exit(2) }; // no unprivileged userns, so bwrap can't run either
            }
            // unshare(CLONE_NEWPID) only moves later children into the new
            // namespace, and the mount has to happen from inside it.
            match unsafe { libc::fork() } {
                -1 => unsafe { libc::_exit(2) },
                0 => unsafe {
                    // Keep the probe mount from propagating to the host.
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

/// The argv to exec: wrapped in bwrap when there is a box, unchanged
/// otherwise. `seccomp_fd` is a memfd with the compiled filter, passed as
/// `--seccomp FD`. bwrap installs it last, so it applies to the payload and
/// not to bwrap's own setup. `fresh_proc` chooses between `--proc` and a
/// read-only bind of the host `/proc` (see [`ProcMode`]).
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
            // Hash randomization is the largest source of run-to-run
            // instruction variance in Python (docs/BENCHMARK.md, Result 4).
            // Pinning it gives up hash-DoS protection, as fixed-seed judges do.
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

/// Open a stream path, returning the fd and whether the parent must close it.
/// `/dev/stdin`, `/dev/stdout` and `/dev/stderr` reuse fd 0/1/2 instead of
/// being opened, since O_TRUNC would truncate whatever file the caller
/// redirected that stream to.
fn resolve_fd(path: &Path, std_fd: RawFd, write: bool) -> io::Result<(RawFd, bool)> {
    let s = path.to_string_lossy();
    let std_path = match std_fd {
        0 => "/dev/stdin",
        1 => "/dev/stdout",
        2 => "/dev/stderr",
        _ => "",
    };
    if s == std_path {
        return Ok((std_fd, false));
    }
    let c = CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // O_NOFOLLOW because these paths are usually in the box, where an earlier
    // --writable run (a compile step) could have left a symlink. This open
    // runs on the host as the calling user, so following the link would
    // truncate any file that user can write, or feed any file it can read to
    // the payload's stdin.
    let (flags, mode) = if write {
        (
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
            0o644,
        )
    } else {
        (libc::O_RDONLY | libc::O_NOFOLLOW, 0)
    };
    let fd = unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ELOOP) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{}: stream path is a symlink, refused (it could redirect the \
                     stream to any file the host user can reach)",
                    path.display()
                ),
            ));
        }
        return Err(e);
    }
    Ok((fd, true))
}

/// Close every fd above 2 except `keep` (the seccomp memfd bwrap reads, or
/// -1), right before exec.
///
/// bwrap doesn't close inherited fds, so anything the caller had open at fork
/// would reach the payload. A directory fd is enough to escape: openat()
/// relative to it resolves outside the sandbox's mount namespace.
///
/// Async-signal-safe: raw syscalls, no allocation.
unsafe fn close_inherited_fds(keep: c_int, ceiling: c_int) {
    let range = |lo: u32, hi: u32| -> bool {
        // close_range rejects lo > hi with EINVAL; an empty range just means
        // there is nothing to close.
        lo > hi || libc::syscall(libc::SYS_close_range, lo, hi, 0u32) == 0
    };
    let closed = if keep > 2 {
        let k = keep as u32;
        range(3, k - 1) && range(k + 1, u32::MAX)
    } else {
        range(3, u32::MAX)
    };
    if closed {
        return;
    }
    // No close_range before Linux 5.9: close each fd up to the caller's limit.
    for fd in 3..=ceiling {
        if fd != keep {
            libc::close(fd);
        }
    }
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
    // The JSON result goes to tallyrun's stdout, and a line the payload wrote
    // there could pass for it. Only the literal `/dev/stdout` needs checking:
    // other spellings such as `/dev/fd/1` are symlinks, which O_NOFOLLOW
    // already refuses.
    for p in [&spec.stdout, &spec.stderr] {
        if p.as_os_str() == "/dev/stdout" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "/dev/stdout is reserved for tallyrun's JSON result; \
                 send the program's output to a file",
            ));
        }
    }
    // The child inherits the filter memfd through exec for bwrap to read.
    // OwnedFd closes the parent's copy on every return path.
    let seccomp_fd: Option<OwnedFd> = match (&spec.box_dir, spec.seccomp) {
        (Some(_), true) => Some(seccomp::install_fd()?),
        _ => None,
    };
    let fresh_proc = spec.box_dir.is_some()
        && match spec.proc_mode {
            ProcMode::Fresh => true,
            ProcMode::Bind => false,
            ProcMode::Auto => {
                let ok = fresh_proc_available();
                if !ok {
                    eprintln!(
                        "tallyrun: warning: cannot mount a fresh /proc here (hardened \
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
                "tallyrun: warning: no per-run cgroup ({e}); cpu_ms/peak_kb degrade \
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
    // The backstop may assume a single core only if the pin took effect.
    let pinned = match (limits.pin_cpu, &cg) {
        (Some(cpu), Some(c)) => match c.set_cpus(cpu) {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "tallyrun: warning: cpu pinning failed ({e}); running unpinned \
                     (needs the cpuset controller delegated)"
                );
                false
            }
        },
        (Some(_), None) => {
            eprintln!("tallyrun: warning: cpu pinning needs a cgroup; running unpinned");
            false
        }
        _ => false,
    };
    // Checked separately: 5.9-5.18 kernels have memory.max but no
    // memory.peak, and the cap alone is enough to skip RLIMIT_AS (see
    // has_memory_cap).
    let cg_mem_cap = cg.as_ref().is_some_and(|c| c.has_memory_cap());
    let cg_mem_peak = cg.as_ref().is_some_and(|c| c.has_memory_peak());
    if limits.require_cgroup && !cg_mem_peak {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroup accounting required but the memory controller is not \
             delegated (peak RSS / memory cap would be per-process only)",
        ));
    }

    // Build the C argv now; the child can't allocate after fork.
    let c_args: Vec<CString> = cmd
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argv contains NUL"))?;
    let mut c_argv: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    c_argv.push(std::ptr::null());

    // Open the streams in the parent so errors show up before fork.
    let (fd_in, own_in) = resolve_fd(&spec.stdin, 0, false)?;
    let (fd_out, own_out) = resolve_fd(&spec.stdout, 1, true)?;
    let (fd_err, own_err) = resolve_fd(&spec.stderr, 2, true)?;

    let mut sync = [0 as c_int; 2];
    if unsafe { libc::pipe(sync.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (sync_r, sync_w) = (sync[0], sync[1]);

    let cpu_seconds = limits.cpu_seconds;
    // RLIMIT_AS counts virtual address space, far more than real RSS, so skip
    // it when the cgroup already caps RSS.
    let mem_kb = if cg_mem_cap { None } else { limits.mem_kb };
    let max_procs = limits.max_procs;
    let max_output = limits.max_output_bytes;
    let max_files = limits.max_open_files;
    let keep_fd = seccomp_fd.as_ref().map_or(-1, |f| f.as_raw_fd());
    // Read the fd ceiling now, while RLIMIT_NOFILE is still the caller's; the
    // child lowers it before the sweep.
    let fd_ceiling = {
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE as _, &mut lim) };
        lim.rlim_max.min(65536) as c_int
    };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        // Child: async-signal-safe calls only.
        unsafe {
            libc::close(sync_w);
            libc::dup2(fd_in, 0);
            libc::dup2(fd_out, 1);
            libc::dup2(fd_err, 2);
            // Close the originals, now duplicated onto 0/1/2.
            if own_in && fd_in > 2 {
                libc::close(fd_in);
            }
            if own_out && fd_out > 2 {
                libc::close(fd_out);
            }
            if own_err && fd_err > 2 {
                libc::close(fd_err);
            }
            libc::setsid(); // new process group, so killpg reaches the whole run
            set_rlimit(libc::RLIMIT_CPU as c_int, cpu_seconds, cpu_seconds + 1);
            if let Some(kb) = mem_kb {
                let b = kb.saturating_mul(1024);
                set_rlimit(libc::RLIMIT_AS as c_int, b, b);
            }
            set_rlimit(libc::RLIMIT_NPROC as c_int, max_procs, max_procs);
            set_rlimit(libc::RLIMIT_FSIZE as c_int, max_output, max_output);
            set_rlimit(libc::RLIMIT_NOFILE as c_int, max_files, max_files);
            // Wait until the parent has set up the cgroup and perf, then exec.
            let mut b = [0u8; 1];
            libc::read(sync_r, b.as_mut_ptr() as *mut c_void, 1);
            libc::close(sync_r);
            close_inherited_fds(keep_fd, fd_ceiling);
            libc::execvp(c_argv[0], c_argv.as_ptr());
            libc::_exit(127);
        }
    }

    // The child has its own copy of the memfd now.
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

    // Move the child into the cgroup while it waits on the pipe, so
    // everything from exec on is accounted.
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
                "tallyrun: warning: cgroup enrollment failed ({e}); accounting \
                 degrades to per-process rusage"
            );
            cg = None;
        }
    }

    // The child is still waiting on the pipe, so if perf is required and
    // fails, it dies before running the payload.
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
                "tallyrun: warning: perf_event_open failed ({e}); instruction \
                 counting disabled, measurement degraded to CPU/wall time"
            );
            None
        }
    };

    // Extras need a working PMU; a counter this PMU doesn't offer is skipped.
    let extra_fds: Vec<(&'static str, c_int)> = match perf_fd {
        Some(_) if limits.extra_counters => EXTRA_COUNTERS
            .iter()
            .filter_map(|&(name, t, c)| perf_open_counter(pid, t, c).map(|fd| (name, fd)))
            .collect(),
        _ => Vec::new(),
    };

    let start = Instant::now();
    let deadline = start + Duration::from_millis(limits.wall_ms);
    unsafe {
        let go = [1u8; 1];
        libc::write(sync_w, go.as_ptr() as *const c_void, 1);
        libc::close(sync_w);
    }

    let kill = || {
        // cgroup.kill takes the whole tree at once, including fork bombs and
        // processes that called setsid. killpg covers runs without a cgroup.
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

    // Sleep in poll(2) on the pidfd, which turns readable when the child
    // exits, until the wall deadline or the next backstop check. The PMU
    // tripwire stops a single task that runs over. The backstop reads of the
    // total instruction count and of cpu.stat catch work spread over several
    // processes or done in the kernel.
    let pidfd = pidfd_open(pid);
    let cores = if pinned {
        1
    } else {
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as u64
    };
    let cpu_budget_ms = limits.cpu_seconds.saturating_mul(1000);

    loop {
        let w = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut ru) };
        if w == pid {
            break; // exited, or killed by the tripwire (attributed below)
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
                None => backstop = Some(NO_PIDFD_TICK), // unreadable: use the fixed tick
            }
        }
        if let Some(used) = cg.as_ref().and_then(|c| c.cpu_ms()) {
            if used > cpu_budget_ms {
                killed = Some("cpu");
                kill();
                unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
                break;
            }
            let t = cpu_backstop_timeout(cpu_budget_ms - used, cores);
            backstop = Some(backstop.map_or(t, |b| b.min(t)));
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
                // poll() takes whole ms, and rounding down would spin just
                // short of the deadline, hence the +1. An early wake only
                // re-runs the checks.
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
    let elapsed = start.elapsed();

    let insn_times = perf_fd.and_then(read_counter_times);
    let instructions = insn_times.map(|(count, _, _)| count);
    let instructions_running = insn_times.and_then(|(_, e, r)| running_fraction(e, r));
    let counters: Vec<Counter> = extra_fds
        .iter()
        .filter_map(|&(name, fd)| {
            let got = read_counter_times(fd);
            unsafe { libc::close(fd) };
            let (count, e, r) = got?;
            Some(Counter {
                name,
                count,
                running: running_fraction(e, r).unwrap_or(0.0),
            })
        })
        .collect();
    if let Some(fd) = perf_fd {
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = pidfd {
        unsafe { libc::close(fd) };
    }

    // A tripwire kill looks like any other SIGKILL, so attribute it here.
    if killed.is_none() && libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL {
        if let (Some(c), Some(l)) = (instructions, limits.insn_limit) {
            if c > l {
                killed = Some("instructions");
            }
        }
    }

    // Read the cgroup before dropping it removes it. rusage, which covers one
    // process, fills in whatever the cgroup can't report.
    let (cg_cpu, cg_peak) = cg
        .as_ref()
        .map_or((None, None), |c| (c.cpu_usec(), c.peak_kb()));
    drop(cg);
    let tv_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
    let rusage_cpu = cgroup::CpuTimes {
        total: tv_us(ru.ru_utime) + tv_us(ru.ru_stime),
        user: tv_us(ru.ru_utime),
        system: tv_us(ru.ru_stime),
    };
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

    let cpu = cg_cpu.unwrap_or(rusage_cpu);
    Ok(RunResult {
        exit_code,
        signal,
        timed_out,
        killed,
        instructions,
        cpu_ms: cpu.total / 1000,
        wall_ms: elapsed.as_millis(),
        peak_kb: cg_peak.unwrap_or(ru.ru_maxrss),
        cpu_us: cpu.total,
        cpu_user_us: cpu.user,
        cpu_sys_us: cpu.system,
        wall_us: elapsed.as_micros(),
        instructions_running,
        counters,
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
            cpu_us: 116_532,
            cpu_user_us: 110_000,
            cpu_sys_us: 6_532,
            wall_us: 117_204,
            instructions_running: Some(1.0),
            counters: Vec::new(),
            accounting: "cgroup",
        }
    }

    #[test]
    fn json_full_measurement() {
        assert_eq!(
            result_full().to_json(),
            "{\"exit_code\":0,\"signal\":null,\"timed_out\":false,\"killed\":null,\
             \"instructions\":1140561942,\"measurement\":\"full\",\"accounting\":\"cgroup\",\
             \"cpu_ms\":116,\"wall_ms\":117,\"peak_kb\":5864,\
             \"cpu_us\":116532,\"cpu_user_us\":110000,\"cpu_sys_us\":6532,\
             \"wall_us\":117204,\"instructions_running\":1.000000}"
        );
    }

    #[test]
    fn json_extra_counters() {
        let r = RunResult {
            instructions_running: Some(0.5),
            counters: vec![
                Counter {
                    name: "cache_misses",
                    count: 42,
                    running: 1.0,
                },
                Counter {
                    name: "branch_misses",
                    count: 7,
                    running: 0.25,
                },
            ],
            ..result_full()
        };
        let j = r.to_json();
        assert!(j.contains("\"instructions_running\":0.500000"));
        assert!(j.ends_with(
            ",\"counters\":{\"cache_misses\":{\"count\":42,\"running\":1.000000},\
             \"branch_misses\":{\"count\":7,\"running\":0.250000}}}"
        ));
    }

    #[test]
    fn json_degraded_when_no_instructions() {
        let r = RunResult {
            instructions: None,
            instructions_running: None,
            accounting: "rusage",
            ..result_full()
        };
        let j = r.to_json();
        assert!(j.contains("\"instructions\":null"));
        assert!(j.contains("\"measurement\":\"degraded\""));
        assert!(j.contains("\"accounting\":\"rusage\""));
        assert!(j.contains("\"instructions_running\":null"));
        assert!(!j.contains("counters"));
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
        // Read-only box by default, payload argv after the `--`.
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
        // one second of peak-rate work on 1 core -> 1s sleep
        assert_eq!(
            backstop_timeout(PEAK_INSN_RATE_PER_CORE, 1),
            Duration::from_secs(1)
        );
        // ten cores burn it ten times faster
        assert_eq!(
            backstop_timeout(PEAK_INSN_RATE_PER_CORE, 10),
            Duration::from_millis(100)
        );
        // a nearly spent budget still sleeps 1ms, so the loop doesn't spin
        assert_eq!(backstop_timeout(0, 16), BACKSTOP_FLOOR);
        assert_eq!(backstop_timeout(1, 16), BACKSTOP_FLOOR);
        // a failed sysconf (cores=0) must not divide by zero
        assert_eq!(
            backstop_timeout(PEAK_INSN_RATE_PER_CORE, 0),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn cpu_backstop_scales_with_headroom() {
        // 8 cores can use up 8s of budget in 1s of wall time
        assert_eq!(cpu_backstop_timeout(8_000, 8), Duration::from_secs(1));
        assert_eq!(cpu_backstop_timeout(8_000, 1), Duration::from_secs(8));
        // a nearly spent budget still sleeps 1ms, so the loop doesn't spin
        assert_eq!(cpu_backstop_timeout(0, 8), BACKSTOP_FLOOR);
        // a failed sysconf (cores=0) must not divide by zero
        assert_eq!(cpu_backstop_timeout(8_000, 0), Duration::from_secs(8));
    }
}
