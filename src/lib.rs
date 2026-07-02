//! runbox core — run one command isolated (bubblewrap), measure its work as a
//! load-independent instruction count (perf), enforce limits, report a
//! structured result.
//!
//! Boundary: this engine runs ONE command. Everything above it — compile steps,
//! test tiers, checkers, verdict mapping (AC/WA/TLE/...) — belongs to the caller
//! (e.g. CodeClash's judging.py). runbox knows nothing about problems or Redis.
//!
//! Isolation reuses bubblewrap (the setup CodeClash already ships): a fresh
//! net/pid/user/ipc/mount namespace, /usr read-only, the work box at /box.
//! Measurement: a `perf_event_open` counter for retired user-space instructions
//! is attached to the bwrap child with `inherit=1`, so it follows the whole
//! subtree across bwrap's new PID namespace. Peak RSS and CPU time come from a
//! per-run cgroup v2 (memory.peak / cpu.stat) with memory.max + swap.max=0
//! caps and atomic cgroup.kill teardown; wait4 rusage is the fallback when no
//! cgroup is available (per-process only — the JSON `accounting` field says
//! which one you got).
//!
//! Note: because we count from the bwrap child's exec, a small, roughly-constant
//! bwrap-setup offset is included in `instructions`. It is stable run-to-run and
//! cancels in limit comparisons; removing it entirely wants native namespaces.

pub mod cgroup;

use std::ffi::CString;
use std::io;
use std::os::raw::{c_int, c_void};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
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
            require_insn: false,
            require_cgroup: false,
        }
    }
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
    /// Stable JSON line — the CLI contract CodeClash's worker parses.
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
        let measurement = if self.instructions.is_some() { "full" } else { "degraded" };
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

const POLL: Duration = Duration::from_millis(5);

fn perf_open_instructions(pid: libc::pid_t) -> io::Result<c_int> {
    let mut attr = PerfEventAttr {
        r#type: PERF_TYPE_HARDWARE,
        config: PERF_COUNT_HW_INSTRUCTIONS,
        flags: DISABLED | INHERIT | EXCLUDE_KERNEL | EXCLUDE_HV | ENABLE_ON_EXEC,
        ..Default::default()
    };
    attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
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
}

fn read_counter(fd: c_int) -> Option<u64> {
    let mut count: u64 = 0;
    let n = unsafe { libc::read(fd, &mut count as *mut u64 as *mut c_void, 8) };
    (n == 8).then_some(count)
}

/// Build the full argv to exec: bwrap-wrapped when a box is given, else raw.
fn build_command(argv: &[String], spec: &SandboxSpec) -> Vec<String> {
    let Some(box_dir) = &spec.box_dir else {
        return argv.to_vec();
    };
    let box_bind = if spec.writable { "--bind" } else { "--ro-bind" };
    let box_str = box_dir.to_string_lossy().into_owned();
    let mut cmd: Vec<String> = [
        BWRAP, "--unshare-all", "--die-with-parent",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/bin", "/bin",
        "--ro-bind", "/proc", "/proc",
        "--dev-bind", "/dev/null", "/dev/null",
        "--dev-bind", "/dev/zero", "/dev/zero",
        "--dev-bind", "/dev/urandom", "/dev/urandom",
        "--dev-bind", "/dev/random", "/dev/random",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
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
fn resolve_fd(path: &PathBuf, std_fd: RawFd, write: bool) -> io::Result<(RawFd, bool)> {
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
    let cmd = build_command(argv, spec);

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
    let perf_fd = match perf_open_instructions(pid) {
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

    loop {
        let w = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut ru) };
        if w == pid {
            break; // exited on its own
        }
        if w < 0 {
            return Err(io::Error::last_os_error());
        }
        if let (Some(fd), Some(limit)) = (perf_fd, limits.insn_limit) {
            if let Some(c) = read_counter(fd) {
                if c > limit {
                    killed = Some("instructions");
                    kill();
                    unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
                    break;
                }
            }
        }
        if Instant::now() >= deadline {
            killed = Some("wall");
            timed_out = true;
            kill();
            unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
            break;
        }
        std::thread::sleep(POLL);
    }
    let wall_ms = start.elapsed().as_millis();

    let instructions = perf_fd.and_then(read_counter);
    if let Some(fd) = perf_fd {
        unsafe { libc::close(fd) };
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
