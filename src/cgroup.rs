//! Per-run cgroup v2: subtree-accurate CPU + peak-RSS accounting across
//! bwrap's PID namespace, real memory caps, and atomic `cgroup.kill` teardown.
//!
//! cgroup v2 forbids a cgroup from having both member processes and
//! controllers enabled for its children ("no internal processes" rule), so
//! `setup` vacates the current cgroup by moving every member into a
//! `tallyrun-init` leaf, then enables controllers in `cgroup.subtree_control`.
//! Per-run cgroups are created as siblings of the leaf. Subsequent
//! invocations are born inside the leaf (their parent was moved there) and
//! skip straight to creating run cgroups.
//!
//! Deployments can instead prepare a delegated directory themselves and point
//! `TALLYRUN_CGROUP_DIR` (or `--cgroup-dir`) at it; tallyrun then only creates
//! per-run children there and never migrates anything.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const INIT_LEAF: &str = "tallyrun-init";
// Controller sets to try, richest first. cpu is deliberately not requested:
// cgroup core maintains cpu.stat's usage_usec on every cgroup regardless, so
// a bare child cgroup already gives subtree-accurate CPU; controllers are
// only needed for the memory cap/peak, pids.max, and (--pin-cpu only)
// cpuset.cpus. An enabled-but-unused cpuset constrains nothing.
const CONTROLLER_SETS: [&str; 3] = ["+memory +pids +cpuset", "+memory +pids", "+memory"];
const ENABLE_RETRIES: u32 = 20;
// cgroup.kill is asynchronous: killed tasks linger as "dying" and rmdir
// returns EBUSY until the kernel reaps them, so removal polls.
const REMOVE_RETRIES: u32 = 100;
const RETRY_SLEEP: Duration = Duration::from_millis(5);

/// This process's cgroup as an absolute fs path (the `0::` v2 line).
fn self_cgroup() -> io::Result<PathBuf> {
    let content = fs::read_to_string("/proc/self/cgroup")?;
    for line in content.lines() {
        if let Some(rel) = line.strip_prefix("0::") {
            return Ok(Path::new(CGROUP_ROOT).join(rel.trim_start_matches('/')));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no cgroup v2 entry in /proc/self/cgroup",
    ))
}

fn subtree_has(base: &Path, controller: &str) -> bool {
    fs::read_to_string(base.join("cgroup.subtree_control"))
        .map(|s| s.split_whitespace().any(|c| c == controller))
        .unwrap_or(false)
}

/// Move every member of `base` (ourselves included) into the init leaf, then
/// enable controllers for children. Retried because concurrent tallyrun
/// invocations may keep appearing in `base` between the move and the enable.
fn vacate_and_enable(base: &Path) -> io::Result<()> {
    let leaf = base.join(INIT_LEAF);
    match fs::create_dir(&leaf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let mut last_err = io::Error::other("unreachable");
    for _ in 0..ENABLE_RETRIES {
        if let Ok(procs) = fs::read_to_string(base.join("cgroup.procs")) {
            for pid in procs.split_whitespace() {
                // Already-exited pids and kernel threads fail; ignore them.
                let _ = fs::write(leaf.join("cgroup.procs"), pid);
            }
        }
        for set in CONTROLLER_SETS {
            match fs::write(base.join("cgroup.subtree_control"), set) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = e,
            }
        }
        std::thread::sleep(RETRY_SLEEP);
    }
    Err(last_err)
}

/// Find (or prepare) the directory where per-run cgroups may be created.
/// Never hard-fails over missing controllers: a bare child cgroup still
/// yields subtree CPU; memory metrics just degrade (visible via
/// `RunCgroup::has_memory_cap` / `has_memory_peak`).
pub fn setup(explicit: Option<&Path>) -> io::Result<PathBuf> {
    let env_dir = std::env::var_os("TALLYRUN_CGROUP_DIR").map(PathBuf::from);
    if let Some(dir) = explicit.map(Path::to_path_buf).or(env_dir) {
        // A prepared dir has no member processes, so no vacating: just make
        // sure child accounting is on (best effort — must be inside the
        // caller's delegated subtree).
        if !subtree_has(&dir, "memory") {
            for set in CONTROLLER_SETS {
                if fs::write(dir.join("cgroup.subtree_control"), set).is_ok() {
                    break;
                }
            }
        }
        return Ok(dir);
    }

    let own = self_cgroup()?;
    // Born inside the leaf (a previous invocation vacated our parent): run
    // cgroups go next to the leaf, and the dance is already done.
    let base = if own.file_name().is_some_and(|n| n == INIT_LEAF) {
        own.parent().unwrap().to_path_buf()
    } else {
        own
    };
    if !subtree_has(&base, "memory") {
        let _ = vacate_and_enable(&base); // best effort; bare cgroup still works
    }
    Ok(base)
}

/// A throwaway cgroup for one sandboxed execution.
pub struct RunCgroup {
    path: PathBuf,
}

impl RunCgroup {
    pub fn create(base: &Path) -> io::Result<RunCgroup> {
        // pid + counter is unique among live threads of one process (the
        // embeddable `run()` may race itself); nanos guard against a stale
        // dir left by a crashed run whose pid got recycled.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path = base.join(format!("tr-{}-{nanos}-{seq}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(RunCgroup { path })
    }

    /// Cap real RSS. swap.max=0 first: without it the kernel pushes
    /// over-limit pages to swap and throttles instead of OOM-killing, so an
    /// over-limit run just runs slowly rather than being caught.
    pub fn set_memory_max(&self, kb: u64) {
        let _ = fs::write(self.path.join("memory.swap.max"), "0");
        let _ = fs::write(self.path.join("memory.max"), (kb * 1024).to_string());
    }

    pub fn set_pids_max(&self, n: u64) {
        let _ = fs::write(self.path.join("pids.max"), n.to_string());
    }

    /// Pin the subtree to one CPU. Kernel-enforced, unlike sched_setaffinity,
    /// which any member could simply widen back. Errors surface to the caller
    /// because the backstop may only assume one core if this took effect.
    pub fn set_cpus(&self, cpu: u32) -> io::Result<()> {
        fs::write(self.path.join("cpuset.cpus"), cpu.to_string())
    }

    /// Whether the memory *cap* is live here (memory.max present). Distinct
    /// from [`has_memory_peak`](Self::has_memory_peak): memory.max landed
    /// long before memory.peak (kernel 5.19), so a 5.9–5.18 kernel (RHEL 9's
    /// 5.14) can enforce the cap while peak reporting degrades to rusage —
    /// conflating the two made such kernels fall back to RLIMIT_AS, which
    /// over-counts virtual space and spuriously kills the JVM and CPython.
    pub fn has_memory_cap(&self) -> bool {
        self.path.join("memory.max").exists()
    }

    /// Whether peak-RSS reporting is live here (memory.peak, kernel 5.19+).
    pub fn has_memory_peak(&self) -> bool {
        self.path.join("memory.peak").exists()
    }

    pub fn add_pid(&self, pid: libc::pid_t) -> io::Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.to_string())
    }

    pub fn cpu_ms(&self) -> Option<u64> {
        let stat = fs::read_to_string(self.path.join("cpu.stat")).ok()?;
        for line in stat.lines() {
            if let Some(v) = line.strip_prefix("usage_usec ") {
                return v.trim().parse::<u64>().ok().map(|us| us / 1000);
            }
        }
        None
    }

    pub fn peak_kb(&self) -> Option<i64> {
        let s = fs::read_to_string(self.path.join("memory.peak")).ok()?;
        s.trim().parse::<i64>().ok().map(|b| b / 1024)
    }

    /// SIGKILL the whole subtree atomically — fork-bomb-proof teardown.
    pub fn kill_all(&self) {
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
    }
}

/// Teardown on drop: kill anything left, then poll rmdir until the kernel
/// has reaped the dying tasks. Read metrics before letting this run.
impl Drop for RunCgroup {
    fn drop(&mut self) {
        self.kill_all();
        for _ in 0..REMOVE_RETRIES {
            match fs::remove_dir(&self.path) {
                Ok(()) => return,
                Err(_) => std::thread::sleep(RETRY_SLEEP),
            }
        }
    }
}
