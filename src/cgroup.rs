//! One cgroup v2 per run. It reports CPU time and peak RSS for the whole
//! process tree (wait4 stops at bwrap's PID namespace), caps real RSS, and
//! tears the run down with `cgroup.kill`.
//!
//! cgroup v2 doesn't let a cgroup hold processes while it has controllers
//! enabled for its children (the "no internal processes" rule). So `setup`
//! moves every process in the current cgroup into a `tallyrun-init` leaf and
//! enables the controllers; run cgroups are then created next to that leaf.
//! Later invocations start inside the leaf, because their parent was moved
//! there, and go straight to creating run cgroups.
//!
//! A deployment can instead prepare a delegated directory and point
//! `TALLYRUN_CGROUP_DIR` or `--cgroup-dir` at it. tallyrun then only creates
//! run cgroups there and never moves processes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const INIT_LEAF: &str = "tallyrun-init";
// Controller sets to try, largest first. There's no +cpu because the cgroup
// core keeps usage_usec in cpu.stat for every cgroup anyway. The controllers
// are for the memory cap and peak, pids.max, and cpuset.cpus, which only
// --pin-cpu sets (an enabled cpuset that is never set restricts nothing).
const CONTROLLER_SETS: [&str; 3] = ["+memory +pids +cpuset", "+memory +pids", "+memory"];
const ENABLE_RETRIES: u32 = 20;
// cgroup.kill is asynchronous. Killed tasks stay around as "dying" and rmdir
// fails with EBUSY until the kernel reaps them, so removal retries.
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

/// Move every process in `base`, this one included, into the init leaf, then
/// enable controllers for children. Retries because other tallyrun processes
/// can appear in `base` between the move and the enable.
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

/// Find or prepare the directory to create per-run cgroups in. Missing
/// controllers aren't an error: a bare child cgroup still reports CPU for
/// the tree, and only the memory side degrades (see
/// `RunCgroup::has_memory_cap` and `has_memory_peak`).
pub fn setup(explicit: Option<&Path>) -> io::Result<PathBuf> {
    let env_dir = std::env::var_os("TALLYRUN_CGROUP_DIR").map(PathBuf::from);
    if let Some(dir) = explicit.map(Path::to_path_buf).or(env_dir) {
        // A prepared dir has no processes to move. Try to enable the
        // controllers; that only works inside a subtree delegated to us.
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
    // Inside the leaf means an earlier run already moved our parent there and
    // did the setup, so run cgroups go next to the leaf.
    let base = if own.file_name().is_some_and(|n| n == INIT_LEAF) {
        own.parent().unwrap().to_path_buf()
    } else {
        own
    };
    if !subtree_has(&base, "memory") {
        let _ = vacate_and_enable(&base); // best effort; a bare cgroup still works
    }
    Ok(base)
}

/// The value of `name` in a flat-keyed cgroup file such as cpu.stat.
fn stat_field(stat: &str, name: &str) -> Option<u64> {
    stat.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// CPU time in microseconds: user+system total, and its split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTimes {
    pub total: u64,
    pub user: u64,
    pub system: u64,
}

/// A cgroup for one run, removed on drop.
pub struct RunCgroup {
    path: PathBuf,
}

impl RunCgroup {
    pub fn create(base: &Path) -> io::Result<RunCgroup> {
        // pid + counter stays unique when several threads of one process call
        // `run()` at once. The nanoseconds avoid a stale dir left by a crashed
        // run whose pid was reused.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path = base.join(format!("tr-{}-{nanos}-{seq}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(RunCgroup { path })
    }

    /// Cap real RSS. swap.max goes to 0 first; otherwise the kernel swaps and
    /// throttles an over-limit run instead of OOM-killing it, and the run just
    /// gets slow.
    pub fn set_memory_max(&self, kb: u64) {
        let _ = fs::write(self.path.join("memory.swap.max"), "0");
        let _ = fs::write(
            self.path.join("memory.max"),
            kb.saturating_mul(1024).to_string(),
        );
    }

    pub fn set_pids_max(&self, n: u64) {
        let _ = fs::write(self.path.join("pids.max"), n.to_string());
    }

    /// Pin the tree to one CPU. Unlike sched_setaffinity, this can't be
    /// widened back from inside. Returns the error because the backstop may
    /// only assume one core if the pin worked.
    pub fn set_cpus(&self, cpu: u32) -> io::Result<()> {
        fs::write(self.path.join("cpuset.cpus"), cpu.to_string())
    }

    /// Whether memory.max exists, so the cap works. memory.peak only arrived
    /// in 5.19, so a 5.9-5.18 kernel (RHEL 9 ships 5.14) can enforce the cap
    /// but can't report the peak. Such kernels must still skip RLIMIT_AS,
    /// which counts virtual address space and kills the JVM and CPython for
    /// no good reason.
    pub fn has_memory_cap(&self) -> bool {
        self.path.join("memory.max").exists()
    }

    /// Whether memory.peak exists (kernel 5.19+).
    pub fn has_memory_peak(&self) -> bool {
        self.path.join("memory.peak").exists()
    }

    pub fn add_pid(&self, pid: libc::pid_t) -> io::Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.to_string())
    }

    pub fn cpu_ms(&self) -> Option<u64> {
        let stat = fs::read_to_string(self.path.join("cpu.stat")).ok()?;
        stat_field(&stat, "usage_usec").map(|us| us / 1000)
    }

    /// CPU time for the tree from cpu.stat, in microseconds. `total` is the
    /// scheduler's exact runtime; the user/system split is tick-sampled and
    /// scaled by the kernel to add up to it.
    pub fn cpu_usec(&self) -> Option<CpuTimes> {
        let stat = fs::read_to_string(self.path.join("cpu.stat")).ok()?;
        Some(CpuTimes {
            total: stat_field(&stat, "usage_usec")?,
            user: stat_field(&stat, "user_usec")?,
            system: stat_field(&stat, "system_usec")?,
        })
    }

    pub fn peak_kb(&self) -> Option<i64> {
        let s = fs::read_to_string(self.path.join("memory.peak")).ok()?;
        s.trim().parse::<i64>().ok().map(|b| b / 1024)
    }

    /// SIGKILL the whole tree in one step, which a fork bomb can't outrun.
    pub fn kill_all(&self) {
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
    }
}

/// Kills whatever is left and retries rmdir until the kernel has reaped the
/// dying tasks. Read the metrics before dropping.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_field_matches_whole_keys_only() {
        let stat = "usage_usec 116532\nuser_usec 110000\nsystem_usec 6532\n\
                    core_sched.force_idle_usec 0\nnr_periods 0\n";
        assert_eq!(stat_field(stat, "usage_usec"), Some(116_532));
        assert_eq!(stat_field(stat, "user_usec"), Some(110_000));
        assert_eq!(stat_field(stat, "system_usec"), Some(6_532));
        // a key that is only a prefix of another line must not match it
        assert_eq!(stat_field(stat, "usage"), None);
        assert_eq!(stat_field(stat, "missing_usec"), None);
    }
}
