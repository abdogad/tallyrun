# Changelog

Notable changes to tallyrun. Format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [SemVer](https://semver.org/) (0.x: minor bumps may change behavior).

## [Unreleased]

### Added

- **The CPU budget is now enforced subtree-wide.** `--cpu-s` used to be only
  a per-process `RLIMIT_CPU`, which a payload spreading work across
  short-lived children never trips — and kernel-mode work is invisible to
  the instruction counter by design, so a multi-process, syscall-heavy
  payload was bounded only by the load-dependent wall clock. The supervisor
  now enforces the same budget on the whole subtree from cgroup `cpu.stat`
  (new JSON value `killed:"cpu"`), with the read cadence sized so the tree
  cannot outrun it — the same headroom-scaled scheme as the instruction
  backstop. `RLIMIT_CPU` stays as the per-process backstop and remains the
  only CPU bound when no cgroup is available.
- Seccomp denylist: `pidfd_getfd` (cross-process fd stealing) now returns
  `EPERM` — same family as `ptrace`/`process_vm_*`. New exhaustive test
  sweeps every syscall number 0–1023 (with and without `CLONE_NEWUSER` in
  arg0) and asserts each gets exactly the verdict its table says.
- `--no-isolate` now prints a loud stderr warning that the command runs
  directly on the host.
- CI: `cargo audit` job (RustSec advisory scan).

### Fixed

- The backstop's per-core peak-retirement constant was calibrated on an
  interpreter loop (~14G insn/s); a high-ILP compiled loop on a fast desktop
  core retires ~30–35G/s, which widened the worst-case multi-process
  overshoot window on exactly the hardware a judge wants. Raised to 40G/s.
- On kernels where `memory.max` exists but `memory.peak` doesn't (5.9–5.18;
  e.g. RHEL 9's 5.14), the two were conflated: tallyrun applied the
  `RLIMIT_AS` fallback *alongside* the working cgroup cap, and `RLIMIT_AS`
  over-counts virtual address space enough to spuriously kill the JVM and
  CPython. The cap probe and the peak probe are now separate: such kernels
  keep the real subtree memory cap, and only peak reporting degrades
  (`accounting:"cpu-only"`).
- Per-run cgroup names: the `rb-` prefix (a `runbox` leftover) is now `tr-`,
  and a process-wide counter joins pid+nanos so two threads embedding
  `tallyrun::run()` cannot collide on a name.

### Changed

- Behavior change: with a cgroup, a run whose *subtree* exceeds `--cpu-s` is
  killed (`killed:"cpu"`) even when no single process exceeded `RLIMIT_CPU`.
  Callers that want the old per-process-only semantics can raise `--cpu-s`.

## [0.4.0] - 2026-07-03

### Added

- `--pin-cpu <N>`: pin the run to one CPU via the cgroup cpuset controller
  (kernel-enforced and tree-wide — the payload cannot widen its own affinity
  back, unlike `sched_setaffinity`). Intended deployment: one worker per
  core. A confirmed pin also tightens the instruction backstop to single-core
  burn rate, cutting worst-case multi-process overshoot ~`nproc`-fold; if the
  cpuset controller isn't delegated, tallyrun warns and runs unpinned with the
  conservative all-core backstop.

### Changed

- Renamed the project from `runbox` to `tallyrun` — binary, crate/lib, the
  `RUNBOX_CGROUP_DIR` env var (→ `TALLYRUN_CGROUP_DIR`), and the internal
  `runbox-init` cgroup leaf (→ `tallyrun-init`). The CLI surface, JSON
  contract, exit codes, and flags are unchanged.
- **Event-driven supervision** replaces the fixed 5 ms polling loop. The
  supervisor now sleeps in `poll(2)` on a `pidfd` (readable the instant the
  child exits) with the wall deadline as the poll timeout: an idle run costs
  a handful of wakeups total instead of 200/s per worker, and wall kills land
  on the deadline instead of up to 5 ms late. Kernels without `pidfd_open`
  (< 5.3) fall back to the old tick.
- **Instruction limits are now enforced in-kernel.** The perf counter is
  armed with `sample_period = insn_limit`, so the PMU overflow interrupt
  SIGKILLs the run's process group the moment a task crosses its budget —
  measured overshoot is thousands of instructions (microseconds), versus up
  to tens of millions under the 5 ms poll. Because inherited counters clone
  the period per task, a multi-process payload could split the aggregate
  budget; a headroom-scaled backstop read covers that: the supervisor never
  sleeps longer than it would take every core at a generous peak rate to
  burn the remaining budget, so forking cannot outrun enforcement. The JSON
  contract is unchanged (`killed:"instructions"`, `signal:9`), and reported
  counts stay exact in all paths.

## [0.3.0] - 2026-07-02

### Added

- **Fresh-procfs isolation, default on.** The sandbox now gets a `/proc`
  scoped to its own PID namespace, so host process IDs and command lines are
  no longer visible inside it (a read-only bind of the host `/proc` leaked
  them even through a fresh PID namespace, because procfs reflects the
  namespace the mount was made in). tallyrun probes at startup — in a throwaway
  user+PID+mount namespace, the same way bwrap mounts it — and only where the
  kernel refuses a fresh procfs (a hardened container whose `/proc` has
  locked masking mounts, the `mount_too_revealing` check) falls back to the
  old read-only bind, with a warning. No regression for container
  deployments; a strict improvement everywhere else.
- `--proc-bind` (force the host bind, silence the fallback warning) and
  `--proc-fresh` (force the fresh mount).

### Changed

- Behavior change: by default sandboxed code can no longer enumerate host
  PIDs via `/proc`. Pass `--proc-bind` for the old behavior.

## [0.2.0] - 2026-07-02

### Added

- **Seccomp-bpf syscall denylist, on by default.** Closes the kernel's
  optional attack surface to sandboxed code: nested user namespaces
  (`unshare`, `setns`, `clone(CLONE_NEWUSER)`), `bpf`, `io_uring`,
  `userfaultfd`, `keyctl`/`add_key`/`request_key`, `ptrace` +
  `process_vm_*`, `perf_event_open`, mount/module/kexec machinery, and more
  (full table in `src/seccomp.rs`). Probe-and-fallback syscalls (`clone3`,
  `io_uring_*`) return `ENOSYS` so glibc and libuv take their tested
  fallback paths; the rest return `EPERM`; a foreign audit arch or x32
  numbering is killed. Hand-assembled cBPF loaded via bwrap `--seccomp` —
  tallyrun's only dependency is still `libc`. CPython, glibc fork/subprocess,
  V8, the JVM, and gcc are exercised under the filter in the test suite.
- `--no-seccomp` to opt out (debugging runtimes that need an exotic syscall).
- **aarch64 release binary** (`tallyrun-aarch64-unknown-linux-musl`): the
  syscall table is keyed off `libc::SYS_*` per architecture, and the release
  workflow cross-builds a static aarch64 artifact alongside x86_64.

### Changed

- Behavior change from 0.1.0: sandboxed code can no longer create nested
  user namespaces or use the syscalls listed above. Pass `--no-seccomp` for
  the old behavior.

[0.2.0]: https://github.com/abdogad/tallyrun/releases/tag/v0.2.0

## [0.1.0] - 2026-07-02

First release.

- `tallyrun run` — one command in, one JSON line out
  ([contract](docs/CONTRACT.md)): exit code/signal, retired user-space
  instruction count, CPU/wall time, peak RSS, and how each was measured.
- Load-invariant measurement via `perf_event_open` (retired user-space
  instructions, `inherit=1` across the whole process tree); `--insn-limit`
  kills over-budget runs; `--require-insn` hard-fails when no PMU.
  Measured variance: ~1e-7 RSD for compiled code, ≤0.25% worst-case load
  shift ([benchmark](docs/BENCHMARK.md)).
- Rootless isolation via bubblewrap: fresh net/PID/user/IPC/mount/UTS
  namespaces, read-only `/usr`, work dir at `/box`, tmpfs `/tmp`, cleared
  and pinned environment (`PYTHONHASHSEED=0`).
- Per-run cgroup v2: subtree-accurate `cpu_ms`/`peak_kb`, real-RSS memory
  cap at 1.25× with `memory.swap.max=0`, `pids.max`, atomic `cgroup.kill`
  teardown; degrades loudly to rusage/rlimits (`--require-cgroup` to
  hard-fail instead).
- Rlimit backstops (CPU, NPROC, FSIZE, NOFILE; AS when no cgroup),
  wall-clock safety timeout.
- `--help` / `--version`.
- Reference judge in [examples/minijudge](examples/minijudge); benchmark
  harness in `bench/`; static musl release binary.

[Unreleased]: https://github.com/abdogad/tallyrun/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/abdogad/tallyrun/releases/tag/v0.4.0
[0.3.0]: https://github.com/abdogad/tallyrun/releases/tag/v0.3.0
[0.1.0]: https://github.com/abdogad/tallyrun/releases/tag/v0.1.0
