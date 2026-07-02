# Changelog

Notable changes to runbox. Format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [SemVer](https://semver.org/) (0.x: minor bumps may change behavior).

## [Unreleased]

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
  runbox's only dependency is still `libc`. CPython, glibc fork/subprocess,
  V8, the JVM, and gcc are exercised under the filter in the test suite.
- `--no-seccomp` to opt out (debugging runtimes that need an exotic syscall).
- **aarch64 release binary** (`runbox-aarch64-unknown-linux-musl`): the
  syscall table is keyed off `libc::SYS_*` per architecture, and the release
  workflow cross-builds a static aarch64 artifact alongside x86_64.

### Changed

- Behavior change from 0.1.0: sandboxed code can no longer create nested
  user namespaces or use the syscalls listed above. Pass `--no-seccomp` for
  the old behavior.

[0.2.0]: https://github.com/abdogad/runbox/releases/tag/v0.2.0

## [0.1.0] - 2026-07-02

First release.

- `runbox run` — one command in, one JSON line out
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

[Unreleased]: https://github.com/abdogad/runbox/compare/v0.2.0...HEAD
[0.1.0]: https://github.com/abdogad/runbox/releases/tag/v0.1.0
