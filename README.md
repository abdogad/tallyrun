# tallyrun

[![CI](https://github.com/abdogad/tallyrun/actions/workflows/ci.yml/badge.svg)](https://github.com/abdogad/tallyrun/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/abdogad/tallyrun)](https://github.com/abdogad/tallyrun/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A rootless Linux sandbox that runs untrusted code and measures the work it
did by counting CPU instructions — a number that stays the same whether the
machine is idle or busy. No `--privileged`, no setuid.**

Judging code by how many seconds it takes is unreliable: CPU time for the
same program swings with machine load and CPU frequency scaling, so a
solution that passes on an idle judge can be ruled "too slow" on a busy one.
tallyrun counts **CPU instructions** instead — a hardware counter
(`perf_event_open`) attached to the whole sandboxed process tree — and a
busy machine doesn't make a program execute more instructions.
[Measured](docs/BENCHMARK.md): on a stock desktop, CPU time for an identical
compiled program varied up to 48% run-to-run while its instruction count
varied by about one part in ten million; under full machine load the count
moved ≤0.5% for every runtime tested.

It's a **small binary you call as a subprocess**: one command in, one JSON
line out. Isolation is bubblewrap (rootless user namespaces), so it runs as a
normal user — no setuid helper, no privileged container.

## Install

Grab the static musl binary from
[GitHub releases](https://github.com/abdogad/tallyrun/releases) — it runs on any
Linux (any distro, any container base image), no dependencies beyond a
`bwrap` binary on the host. x86-64 shown; an aarch64 build
(`tallyrun-aarch64-unknown-linux-musl`) is attached to the same release:

```bash
curl -fL -o tallyrun https://github.com/abdogad/tallyrun/releases/latest/download/tallyrun-x86_64-unknown-linux-musl
chmod +x tallyrun && sudo mv tallyrun /usr/local/bin/
```

Or build from source: `cargo build --release`.

## Quickstart

```bash
cargo build --release          # needs bubblewrap (`bwrap`) on the host

mkdir -p /tmp/box && echo 'print(sum(i*i for i in range(10**6)))' > /tmp/box/m.py
./target/release/tallyrun run --box /tmp/box --insn-limit 10000000000 \
    --wall-ms 5000 --mem-kb 262144 --require-insn -- python3 m.py
```

```json
{"exit_code":0,"signal":null,"timed_out":false,"killed":null,"instructions":1140561942,"measurement":"full","accounting":"cgroup","cpu_ms":116,"wall_ms":117,"peak_kb":5864}
```

Exceed `--insn-limit` and the run is killed with `"killed":"instructions"` —
a "too slow" verdict that doesn't depend on machine load. `--wall-ms` is just
a safety net for genuine hangs (a blocked program burns no instructions).
`cpu_ms` and `peak_kb` are measured with a per-run cgroup, so they cover
every process the submission spawns; `"accounting"` tells you whether you
got that (`cgroup`) or the weaker per-process fallback (`rusage`), and
`--require-cgroup` turns the fallback into a hard error.

The full field-by-field contract — every JSON field, every exit code, and
what is guaranteed stable — is [docs/CONTRACT.md](docs/CONTRACT.md).
Building a judge on top of it takes ~100 lines of glue:
[`examples/minijudge`](examples/minijudge) is a complete
AC/WA/CE/RE/TLE/MLE judge.

## What instruction counting promises — and what it doesn't

The claim is a stable, load-independent count, not a perfect one. The
limits:

- **Not bit-exact.** Page faults and interrupts perturb the raw count
  slightly (this is why [rr](https://rr-project.org/) uses retired
  conditional branches for its replay clock). What matters for judging is
  that verdicts stay stable with normal limit headroom — and ~1e-7 relative
  noise delivers that.
- **Not portable across CPU models.** Absolute counts differ between CPU
  families, so calibrate instruction limits on the hardware that will run
  the judge — the same way every judge already calibrates time limits per
  machine.
- **Interpreted runtimes add their own noise.** CPython's hash randomization
  alone adds ~1.5% run-to-run variance — as noisy as CPU time. tallyrun pins
  `PYTHONHASHSEED=0` inside the sandbox, which brings Python down to
  0.0002–0.17% depending on workload. JIT runtimes (V8, JVM) land at
  0.05–0.6%. Full per-runtime numbers: [docs/BENCHMARK.md](docs/BENCHMARK.md).
- **Kernel time is invisible.** The counter sees only user-mode
  instructions, so work done inside syscalls isn't counted — syscall-heavy
  code is scored cheaper than compute-heavy code doing the same total work.
  The CPU budget (`--cpu-s`) closes this gap: enforced from the per-run
  cgroup's `cpu.stat`, it bounds the whole process tree (`killed:"cpu"`),
  including kernel-mode and fork-spread work, without falling back to
  load-dependent wall time.
- **A constant sandbox-startup offset** (bwrap's own setup instructions) is
  included in the count. It's the same every run, so it cancels out when
  limits are calibrated through tallyrun itself.

## Host requirements

Instruction counting needs unprivileged perf access. Without it tallyrun still
runs, but reports `"measurement":"degraded"` (with a stderr warning) and falls
back to CPU/wall time. Judges should pass `--require-insn` to hard-fail
instead of silently degrading.

- `kernel.perf_event_paranoid` ≤ 2. Fedora ships 2 (works); **Ubuntu ships 4
  (blocked)** — set `sysctl kernel.perf_event_paranoid=2`.
- A real PMU. Bare metal or a PMU-enabled VM (KVM's vPMU works — measured on
  a Hetzner Cloud instance); most CI runners (GitHub Actions included)
  expose none.
- In containers, the default Docker/Podman seccomp profiles block
  `perf_event_open` — run with a profile that allows it.

Subtree-accurate `cpu_ms`/`peak_kb` and the real memory cap additionally
need a **delegated cgroup v2 directory** where tallyrun can create per-run
children. tallyrun finds one by itself in the common cases (it vacates its own
cgroup into a `tallyrun-init` leaf, systemd-style delegation permitting);
deployments can instead prepare a directory and point `TALLYRUN_CGROUP_DIR` or
`--cgroup-dir` at it. Without one, accounting degrades to per-process
`rusage` (reported as `"accounting":"rusage"`; `--require-cgroup` hard-fails
instead). Two systemd caveats: run the judge service with
`OOMPolicy=continue`, or systemd stops the whole service when a memory-bomb
submission gets OOM-killed inside its cap; and `Delegate=yes` on the unit
gives tallyrun its subtree.

## Security model

- **Isolation:** `bwrap --unshare-all --die-with-parent` → fresh network (no
  route out), PID, user, IPC, mount, UTS namespaces; unprivileged (rootless
  user namespace), capabilities dropped, `no_new_privs`.
- **Syscall filter (default on):** a seccomp-bpf denylist closes the kernel's
  optional attack surface — nested user namespaces (`unshare`/`setns`/
  `clone(CLONE_NEWUSER)`), `bpf`, `io_uring`, `userfaultfd`, `keyctl`,
  `ptrace`, `perf_event_open`, mount/module/kexec machinery — while leaving
  everything real runtimes use untouched (CPython, glibc `clone3→clone`
  fallback, V8, the JVM, gcc are all exercised under it in the test suite).
  Probe-and-fallback syscalls return `ENOSYS`, the rest `EPERM`; a foreign
  audit arch or x32 numbering kills the process. `--no-seccomp` opts out.
- **Filesystem:** `/usr` read-only plus the work box at `/box` (read-only
  unless `--writable`, for compile steps); tmpfs `/tmp`; `--clearenv` with a
  pinned environment. I/O rides on inherited fds, so the sandbox never sees
  the paths behind stdin/stdout/stderr.
- **`/proc`:** a fresh procfs scoped to the sandbox's own PID namespace, so
  host PIDs and their command lines are invisible (a bind of the host `/proc`
  leaks all of them even through a fresh PID namespace). tallyrun probes at
  startup and, only where the kernel forbids a fresh procfs — a hardened
  container whose `/proc` carries locked masking mounts — falls back to a
  read-only host bind with a warning. `--proc-bind` forces the bind (and
  silences the warning); `--proc-fresh` forces the fresh mount.
- **Resource bounds:** instruction budget + wall-clock safety timeout; a
  per-run cgroup with `memory.max` at 1.25× the limit (real RSS, whole
  subtree — a run between 1.0× and 1.25× is *measured* over-limit, not
  OOM-guessed), `memory.swap.max=0`, `pids.max`, a subtree-wide CPU budget
  enforced from `cpu.stat` (`killed:"cpu"`), and atomic
  `cgroup.kill` teardown (fork-bomb-proof); rlimits (`CPU`, `NPROC`,
  `FSIZE`, `NOFILE`) as backstops, plus `RLIMIT_AS` when no cgroup memory
  cap is available.
- **Known limits:** the threat model — what is in and out of scope, and the
  documented degradations — lives in [SECURITY.md](SECURITY.md); hardening
  ideas welcome via issues.

## Status

Working end-to-end and used in production judging by
[CodeClash](https://github.com/abdogad/code-clash), where instruction
budgets replaced CPU-time verdicts. Ships with a
[variance benchmark](docs/BENCHMARK.md), a reference
[mini-judge](examples/minijudge), static release binaries
(x86-64 + aarch64), and a stable one-line JSON contract
([docs/CONTRACT.md](docs/CONTRACT.md)).

## How it compares

| | tallyrun | isolate | sio2jail | nsjail | Judge0 |
|---|---|---|---|---|---|
| Shape | **small binary → 1 JSON line** | binary | binary | binary | HTTP service |
| Rootless (no setuid / `--privileged`) | **yes** | setuid root | yes (perf sysctl) | depends on config | privileged container |
| Verdict basis | **instructions (perf)** | cgroup CPU time | instructions (perf) | wall/CPU time | CPU time (via isolate) |
| cgroup-v2 memory cap + subtree accounting | **yes** | yes | no (ptrace) | v1/v2 | via isolate |
| seccomp filter | **yes** (kernel-surface denylist) | no (default) | yes | **yes** | via isolate |

**What tallyrun is:** a small, embeddable, rootless runner with
load-independent measurement — for judges, autograders, and code-execution
backends running semi-trusted code. **What it isn't:** a hardware isolation
boundary.
For fully hostile code, put it behind gVisor or a microVM — but note microVMs
generally don't expose the PMU, which disables instruction counting.

## Tests

```bash
cargo build --release        # the suite drives this binary via its JSON contract
cargo test                   # Rust unit tests
pip install pytest
systemd-run --user --scope -q -p OOMPolicy=continue -- python3 -m pytest -v
```

(The `systemd-run` wrapper gives the suite a fresh delegated scope and stops
systemd from killing it when the memory-bomb tests trip the OOM killer; plain
`pytest -v` also works, with cgroup-dependent asserts skipping if delegation
is unavailable.)

`tests/test_adversarial.py`: output flood, memory bomb, **fork-spread memory
bomb** (16 × 64 MB vs a 128 MB limit — invisible to per-process accounting,
caught by the cgroup), fork bomb, infinite loop.

## Contributing & security

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Report
vulnerabilities privately per [SECURITY.md](SECURITY.md). Release history:
[CHANGELOG.md](CHANGELOG.md).

## License

MIT.
