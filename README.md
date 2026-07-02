# runbox

[![CI](https://github.com/abdogad/runbox/actions/workflows/ci.yml/badge.svg)](https://github.com/abdogad/runbox/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/abdogad/runbox)](https://github.com/abdogad/runbox/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Rootless Linux sandbox that runs untrusted code and reports low-variance,
load-invariant cost measurements — no `--privileged`, no setuid.**

Time-based judging flips verdicts: the same solution that passes on an idle
judge can TLE on a busy one. [Measured](docs/BENCHMARK.md): the CPU time of an
identical program varies **up to 48% run-to-run** under a default frequency
governor and its mean shifts **−16% to +117%** when the machine is loaded.
runbox instead measures work in **retired user-space instructions** — a
hardware counter (`perf_event_open`) attached across the whole sandboxed
process tree — which measured **0.00001% RSD for compiled code and a ≤0.25%
load shift in the worst (JIT) case** on the same machine, because a busy
judge doesn't make your program execute more instructions.

It's a **small binary you call as a subprocess**: one command in, one JSON
line out. Isolation is bubblewrap (rootless user namespaces), so it runs as a
normal user — no setuid helper, no privileged container.

## Install

Grab the static musl binary from
[GitHub releases](https://github.com/abdogad/runbox/releases) — it runs on any
Linux (any distro, any container base image), no dependencies beyond a
`bwrap` binary on the host. x86-64 shown; an aarch64 build
(`runbox-aarch64-unknown-linux-musl`) is attached to the same release:

```bash
curl -fL -o runbox https://github.com/abdogad/runbox/releases/latest/download/runbox-x86_64-unknown-linux-musl
chmod +x runbox && sudo mv runbox /usr/local/bin/
```

Or build from source: `cargo build --release`.

> **Note:** the `runbox` crate on crates.io is an unrelated project. This
> runbox is distributed as the static binary above, or built from source.

## Quickstart

```bash
cargo build --release          # needs bubblewrap (`bwrap`) on the host

mkdir -p /tmp/box && echo 'print(sum(i*i for i in range(10**6)))' > /tmp/box/m.py
./target/release/runbox run --box /tmp/box --insn-limit 10000000000 \
    --wall-ms 5000 --mem-kb 262144 --require-insn -- python3 m.py
```

```json
{"exit_code":0,"signal":null,"timed_out":false,"killed":null,"instructions":1140561942,"measurement":"full","accounting":"cgroup","cpu_ms":116,"wall_ms":117,"peak_kb":5864}
```

Exceed `--insn-limit` and the run is killed with `"killed":"instructions"` — a
TLE verdict that doesn't depend on machine load. `--wall-ms` survives only as
a safety net for genuine hangs (a blocked program burns no instructions).
`cpu_ms` and `peak_kb` come from a per-run cgroup, so they cover the whole
process tree across bwrap's PID namespace; `"accounting"` tells you whether
you got that (`cgroup`) or the per-process fallback (`rusage`), and
`--require-cgroup` turns the fallback into a hard error.

The full field-by-field contract — every JSON field, every exit code, and
what is guaranteed stable — is [docs/CONTRACT.md](docs/CONTRACT.md).
Building a judge on top of it takes ~100 lines of glue:
[`examples/minijudge`](examples/minijudge) is a complete AC/WA/CE/RE/TLE/MLE
judge you can run right now.

## Low-variance measurement (the point) — and its honest limits

The claim is **low variance and load invariance**, not determinism. Precisely:

- **Not bit-exact.** Page faults and interrupts perturb the raw count slightly
  (this is why [rr](https://rr-project.org/) uses retired conditional branches
  for its replay clock). For judging, verdict stability with normal limit
  headroom is what matters, and ~1e-7 relative noise delivers it.
- **Not portable across CPU microarchitectures.** Absolute counts differ
  between CPU families. Calibrate instruction limits on the judging hardware
  class — the same way every judge already calibrates time limits per machine.
- **Interpreted runtimes add their own nondeterminism.** CPython's hash
  randomization alone is ~1.5% RSD — as noisy as CPU time. runbox pins
  `PYTHONHASHSEED=0` inside the sandbox, which brings Python to 0.0002–0.17%
  depending on workload. JIT runtimes (V8, JVM) land at 0.05–0.6%. Full
  per-runtime numbers: [docs/BENCHMARK.md](docs/BENCHMARK.md).
- **Kernel time is invisible.** The counter excludes kernel mode, so
  syscall-heavy code is undercounted. The `RLIMIT_CPU` backstop is therefore
  part of the verdict contract, not optional hardening.
- **A constant bwrap-setup offset** (sandbox startup instructions) is included
  in the count. It is stable run-to-run and cancels when limits are calibrated
  through runbox itself.

## Host requirements (read this before deploying)

Instruction counting needs unprivileged perf access. Without it runbox still
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
need a **delegated cgroup v2 directory** where runbox can create per-run
children. runbox finds one by itself in the common cases (it vacates its own
cgroup into a `runbox-init` leaf, systemd-style delegation permitting);
deployments can instead prepare a directory and point `RUNBOX_CGROUP_DIR` or
`--cgroup-dir` at it. Without one, accounting degrades to per-process
`rusage` (reported as `"accounting":"rusage"`; `--require-cgroup` hard-fails
instead). Two systemd gotchas: run the judge service with
`OOMPolicy=continue`, or systemd stops the whole service when a memory-bomb
submission gets OOM-killed inside its cap; and `Delegate=yes` on the unit
gives runbox its subtree.

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
  leaks all of them even through a fresh PID namespace). runbox probes at
  startup and, only where the kernel forbids a fresh procfs — a hardened
  container whose `/proc` carries locked masking mounts — falls back to a
  read-only host bind with a warning. `--proc-bind` forces the bind (and
  silences the warning); `--proc-fresh` forces the fresh mount.
- **Resource bounds:** instruction budget + wall-clock safety timeout; a
  per-run cgroup with `memory.max` at 1.25× the limit (real RSS, whole
  subtree — a run between 1.0× and 1.25× is *measured* over-limit, not
  OOM-guessed), `memory.swap.max=0`, `pids.max`, and atomic `cgroup.kill`
  teardown (fork-bomb-proof); rlimits (`CPU`, `NPROC`, `FSIZE`, `NOFILE`) as
  backstops, plus `RLIMIT_AS` when no cgroup is available.
- **Known limits (roadmap):** no user-facing gaps outstanding; hardening
  ideas welcome via issues.

## Status

- **Engine:** Rust (`src/lib.rs`, `src/cgroup.rs`, `src/main.rs`) — perf
  instruction counting, bwrap isolation, per-run cgroup v2 accounting and
  caps, rlimit backstops, one-line JSON contract
  ([docs/CONTRACT.md](docs/CONTRACT.md)).
- **Done:** [variance benchmark](docs/BENCHMARK.md), cgroup v2 port,
  reference mini-judge, static release binaries (x86-64 + aarch64),
  seccomp-bpf denylist, fresh-procfs isolation with auto-fallback.
- **Used by:** [CodeClash](https://github.com/abdogad/code-clash), where
  instruction budgets replaced CPU-time verdicts in production judging.

## How it compares

| | runbox | isolate | sio2jail | nsjail | Judge0 |
|---|---|---|---|---|---|
| Shape | **small binary → 1 JSON line** | binary | binary | binary | HTTP service |
| Rootless (no setuid / `--privileged`) | **yes** | setuid root | yes (perf sysctl) | depends on config | privileged container |
| Verdict basis | **instructions (perf)** | cgroup CPU time | instructions (perf) | wall/CPU time | CPU time (via isolate) |
| cgroup-v2 memory cap + subtree accounting | **yes** | yes | no (ptrace) | v1/v2 | via isolate |
| seccomp filter | **yes** (kernel-surface denylist) | no (default) | yes | **yes** | via isolate |

**What runbox is:** a small, embeddable, rootless runner with measurement you
can trust across load — for judges, autograders, and code-execution backends
running semi-trusted code. **What it isn't:** a hardware isolation boundary.
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
