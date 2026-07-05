# The tallyrun contract

Everything a caller may depend on: the invocation, the exit status, and the
one-line JSON result. If behavior differs from this document, that is a bug —
please open an issue.

## Invocation

```
tallyrun run [OPTIONS] -- <command...>
```

One `tallyrun` process runs one command. The JSON result is the **only** thing
printed to tallyrun's stdout; warnings and errors go to stderr, prefixed
`tallyrun:`. The sandboxed program's own streams go wherever `--stdin` /
`--stdout` / `--stderr` point (defaults: `/dev/null` in, `/dev/null` out,
inherited stderr) — they never mix with the JSON. `tallyrun --help` documents
every option.

## Exit status

| exit | meaning |
|---|---|
| = child | the run completed (even killed/over-limit): tallyrun mirrors the child's exit code, or 1 if the child died to a signal. **Parse the JSON for the verdict, not the exit code.** |
| 2 | usage error (bad flags); nothing was run |
| 3 | the sandbox itself failed: setup error, or a `--require-insn` / `--require-cgroup` guarantee could not be met. No JSON is printed; stderr says why |

## The JSON result

```json
{"exit_code":0,"signal":null,"timed_out":false,"killed":null,"instructions":1140561942,"measurement":"full","accounting":"cgroup","cpu_ms":116,"wall_ms":117,"peak_kb":5864}
```

| field | type | meaning |
|---|---|---|
| `exit_code` | int \| null | the command's exit code; `null` if it was killed by a signal |
| `signal` | int \| null | the signal that terminated it (e.g. `9` after a limit kill, `24`/SIGXCPU from the RLIMIT_CPU backstop); `null` if it exited normally |
| `timed_out` | bool | the wall-clock safety timeout fired — a genuine hang (sleep, deadlock, blocked I/O), since a hung program burns no instructions |
| `killed` | `"instructions"` \| `"cpu"` \| `"wall"` \| null | why **tallyrun** killed the run; `null` when it ended on its own (including OOM kills and rlimit signals) |
| `instructions` | int \| null | retired user-space instructions summed over the whole process tree — the load-invariant "virtual time". `null` when perf is unavailable |
| `measurement` | `"full"` \| `"degraded"` | `"degraded"` = no PMU/perf: `instructions` is null and any verdict from this run is time-based and load-dependent. Judges pass `--require-insn` to get exit 3 instead |
| `accounting` | `"cgroup"` \| `"cpu-only"` \| `"rusage"` | where `cpu_ms`/`peak_kb` came from: `"cgroup"` = whole subtree (trustworthy for multi-process runs); `"cpu-only"` = subtree CPU but per-process memory; `"rusage"` = per-process only — a forking submission is under-accounted. `--require-cgroup` turns anything less than `"cgroup"` into exit 3 |
| `cpu_ms` | int | CPU time in milliseconds (user+sys) |
| `wall_ms` | int | wall-clock duration of the run |
| `peak_kb` | int | peak resident memory in KiB (`memory.peak` for cgroup accounting, `ru_maxrss` otherwise) |

## Semantics a judge builds on

- **TLE (load-invariant):** `killed == "instructions"`, or compare
  `instructions` to your budget. Convert per-problem time limits with an
  instructions-per-ms constant calibrated on your hardware
  ([examples/minijudge](../examples/minijudge) uses 2,000,000 — the
  "2 GHz virtual CPU" convention).
- **TLE (CPU backstop):** `killed == "cpu"` — the whole subtree exceeded the
  `--cpu-s` budget (cgroup `cpu.stat`). This bounds the work the instruction
  counter cannot see — kernel-mode time and work spread across short-lived
  children — without depending on wall-clock load. Without a cgroup only the
  per-process `RLIMIT_CPU` applies (typically `signal: 24`/SIGXCPU).
- **MLE:** compare `peak_kb` to your limit. With cgroup accounting the cap is
  set at 1.25× your `--mem-kb`, so a run that lands between 1.0× and 1.25× is
  *measured* over-limit rather than OOM-guessed; at ≥1.25× the kernel
  OOM-kills it (typically `signal: 9` with `peak_kb` ≈ the cap).
- **RE:** nonzero `exit_code` or a `signal` with `killed == null`.
- **Hang:** `timed_out == true` — wall time is a safety net, never the verdict.

## Sandbox environment (what the measured program sees)

Fresh net/PID/user/IPC/mount/UTS namespaces; `/usr` read-only (plus `/bin`,
`/lib`, `/lib64` symlinks); the work dir at `/box` (cwd; read-only unless
`--writable`); tmpfs `/tmp`; environment cleared and pinned to:

```
PATH=/usr/local/bin:/usr/bin:/bin  HOME=/tmp  TMPDIR=/tmp
PYTHONHASHSEED=0  PYTHONPYCACHEPREFIX=/tmp/pycache
```

`PYTHONHASHSEED=0` is part of the measurement contract: hash randomization
alone adds ~1.5% instruction-count variance
([docs/BENCHMARK.md](BENCHMARK.md), Result 4).

A seccomp-bpf denylist (see the README security model and `src/seccomp.rs`)
is loaded by default: kernel-attack-surface syscalls return `EPERM`,
probe-and-fallback ones (`clone3`, `io_uring_*`) return `ENOSYS` so runtimes
take their normal fallback paths. `--no-seccomp` disables it; `--no-isolate`
runs never have it (it rides on bwrap).

`/proc` is a fresh procfs scoped to the sandbox's PID namespace, so host PIDs
are invisible. In a hardened container that forbids a fresh procfs, tallyrun
warns on stderr and falls back to a read-only bind of the host `/proc` (host
PIDs become visible). `--proc-bind` forces the bind; `--proc-fresh` forces
the fresh mount.

A small, run-to-run-stable bwrap startup offset is included in
`instructions`; it cancels when limits are calibrated through tallyrun itself.

## Stability promise

- Existing fields are never renamed, removed, or retyped.
- New fields may be **added** — parse leniently (ignore unknown keys).
- The documented value sets (`measurement`, `accounting`, `killed`) may gain
  new members in a minor release; treat unknown values conservatively.
- The result is always a single line of JSON on stdout, nothing else.
