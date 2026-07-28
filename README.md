# tallyrun

[![CI](https://github.com/abdogad/tallyrun/actions/workflows/ci.yml/badge.svg)](https://github.com/abdogad/tallyrun/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/abdogad/tallyrun)](https://github.com/abdogad/tallyrun/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Run untrusted code in a rootless Linux sandbox and limit it by CPU
instructions instead of unreliable wall-clock time.**

tallyrun is a small command-line tool for online judges, autograders, and
code-execution services. Give it a command and some resource limits; it runs
the command in an isolated process tree and returns one line of JSON:

```text
your judge  ->  tallyrun  ->  rootless sandbox  ->  submitted program
                  |
                  +---- JSON result (instructions, time, memory, exit status)
```

tallyrun handles **one execution**. Your application still decides how to
compile submissions, compare output, and turn the result into verdicts such as
AC, WA, TLE, or MLE. See the complete
[mini-judge example](examples/minijudge) for that integration.

## Why count instructions?

A time limit can behave differently on an idle machine and a busy one. CPU
frequency scaling and competing workloads change how long the same program
takes to finish.

tallyrun instead counts retired CPU instructions across the sandboxed process
tree. Machine load may make a run take longer, but it does not make that run do
more computational work. This gives judges a much more stable basis for a
"too slow" verdict.

The instruction count is not perfectly exact and is not comparable across
different CPU models. It is intended to be **stable enough for limits with
normal headroom**, calibrated on the hardware that will run the judge. The
[benchmark report](docs/BENCHMARK.md) contains the measurements and caveats.

## Quick start

You need Linux, [bubblewrap](https://github.com/containers/bubblewrap)
(`bwrap`), and access to the CPU performance counter. See
[Host setup](#host-setup) if the command reports degraded measurement.

Install the latest x86-64 release:

```bash
curl -fL -o tallyrun \
  https://github.com/abdogad/tallyrun/releases/latest/download/tallyrun-x86_64-unknown-linux-musl
chmod +x tallyrun
sudo mv tallyrun /usr/local/bin/
```

An aarch64 binary is available from the same
[release page](https://github.com/abdogad/tallyrun/releases). You can also use
`cargo install tallyrun` or build this repository with `cargo build --release`.

Create a small program and run it in the sandbox:

```bash
mkdir -p /tmp/tallyrun-box
echo 'print(sum(i*i for i in range(10**6)))' > /tmp/tallyrun-box/main.py

tallyrun run \
  --box /tmp/tallyrun-box \
  --insn-limit 10000000000 \
  --wall-ms 5000 \
  --mem-kb 262144 \
  --require-insn \
  -- python3 main.py
```

The submitted program's output is discarded by default, keeping tallyrun's
stdout reserved for the result:

```json
{"exit_code":0,"signal":null,"timed_out":false,"killed":null,"instructions":1140561942,"measurement":"full","accounting":"cgroup","cpu_ms":116,"wall_ms":117,"peak_kb":5864}
```

The most important fields are:

| Field | What it tells you |
|---|---|
| `killed` | Which tallyrun limit stopped the run: `instructions`, `cpu`, or `wall` |
| `instructions` | Retired user-space instructions for the process tree |
| `measurement` | `full` when instruction counting worked; otherwise `degraded` |
| `accounting` | `cgroup` for whole-tree accounting, or a weaker fallback |
| `cpu_ms` / `wall_ms` | CPU time and elapsed time |
| `peak_kb` | Peak resident memory |
| `exit_code` / `signal` | How the submitted command ended |

Use `--stdout <path>` and `--stderr <path>` when your judge needs to capture
the program's output. The complete, stable interface is documented in the
[CLI and JSON contract](docs/CONTRACT.md).

## What each limit does

No single resource counter catches every kind of runaway program, so tallyrun
uses several complementary limits:

| Option | Purpose |
|---|---|
| `--insn-limit N` | Primary, load-independent compute budget |
| `--cpu-s N` | Bounds kernel work and work spread across processes |
| `--wall-ms N` | Safety net for sleeping, deadlocked, or blocked programs |
| `--mem-kb N` | Memory limit and MLE measurement |
| `--pin-cpu N` | Pins the whole run to one CPU for tighter control |

For a production judge, use `--require-insn` so a missing performance counter
causes a clear setup error instead of silently falling back to time-based
measurement. Use `--require-cgroup` when accurate whole-process-tree CPU and
memory accounting is also required.

Run `tallyrun --help` for every option.

## How the sandbox works

tallyrun combines existing Linux primitives rather than requiring a privileged
daemon:

- **bubblewrap** creates new user, PID, network, mount, IPC, and UTS
  namespaces. The sandbox has no network route.
- The work directory is mounted at `/box`, read-only by default. Pass
  `--writable` for a compile step.
- `/usr` is read-only, `/tmp` is temporary, and the environment is cleared and
  made deterministic.
- A default **seccomp** filter blocks syscalls that expose unnecessary kernel
  attack surface.
- `perf_event_open` counts user-space instructions for the whole process tree.
- A delegated **cgroup v2** subtree provides tree-wide CPU and memory
  accounting, caps, and reliable cleanup of forked processes.

This requires neither a setuid helper nor a `--privileged` container.

### Security boundary

tallyrun is designed for semi-trusted code submitted to judges and
autograders. It is not a hardware isolation boundary. For fully hostile code,
add a stronger outer boundary such as gVisor or a microVM; note that an outer
runtime must expose a performance monitoring unit (PMU) for instruction
counting to work.

Read [SECURITY.md](SECURITY.md) for the exact threat model, known limitations,
and private vulnerability-reporting instructions.

## Host setup

### 1. Instruction counting

Instruction counting needs all of the following:

- `kernel.perf_event_paranoid` set to `2` or lower. Fedora commonly ships a
  usable value; Ubuntu commonly needs
  `sudo sysctl kernel.perf_event_paranoid=2`.
- A real PMU, either on bare metal or exposed by the virtual machine.
- A container seccomp profile that allows `perf_event_open`, if tallyrun itself
  runs inside a container.

Without access to the counter, tallyrun still runs and returns
`"measurement":"degraded"` with `instructions: null`. `--require-insn` turns
this into exit status 3, which is safer for production judges. Many hosted CI
runners do not expose a PMU, so degraded results there are expected.

### 2. Whole-tree resource accounting

Accurate `cpu_ms`, `peak_kb`, CPU enforcement, and memory enforcement need a
delegated cgroup v2 directory. tallyrun discovers one automatically in common
setups. A service can provide one with systemd's `Delegate=yes`, or set
`TALLYRUN_CGROUP_DIR` / `--cgroup-dir` to a prepared directory.

Without cgroup delegation, tallyrun falls back to per-process `rusage`; the
JSON `accounting` field makes this visible. Pass `--require-cgroup` if that
fallback is unacceptable.

For a systemd judge service, also set `OOMPolicy=continue` so an OOM-killed
submission does not stop the whole service. A reference container setup is in
[deploy/](deploy).

## Building a judge with tallyrun

A typical judge does the following:

1. Compile the submission in a writable box.
2. Run the compiled program once per test case in a read-only box.
3. Parse tallyrun's JSON result.
4. Check resource limits, exit status, and expected output.
5. Produce the platform's verdict.

[`examples/minijudge`](examples/minijudge) implements that flow in about 100
lines of Python, including AC, WA, CE, RE, TLE, and MLE verdicts.

Important integration details:

- Calibrate instruction limits on the same CPU model used by the judge.
- Leave normal headroom; instruction counts have a small amount of noise.
- Use the CPU budget to cover syscall-heavy work, because the instruction
  counter intentionally excludes kernel-mode instructions.
- Parse the JSON for verdicts. tallyrun's process exit status mirrors the
  submitted command and is not itself the verdict.

## Measurement limits

- Counts vary slightly because of page faults, interrupts, runtimes, and other
  nondeterminism.
- Absolute counts differ across CPU models.
- JIT and interpreted runtimes introduce more variance than native binaries.
  tallyrun pins `PYTHONHASHSEED=0` to remove a major source of Python variance.
- Kernel-mode instructions are not counted; `--cpu-s` is the backstop for that
  work.
- The count includes a small, stable bubblewrap startup cost.

See [docs/BENCHMARK.md](docs/BENCHMARK.md) for measured variance under idle
and loaded conditions and instructions for reproducing the benchmark.

## Development

Build and run the test suites:

```bash
cargo build --release
cargo test
python3 -m pip install pytest
systemd-run --user --scope -q -p OOMPolicy=continue -- python3 -m pytest -v
```

Plain `python3 -m pytest -v` also works; tests that require cgroup delegation
skip when it is unavailable. The Python suite includes adversarial cases such
as output floods, memory bombs, fork bombs, and infinite loops.

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow and [CHANGELOG.md](CHANGELOG.md) for release history.

## Project documentation

- [CLI and JSON contract](docs/CONTRACT.md)
- [Benchmark methodology and results](docs/BENCHMARK.md)
- [Complete mini-judge example](examples/minijudge)
- [Security policy and threat model](SECURITY.md)
- [Container deployment example](deploy)

## License

[MIT](LICENSE)
