# Benchmark: instruction counting vs. time-based judging

Same compiled program, 12 runs: the instruction count varies **0.00001%**;
CPU time varies **48%** on an idle machine with a default frequency governor,
and its mean shifts −16% to +117% when the machine is loaded (wall time:
+127% to +573%). A submission at 90% of a CPU-time limit on an idle judge
reaches ~195% of it on a loaded one — a flipped verdict; the same
submission's instruction count moves ≤0.25%.

Two secondary findings:

- Page faults and interrupts — the standard objection to instruction
  counting — are measurable but negligible at judging scale: the most
  page-fault-heavy workload measured 0.00003% RSD.
- The dominant noise source is not the hardware counter but runtime
  nondeterminism: CPython hash randomization alone contributes ~1.5% RSD.
  The sandbox must pin it; tallyrun does (`PYTHONHASHSEED=0`, `--clearenv`).

## Setup

| | |
|---|---|
| CPU | AMD Ryzen 7 4800H (Zen 2, 8C/16T), `schedutil` governor |
| Kernel | 6.14.5 (Fedora 40), `perf_event_paranoid=2` |
| Method | N=12 runs per workload per condition, min/max dropped, RSD of the remaining 10 — the [COFFE](https://arxiv.org/abs/2502.02827) methodology |
| Conditions | "idle" = normal desktop (ambient loadavg ~2–3, an in-use machine rather than a lab box); "loaded" = 32 shell busy-loops (2× nproc) |
| Harness | [`bench/measure.py`](../bench/measure.py) shelling out to `tallyrun run --no-isolate` so `cpu_ms` comes from `wait4` on the payload itself |

Workloads: C spin loop (volatile store-load; labeled `C spin (ALU-bound)`,
its pre-rename name, in the raw JSON), C 64 MiB random memory walk
(page-fault heavy), CPython arithmetic, CPython string-dict churn
(hash-seed sensitive, run pinned and unpinned), Node hot loop (V8 JIT),
Java hot loop via source launcher (in-process javac + C2 JIT).

## Result 1 — run-to-run variance (idle machine)

| workload | instructions | cpu_ms | wall_ms |
|---|---|---|---|
| C spin (volatile store-load) | **0.00001%** | 47.76% | 47.49% |
| C mem (64 MiB random walk) | **0.00002%** | 3.98% | 4.36% |
| Python arithmetic (seed pinned) | **0.00017%** | 4.26% | 4.04% |
| Python dict/str (seed pinned) | 0.16877% | 2.85% | 2.99% |
| Python dict/str (seed random) | 1.52646% | 5.12% | 5.17% |
| Node loop (V8 JIT) | 0.07977% | 2.38% | 2.75% |
| Java source-run (javac+JIT) | 0.26867% | 3.08% | 2.79% |

The 48% CPU-time RSD on the C loop is frequency scaling: under the default
`schedutil` governor a sub-second burst may run anywhere between base and
boost clocks, so the time to execute a fixed amount of work varies by half.
This is why isolate's documentation tells judge operators to pin frequencies
and disable turbo. The instruction count does not depend on clock frequency.

## Result 2 — the same workloads under full load

| workload | instructions | cpu_ms | wall_ms |
|---|---|---|---|
| C spin (volatile store-load) | **0.00001%** | 22.94% | 35.77% |
| C mem (64 MiB random walk) | **0.00003%** | 2.68% | 22.23% |
| Python arithmetic (seed pinned) | **0.00002%** | 1.22% | 39.70% |
| Python dict/str (seed pinned) | 0.15315% | 1.84% | 50.39% |
| Python dict/str (seed random) | 1.30568% | 1.04% | 33.54% |
| Node loop (V8 JIT) | 0.05348% | 0.42% | 41.17% |
| Java source-run (javac+JIT) | 0.57980% | 1.59% | 22.91% |

CPU-time RSD *improves* under load, because contention pegs the clock at a
constant all-core frequency. Run-to-run variance alone would therefore
suggest CPU time is stable on a busy judge; what actually moves is the mean.

## Result 3 — idle → loaded shift of the mean

| workload | instructions | cpu_ms | wall_ms |
|---|---|---|---|
| C spin (volatile store-load) | **+0.0000%** | −15.9% | +126.8% |
| C mem (64 MiB random walk) | **+0.0001%** | +34.7% | +160.9% |
| Python arithmetic (seed pinned) | **+0.0001%** | +116.7% | +436.5% |
| Python dict/str (seed pinned) | +0.0115% | +82.1% | +316.7% |
| Python dict/str (seed random) | +0.1971% | +76.1% | +522.1% |
| Node loop (V8 JIT) | −0.1618% | +86.3% | +419.0% |
| Java source-run (javac+JIT) | −0.2481% | +50.3% | +572.9% |

CPU time for the identical program moves by up to ~2.2× with machine load
(SMT contention halves per-thread retirement rate; all-core clocks differ
from burst clocks), and it moves in *both* directions: the C loop ran 16%
faster per CPU-second under load because contention held the clock higher
than the idle governor did. No fixed headroom factor absorbs a double-digit
swing in either direction. The instruction count moves ≤0.25% in the worst
(JIT) case and ≤0.0001% for compiled code.

The small negative shifts for Node and Java are real — JIT
background-compilation threads behave differently under contention — but at
0.16–0.25% they are 200–400× smaller than the CPU-time shift and are
absorbed by normal limit headroom.

## The dedicated-judge-box rerun

The numbers above come from a laptop in active desktop use, so two confounds
were checked against the raw per-run sequences in
`bench/results/latest.json`:

- **Thermal throttling** would show as a gradual slowdown as the package
  heats. The C-spin idle cpu_ms sequence —
  `213, 1103, 686, 1159, 1135, 526, 208, 1128, 674, 1125, 213, 841` — shows
  discrete speed states, no trend, and a return to 213 ms on run 11; the
  loaded (hotter) condition was 16% *faster* on this workload than idle.
- **Desktop interference** contributes through a specific mechanism: the
  ~5.4× slow runs match a governor-parked clock (4.28 → 1.4 GHz, ~3×)
  combined with landing on the SMT sibling of a busy core (~1.8×). The
  dominant effect is `schedutil` not ramping up for sub-second bursts.

The instruction counts of those same runs agreed to seven digits. What the
confounds do limit is the generality of the time-side magnitudes: a
dedicated judge server with a pinned governor and nothing else running shows
far smaller CPU-time noise than 48%. The study was therefore rerun in that
configuration: `performance` governor, boost disabled (fixed 2.9 GHz —
verified per run; the harness records package temperature and max core
frequency for every run), desktop apps closed (loadavg 0.5), 1 s cool-down
between runs.

| workload | insn RSD idle | cpu RSD idle | cpu RSD loaded | cpu shift under load |
|---|---|---|---|---|
| C lcg (register chain) | 0.00000% | 0.14% | 0.13% | **+0.6%** |
| C spin (volatile store-load) | 0.00002% | **83.56%** | 18.75% | −20.0% |
| C mem (64 MiB random walk) | 0.00002% | 1.07% | 1.56% | +37.2% |
| Python arithmetic (seed pinned) | 0.00052% | 0.48% | 0.66% | +71.6% |
| Python dict/str (seed pinned) | 0.16711% | 0.80% | 1.11% | +60.0% |
| Python dict/str (seed random) | 0.65986% | 0.75% | 1.79% | +64.5% |
| Node loop (V8 JIT) | 0.01904% | 0.22% | 0.82% | +53.6% |
| Java source-run (javac+JIT) | 0.24071% | 1.31% | 1.27% | +35.0% |

(Raw data: `bench/results/tuned.json`, `bench/results/tuned-lcg.json`.
Instruction shifts under load stayed ≤0.5% for every workload.)

Three results:

1. **Tuning works, within limits.** Idle CPU-time RSD collapses to
   0.14–1.6% for every well-behaved workload, but the loaded shift survives
   at +35–72%: SMT and cache contention are unaffected by governor settings.
2. **The load penalty is workload-dependent**, from +0.6% (latency-bound
   register chain, which shares an idle multiplier pipeline with its SMT
   sibling) to +72% (interpreter). The gradient is itself an unfairness: on
   a busy CPU-time judge, which solutions slow down depends on what kind of
   code they are.
3. **A microarchitectural counterexample.** The `volatile` store-load loop
   kept an 83% CPU-time RSD on the tuned machine — 283 ms to 2232 ms for
   the identical binary — with telemetry flat at 2900 MHz and 50 °C, ASLR
   disabled (`setarch -R`) making no difference, and a register-chain
   control at 0.14%. The bimodality lives in the memory-pipeline state of
   each process instance: a tuned, idle machine can still give the same
   program 8× different CPU time, and no operator configuration removes it.
   The instruction counts of those runs agreed to seven digits.

Read in both directions: a tuned, dedicated box judging one latency-bound
compiled submission at a time gets genuinely good CPU-time numbers — the
regime isolate's operational guidance (pin clocks, disable turbo, run
serially) is designed to create. Instruction counting removes the tuning
requirement (verdicts survive default governors, thermals, and desktop-class
hosts), allows judging on all cores concurrently without the +35–72%
cross-contamination, and is unaffected by effects like the store-forwarding
bimodality.

## Result 4 — noise sources, ranked

By measured RSD, idle:

1. **Hardware counter: ~1e-7**, including the page-fault-heavy workload.
   The Weaver & McKee overcount effects (page faults, interrupts) are real
   but four orders of magnitude below anything verdict-relevant; switching
   to retired-conditional-branch counting (rr's replay clock) would buy
   nothing measurable.
2. **CPython pointer-hashing residue: ~0.17%** (dict/str pinned). With the
   hash seed pinned, object-identity hashes still depend on ASLR addresses.
3. **JIT runtimes: ~0.08% (V8), ~0.27–0.58% (JVM).** Tiering decisions vary.
4. **CPython hash randomization: ~1.5%** (dict/str unpinned) — as noisy as
   CPU time. The sandbox must pin `PYTHONHASHSEED`; tallyrun does, inside
   `--clearenv`.

Practical limit headroom by runtime class: compiled ~1.001× measurement
noise, CPython ~1.01×, JIT runtimes ~1.02× — all absorbed by the ~2×
headroom problem setters already use.

## Result 5 — the sandbox startup offset

Instruction counts include bubblewrap's setup (the counter attaches before
exec so it can follow the whole process tree):

- bare run mean: 3,826,406,503 instructions (RSD 0.00002%)
- isolated (`--box`) mean: 3,861,451,374 instructions (RSD 0.00153%)
- offset: ~35.0M instructions ≈ 0.9% of this ~0.5 s Python workload

The offset is constant to within ~0.002% of a typical run and cancels when
limits are calibrated by running reference solutions through tallyrun —
which is how judges calibrate limits anyway.

## Reproduce

```bash
cargo build --release
python3 bench/measure.py            # full study, ~4 min; loads the machine in phase 2
python3 bench/measure.py --quick    # 30 s sanity check
```

Raw data lands in `bench/results/latest.json`. The harness needs
unprivileged perf access and a PMU — see the README's host requirements.
Results from other CPU microarchitectures are welcome: absolute counts are
expected to differ across CPU families; the claim under test is per-machine
variance and load invariance.

## Caveats

- One machine, one microarchitecture (Zen 2) so far, plus a functional check
  on a Hetzner Cloud KVM VM (its vPMU exposes the core counters; variance
  under noisy-neighbor co-tenancy is unmeasured). Absolute counts are
  **not** portable across CPU families; calibrate limits on the judging
  hardware class.
- The headline time-side magnitudes (48% RSD, +117% shift) are
  environment-specific: laptop, default `schedutil` governor, boost on,
  desktop in use. The dedicated-judge-box rerun above gives the tuned
  counterparts: idle CPU-time RSD of 0.14–1.6%, a loaded shift of +35–72%,
  and the store-forwarding bimodality intact.
- Variance of a fixed workload is the right proxy for verdict stability at a
  fixed limit, but this is not a full judging study (different submissions,
  checker overhead, I/O-heavy programs).
- Kernel-mode work is excluded from the count by design; syscall-heavy code
  is undercounted, which is why the CPU budget (`--cpu-s`) is part of the
  verdict contract.
- These numbers are consistent with COFFE's (0.003–0.005% instruction RSD vs
  2–5% time on their harness) and extend them with the loaded-machine and
  frequency-governor effects, which dominate in practice.
