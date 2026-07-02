# minijudge — a complete judge in ~100 lines on top of runbox

Everything a judge needs from a sandbox — isolation, load-invariant
measurement, limit enforcement, killing — lives in the `runbox` binary. What
remains, and what this example shows, is pure policy glue: build the CLI
invocation, parse the one-line JSON result, compare outputs, name the verdict.

```console
$ cargo build --release            # from the repo root
$ cd examples/minijudge
$ python3 judge.py solutions/ac.py problem/
ok   01      68/1000 ms     5992/65536 kB
ok   02      68/1000 ms     5976/65536 kB
ok   03      68/1000 ms     5920/65536 kB
AC
$ python3 judge.py solutions/tle.py problem/
TLE  01    1004/1000 ms     5972/65536 kB
$ python3 judge.py solutions/mle.py problem/
MLE  01      65/1000 ms    81920/65536 kB
```

`solutions/` holds one file per verdict: `ac.py`, `wa.py`, `tle.py`, `mle.py`,
`re.py`, plus `ac.c` to show the compile-inside-the-box flow (`--writable`).
`problem/` is `limits.json` + `tests/NN.in`/`NN.out`.

## The pattern

One `runbox run` per execution, verdict decided from the JSON:

| JSON field | verdict use |
|---|---|
| `instructions`, `killed:"instructions"` | TLE on *virtual time* = instructions / `INSN_PER_MS` — load-invariant |
| `measurement` | `"degraded"` = no PMU: fall back to `cpu_ms` like a classic judge |
| `peak_kb` (cgroup `memory.peak`, whole subtree) | MLE |
| `timed_out` / `killed:"wall"` | genuine hang (sleeping, deadlock) — safety net only |
| `exit_code`, `signal` | RE / the SIGXCPU (24) runaway backstop |
| `accounting` | `"cgroup"`, `"cpu-only"` or `"rusage"` — how trustworthy cpu/peak are |

The instruction budget is the one policy knob: `INSN_PER_MS` (default
2 000 000 — sio2jail's "2 GHz virtual CPU" convention) converts a per-problem
ms limit into instructions. Calibrate it against reference solutions on your
own problems; a production example with a deliberately conservative choice is
CodeClash's `judge/judging.py`.

Run it under a scope locally so runbox's self-service cgroup setup stays out
of your desktop session and an OOM-killed `mle.py` can't stop the scope:

```console
$ systemd-run --user --scope -q -p OOMPolicy=continue -- \
      python3 judge.py solutions/mle.py problem/
```
