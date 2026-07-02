#!/usr/bin/env python3
"""runbox variance study: instruction count vs CPU time vs wall time.

Methodology follows COFFE (arXiv:2502.02827): run each workload N times,
drop the min and max, report the relative standard deviation (RSD) of the
rest. Conditions: idle machine, then loaded (2x nproc shell busy-loops).
Also measures the bwrap isolation offset (isolated minus bare instruction
count) and its run-to-run stability.

All runs go through `runbox run --no-isolate` so cpu_ms/peak_kb come from
wait4 on the payload itself (no PID-namespace blind spot); the isolation
offset experiment is the only part that uses `--box`.

Usage:
    python bench/measure.py               # full study (~3-5 min, lags the box)
    python bench/measure.py --quick       # 4 runs, idle only (sanity check)
    python bench/measure.py --skip-load   # skip the loaded condition

Needs: target/release/runbox, cc. Optional: node, java (>= 11).
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
REPO = BENCH.parent
RUNBOX = REPO / "target" / "release" / "runbox"
WL = BENCH / "workloads"
PY = sys.executable or "/usr/bin/python3"


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def _cpu_temp_sensor():
    for h in Path("/sys/class/hwmon").glob("hwmon*"):
        try:
            if (h / "name").read_text().strip() in ("k10temp", "coretemp", "zenpower"):
                return h / "temp1_input"
        except OSError:
            pass
    return None


TEMP_SENSOR = _cpu_temp_sensor()


def telemetry():
    """(package °C, max core MHz) right now — evidence against thermal/governor
    confounds: thermal drift shows as temp trending with cpu_ms, governor
    parking as low MHz on slow runs."""
    temp = None
    if TEMP_SENSOR:
        temp = int(TEMP_SENSOR.read_text()) // 1000
    mhz = 0.0
    with open("/proc/cpuinfo") as f:
        for ln in f:
            if ln.startswith("cpu MHz"):
                mhz = max(mhz, float(ln.split(":", 1)[1]))
    return temp, round(mhz)


def build_workloads(tmp):
    """Compile what needs compiling; return [(name, argv, env_overrides)].

    env_overrides: value None means "must be unset"; everything else is set.
    """
    wl = []
    cc = shutil.which("cc")
    if cc:
        for src, name in [
            ("lcg.c", "C lcg (register chain)"),
            ("spin.c", "C spin (volatile store-load)"),
            ("mem.c", "C mem (64 MiB random walk)"),
        ]:
            out = tmp / src.removesuffix(".c")
            subprocess.run([cc, "-O2", "-o", str(out), str(WL / src)], check=True)
            wl.append((name, [str(out)], {}))
    else:
        log("warning: no C compiler, skipping native workloads")
    wl += [
        ("Python arithmetic (seed pinned)", [PY, str(WL / "cpu.py")], {"PYTHONHASHSEED": "0"}),
        ("Python dict/str (seed pinned)", [PY, str(WL / "dict.py")], {"PYTHONHASHSEED": "0"}),
        ("Python dict/str (seed random)", [PY, str(WL / "dict.py")], {"PYTHONHASHSEED": None}),
    ]
    node = shutil.which("node")
    if node:
        wl.append(("Node loop (V8 JIT)", [node, str(WL / "fib.js")], {}))
    java = shutil.which("java")
    if java:
        wl.append(("Java source-run (javac+JIT)", [java, str(WL / "Spin.java")], {}))
    return wl


def run_once(argv, env_over, extra_flags=()):
    env = dict(os.environ)
    env.pop("PYTHONHASHSEED", None)
    for k, v in env_over.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    iso = () if "--box" in extra_flags else ("--no-isolate",)
    cmd = [str(RUNBOX), "run", *iso, "--wall-ms", "120000",
           "--stdout", "/dev/null", *extra_flags, "--", *argv]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
    r = json.loads(line)
    if r["exit_code"] != 0 or r["measurement"] != "full":
        raise RuntimeError(f"bad run {cmd}: {line} {p.stderr}")
    return r


def study(workloads, runs, label, cooldown=0.0):
    out = []
    for name, argv, env in workloads:
        log(f"  [{label}] {name} ({runs} runs)...")
        run_once(argv, env)  # warm-up: page cache, first-compile; discarded
        rows, temps, mhzs = [], [], []
        for _ in range(runs):
            if cooldown:
                time.sleep(cooldown)
            t, m = telemetry()
            temps.append(t)
            mhzs.append(m)
            rows.append(run_once(argv, env))
        out.append({
            "name": name,
            "instructions": [r["instructions"] for r in rows],
            "cpu_ms": [r["cpu_ms"] for r in rows],
            "wall_ms": [r["wall_ms"] for r in rows],
            "temp_c": temps,
            "cpu_mhz": mhzs,
        })
    return out


def isolation_offset(runs):
    """Same workload bare vs bwrap-isolated: the offset and its stability."""
    log(f"  [offset] Python arithmetic, bare vs --box ({runs} runs each)...")
    with tempfile.TemporaryDirectory() as box:
        shutil.copy(WL / "cpu.py", box)
        os.chmod(box, 0o755)
        pin = {"PYTHONHASHSEED": "0"}
        bare = [run_once([PY, str(WL / "cpu.py")], pin)["instructions"]
                for _ in range(runs)]
        # bwrap pins PYTHONHASHSEED itself; binary resolved via sandbox PATH
        iso = [run_once(["python3", "cpu.py"], pin, ("--box", box))["instructions"]
               for _ in range(runs)]
    return {"bare": bare, "isolated": iso}


class Load:
    """2x-nproc shell busy-loops: oversubscription + all-core boost clocks."""

    def __init__(self, n):
        self.n, self.procs = n, []

    def __enter__(self):
        log(f"  spinning up {self.n} busy-loop load processes...")
        self.procs = [subprocess.Popen(["sh", "-c", "while :; do :; done"])
                      for _ in range(self.n)]
        return self

    def __exit__(self, *_exc):
        for p in self.procs:
            p.kill()
        for p in self.procs:
            p.wait()
        log("  load processes killed")


def trimmed(xs):
    xs = sorted(xs)
    return xs[1:-1] if len(xs) > 4 else xs


def rsd(xs):
    t = trimmed(xs)
    m = statistics.mean(t)
    return statistics.stdev(t) / m * 100 if m and len(t) > 1 else float("nan")


def mean(xs):
    return statistics.mean(trimmed(xs))


def machine_info():
    model = ""
    with open("/proc/cpuinfo") as f:
        for ln in f:
            if ln.startswith("model name"):
                model = ln.split(":", 1)[1].strip()
                break
    paranoid = Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip()
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    boost = Path("/sys/devices/system/cpu/cpufreq/boost")
    return {
        "cpu": model,
        "nproc": os.cpu_count(),
        "kernel": platform.release(),
        "perf_event_paranoid": paranoid,
        "governor": gov.read_text().strip() if gov.exists() else "n/a",
        "boost": boost.read_text().strip() if boost.exists() else "n/a",
        "python": platform.python_version(),
        "date": datetime.date.today().isoformat(),
    }


def report(results):
    md = []
    for label in [k for k in ("idle", "loaded") if results.get(k)]:
        md.append(f"\n### RSD, {label} machine (N={results['runs']}, min/max trimmed)\n")
        md.append("| workload | instructions | cpu_ms | wall_ms |")
        md.append("|---|---|---|---|")
        for w in results[label]:
            md.append(f"| {w['name']} | {rsd(w['instructions']):.5f}% "
                      f"| {rsd(w['cpu_ms']):.2f}% | {rsd(w['wall_ms']):.2f}% |")
    if results.get("loaded"):
        md.append("\n### Idle -> loaded shift of the mean (verdict-flipping pressure)\n")
        md.append("| workload | instructions | cpu_ms | wall_ms |")
        md.append("|---|---|---|---|")
        for wi, wl in zip(results["idle"], results["loaded"]):
            def shift(key):
                a, b = mean(wi[key]), mean(wl[key])
                return (b - a) / a * 100 if a else float("nan")
            md.append(f"| {wi['name']} | {shift('instructions'):+.4f}% "
                      f"| {shift('cpu_ms'):+.1f}% | {shift('wall_ms'):+.1f}% |")
    off = results.get("offset")
    if off:
        d = mean(off["isolated"]) - mean(off["bare"])
        md.append("\n### bwrap isolation offset (instructions)\n")
        md.append(f"- bare mean: {mean(off['bare']):,.0f} (RSD {rsd(off['bare']):.5f}%)")
        md.append(f"- isolated mean: {mean(off['isolated']):,.0f} (RSD {rsd(off['isolated']):.5f}%)")
        md.append(f"- offset: {d:,.0f} instructions "
                  f"({d / mean(off['bare']) * 100:.3f}% of this workload)")
    return "\n".join(md)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=12)
    ap.add_argument("--quick", action="store_true", help="4 runs, idle only")
    ap.add_argument("--skip-load", action="store_true")
    ap.add_argument("--cooldown", type=float, default=0.0,
                    help="seconds to sleep before each run (thermal settling)")
    ap.add_argument("--out", default=str(BENCH / "results" / "latest.json"))
    args = ap.parse_args()
    if args.quick:
        args.runs, args.skip_load = 4, True

    if not RUNBOX.exists():
        sys.exit("build first: cargo build --release")
    if os.getloadavg()[0] > 2:
        log(f"warning: loadavg {os.getloadavg()[0]:.1f} — 'idle' numbers will be dirty")

    results = {"machine": machine_info(), "runs": args.runs}
    with tempfile.TemporaryDirectory() as tmp:
        workloads = build_workloads(Path(tmp))
        log("== idle condition ==")
        results["idle"] = study(workloads, args.runs, "idle", args.cooldown)
        results["offset"] = isolation_offset(args.runs)
        if not args.skip_load:
            log("== loaded condition ==")
            with Load(2 * (os.cpu_count() or 4)):
                results["loaded"] = study(workloads, args.runs, "loaded", args.cooldown)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=1))
    log(f"raw data -> {out}")
    print(f"Machine: {results['machine']['cpu']}, kernel {results['machine']['kernel']}, "
          f"governor {results['machine']['governor']}, boost {results['machine']['boost']}, "
          f"perf_event_paranoid={results['machine']['perf_event_paranoid']}")
    print(report(results))


if __name__ == "__main__":
    main()
