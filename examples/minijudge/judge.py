#!/usr/bin/env python3
"""minijudge — the smallest real judge you can build on tallyrun.

    python3 judge.py solutions/ac.py problem/
    python3 judge.py solutions/tle.c problem/

One solution, one problem directory (tests/NN.in + NN.out + limits.json),
verdicts AC/WA/CE/RE/TLE/MLE. ~100 lines of stdlib glue: tallyrun does the
isolation (bubblewrap), the measurement (retired-instruction counter, per-run
cgroup) and the killing; this script only builds CLI invocations, parses the
one-line JSON contract, and compares outputs.

The point of instructions: the TLE verdict is decided on *virtual time* —
instructions / INSN_PER_MS — which is load-invariant to ~1e-5 % for compiled
code, so the same solution gets the same verdict on a busy laptop and an idle
server. On hosts without a PMU (most CI) tallyrun reports measurement:"degraded"
and this judge falls back to measured CPU time, like a classic judge.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_LOCAL_BUILD = HERE.parent.parent / "target" / "release" / "tallyrun"
TALLYRUN = os.environ.get("TALLYRUN") or (
    _LOCAL_BUILD if _LOCAL_BUILD.exists() else shutil.which("tallyrun"))

# The virtual clock: how many retired instructions one millisecond of the
# problem's time limit buys. 2e6/ms = sio2jail's "2 GHz CPU retiring one
# instruction per cycle" convention. It is a policy knob: calibrate it (and
# per-problem limits) with reference solutions on your own workloads.
INSN_PER_MS = int(os.environ.get("INSN_PER_MS", 2_000_000))

LANGS = {
    ".py": {"compile": None,
            "run": ["/usr/bin/python3", "solution.py"], "source": "solution.py"},
    ".c": {"compile": ["/usr/bin/gcc", "-O2", "-o", "/box/solution", "/box/solution.c"],
           "run": ["/box/solution"], "source": "solution.c"},
    ".cpp": {"compile": ["/usr/bin/g++", "-O2", "-o", "/box/solution", "/box/solution.cpp"],
             "run": ["/box/solution"], "source": "solution.cpp"},
}


def tallyrun(box, argv, *, stdin="/dev/null", stdout="/dev/null", stderr,
           wall_ms, cpu_s, mem_kb, insn_limit=None, writable=False, binds=()):
    """One sandboxed execution -> the parsed JSON result. tallyrun prints the
    result on ITS stdout; the sandboxed program's streams go to the files
    passed via --stdin/--stdout/--stderr (opened outside the sandbox, so the
    program never sees the host paths)."""
    cmd = [str(TALLYRUN), "run", "--box", str(box),
           "--stdin", str(stdin), "--stdout", str(stdout), "--stderr", str(stderr),
           "--wall-ms", str(wall_ms), "--cpu-s", str(cpu_s), "--mem-kb", str(mem_kb)]
    if insn_limit is not None:
        cmd += ["--insn-limit", str(insn_limit)]
    if writable:
        cmd += ["--writable"]
    for b in binds:
        cmd += ["--bind", b]
    p = subprocess.run(cmd + ["--", *argv], capture_output=True, text=True)
    lines = p.stdout.strip().splitlines()
    if not lines:  # no JSON = tallyrun itself failed (infra, not the solution)
        sys.exit(f"tallyrun failed: {p.stderr.strip()}")
    return json.loads(lines[-1])


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip().splitlines()[2].strip())
    solution, problem = Path(sys.argv[1]), Path(sys.argv[2])
    lang = LANGS.get(solution.suffix) or sys.exit(f"no language for {solution.suffix}")
    limits = json.loads((problem / "limits.json").read_text())
    time_ms, mem_kb = limits["time_ms"], limits["mem_kb"]

    box = Path(tempfile.mkdtemp(prefix="minijudge-"))
    try:
        shutil.copy(solution, box / lang["source"])
        err = box / "stderr"

        if lang["compile"]:  # build inside the box (--writable), generous limits
            # Fedora-family hosts route /usr/bin/ld through /etc/alternatives
            # symlinks; lend the compile step (only) that directory read-only.
            binds = (["/etc/alternatives:/etc/alternatives"]
                     if Path("/etc/alternatives").is_dir() else [])
            r = tallyrun(box, lang["compile"], stderr=err, binds=binds,
                       wall_ms=15000, cpu_s=12, mem_kb=512 * 1024, writable=True)
            if r["exit_code"] != 0:
                print(f"CE\n{err.read_text()[:400]}")
                return 1

        for tin in sorted(problem.glob("tests/*.in")):
            out, expected = box / "stdout", tin.with_suffix(".out")
            r = tallyrun(box, lang["run"], stdin=tin, stdout=out, stderr=err,
                       wall_ms=2 * time_ms + 5000,  # hang net; never the verdict
                       cpu_s=(3 * time_ms) // 1000 + 2,  # runaway burn bound
                       mem_kb=mem_kb, insn_limit=time_ms * INSN_PER_MS)

            # Virtual time when the counter is live; measured CPU when degraded.
            if r["measurement"] == "full":
                used_ms = r["instructions"] // INSN_PER_MS
            else:
                used_ms = r["cpu_ms"]
            stat = (f"{used_ms:6d}/{time_ms} ms  {r['peak_kb']:7d}/{mem_kb} kB"
                    + ("  [degraded: CPU time]" if r["measurement"] != "full" else ""))

            if r["killed"] in ("instructions", "cpu") or used_ms > time_ms \
                    or r["timed_out"] or r["signal"] == 24:      # SIGXCPU backstop
                print(f"TLE  {tin.stem}  {stat}")
                return 1
            if r["peak_kb"] > mem_kb:
                print(f"MLE  {tin.stem}  {stat}")
                return 1
            if r["exit_code"] != 0:
                sig = f" (signal {r['signal']})" if r["signal"] else ""
                print(f"RE   {tin.stem}  exit {r['exit_code']}{sig}  "
                      f"{err.read_text()[:200].strip()}")
                return 1
            if out.read_text().split() != expected.read_text().split():
                print(f"WA   {tin.stem}  {stat}")
                return 1
            print(f"ok   {tin.stem}  {stat}")
        print("AC")
        return 0
    finally:
        shutil.rmtree(box, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
