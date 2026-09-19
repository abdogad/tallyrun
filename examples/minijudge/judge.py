#!/usr/bin/env python3
"""minijudge: a minimal judge built on tallyrun.

    python3 judge.py solutions/ac.py problem/
    python3 judge.py solutions/ac.c problem/

Takes one solution and one problem directory (tests/NN.in, NN.out and
limits.json) and prints AC, WA, CE, RE, TLE or MLE. tallyrun does the
isolation, the measurement and the killing; this script builds the command
lines, reads the JSON result and compares outputs.

TLE is decided on virtual time, instructions / INSN_PER_MS. For compiled
code that holds to ~1e-5 % whatever the machine load, so a solution gets the
same verdict on a busy laptop and an idle server. Where there's no PMU (most
CI), tallyrun reports measurement:"degraded" and the judge uses CPU time
instead, like a classic judge.
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

# How many retired instructions count as one millisecond of the time limit.
# 2e6/ms is sio2jail's convention: a 2 GHz CPU retiring one instruction per
# cycle. Calibrate it, and the per-problem limits, with reference solutions.
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
    """Run once in the sandbox and return the parsed JSON. tallyrun prints the
    JSON on its own stdout. The program's streams go to the --stdin, --stdout
    and --stderr files, which tallyrun opens outside the sandbox, so the
    program never sees the host paths."""
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
    if not lines:  # no JSON: tallyrun itself failed, not the solution
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
            # On Fedora-family hosts /usr/bin/ld is a symlink into
            # /etc/alternatives, so bind that read-only for compiling only.
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
                       wall_ms=2 * time_ms + 5000,  # only catches hangs
                       cpu_s=(3 * time_ms) // 1000 + 2,  # loose cap on CPU burn
                       mem_kb=mem_kb, insn_limit=time_ms * INSN_PER_MS)

            # Virtual time when the counter is live; measured CPU when degraded.
            if r["measurement"] == "full":
                used_ms = r["instructions"] // INSN_PER_MS
            else:
                used_ms = r["cpu_ms"]
            stat = (f"{used_ms:6d}/{time_ms} ms  {r['peak_kb']:7d}/{mem_kb} kB"
                    + ("  [degraded: CPU time]" if r["measurement"] != "full" else ""))

            if r["killed"] in ("instructions", "cpu") or used_ms > time_ms \
                    or r["timed_out"] or r["signal"] == 24:      # SIGXCPU from RLIMIT_CPU
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
