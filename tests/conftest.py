"""Shared harness: every test drives the release binary as a subprocess and
parses its one-line JSON contract — the same way a judge consumes runbox.

Capability probes make the suite portable: cgroup-dependent asserts skip
where delegation is unavailable (plain CI), instruction asserts skip without
a PMU (most CI runners). Locally, run the suite inside a fresh scope so the
cgroup dance doesn't migrate your desktop session, and with OOMPolicy=continue
so systemd doesn't stop the scope when a memory-bomb test gets OOM-killed:

    systemd-run --user --scope -q -p OOMPolicy=continue -- python3 -m pytest -v
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RUNBOX = REPO / "target" / "release" / "runbox"

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap not installed"
)


def run_box(box, argv, *, wall=5000, cpu_s=3, mem_kb=131072, insn=None,
            writable=False, binds=(), stdin=None, no_seccomp=False):
    """Run argv in the sandbox at `box`; return the parsed JSON result with
    the captured stdout text attached as res['_stdout']."""
    box = Path(box)
    out, err = box / "o", box / "e"
    cmd = [str(RUNBOX), "run", "--box", str(box),
           "--wall-ms", str(wall), "--cpu-s", str(cpu_s),
           "--mem-kb", str(mem_kb),
           "--stdout", str(out), "--stderr", str(err)]
    if insn is not None:
        cmd += ["--insn-limit", str(insn)]
    if writable:
        cmd += ["--writable"]
    for b in binds:
        cmd += ["--bind", b]
    if stdin is not None:
        cmd += ["--stdin", str(stdin)]
    if no_seccomp:
        cmd += ["--no-seccomp"]
    cmd += ["--", *argv]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    # runbox mirrors the child's exit code, so its own failures (usage error,
    # run failure) are recognized by the absence of the JSON line, not by code.
    lines = p.stdout.strip().splitlines()
    assert lines, f"runbox produced no result (exit {p.returncode}): {p.stderr}"
    res = json.loads(lines[-1])
    res["_stdout"] = out.read_text() if out.exists() else ""
    res["_stderr"] = err.read_text() if err.exists() else ""
    return res


def write_box(box, files):
    for name, content in files.items():
        (Path(box) / name).write_text(content)


def _probe():
    """One trivial isolated run tells us which capabilities this host has."""
    if not RUNBOX.exists() or shutil.which("bwrap") is None:
        return False, False
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        try:
            res = run_box(d, ["/bin/true"], wall=10000)
        except Exception:
            return False, False
    return res["accounting"] == "cgroup", res["measurement"] == "full"


if not RUNBOX.exists():
    pytest.exit(f"build the engine first: cargo build --release ({RUNBOX} missing)")

HAVE_CG, HAVE_INSN = _probe()


def pytest_report_header(config):
    # One glance at a CI log answers "what could this host measure?" —
    # e.g. a broken bwrap shows up as every capability False.
    return f"runbox capabilities: cgroup={HAVE_CG} instructions={HAVE_INSN}"

needs_cgroup = pytest.mark.skipif(
    not HAVE_CG, reason="cgroup delegation unavailable (accounting=rusage)"
)
needs_insn = pytest.mark.skipif(
    not HAVE_INSN, reason="perf instruction counting unavailable (no PMU / paranoid)"
)
