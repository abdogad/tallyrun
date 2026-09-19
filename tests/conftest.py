"""Test harness. Each test runs the release binary as a subprocess and parses
its JSON line, the same way a judge would.

The suite probes the host first: cgroup asserts skip without cgroup
delegation (plain CI), and instruction asserts skip without a PMU (most CI
runners).

Every tallyrun call runs in its own transient systemd scope with
OOMPolicy=continue. Started straight from an IDE terminal, tallyrun's cgroup
setup would move the processes of the IDE's scope, and a memory-bomb test's
OOM kill would be counted in that scope's memory.events. systemd's default
OOMPolicy=stop then stops the whole scope, editor included (the desktop
calls it "memory shortage avoided"). The transient scope is a sibling of the
IDE's, so the event never reaches it. Without a systemd user manager (CI
containers) runs go unscoped, which is fine there.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TALLYRUN = REPO / "target" / "release" / "tallyrun"


def _scope_prefix():
    """Prefix that runs one tallyrun call in its own systemd scope (see the
    module docstring), or [] when no user manager answers (CI)."""
    if shutil.which("systemd-run") is None:
        return []
    prefix = ["systemd-run", "--user", "--scope", "-q",
              "-p", "OOMPolicy=continue", "--"]
    probe = subprocess.run([*prefix, "/bin/true"], capture_output=True)
    return prefix if probe.returncode == 0 else []


SCOPE = _scope_prefix()

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap not installed"
)


def run_box(box, argv, *, wall=5000, cpu_s=3, mem_kb=131072, insn=None,
            writable=False, binds=(), stdin=None, no_seccomp=False,
            proc_bind=False, pin_cpu=None):
    """Run argv in the sandbox at `box` and return the parsed JSON, with the
    program's output added as res['_stdout'] and res['_stderr']."""
    box = Path(box)
    out, err = box / "o", box / "e"
    cmd = [*SCOPE, str(TALLYRUN), "run", "--box", str(box),
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
    if proc_bind:
        cmd += ["--proc-bind"]
    if pin_cpu is not None:
        cmd += ["--pin-cpu", str(pin_cpu)]
    cmd += ["--", *argv]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    # The exit code mirrors the payload's, so a failure in tallyrun itself
    # shows up as a missing JSON line.
    lines = p.stdout.strip().splitlines()
    assert lines, f"tallyrun produced no result (exit {p.returncode}): {p.stderr}"
    res = json.loads(lines[-1])
    res["_stdout"] = out.read_text() if out.exists() else ""
    res["_stderr"] = err.read_text() if err.exists() else ""
    return res


def write_box(box, files):
    for name, content in files.items():
        (Path(box) / name).write_text(content)


def _probe():
    """Run /bin/true once to see what this host can measure."""
    if not TALLYRUN.exists() or shutil.which("bwrap") is None:
        return False, False
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        try:
            res = run_box(d, ["/bin/true"], wall=10000)
        except Exception:
            return False, False
    return res["accounting"] == "cgroup", res["measurement"] == "full"


if not TALLYRUN.exists():
    pytest.exit(f"build the engine first: cargo build --release ({TALLYRUN} missing)")

HAVE_CG, HAVE_INSN = _probe()


def pytest_report_header(config):
    # Puts what the host could measure at the top of the CI log. A broken
    # bwrap shows up as everything False.
    return f"tallyrun capabilities: cgroup={HAVE_CG} instructions={HAVE_INSN}"

needs_cgroup = pytest.mark.skipif(
    not HAVE_CG, reason="cgroup delegation unavailable (accounting=rusage)"
)
needs_insn = pytest.mark.skipif(
    not HAVE_INSN, reason="perf instruction counting unavailable (no PMU / paranoid)"
)
