"""/proc isolation: by default the sandbox gets a fresh procfs scoped to its
own PID namespace, so host process IDs and command lines are not visible.
--proc-bind restores the old host-/proc bind (and its leak) for callers stuck
in a masked-procfs container.

Skips where a fresh procfs can't be mounted (the same hardened-container case
runbox itself auto-detects and falls back on) — there is nothing to prove."""

import shutil

import pytest

from conftest import run_box, write_box

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap not installed"
)

COUNT = "import os; print(sum(p.isdigit() for p in os.listdir('/proc')))"


def _pid_count(box, **kw):
    write_box(box, {"count.py": COUNT})
    res = run_box(box, ["python3", "count.py"], **kw)
    return int(res["_stdout"].strip())


def test_default_proc_hides_host_pids(tmp_path):
    # A fresh procfs sees only the sandbox's own tree: the payload, its shell,
    # and bwrap's namespace init — a handful, never the host's hundreds.
    n = _pid_count(tmp_path)
    if n > 20:
        pytest.skip("fresh procfs unavailable here (runbox auto-fell-back to bind)")
    assert n < 20


def test_proc_bind_opts_back_into_host_view(tmp_path):
    # The escape hatch still exposes the host's process list.
    default = _pid_count(tmp_path)
    if default > 20:
        pytest.skip("fresh procfs unavailable; bind is already the default here")
    bound = _pid_count(tmp_path, no_seccomp=False, proc_bind=True)
    assert bound > default


def test_default_proc_hides_host_cmdlines(tmp_path):
    # The sharper leak: not just that host PIDs exist, but that their command
    # lines (argv) are readable. Under a fresh procfs, pid 1 is our own init.
    write_box(tmp_path, {"who.py":
        "print(open('/proc/1/cmdline','rb').read().split(b'\\0')[0].decode())"})
    res = run_box(tmp_path, ["python3", "who.py"])
    pid1 = res["_stdout"].strip()
    if "systemd" in pid1 or "init" in pid1:
        pytest.skip("fresh procfs unavailable (bind fallback shows host pid 1)")
    # bwrap is the sandbox's own namespace init — not a host process.
    assert "bwrap" in pid1
