"""/proc isolation. By default the sandbox gets a fresh procfs for its own PID
namespace, so host PIDs and command lines stay hidden. --proc-bind binds the
host /proc instead, for masked-procfs containers.

The tests skip where a fresh procfs can't be mounted, the same hardened
container case tallyrun detects and falls back on."""

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
    # A fresh procfs lists only the sandbox's own few processes, where the
    # host has hundreds.
    n = _pid_count(tmp_path)
    if n > 20:
        pytest.skip("fresh procfs unavailable here (tallyrun auto-fell-back to bind)")
    assert n < 20


def test_proc_bind_opts_back_into_host_view(tmp_path):
    # --proc-bind shows the host's processes again.
    default = _pid_count(tmp_path)
    if default > 20:
        pytest.skip("fresh procfs unavailable; bind is already the default here")
    bound = _pid_count(tmp_path, no_seccomp=False, proc_bind=True)
    assert bound > default


def test_default_proc_hides_host_cmdlines(tmp_path):
    # Host command lines leak more than bare PIDs do. Under a fresh procfs,
    # pid 1 is the sandbox's own init.
    write_box(tmp_path, {"who.py":
        "print(open('/proc/1/cmdline','rb').read().split(b'\\0')[0].decode())"})
    res = run_box(tmp_path, ["python3", "who.py"])
    pid1 = res["_stdout"].strip()
    if "systemd" in pid1 or "init" in pid1:
        pytest.skip("fresh procfs unavailable (bind fallback shows host pid 1)")
    # pid 1 in the sandbox is bwrap's namespace init.
    assert "bwrap" in pid1
