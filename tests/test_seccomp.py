"""The seccomp denylist. Dangerous syscalls fail, and the ones runtimes probe
return ENOSYS so they take their fallback paths (glibc clone3 -> clone, libuv
io_uring -> epoll). Each probe exits with the errno its syscall returned.

The filter is on by default, so the rest of the suite also checks that it
doesn't break ordinary programs."""

import shutil

import pytest

from conftest import run_box, write_box

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap not installed"
)

EPERM, ENOSYS = 1, 38
# These numbers are the same on x86_64 and aarch64.
SYS_CLONE3, SYS_IO_URING_SETUP = 435, 425

PROBE = """\
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
rc = {call}
sys.exit(0 if rc == 0 else ctypes.get_errno())
"""


def errno_of(box, call, *, no_seccomp=False):
    write_box(box, {"probe.py": PROBE.format(call=call)})
    return run_box(box, ["python3", "probe.py"], no_seccomp=no_seccomp)["exit_code"]


def test_nested_userns_is_blocked(tmp_path):
    # unshare(CLONE_NEWUSER) makes an unprivileged user root inside a new
    # namespace, the step behind most container-era kernel LPEs.
    assert errno_of(tmp_path, "libc.unshare(0x10000000)") == EPERM


def test_fork_and_subprocess_survive_the_filter(tmp_path):
    # clone3 returns ENOSYS, so glibc falls back to clone(), whose flags the
    # filter checks (unit tests in src/seccomp.rs). If that fallback broke,
    # fork and subprocess would fail in every runtime.
    write_box(tmp_path, {"fork.py":
        "import subprocess, sys\n"
        "sys.exit(subprocess.run(['/bin/true']).returncode)\n"})
    assert run_box(tmp_path, ["python3", "fork.py"])["exit_code"] == 0


def test_clone3_reads_as_enosys_for_glibc_fallback(tmp_path):
    assert errno_of(tmp_path, f"libc.syscall({SYS_CLONE3}, None, 0)") == ENOSYS


def test_io_uring_reads_as_enosys_for_libuv_fallback(tmp_path):
    assert errno_of(tmp_path, f"libc.syscall({SYS_IO_URING_SETUP}, 1, None)") == ENOSYS


def test_ptrace_is_blocked(tmp_path):
    # PTRACE_TRACEME succeeds unprivileged when allowed, so EPERM here can
    # only come from the filter.
    assert errno_of(tmp_path, "libc.ptrace(0, 0, 0, 0)") == EPERM


def test_no_seccomp_flag_removes_the_filter(tmp_path):
    # Without the filter, clone3(NULL, 0) reaches the kernel and fails with
    # EINVAL instead of the filter's ENOSYS.
    errno = errno_of(tmp_path, f"libc.syscall({SYS_CLONE3}, None, 0)",
                     no_seccomp=True)
    assert errno != ENOSYS
