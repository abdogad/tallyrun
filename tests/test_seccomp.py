"""The seccomp denylist: kernel attack surface is closed to sandboxed code,
and blocked-but-probed syscalls read as ENOSYS so runtimes take their tested
fallback paths (glibc clone3 -> clone, libuv io_uring -> epoll). Probes exit
with the errno the syscall produced, so the asserts read as errno checks.

The rest of the suite doubles as the compatibility proof: every other test
(fork bombs, compiles, floods) runs under the default-on filter."""

import shutil

import pytest

from conftest import run_box, write_box

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap not installed"
)

EPERM, ENOSYS = 1, 38
# Generic syscall numbers — identical on x86_64 and aarch64.
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
    # unshare(CLONE_NEWUSER): the "unprivileged user gains a namespace where
    # it is root" amplifier behind most container-era kernel LPEs.
    assert errno_of(tmp_path, "libc.unshare(0x10000000)") == EPERM


def test_fork_and_subprocess_survive_the_filter(tmp_path):
    # The compatibility keystone: clone3 -> ENOSYS forces glibc onto clone(),
    # whose flags the filter inspects (CLONE_NEWUSER denied, fork/thread
    # shapes allowed — flag semantics unit-tested in src/seccomp.rs). If the
    # fallback chain broke, every subprocess/fork in every runtime would too.
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
    # Differential proof the flag works: clone3(NULL, 0) hits the real kernel
    # and fails argument validation (EINVAL) instead of the filter's ENOSYS.
    errno = errno_of(tmp_path, f"libc.syscall({SYS_CLONE3}, None, 0)",
                     no_seccomp=True)
    assert errno != ENOSYS
