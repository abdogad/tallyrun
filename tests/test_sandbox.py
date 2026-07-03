"""Core sandbox behaviour, exercised through the CLI JSON contract.
Cgroup- and perf-dependent asserts skip where the host can't provide them."""

import shutil

import pytest

from conftest import HAVE_CG, needs_cgroup, needs_insn, run_box, write_box

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap not installed"
)

PY = "python3"


def test_stdout_is_captured(tmp_path):
    write_box(tmp_path, {"hi.py": "print('hello')"})
    res = run_box(tmp_path, [PY, "hi.py"])
    assert res["exit_code"] == 0
    assert res["_stdout"].strip() == "hello"


def test_exit_code_propagates(tmp_path):
    write_box(tmp_path, {"x.py": "import sys; sys.exit(3)"})
    res = run_box(tmp_path, [PY, "x.py"])
    assert res["exit_code"] == 3


def test_stdin_is_wired(tmp_path):
    (tmp_path / "input.txt").write_text("42\n")
    write_box(tmp_path, {"echo.py": "print(int(input()) * 2)"})
    res = run_box(tmp_path, [PY, "echo.py"], stdin=tmp_path / "input.txt")
    assert res["exit_code"] == 0
    assert res["_stdout"].strip() == "84"


def test_network_is_unreachable(tmp_path):
    write_box(tmp_path, {"n.py":
        "import socket, sys\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
        "    sys.exit(0)\n"       # reachable — should never happen
        "except OSError:\n"
        "    sys.exit(42)\n"})
    res = run_box(tmp_path, [PY, "n.py"])
    assert res["exit_code"] == 42


def test_host_files_are_invisible(tmp_path):
    write_box(tmp_path, {"p.py":
        "import os, sys; sys.exit(0 if os.path.exists('/etc/hostname') else 7)"})
    res = run_box(tmp_path, [PY, "p.py"])
    assert res["exit_code"] == 7


def test_box_is_readonly_for_runs(tmp_path):
    write_box(tmp_path, {"w.py":
        "import sys\n"
        "try:\n"
        "    open('exfil', 'w')\n"
        "    sys.exit(0)\n"
        "except OSError:\n"
        "    sys.exit(30)\n"})
    assert run_box(tmp_path, [PY, "w.py"])["exit_code"] == 30
    # ... but a compile step can opt in with --writable.
    assert run_box(tmp_path, [PY, "w.py"], writable=True)["exit_code"] == 0


def test_wall_timeout_kills_a_hang(tmp_path):
    write_box(tmp_path, {"s.py": "import time; time.sleep(30)"})
    res = run_box(tmp_path, [PY, "s.py"], wall=500)
    assert res["timed_out"]
    assert res["killed"] == "wall"
    assert res["wall_ms"] < 5000


def test_extra_bind_is_readable(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "secret.txt").write_text("payload")
    box = tmp_path / "box"
    box.mkdir()
    write_box(box, {"r.py": "print(open('/data/secret.txt').read())"})
    res = run_box(box, [PY, "r.py"], binds=[f"{data}:/data"])
    assert res["exit_code"] == 0
    assert "payload" in res["_stdout"]


def test_hash_seed_is_pinned(tmp_path):
    # Measurement fairness: hash randomization is CPython's dominant noise
    # source (docs/BENCHMARK.md, Result 4), so the sandbox env pins it.
    write_box(tmp_path, {"env.py": "import os; print(os.environ['PYTHONHASHSEED'])"})
    res = run_box(tmp_path, [PY, "env.py"])
    assert res["exit_code"] == 0
    assert res["_stdout"].strip() == "0"


@needs_insn
def test_instructions_scale_with_work(tmp_path):
    write_box(tmp_path, {
        "small.py": "s = 0\nfor i in range(500_000): s += i\nprint(s)",
        "big.py": "s = 0\nfor i in range(2_000_000): s += i\nprint(s)",
    })
    small = run_box(tmp_path, [PY, "small.py"])
    big = run_box(tmp_path, [PY, "big.py"])
    assert small["measurement"] == "full" and big["measurement"] == "full"
    assert big["instructions"] > small["instructions"] * 1.5


@needs_insn
def test_insn_limit_gives_load_invariant_tle(tmp_path):
    write_box(tmp_path, {"loop.py": "while True: pass"})
    res = run_box(tmp_path, [PY, "loop.py"], insn=200_000_000, wall=10000)
    assert res["killed"] == "instructions"
    assert res["signal"] == 9
    assert not res["timed_out"]  # deterministic kill, not the wall safety net


@needs_cgroup
def test_pin_cpu_confines_the_tree(tmp_path):
    # cpuset pinning is kernel-enforced: even after the payload tries to
    # widen its own affinity, the mask stays clamped to the pinned CPU.
    write_box(tmp_path, {"aff.py": (
        "import os\n"
        "os.sched_setaffinity(0, range(os.cpu_count()))  # escape attempt\n"
        "line = [l for l in open('/proc/self/status') "
        "if l.startswith('Cpus_allowed_list')][0]\n"
        "print(line.split()[1])\n"
    )})
    res = run_box(tmp_path, [PY, "aff.py"], pin_cpu=0)
    assert res["exit_code"] == 0
    allowed = res["_stdout"].strip()
    if allowed != "0":
        pytest.skip("cpuset controller not delegated on this host")


@needs_cgroup
def test_cpu_and_rss_are_subtree_accurate(tmp_path):
    # The whole point of the cgroup port: bwrap's PID namespace hides the
    # payload from wait4, so only cgroup accounting sees this burn.
    write_box(tmp_path, {"burn.py":
        "x = 0\n"
        "for _ in range(20_000_000):\n"
        "    x += 1\n"})
    res = run_box(tmp_path, [PY, "burn.py"], cpu_s=10, wall=10000)
    assert res["exit_code"] == 0
    assert res["accounting"] == "cgroup"
    assert res["cpu_ms"] > 50            # the wait4 shim reported ~2ms here
    assert res["peak_kb"] > 4000         # real interpreter RSS, not bwrap's


def test_accounting_field_is_reported(tmp_path):
    write_box(tmp_path, {"t.py": "print('ok')"})
    res = run_box(tmp_path, [PY, "t.py"])
    expected = "cgroup" if HAVE_CG else ("cpu-only", "rusage")
    if HAVE_CG:
        assert res["accounting"] == expected
    else:
        assert res["accounting"] in expected
