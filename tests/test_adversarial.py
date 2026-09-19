"""Hostile payloads. Each one has to be contained and still measured
correctly, so the caller can turn the result into a verdict. Memory verdicts
compare the measured peak to the limit; with memory.max at 1.25x the limit,
an over-limit run is usually measured instead of inferred from an OOM kill."""

import shutil

import pytest

from conftest import HAVE_CG, needs_cgroup, needs_insn, run_box, write_box

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap not installed"
)

PY = "python3"
MEM_KB = 131072  # 128 MiB verdict limit used throughout


def test_output_flood_is_capped(tmp_path):
    # RLIMIT_FSIZE kills a 100MB writer (SIGXFSZ) instead of filling the disk.
    write_box(tmp_path, {"flood.py":
        "import sys\n"
        "buf = 'x' * (1 << 20)\n"
        "for _ in range(100):\n"
        "    sys.stdout.write(buf)\n"})
    res = run_box(tmp_path, [PY, "flood.py"])
    assert res["exit_code"] != 0
    assert len(res["_stdout"]) <= 9 * 1024 * 1024  # 8 MiB cap + slack


def test_memory_bomb_is_stopped(tmp_path):
    # 2GB against a 128MB limit. memory.max OOM-kills it, or RLIMIT_AS stops
    # it when there's no cgroup.
    write_box(tmp_path, {"bomb.py":
        "held = []\n"
        "for _ in range(32):\n"
        "    held.append(bytearray(64 * 1024 * 1024))\n"
        "print('ALLOCATED')\n"})
    res = run_box(tmp_path, [PY, "bomb.py"], mem_kb=MEM_KB)
    assert "ALLOCATED" not in res["_stdout"]
    if HAVE_CG:
        # A measured peak over the limit is what a judge calls MLE.
        assert res["peak_kb"] > MEM_KB
    else:
        assert res["exit_code"] != 0


@needs_cgroup
def test_fork_spread_memory_bomb_is_accounted(tmp_path):
    # 16 children x 64MB = 1GB against a 128MB limit, with no single process
    # over ~64MB, so per-process accounting would miss it. memory.max caps
    # the total and memory.peak reports it.
    write_box(tmp_path, {"spread.py":
        "import os, time\n"
        "for _ in range(16):\n"
        "    if os.fork() == 0:\n"
        "        x = bytearray(64 * 1024 * 1024)\n"
        "        time.sleep(3)\n"
        "        os._exit(0)\n"
        "time.sleep(3)\n"
        "print('SURVIVED')\n"})
    res = run_box(tmp_path, [PY, "spread.py"], mem_kb=MEM_KB, wall=8000)
    assert res["peak_kb"] > MEM_KB  # the tree's peak gives the MLE verdict


@needs_cgroup
def test_fork_spread_cpu_burn_is_killed(tmp_path):
    # The CPU version of the test above: 8 children burn ~0.5s each. Each
    # stays under the 1s RLIMIT_CPU, but together they use ~4s against a 1s
    # budget. Only the cpu.stat check sees the total, and it has to kill the
    # run ("cpu") well before the wall timeout, which depends on load.
    write_box(tmp_path, {"burn.py":
        "import os, time\n"
        "for _ in range(8):\n"
        "    if os.fork() == 0:\n"
        "        t = time.process_time()\n"
        "        while time.process_time() - t < 0.5:\n"
        "            pass\n"
        "        os._exit(0)\n"
        "for _ in range(8):\n"
        "    os.wait()\n"
        "print('SURVIVED')\n"})
    res = run_box(tmp_path, [PY, "burn.py"], cpu_s=1, wall=20000)
    assert res["killed"] == "cpu"
    assert "SURVIVED" not in res["_stdout"]
    assert res["wall_ms"] < 10000  # killed by the CPU budget, not the wall


@needs_cgroup
@needs_insn
def test_fork_bomb_is_contained(tmp_path):
    # The inherited counter includes every forked child, so the bomb runs
    # through its instruction budget fast and cgroup.kill removes the tree.
    write_box(tmp_path, {"fork.py":
        "import os\n"
        "while True:\n"
        "    try:\n"
        "        os.fork()\n"
        "    except OSError:\n"
        "        pass\n"})
    res = run_box(tmp_path, [PY, "fork.py"], insn=500_000_000, wall=4000)
    # Any of these kills is fine: the instruction budget, the wall timeout, or
    # the OOM killer taking out the namespace init once thousands of
    # processes hit memory.max. A clean exit or outliving the wall is not.
    assert res["killed"] is not None or res["exit_code"] != 0
    assert res["wall_ms"] <= 4500


@needs_insn
def test_infinite_loop_dies_by_instruction_budget(tmp_path):
    write_box(tmp_path, {"loop.py": "while True: pass"})
    res = run_box(tmp_path, [PY, "loop.py"], insn=300_000_000, wall=10000)
    assert res["killed"] == "instructions"
    assert res["wall_ms"] < 5000
