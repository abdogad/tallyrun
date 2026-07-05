"""Adversarial proofs: hostile behaviour is contained AND correctly measured,
so the caller can map it to a verdict. Memory verdicts are decided on
measured peak vs. the limit (the 1.25x memory.max headroom means an
over-limit run is usually measured, not OOM-guessed)."""

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
    # A 2GB allocation against a 128MB limit: cgroup memory.max OOM-kills it
    # (RLIMIT_AS in the fallback). Either way it never completes.
    write_box(tmp_path, {"bomb.py":
        "held = []\n"
        "for _ in range(32):\n"
        "    held.append(bytearray(64 * 1024 * 1024))\n"
        "print('ALLOCATED')\n"})
    res = run_box(tmp_path, [PY, "bomb.py"], mem_kb=MEM_KB)
    assert "ALLOCATED" not in res["_stdout"]
    if HAVE_CG:
        # Measured over-limit: this is the MLE signal a judge gates on.
        assert res["peak_kb"] > MEM_KB
    else:
        assert res["exit_code"] != 0


@needs_cgroup
def test_fork_spread_memory_bomb_is_accounted(tmp_path):
    # The hole per-process accounting can't see: 16 children x 64MB = 1GB
    # total against a 128MB limit, no single process over ~64MB. memory.max
    # caps the subtree total and memory.peak reports it.
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
    assert res["peak_kb"] > MEM_KB  # subtree peak proves the MLE verdict


@needs_cgroup
def test_fork_spread_cpu_burn_is_killed(tmp_path):
    # The CPU-side analogue of the fork-spread memory bomb: 8 children each
    # burn ~0.5s of CPU — every one under the 1s per-process RLIMIT_CPU, but
    # ~4s for the subtree against a 1s budget. Only the cgroup cpu.stat
    # enforcement sees the aggregate; it must kill ("cpu") long before the
    # wall timeout, which is the load-dependent bound this exists to replace.
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
    assert res["wall_ms"] < 10000  # killed on CPU budget, nowhere near wall


@needs_cgroup
@needs_insn
def test_fork_bomb_is_contained(tmp_path):
    # perf inherit counts instructions across every forked child, so the bomb
    # blows the instruction budget fast; cgroup.kill then reaps the whole
    # subtree atomically. Wall stays far under the timeout.
    write_box(tmp_path, {"fork.py":
        "import os\n"
        "while True:\n"
        "    try:\n"
        "        os.fork()\n"
        "    except OSError:\n"
        "        pass\n"})
    res = run_box(tmp_path, [PY, "fork.py"], insn=500_000_000, wall=4000)
    # Containment has three possible faces, all fine: the instruction budget
    # fires, the wall fires, or the cgroup OOM killer takes out the
    # namespace init as thousands of spinners hit memory.max. What must never
    # happen: a clean exit, or outliving the wall timeout.
    assert res["killed"] is not None or res["exit_code"] != 0
    assert res["wall_ms"] <= 4500


@needs_insn
def test_infinite_loop_dies_by_instruction_budget(tmp_path):
    write_box(tmp_path, {"loop.py": "while True: pass"})
    res = run_box(tmp_path, [PY, "loop.py"], insn=300_000_000, wall=10000)
    assert res["killed"] == "instructions"
    assert res["wall_ms"] < 5000
