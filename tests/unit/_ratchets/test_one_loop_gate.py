"""The one-loop gate detects the pattern, not the names.

A gate nobody has seen fail is not known to work, so these plant the loop the
gate exists to catch and the near-misses it must not catch. Demonstrated by hand
in #632 as well; this is what keeps it true.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
GATE = REPO / "scripts" / "check_one_loop.py"

pytestmark = pytest.mark.unit

# A fifth loop, written the way a reasonable person would write it: nothing here
# looks wrong on its own, which is the whole argument for a gate over review.
A_TOOL_LOOP = """
async def investigate(client, messages, tools):
    for _ in range(10):
        response = await client.messages.create(model="m", messages=messages, tools=tools)
        calls = [b for b in response.content if b.type == "tool_use"]
        if not calls:
            return response
        messages.append({"role": "assistant", "content": response.content})
"""

# Same shape on the OpenAI surface, so the gate is not keyed to one vendor.
AN_OPENAI_TOOL_LOOP = """
async def investigate(client, messages, tools):
    while True:
        response = await client.chat.completions.create(model="m", messages=messages)
        if not response.choices[0].message.tool_calls:
            return response
        messages.append(response.choices[0].message)
"""

# A retry, not a tool loop: it calls a provider repeatedly and reads no tool call.
A_RETRY_LOOP = """
async def ask(client, messages):
    for _ in range(3):
        response = await client.messages.create(model="m", messages=messages)
        if response:
            return response
    return None
"""

# Tool handling with no provider call: a fold over blocks somebody else fetched.
TOOL_HANDLING_ALONE = """
def collect(blocks):
    out = []
    for block in blocks:
        if block.type == "tool_use":
            out.append(block)
    return out
"""


def run_gate(gate: Path = GATE) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(gate)], capture_output=True, text=True)


@pytest.fixture(scope="module")
def tree_copy(tmp_path_factory) -> Path:
    """A copy of every Python file the gate scans, with the gate beside it.

    The gate roots itself at its own parent directory, so a copy of it scans the
    copy. Planting there keeps the real tree untouched: other tests walk core/
    too, and under xdist they would race a module that appears and vanishes.
    """
    root = tmp_path_factory.mktemp("one_loop_tree")
    sys.path.insert(0, str(GATE.parent))
    try:
        import check_one_loop as gate
    finally:
        sys.path.pop(0)
    for top in gate.SCAN:
        for src in (REPO / top).rglob("*.py"):
            rel = src.relative_to(REPO)
            if any(part in gate.SKIP for part in rel.parts):
                continue
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
    # The copy is a faithful stand-in only if the gate sees it clean as it sees
    # the real tree, and it saw every file.
    result = run_gate(root / "scripts" / GATE.name)
    assert result.returncode == 0, result.stdout
    real = run_gate()
    assert result.stdout == real.stdout, (result.stdout, real.stdout)
    return root


@pytest.fixture()
def planted(request, tree_copy):
    """Write a module into the copied tree, and always take it back out."""
    path = tree_copy / "core" / "llm" / "_gate_fixture.py"
    path.write_text(request.param)
    yield tree_copy / "scripts" / GATE.name
    path.unlink(missing_ok=True)


def test_the_tree_is_clean():
    result = run_gate()
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("planted", [A_TOOL_LOOP, AN_OPENAI_TOOL_LOOP], indirect=True)
def test_fails_on_a_planted_loop(planted):
    result = run_gate(planted)
    assert result.returncode == 1
    assert "_gate_fixture.py" in result.stdout
    # Names where the loop belongs, so the failure is actionable rather than a veto.
    assert "services/agent/core/stream.ts" in result.stdout


@pytest.mark.parametrize("planted", [A_RETRY_LOOP, TOOL_HANDLING_ALONE], indirect=True)
def test_leaves_the_near_misses_alone(planted):
    # A gate that fires on either of these gets switched off within a week.
    result = run_gate(planted)
    assert result.returncode == 0, result.stdout
