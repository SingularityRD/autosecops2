"""The console's "always needs a person" promise is the code's list (W0.32, gap T1).

Before W0.32 the setup wizard said host isolation always needs a person while
``isolate_host`` was autonomous-eligible. The console's wording lives in one
file, ``clients/web/src/shared/autonomy.ts``; its ids must be exactly
``core.autonomy.tiers.ALWAYS_HUMAN``, no other web file may state the promise in
its own words, and the admin guide must list the same classes (and the same
autonomous-eligible ones) as the code.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.autonomy.tiers import ALWAYS_HUMAN, AUTONOMOUS_ELIGIBLE

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
WEB_SRC = REPO / "clients" / "web" / "src"
PROMISE_TS = WEB_SRC / "shared" / "autonomy.ts"
GUIDE = REPO / "docs" / "guide" / "yonetici-kilavuzu.md"

# Phrases that state the promise; only autonomy.ts may carry them.
PROMISE_PHRASES = re.compile(r"always (?:need|needs) a person|isolating a host", re.I)


def _ui_ids() -> set[str]:
    text = PROMISE_TS.read_text(encoding="utf-8")
    block = re.search(r"ALWAYS_HUMAN_ACTIONS = \[(.*?)\] as const", text, re.S)
    assert block, "ALWAYS_HUMAN_ACTIONS not found in shared/autonomy.ts"
    return set(re.findall(r"id: '([a-z_]+)'", block.group(1)))


def _guide_line(prefix: str) -> set[str]:
    for line in GUIDE.read_text(encoding="utf-8").splitlines():
        if line.lstrip("- ").startswith(prefix):
            return set(re.findall(r"`([a-z_]+)`", line))
    raise AssertionError(f"{GUIDE.name} has no line starting {prefix!r}")


def test_the_console_list_is_the_code_list():
    assert _ui_ids() == set(ALWAYS_HUMAN)


def test_the_console_names_what_it_promises():
    text = PROMISE_TS.read_text(encoding="utf-8")
    summary = re.search(r"ALWAYS_HUMAN_SUMMARY =\s*'([^']+)'", text)
    assert summary
    for phrase in ("isolating a host", "disabling or locking an account", "blocking on a firewall"):
        assert phrase in summary.group(1).lower()


def test_no_other_web_file_words_the_promise_itself():
    offenders = []
    for path in WEB_SRC.rglob("*.ts*"):
        if path == PROMISE_TS or ".test." in path.name or "generated" in path.parts:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if PROMISE_PHRASES.search(line):
                offenders.append(f"{path.relative_to(REPO)}:{number}")
    assert not offenders, (
        "state the always-a-person promise through shared/autonomy.ts: " + ", ".join(offenders)
    )


def test_the_admin_guide_lists_the_code_lists():
    assert _guide_line("Her zaman kişi:") == set(ALWAYS_HUMAN)
    assert _guide_line("Otonom olabilen sınıflar:") == set(AUTONOMOUS_ELIGIBLE)
