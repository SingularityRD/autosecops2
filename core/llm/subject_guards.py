"""Keep text a subject writes to its reviewer out of the triage prompt (W0.30).

The Python half of upstream 6d34c7cd's guards (``services/agent/core/guards.ts``),
cut to what fits a one-call triage path. The TypeScript side has a guarded
*reader* -- a second, tool-less model that reads every estate result -- and the
deciding model sees only typed findings and handles. Doing that here would add a
second model call to every triaged finding, so it is not ported. What is ported is
the part decided by code, not by a model: a value in the ADVERSARY-INFLUENCEABLE
group that reads as steering a reviewer ("approved", "benign", "close the case",
"ignore previous instructions" ...) is withheld from the prompt, whole, and
replaced by a marker saying so. The rest of the alert is shown as before.

Off by default (``triage_subject_guards``): a withheld value also withholds
whatever legitimate signal sat in the same field, so it moves accuracy as well
as attack success, and the default only changes on a live-model measurement.
"""

from __future__ import annotations

import re
from typing import Dict, List, Sequence, Tuple

from core.llm.security import scan_for_injection

# What the model sees in place of a withheld value. Says why, so a model does not
# read the gap as an empty field, and says nothing the subject wrote.
WITHHELD = (
    "[withheld by AutoSecOps: this value addresses whoever reviews the alert "
    "(it says what the activity is or what to do), so it is not shown]"
)

# guards.ts STEERING: phrases an injected note uses that a prompt-syntax scanner
# does not -- telling a reviewer what the activity is or what to do. Kept the same
# as upstream on purpose: tuning it on eval/suites/injection would grade the
# defence on the data it was fitted to.
_STEERING = re.compile(
    r"\b(authori[sz]ed|approved|sanctioned|whitelisted|allow-?listed|false positive|"
    r"benign|no action|do not (escalate|investigate|report)|close (this|the) "
    r"(case|ticket)|abandon|conclude|mark (it|this|as))\b",
    re.IGNORECASE,
)

# security.ts INSTRUCTION_LIKE, the agent layer's scanner, alongside
# core.llm.security.scan_for_injection.
_INSTRUCTION_LIKE: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\b", re.I),
    re.compile(
        r"\bdisregard\s+(all\s+|any\s+)?(previous|prior|above|earlier|instructions)\b",
        re.I,
    ),
    re.compile(r"\byou\s+(must|should|need to|are required to)\b", re.I),
    re.compile(r"\b(system|developer)\s+(prompt|message|instruction)", re.I),
    re.compile(r"\bnew\s+instructions?\b", re.I),
)

# The group a value is checked in. SENSOR and THIRD_PARTY values are not the
# subject's to write.
GUARDED_AUTHOR = "adversary"


def _steering(text: str) -> bool:
    if _STEERING.search(text) or any(p.search(text) for p in _INSTRUCTION_LIKE):
        return True
    return bool(scan_for_injection(text))


def steering(text: str) -> bool:
    """True when ``text`` reads as addressed to a reviewer. Words joined into
    one identifier (APPROVED_MAINT_OK) are checked split as well, as in
    guards.ts ``steeringIn``."""
    text = str(text)
    return _steering(text) or _steering(re.sub(r"[_.\-]+", " ", text))


def guard_groups(
    groups: Dict[str, List[Tuple[str, str]]],
    authors: Sequence[str] = (GUARDED_AUTHOR,),
) -> Tuple[Dict[str, List[Tuple[str, str]]], List[str]]:
    """``groups`` with every steering value in ``authors`` replaced by
    :data:`WITHHELD`, and the names of the fields withheld (for the log and the
    finding; never the values)."""
    out: Dict[str, List[Tuple[str, str]]] = {}
    withheld: List[str] = []
    for author, fields in groups.items():
        if author not in authors:
            out[author] = list(fields)
            continue
        kept: List[Tuple[str, str]] = []
        for name, value in fields:
            if steering(value):
                kept.append((name, WITHHELD))
                withheld.append(name)
            else:
                kept.append((name, value))
        out[author] = kept
    return out, withheld
