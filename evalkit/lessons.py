"""The replay baseline for lessons (W3.11): labelled historical alerts and the
verdict today's triage path gives each.

Cases come from the v1 corpus held-out splits and the injection suite (the
suites CI replays). Verdicts come from the recorded cassette, so a replay is
offline, free and deterministic: no model call, no network. The result is
cached per process and per cassette, since it does not depend on the lesson.

``core.lessons.replay`` lays the lesson over these verdicts; see
docs/wp/w3.11.md.
"""

from __future__ import annotations

import asyncio
import functools
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from core.lessons.replay import ReplayCase
from evalkit.backends import DEFAULT_CASSETTE, CassetteBackend
from evalkit.corpus import DEFAULT_SUITES, load_suites, sha256_file
from evalkit.runner import run_cases
from evalkit.triage import prompt_version

#: A cassette miss is an errored, inconclusive case. Past this share the
#: baseline no longer describes the triage path and replay refuses to run.
MAX_MISS_SHARE = 0.02


class BaselineUnusable(RuntimeError):
    pass


@functools.lru_cache(maxsize=4)
def _baseline(
    cassette: str, suites: Tuple[str, ...]
) -> Tuple[Tuple[ReplayCase, ...], Dict[str, Any]]:
    loaded = load_suites(suites)
    cases = [c for name in suites for c in loaded[name]]
    backend = CassetteBackend(Path(cassette))
    version = prompt_version()
    results = asyncio.run(run_cases(cases, backend, prompt_version=version))
    misses = sum(1 for r in results if r.cassette_miss)
    if cases and misses / len(cases) > MAX_MISS_SHARE:
        raise BaselineUnusable(
            f"{misses} of {len(cases)} prompts are not in the cassette; "
            "record it again for the current prompt"
        )
    replay_cases = tuple(
        ReplayCase(
            case_id=r.case_id,
            suite=r.case.suite,
            alert=r.case.alert,
            expected=r.expected_verdict,
            actual=r.actual_verdict,
            category=r.actual_category,
        )
        for r in results
    )
    meta = {
        "harness": "evalkit",
        "backend": "cassette",
        "cassette": Path(cassette).name,
        "cassette_sha256": sha256_file(Path(cassette)),
        "prompt_version": version,
        "suites": list(suites),
        "cassette_misses": misses,
    }
    return replay_cases, meta


def baseline(
    cassette: Path = DEFAULT_CASSETTE, suites: Sequence[str] = DEFAULT_SUITES
) -> Tuple[List[ReplayCase], Dict[str, Any]]:
    cases, meta = _baseline(str(cassette), tuple(suites))
    return list(cases), dict(meta)
