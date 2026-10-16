"""Medic status timings (C5 §5.3-5.4), with no imports at all.

Split out of ``core.platform.medic_status`` so a dependency-light caller can read
them without pulling in the backend's settings chain (``core.config`` needs
pydantic): the ``Medic on Compose`` CI job runs ``tests/medic_compose`` with only
pytest and PyYAML installed. ``medic_status`` re-exports these names, and
``tests/unit/platform/test_medic_status.py`` keeps this module import-free.
"""

# C5 §5.3: one poll a minute. PRD US-05: a dead Medic shows Down within 5 min.
# 270 s, not 300, leaves a poll's slack: at 300 the live Down landed at 298-301 s
# (V2-2).
POLL_INTERVAL_S = 60
POLL_TIMEOUT_S = 10
DOWN_AFTER_S = 270
