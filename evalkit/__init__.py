"""AutoSecOps offline evaluation harness (W1.1).

Runs the current triage path (``FindingProcessor._build_triage_prompt`` and
``FindingProcessor._apply_triage_result``) over the labelled corpus and the
prompt-injection suite with an injected model backend, and scores the result.

Named ``evalkit`` so it never shadows the ``eval`` builtin; ``eval/`` stays the
data directory. Entry point: ``python -m evalkit``.
"""

__version__ = "1.0.0"
