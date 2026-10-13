"""A caller-chosen seed would choose the QA sample; it is honoured only in tests (W0.10)."""

from __future__ import annotations

import logging

import pytest

from core.quality import qa_router

pytestmark = pytest.mark.unit


class _Settings:
    def __init__(self, testing: bool):
        self.testing = testing


def test_the_seed_is_ignored_and_logged_outside_tests(monkeypatch, caplog):
    monkeypatch.setattr(qa_router, "get_settings", lambda: _Settings(False))
    with caplog.at_level(logging.WARNING, logger=qa_router.__name__):
        assert qa_router._honoured_seed(42) is None
    assert "ignoring caller-supplied seed 42" in caplog.text


def test_the_seed_is_honoured_under_testing(monkeypatch):
    monkeypatch.setattr(qa_router, "get_settings", lambda: _Settings(True))
    assert qa_router._honoured_seed(42) == 42


def test_no_seed_is_no_seed(monkeypatch, caplog):
    monkeypatch.setattr(qa_router, "get_settings", lambda: _Settings(False))
    with caplog.at_level(logging.WARNING, logger=qa_router.__name__):
        assert qa_router._honoured_seed(None) is None
    assert caplog.text == ""


def test_the_draw_route_uses_the_honoured_seed(monkeypatch):
    """Outside tests, two draws with the same seed do not share an RNG stream."""
    monkeypatch.setattr(qa_router, "get_settings", lambda: _Settings(False))
    seen = []

    def fake_draw(session, *, days, per_category, risk_weighted_extra, rng):
        seen.append(rng.random())

        class _R:
            per_category = {}
            risk_weighted_population = 0
            risk_weighted_drawn = 0

        return _R()

    monkeypatch.setattr(qa_router.sampling, "draw_samples", fake_draw)
    body = qa_router.QADrawRequest(seed=7)
    qa_router.draw_samples(body, session=None)
    qa_router.draw_samples(body, session=None)
    assert seen[0] != seen[1]

    monkeypatch.setattr(qa_router, "get_settings", lambda: _Settings(True))
    seen.clear()
    qa_router.draw_samples(body, session=None)
    qa_router.draw_samples(body, session=None)
    assert seen[0] == seen[1]
