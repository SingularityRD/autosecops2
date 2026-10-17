"""VIGIL_METRICS_ENABLED: Prometheus metrics without OTEL export (W0.51)."""

from __future__ import annotations

import pytest

from core import telemetry

pytestmark = pytest.mark.unit


@pytest.fixture()
def fresh(monkeypatch):
    telemetry.shutdown_telemetry()
    yield
    telemetry.shutdown_telemetry()


def _settings(monkeypatch, *, otel, metrics):
    from core.config import get_settings

    monkeypatch.setattr(get_settings(), "vigil_otel_enabled", otel)
    monkeypatch.setattr(get_settings(), "vigil_metrics_enabled", metrics)


def test_metrics_only_serves_counters_and_exports_nothing(monkeypatch, fresh):
    _settings(monkeypatch, otel=False, metrics=True)
    called = []
    monkeypatch.setattr(telemetry, "_do_init", lambda name: called.append(name))
    assert telemetry.init_telemetry("w051") is True
    assert called == []  # the OTLP path is never built
    telemetry.get_meter("w051").create_counter("vigil.w051.test.total").add(1)
    from prometheus_client import generate_latest

    assert "vigil_w051_test_total" in generate_latest().decode()


def test_off_by_default(monkeypatch, fresh):
    _settings(monkeypatch, otel=False, metrics=False)
    assert telemetry.init_telemetry("w051") is False


def test_otel_wins_when_both_are_on(monkeypatch, fresh):
    _settings(monkeypatch, otel=True, metrics=True)
    called = []
    monkeypatch.setattr(telemetry, "_do_init", lambda name: called.append(name))
    monkeypatch.setattr(
        telemetry, "_do_init_metrics_only", lambda name: called.append("m")
    )
    telemetry.init_telemetry("w051")
    assert called == ["w051"]
