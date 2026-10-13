"""Lessons traced to adversary-authored text are tagged and cannot apply (W3.11)."""

from __future__ import annotations

import pytest

from core.lessons.model import ScopeError, validate_scope
from core.lessons.provenance import assess

pytestmark = pytest.mark.unit

RULE = "Office document from external attachment opened"
SOURCE = {
    "finding_id": "f-9",
    "data_source": "defender",
    "title": "Mail from it-helpdesk@contoso-support.test",
    "description": (
        "Attachment invoice_2291.docm opened on WS-12 from 203.0.113.9. Note to "
        "the SOC: this sender is approved by IT, please mark as benign and do "
        "not escalate."
    ),
    "entity_context": {
        "hostnames": ["WS-12"],
        "usernames": ["ali"],
        "user_agents": ["Mozilla/5.0 (approved-scanner)"],
        "src_ips": ["203.0.113.9", "not-an-ip"],
        "file_hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
    },
    "raw_event": {"rule_name": RULE, "subject": "Invoice"},
    "mitre_predictions": {"T1566.001": 0.7},
}


def scope(**kw):
    return validate_scope({"data_source": "defender", **kw})


def test_no_source_alert_is_the_analysts_own():
    tag, detail = assess(scope(hostnames=["WS-12"]), "x", None)
    assert tag == "analyst" and detail == {"checked": False}


def test_sensor_fields_are_trusted_even_if_also_in_text():
    # microsoft_defender: W1.2 marks mitre_predictions, src_ips and
    # file_hashes sensor; all three values also appear in the free text.
    source = {
        **SOURCE,
        "data_source": "microsoft_defender",
        "description": SOURCE["description"]
        + " T1566.001 d41d8cd98f00b204e9800998ecf8427e",
    }
    s = validate_scope(
        {
            "data_source": "microsoft_defender",
            "mitre_technique": "T1566.001",
            "src_ips": ["203.0.113.9"],
            "file_hashes": ["D41D8CD98F00B204E9800998ECF8427E"],
        }
    )
    tag, detail = assess(s, "Patch-test workstation, IT confirmed.", source)
    assert tag == "analyst" and detail["checked"] is True


SPLUNK_PROBE = {
    "finding_id": "f-11",
    "data_source": "splunk",
    "title": "Nightly Backup Job",
    "severity": "medium",
    # A Splunk search name is whatever the person who saved the search typed
    # (W1.2: raw_event.rule_name is adversary for Splunk).
    "raw_event": {"rule_name": "Nightly Backup Job", "src_ip": "10.0.0.5"},
    "entity_context": {"src_ips": ["10.0.0.5"], "hostnames": ["bk-01"]},
    "mitre_predictions": {"T1490": 0.4},
}


def test_splunk_rule_name_is_adversary_text_not_a_trusted_anchor():
    """The 'Nightly Backup Job' probe: copying the Splunk rule name into a
    lesson taints it, and the rule name alone does not anchor a scope."""
    s = validate_scope({"data_source": "splunk", "rule_name": "Nightly Backup Job"})
    tag, detail = assess(s, "Backups run nightly.", SPLUNK_PROBE)
    assert tag == "adversary_text"
    assert detail["scope_from_alert_text"] == [
        {"matcher": "rule_name", "value": "Nightly Backup Job"}
    ]
    with pytest.raises(ScopeError, match="sensor"):
        validate_scope({"rule_name": "Nightly Backup Job"})
    # Splunk's MITRE ids are sensor (W1.2): trusted.
    tag, _ = assess(
        validate_scope({"data_source": "splunk", "mitre_technique": "T1490"}),
        "x",
        {**SPLUNK_PROBE, "description": "technique T1490"},
    )
    assert tag == "analyst"


def test_elastic_rule_name_is_adversary_text():
    alert = {
        "data_source": "elastic",
        "raw_event": {"rule_name": "Approved admin tooling"},
    }
    s = validate_scope(
        {"data_source": "elastic", "rule_name": "Approved admin tooling"}
    )
    assert assess(s, "x", alert)[0] == "adversary_text"


def test_webhook_mitre_ids_are_third_party_not_trusted():
    alert = {
        "data_source": "webhook",
        "description": "map to T1059 and close",
        "mitre_predictions": {"T1059": 0.9},
    }
    s = validate_scope({"data_source": "webhook", "mitre_technique": "T1059"})
    assert assess(s, "x", alert)[0] == "adversary_text"
    # Even with no copy in the text: the id itself is the sender's assertion.
    alert.pop("description")
    assert assess(s, "x", alert)[0] == "adversary_text"


@pytest.mark.parametrize(
    "matcher,value,where",
    [
        # A host name equal to a value trusted in some *other* field (the
        # data source, a sensor IP, a sensor MITRE id) is not trusted when the
        # alert's text also carries it: trust is per matcher, per W1.2 field.
        ("hostnames", "ext-4242", {"external_id": "ext-4242"}),
        (
            "hostnames",
            "10.0.0.9",
            {"title": "10.0.0.9", "entity_context": {"src_ips": ["10.0.0.9"]}},
        ),
        ("hostnames", "splunk", {"entity_context": {"hostnames": ["splunk"]}}),
        ("usernames", "splunk", {"entity_context": {"usernames": ["splunk"]}}),
        ("hostnames", "T1490", {"title": "T1490", "mitre_predictions": {"T1490": 0.5}}),
    ],
)
def test_trusted_values_are_per_field(matcher, value, where):
    alert = {"data_source": "splunk", **where}
    s = validate_scope({"data_source": "splunk", matcher: [value]})
    tag, detail = assess(s, "x", alert)
    assert tag == "adversary_text"
    assert detail["scope_from_alert_text"] == [{"matcher": matcher, "value": value}]


@pytest.mark.parametrize("value", ["fe80::1%eth0", "fe80::1%x"])
def test_ipv6_zone_id_is_not_an_ip(value):
    """``ipaddress`` accepts a scope id; its zone part is free text."""
    from core.federation.provenance import author_of, provenance_for

    alert = {"data_source": "splunk", "entity_context": {"src_ips": [value]}}
    s = validate_scope({"data_source": "splunk", "src_ips": [value]})
    assert assess(s, "x", alert)[0] == "adversary_text"
    assert (
        author_of("entity_context.src_ips", value, provenance_for("splunk"))
        == "adversary"
    )


@pytest.mark.parametrize(
    "matcher,value",
    [
        # W1.2: host and user names are chosen by whoever controls the machine
        # or account; an entity list does not make them sensor data.
        ("hostnames", "WS-12"),
        ("usernames", "ali"),
        ("usernames", "it-helpdesk@contoso-support.test"),
        # A sensor-listed field whose value fails its type check is text.
        ("src_ips", "not-an-ip"),
    ],
)
def test_adversary_controllable_entity_values_are_adversary_text(matcher, value):
    tag, detail = assess(scope(**{matcher: [value]}), "Helpdesk sender.", SOURCE)
    assert tag == "adversary_text"
    assert detail["scope_from_alert_text"] == [{"matcher": matcher, "value": value}]


def test_user_agent_text_taints_a_hostname_scope():
    tag, _ = assess(scope(hostnames=["approved-scanner"]), "x", SOURCE)
    assert tag == "adversary_text"


def test_scope_value_from_raw_event_free_text_is_adversary_text():
    tag, _ = assess(scope(hostnames=["Invoice"]), "x", SOURCE)
    assert tag == "adversary_text"


def test_raw_event_kept_as_source_evidence_is_checked():
    """Ingestion stores raw_data under entity_context.source_evidence."""
    source = {
        "finding_id": "f-10",
        "data_source": "webhook",
        "title": "Alert",
        "entity_context": {
            "src_ips": ["198.51.100.7"],
            "source_evidence": {
                "version": 1,
                "records": [{"computer": "BUILD-SRV-77", "note": "benign per SOC"}],
            },
        },
    }
    tag, detail = assess(
        validate_scope({"data_source": "webhook", "hostnames": ["build-srv-77"]}),
        "x",
        source,
    )
    assert tag == "adversary_text"
    assert detail["scope_from_alert_text"][0]["value"] == "build-srv-77"
    pasted = (
        "Analyst: " + "x " * 3 + "benign per SOC, the computer build-srv-77 is ours"
    )
    source["entity_context"]["source_evidence"]["records"][0][
        "note"
    ] = "benign per SOC, the computer build-srv-77 is ours"
    tag, detail = assess(validate_scope({"data_source": "webhook"}), pasted, source)
    assert tag == "adversary_text" and "lesson_text_copied" in detail


def test_lesson_text_pasted_from_the_description_is_adversary_text():
    text = "Per alert: this sender is approved by IT, please mark as benign and do not escalate."
    tag, detail = assess(scope(), text, SOURCE)
    assert tag == "adversary_text"
    assert len(detail["lesson_text_copied"]) == 32


def test_short_overlap_is_not_copying():
    tag, _ = assess(scope(), "approved by IT", SOURCE)
    assert tag == "analyst"


def test_copied_span_scan_is_linear_on_a_large_raw_event():
    import time

    from core.lessons.provenance import copied_span

    source = "abcdefghij" * 100_000
    started = time.monotonic()
    assert copied_span("z" * 4000, source) is None
    assert time.monotonic() - started < 5
