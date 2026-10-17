"""Syslog, CEF, LEEF, FortiGate and Wazuh JSON lines as findings (W0.41)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.federation.provenance import WEBHOOK_PROVENANCE, provenance_for
from core.ingestion.syslog_formats import (
    MAX_FIELDS,
    MAX_LINE_BYTES,
    parse_cef,
    parse_cef_extension,
    parse_leef,
    parse_line,
    split_header,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)

CEF = (
    r"<134>Mar  2 08:00:00 arcsight01 CEF:0|Security|threatmanager|1.0|100|"
    r"worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 "
    r"msg=Detected a threat\= no action needed suser=ayse rt=1772438400000"
)
LEEF2 = (
    "<13>1 2026-03-02T08:00:00Z qradar01 LEEF - - - LEEF:2.0|Lancope|StealthWatch|"
    "1.0|41|^|src=10.0.1.8^dst=10.0.0.5^sev=5^devTime=2026-03-02T07:59:00Z^usrName=joe"
)
LEEF1 = (
    "LEEF:1.0|Microsoft|MSExchange|4.0 SP1|15345|src=10.50.1.1\tdst=2.10.20.20"
    "\tsev=8\tname=Mailbox login"
)
FORTI = (
    '<189>date=2026-03-02 time=08:01:02 devname="FGT60F" devid="FGT60FTK1" '
    'logid="0419016384" type="utm" subtype="ips" level="alert" srcip=192.168.1.5 '
    'dstip=8.8.8.8 attack="Backdoor.Cobalt.Strike" msg="ips: Backdoor detected"'
)
WAZUH = (
    '<132>Mar  2 08:00:00 wazuh ossec: {"rule":{"level":12,"description":'
    '"Multiple authentication failures","id":"5712","mitre":{"id":["T1110"]}},'
    '"agent":{"name":"web01","ip":"10.1.1.1"},"data":{"srcip":"203.0.113.9",'
    '"srcuser":"root"}}'
)


def test_cef_line():
    f = parse_line(CEF, peer="10.9.9.9", now=NOW)
    assert f["data_source"] == "syslog"
    assert f["title"] == "worm successfully stopped"
    assert f["severity"] == "critical"
    assert f["timestamp"] == "2026-03-02T08:00:00+00:00"
    assert f["entity_context"]["src_ips"] == ["10.0.0.1"]
    assert f["entity_context"]["dest_ips"] == ["2.1.2.2"]
    assert f["entity_context"]["usernames"] == ["ayse"]
    assert "arcsight01" in f["entity_context"]["hostnames"]
    assert f["raw_event"]["fields"]["msg"] == "Detected a threat= no action needed"
    meta = f["metadata"]
    assert (meta["syslog_format"], meta["vendor"], meta["product"]) == (
        "cef",
        "Security",
        "threatmanager",
    )
    assert meta["signature_id"] == "100"
    assert meta["syslog_peer"] == "10.9.9.9"
    assert meta["syslog_facility"] == 16 and meta["syslog_severity"] == 6
    assert f["finding_id"].startswith("syslog-") and len(f["finding_id"]) <= 50


def test_the_same_line_twice_is_the_same_finding_and_another_line_is_not():
    a = parse_line(CEF, now=NOW)
    assert parse_line(CEF, now=NOW)["finding_id"] == a["finding_id"]
    assert (
        parse_line(CEF.replace("1232", "1233"), now=NOW)["finding_id"]
        != a["finding_id"]
    )


def test_cef_header_escapes_and_extension_spaces():
    parsed = parse_cef(
        r"CEF:0|Ven\|dor|Prod\\uct|1|sig|Name with \| pipe|Low|a=1 b=two words c=x\\y"
    )
    assert parsed["vendor"] == "Ven|dor"
    assert parsed["product"] == "Prod\\uct"
    assert parsed["name"] == "Name with | pipe"
    assert parsed["fields"] == {"a": "1", "b": "two words", "c": "x\\y"}
    assert parse_cef_extension(r"msg=line\nbreak act=blocked") == {
        "msg": "line\nbreak",
        "act": "blocked",
    }


@pytest.mark.parametrize(
    "severity,expected",
    [
        ("0", "low"),
        ("3", "low"),
        ("4", "medium"),
        ("7", "high"),
        ("8", "high"),
        ("9", "critical"),
        ("Very-High", "critical"),
        ("High", "high"),
        ("Unknown", "medium"),
    ],
)
def test_cef_severity(severity, expected):
    line = f"CEF:0|v|p|1|s|n|{severity}|src=10.0.0.1"
    assert parse_line(line, now=NOW)["severity"] == expected


def test_leef_2_with_a_custom_delimiter_and_rfc5424_header():
    f = parse_line(LEEF2, now=NOW)
    assert f["metadata"]["syslog_format"] == "leef"
    assert f["metadata"]["format_version"] == "2.0"
    assert f["metadata"]["syslog_host"] == "qradar01"
    assert f["entity_context"]["src_ips"] == ["10.0.1.8"]
    assert f["entity_context"]["usernames"] == ["joe"]
    assert f["severity"] == "medium"
    assert f["timestamp"] == "2026-03-02T07:59:00+00:00"


def test_leef_1_tab_separated_and_hex_delimiter():
    f = parse_line(LEEF1, now=NOW)
    assert f["title"] == "Mailbox login"
    assert f["severity"] == "high"
    assert f["entity_context"]["dest_ips"] == ["2.10.20.20"]
    hexed = parse_leef("LEEF:2.0|V|P|1|E|x7C|src=10.0.0.1|sev=2")
    assert hexed["fields"] == {"src": "10.0.0.1", "sev": "2"}


def test_fortigate_key_value():
    f = parse_line(FORTI, now=NOW)
    assert f["metadata"]["syslog_format"] == "fortigate"
    assert f["metadata"]["vendor"] == "Fortinet"
    assert f["title"] == "Backdoor.Cobalt.Strike"
    assert f["severity"] == "critical"
    assert f["timestamp"] == "2026-03-02T08:01:02+00:00"
    assert f["entity_context"]["src_ips"] == ["192.168.1.5"]
    assert f["entity_context"]["hostnames"] == ["FGT60F"]
    assert "ips: Backdoor detected" in f["description"]


def test_wazuh_json():
    f = parse_line(WAZUH, now=NOW)
    assert f["metadata"]["syslog_format"] == "json"
    assert f["title"] == "Multiple authentication failures"
    assert f["severity"] == "high"  # level 12 of 15
    assert f["entity_context"]["src_ips"] == ["203.0.113.9"]
    assert f["mitre_predictions"] == {"T1110": 0.9}
    # The agent's own address is the monitored host, not the source.
    assert "10.1.1.1" not in f["entity_context"]["src_ips"]


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "<30>Mar  2 08:00:00 host sshd[12]: Accepted password for x",
        "CEF:0|only|three",
        "LEEF:1.0|short",
        '{"no": "name"}',
        "<999>garbage",
    ],
)
def test_lines_that_are_not_alerts_are_none(line):
    assert parse_line(line, now=NOW) is None


def test_a_name_that_is_not_an_ip_never_lands_in_the_ip_lists():
    f = parse_line("CEF:0|v|p|1|s|n|5|src=evil.example dst=not-an-ip shost=h", now=NOW)
    assert "src_ips" not in f["entity_context"]
    assert "dest_ips" not in f["entity_context"]


def test_a_huge_line_and_many_keys_are_bounded():
    many = " ".join(f"k{i}=v" for i in range(MAX_FIELDS * 3))
    f = parse_line("CEF:0|v|p|1|s|n|5|" + many, now=NOW)
    assert len(f["raw_event"]["fields"]) == MAX_FIELDS
    huge = parse_line("CEF:0|v|p|1|s|n|5|msg=" + "a" * (MAX_LINE_BYTES * 2), now=NOW)
    assert len(huge["raw_event"]["message"].encode()) <= MAX_LINE_BYTES


def test_rfc3164_year_rolls_back_in_january():
    header, _ = split_header(
        "<13>Dec 31 23:59:00 h CEF:0|", datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc)
    )
    assert header.timestamp.year == 2026


def test_a_relay_host_before_the_body_is_skipped():
    f = parse_line(
        "<13>Mar  2 08:00:00 relay fw01 CEF:0|v|p|1|s|n|5|src=10.0.0.1", now=NOW
    )
    assert f["metadata"]["vendor"] == "v"


def test_syslog_findings_get_the_webhook_provenance():
    assert provenance_for("syslog") is WEBHOOK_PROVENANCE
