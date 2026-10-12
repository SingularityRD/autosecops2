"""Per-source provenance maps for triage citations (W1.3).

Each Federation adapter, the known-answer probe and every other source
(webhook, kafka, imports) has a map from finding field to author; the field
names are the ones ``prompt_fields`` shows the model. Unknown fields are
adversary.
"""

from __future__ import annotations

import pytest

from core.contracts.verdict import AUTHORED, UNKNOWN_FIELD_AUTHOR, resolve_authored
from core.federation import provenance as prov
from core.federation.contract import _ADAPTER_FACTORIES
from core.federation.registry import (
    _BUILTIN_ADAPTER_MODULES,
    _ensure_builtins_loaded,
)

pytestmark = pytest.mark.unit

ALL_MAPS = {
    **prov.ADAPTER_PROVENANCE,
    "probe": prov.PROBE_PROVENANCE,
    "webhook": prov.WEBHOOK_PROVENANCE,
}


def _author(data_source, field):
    return resolve_authored(field, prov.provenance_for(data_source))


class TestTheMaps:
    def test_every_builtin_federation_adapter_has_a_map(self):
        # Other tests register fake adapters, so compare against the builtins:
        # each module under core/integrations/<name>/adapter.py registers
        # <name>.
        _ensure_builtins_loaded()
        builtins = {m.split(".")[2] for m in _BUILTIN_ADAPTER_MODULES}
        assert builtins <= set(_ADAPTER_FACTORIES)
        assert builtins == set(prov.ADAPTER_PROVENANCE)
        assert len(prov.ADAPTER_PROVENANCE) == 7

    @pytest.mark.parametrize("name", sorted(ALL_MAPS))
    def test_every_map_is_well_formed(self, name):
        prov.check_map(ALL_MAPS[name])
        assert set(ALL_MAPS[name].values()) <= set(AUTHORED)

    def test_check_map_refuses_a_bad_author_or_key(self):
        with pytest.raises(ValueError):
            prov.check_map({"title": "model"})
        with pytest.raises(ValueError):
            prov.check_map({"a..b": "sensor"})
        with pytest.raises(ValueError):
            prov.check_map({"a.*.b": "sensor"})

    @pytest.mark.parametrize(
        "data_source",
        ["webhook", "kafka:alerts", "csv_import", "imported", "zeek", None, ""],
    )
    def test_any_other_source_gets_the_webhook_map(self, data_source):
        assert prov.provenance_for(data_source) is prov.WEBHOOK_PROVENANCE

    def test_the_probe_source_name_matches_the_daemon(self):
        from services.daemon.probes import PROBE_DATA_SOURCE

        assert prov.PROBE_DATA_SOURCE == PROBE_DATA_SOURCE
        assert prov.provenance_for("probe") is prov.PROBE_PROVENANCE


# Decisions every source shares.
@pytest.mark.parametrize("data_source", sorted(ALL_MAPS.keys() - {"probe"}))
class TestEverySource:
    @pytest.mark.parametrize(
        "field",
        [
            "title",
            "description",
            "entity_context.usernames",
            "entity_context.domains",
            "never.heard.of.it",
            "raw_event",
            "raw_event.x.y",
            "title.extra",
            "entity_context.src_ips.0",
        ],
    )
    def test_adversary_influenceable(self, data_source, field):
        assert _author(data_source, field) == "adversary"

    @pytest.mark.parametrize("field", ["severity", "timestamp"])
    def test_the_products_own_rating_and_clock(self, data_source, field):
        assert _author(data_source, field) == "sensor"

    def test_enrichment_is_third_party(self, data_source):
        assert _author(data_source, "enrichment.ip_10_0_0_1.virustotal") == (
            "third_party"
        )


@pytest.mark.parametrize(
    "data_source,field,author",
    [
        # CrowdStrike (EDR)
        ("crowdstrike", "entity_context.src_ips", "sensor"),
        ("crowdstrike", "entity_context.file_hashes", "sensor"),
        ("crowdstrike", "entity_context.device_id", "sensor"),
        ("crowdstrike", "entity_context.hostnames", "adversary"),
        ("crowdstrike", "mitre_predictions", "sensor"),
        ("crowdstrike", "raw_event.device.local_ip", "sensor"),
        ("crowdstrike", "raw_event.device.hostname", "adversary"),
        ("crowdstrike", "raw_event.behaviors.0.cmdline", "adversary"),
        ("crowdstrike", "raw_event.behaviors.0.filename", "adversary"),
        ("crowdstrike", "raw_event.user_name", "adversary"),
        # Splunk
        ("splunk", "raw_event.src_ip", "sensor"),
        ("splunk", "raw_event.sourcetype", "sensor"),
        ("splunk", "raw_event._time", "sensor"),
        ("splunk", "raw_event._raw", "adversary"),
        ("splunk", "raw_event.http_user_agent", "adversary"),
        ("splunk", "raw_event.url", "adversary"),
        ("splunk", "raw_event.CommandLine", "adversary"),
        ("splunk", "raw_event.query", "adversary"),
        ("splunk", "raw_event.subject", "adversary"),
        ("splunk", "raw_event.file_name", "adversary"),
        ("splunk", "raw_event.host", "adversary"),
        ("splunk", "raw_event.some_custom_field", "adversary"),
        # Elastic (ECS and Wazuh)
        ("elastic", "raw_event._source.source.ip", "sensor"),
        ("elastic", "raw_event._source.host.id", "sensor"),
        ("elastic", "raw_event._source.host.name", "adversary"),
        ("elastic", "raw_event._source.process.hash.sha256", "sensor"),
        ("elastic", "raw_event._source.process.command_line", "adversary"),
        ("elastic", "raw_event._source.user_agent.original", "adversary"),
        ("elastic", "raw_event._source.url.full", "adversary"),
        ("elastic", "raw_event._source.dns.question.name", "adversary"),
        ("elastic", "raw_event._source.email.subject", "adversary"),
        ("elastic", "raw_event._source.file.name", "adversary"),
        ("elastic", "raw_event._source.kibana.alert.rule.name", "adversary"),
        ("elastic", "raw_event._source.kibana.alert.rule.threat.0.id", "sensor"),
        ("elastic", "raw_event._source.data.srcip", "sensor"),
        ("elastic", "raw_event._source.data.win.eventdata.commandLine", "adversary"),
        ("elastic", "raw_event._source.predecoder.hostname", "adversary"),
        ("elastic", "metadata.rule_id", "sensor"),
        ("elastic", "metadata.rule_name", "adversary"),
        # OpenSearch
        ("opensearch", "metadata.monitor_id", "sensor"),
        ("opensearch", "metadata.detector_name", "adversary"),
        ("opensearch", "raw_event._source.queries.0.name", "adversary"),
        ("opensearch", "raw_event._source.destination.ip", "sensor"),
        # Microsoft Defender
        ("microsoft_defender", "entity_context.src_ips", "sensor"),
        ("microsoft_defender", "entity_context.file_hashes", "sensor"),
        ("microsoft_defender", "entity_context.category", "sensor"),
        ("microsoft_defender", "entity_context.threat_family", "sensor"),
        ("microsoft_defender", "entity_context.domains", "adversary"),
        # AWS Security Hub
        ("aws_security_hub", "entities.ip_addresses", "sensor"),
        ("aws_security_hub", "entities.hostnames", "sensor"),
        ("aws_security_hub", "entities.domains", "adversary"),
        ("aws_security_hub", "metadata.aws_account_id", "sensor"),
        ("aws_security_hub", "raw_data.Network.SourceIpV4", "sensor"),
        ("aws_security_hub", "raw_data.Network.SourceDomain", "adversary"),
        ("aws_security_hub", "raw_data.Resources.0.Id", "sensor"),
        ("aws_security_hub", "raw_data.ThreatIntelIndicators.0.Value", "third_party"),
        ("aws_security_hub", "raw_data.Title", "adversary"),
        # Azure Sentinel
        ("azure_sentinel", "entities.ip_addresses", "sensor"),
        ("azure_sentinel", "entities.hostnames", "adversary"),
        ("azure_sentinel", "entities.usernames", "adversary"),
        ("azure_sentinel", "metadata.incident_id", "sensor"),
        ("azure_sentinel", "raw_data.title", "adversary"),
        # Webhook and other pushes
        ("webhook", "entity_context.src_ips", "sensor"),
        ("webhook", "entity_context.file_hashes", "sensor"),
        ("webhook", "entity_context.hostnames", "adversary"),
        ("webhook", "mitre_predictions", "third_party"),
        ("webhook", "raw_event.vendor", "adversary"),
        ("kafka:edr", "entity_context.dest_ips", "sensor"),
        # The probe is ours
        ("probe", "description", "sensor"),
        ("probe", "entity_context.src_ips", "sensor"),
        ("probe", "entity_context.hostnames", "sensor"),
        ("probe", "raw_event.x", "adversary"),
    ],
)
def test_per_source_decisions(data_source, field, author):
    assert _author(data_source, field) == author


def test_unknown_fields_take_the_contracts_default():
    assert UNKNOWN_FIELD_AUTHOR == "adversary"
    for data_source in ALL_MAPS:
        assert _author(data_source, "zz.unknown") == "adversary"


class TestPromptFields:
    def test_a_finding_flattens_into_dotted_names_in_section_order(self):
        finding = {
            "finding_id": "f",
            "data_source": "crowdstrike",
            "raw_event": {"device": {"local_ip": "10.0.0.1"}},
            "title": "T",
            "description": "D",
            "severity": "high",
            "mitre_predictions": {"T1059.001": 0.9, "T1105": 0.5},
            "entity_context": {
                "src_ips": ["10.0.0.1", "10.0.0.2"],
                "usernames": [],
                "device_id": None,
                "probe": {"expected": {"verdict": ["benign"]}},
            },
        }
        fields, omitted = prov.prompt_fields(finding)
        assert fields == [
            ("title", "T"),
            ("description", "D"),
            ("severity", "high"),
            ("mitre_predictions", "T1059.001, T1105"),
            ("entity_context.src_ips", "10.0.0.1, 10.0.0.2"),
            ("raw_event.device.local_ip", "10.0.0.1"),
        ]
        assert omitted == 0

    def test_lists_of_objects_get_index_segments(self):
        fields, _ = prov.prompt_fields(
            {"raw_event": {"behaviors": [{"cmdline": "a"}, {"cmdline": "b"}]}}
        )
        assert fields == [
            ("raw_event.behaviors.0.cmdline", "a"),
            ("raw_event.behaviors.1.cmdline", "b"),
        ]

    def test_dotted_keys_split_into_segments(self):
        fields, _ = prov.prompt_fields(
            {"raw_event": {"_source": {"kibana.alert.rule.name": "R"}}}
        )
        assert fields == [("raw_event._source.kibana.alert.rule.name", "R")]

    @pytest.mark.parametrize(
        "key", ["a b", "a..b", "", "a.", "@timestamp", "x\ny", "é", "a" * 65]
    )
    def test_unnameable_keys_are_left_out(self, key):
        fields, omitted = prov.prompt_fields({"raw_event": {key: "v"}})
        assert fields == [] and omitted == 1

    def test_values_and_field_count_are_bounded(self):
        finding = {
            "description": "d" * 5000,
            "title": "t" * 5000,
            "raw_event": {f"k{i}": "v" for i in range(500)},
        }
        fields, omitted = prov.prompt_fields(finding)
        assert len(fields) == prov.MAX_FIELDS
        assert omitted == 2 + 500 - prov.MAX_FIELDS
        values = dict(fields)
        assert len(values["description"]) <= prov.MAX_DESCRIPTION_CHARS + 20
        assert len(values["title"]) <= prov.MAX_VALUE_CHARS + 20

    def test_depth_is_bounded(self):
        deep: dict = {"v": "x"}
        for _ in range(20):
            deep = {"k": deep}
        fields, omitted = prov.prompt_fields({"raw_event": deep})
        assert fields == [] and omitted == 1

    def test_a_repeated_name_keeps_the_first_value(self):
        fields, _ = prov.prompt_fields(
            {"raw_event": {"a": {"b": "nested"}, "a.b": "dotted"}}
        )
        assert fields == [("raw_event.a.b", "nested")]

    def test_group_fields_uses_the_sources_map(self):
        finding = {
            "data_source": "splunk",
            "title": "T",
            "entity_context": {"src_ips": ["10.0.0.1"]},
            "enrichment": {"ip_10_0_0_1": {"virustotal": {"malicious": 3}}},
            "raw_event": {"http_user_agent": "curl"},
        }
        groups, _ = prov.group_fields(finding)
        assert [n for n, _ in groups["sensor"]] == ["entity_context.src_ips"]
        assert [n for n, _ in groups["third_party"]] == [
            "enrichment.ip_10_0_0_1.virustotal.malicious"
        ]
        assert [n for n, _ in groups["adversary"]] == [
            "title",
            "raw_event.http_user_agent",
        ]

    def test_presented_provenance_covers_only_what_was_shown(self):
        finding = {
            "data_source": "crowdstrike",
            "title": "T",
            "entity_context": {"src_ips": ["10.0.0.1"], "dest_ips": []},
        }
        shown = prov.presented_provenance(finding)
        assert shown == {"title": "adversary", "entity_context.src_ips": "sensor"}
        assert resolve_authored("entity_context.dest_ips", shown) == "adversary"


class TestAdapterOutput:
    """The adapters' own transforms produce the field names the maps cover."""

    def test_crowdstrike_detection(self):
        from core.integrations.crowdstrike.adapter import _detection_to_finding

        finding = _detection_to_finding(
            {
                "detection_id": "ldt:1",
                "scenario": "suspicious_activity",
                "description": "cmd ran",
                "device": {"local_ip": "10.0.0.9", "hostname": "ws-9"},
                "user_name": "bob",
                "behaviors": [{"cmdline": "x", "technique": "T1059"}],
            }
        )
        groups, _ = prov.group_fields(finding)
        sensor = dict(groups["sensor"])
        adversary = dict(groups["adversary"])
        assert sensor["entity_context.src_ips"] == "10.0.0.9"
        assert sensor["raw_event.device.local_ip"] == "10.0.0.9"
        assert "entity_context.hostnames" in adversary
        assert "entity_context.usernames" in adversary
        assert "raw_event.behaviors.0.cmdline" in adversary
        assert "title" in adversary and "description" in adversary

    def test_splunk_event(self):
        from core.integrations.splunk.adapter import _splunk_event_to_finding

        finding = _splunk_event_to_finding(
            {
                "_cd": "1:2",
                "src_ip": "10.0.0.3",
                "user": "alice",
                "http_user_agent": "Mozilla/5.0 (benign, trust me)",
                "search_name": "Odd UA",
                "_raw": "GET / HTTP/1.1",
            }
        )
        groups, _ = prov.group_fields(finding)
        sensor = dict(groups["sensor"])
        adversary = dict(groups["adversary"])
        assert sensor["entity_context.src_ips"] == "10.0.0.3"
        assert sensor["raw_event.src_ip"] == "10.0.0.3"
        assert "raw_event.http_user_agent" in adversary
        assert "raw_event._raw" in adversary
        assert "raw_event.user" in adversary
