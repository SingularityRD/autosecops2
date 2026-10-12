"""Who authored each field of a finding, per ``data_source`` (W1.3).

The triage verdict contract (:mod:`core.contracts.verdict`) labels every
field a verdict cites with ``authored``: ``sensor`` (our own instrumentation
observed it), ``adversary`` (the party under suspicion can write or shape it)
or ``third_party`` (someone else asserted it: threat-intel feeds, reputation
services). The label is set by code from the maps below, never by the model,
and ``enforce_provenance`` downgrades a ``benign`` verdict that cites no
sensor field to ``inconclusive``.

Field names
-----------
:func:`prompt_fields` flattens a finding into dotted field names, the names
the triage prompt shows the model and the model cites back: ``title``,
``entity_context.src_ips``, ``raw_event.device.hostname``,
``raw_event._source.process.command_line``. Lists of scalars are one field;
lists of objects get an index segment (``raw_event.behaviors.0.cmdline``).
Keys that are not ``[A-Za-z0-9_-]`` segments are left out rather than
rewritten, so a crafted key cannot be renamed into a sensor field.

Maps
----
A map is ``{field: author}`` with exact keys and ``prefix.*`` keys (every
child of ``prefix``); an exact key beats a prefix and the longest prefix wins
(:func:`core.contracts.verdict.resolve_authored`). A field no key covers is
``adversary``. The maps therefore only *need* to list what is sensor or
third-party; adversary keys are listed anyway where they document a decision
(user agent, URL, command line, file name, e-mail subject/body, DNS query,
rule title text).

Decisions that hold for every source:

* ``title`` and ``description`` are ``adversary``: rule titles and alert
  descriptions are templated from event content (a file name, a subject line,
  a command line) or written by external rule authors.
* ``severity`` and ``timestamp`` are the source product's own rating and
  clock: ``sensor``.
* ``enrichment.*`` (VirusTotal, Shodan, threat-indicator feed hits) is
  ``third_party``.
* Network addresses, file hashes, ports, process ids and the ids a product
  assigns (device id, cloud resource ARN, alert and rule ids) are what the
  product observed or assigned: ``sensor``.
* Host names and user names are ``adversary``. The product reports them
  faithfully, but their *value* is a name someone chose: whoever controls a
  machine names it, a failed logon records whatever name was typed, an
  attacker creates the account it uses. A verdict cannot clear a finding
  because the host is called ``build-server``. (This matches the labels of
  the v1 eval corpus and its injection suite, eval/, which place injected
  text in host and user names.)
* Domains, URLs, user agents, command lines, process and file names, e-mail
  subjects and bodies, DNS questions and raw log lines are ``adversary``.

A ``data_source`` that is not one of the seven Federation adapters or the
known-answer probe (webhook pushes, ``kafka:<topic>``, imports, anything a
sender names) gets :data:`WEBHOOK_PROVENANCE`. A webhook sender chooses its
own ``data_source``; it is authenticated by the webhook token, which is the
existing trust boundary.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from core.contracts.verdict import (
    AUTHORED,
    CHILDREN_SUFFIX,
    Authored,
    ProvenanceMap,
    resolve_authored,
)

SENSOR: Authored = "sensor"
ADVERSARY: Authored = "adversary"
THIRD_PARTY: Authored = "third_party"

# --------------------------------------------------------------------------
# Maps
# --------------------------------------------------------------------------

# Every source: the product's own rating and clock, and our enrichment.
_COMMON: Dict[str, Authored] = {
    "severity": SENSOR,
    "timestamp": SENSOR,
    "title": ADVERSARY,
    "description": ADVERSARY,
    "enrichment.*": THIRD_PARTY,
}

# The normalized entity_context most adapters emit.
_ENTITY_CONTEXT: Dict[str, Authored] = {
    "entity_context.src_ips": SENSOR,
    "entity_context.dest_ips": SENSOR,
    "entity_context.file_hashes": SENSOR,
    "entity_context.hostnames": ADVERSARY,
    "entity_context.usernames": ADVERSARY,
    "entity_context.domains": ADVERSARY,
    "entity_context.urls": ADVERSARY,
    "entity_context.user_agents": ADVERSARY,
    "entity_context.file_names": ADVERSARY,
    "entity_context.command_lines": ADVERSARY,
    "entity_context.email_subjects": ADVERSARY,
}

# The ``entities`` block SIEMIngestionService.extract_entities builds
# (AWS Security Hub, Azure Sentinel).
_ENTITIES: Dict[str, Authored] = {
    "entities.ip_addresses": SENSOR,
    "entities.file_hashes": SENSOR,
    "entities.hostnames": ADVERSARY,
    "entities.usernames": ADVERSARY,
    "entities.domains": ADVERSARY,
}

# ECS documents (Elastic Security, OpenSearch with ECS payloads), under the
# hit's ``_source``. Observed by the agent/sensor: agent and host ids,
# addresses, ports, hashes, pids, event classification. Shaped by the actor:
# host and user names, process command lines and names, file names and
# paths, URLs, user agents, DNS questions, e-mail content, the original log
# line.
_ECS_SENSOR = (
    "host.*",
    "agent.*",
    "observer.*",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "network.transport",
    "network.protocol",
    "network.direction",
    "process.pid",
    "process.parent.pid",
    "process.hash.*",
    "process.parent.hash.*",
    "file.hash.*",
    "event.kind",
    "event.category",
    "event.type",
    "event.action",
    "event.module",
    "event.dataset",
    "event.outcome",
    "event.severity",
    "event.created",
    "event.ingested",
)
_ECS_ADVERSARY = (
    "host.name",
    "host.hostname",
    "agent.name",
    "agent.hostname",
    "observer.name",
    "observer.hostname",
    "process.command_line",
    "process.args",
    "process.name",
    "process.executable",
    "process.parent.command_line",
    "process.parent.name",
    "process.parent.executable",
    "file.name",
    "file.path",
    "url.*",
    "user_agent.*",
    "http.*",
    "dns.question.name",
    "dns.*",
    "email.*",
    "user.*",
    "message",
    "event.original",
    "kibana.alert.reason",
)


def _under(prefix: str, keys: Iterable[str], author: Authored) -> Dict[str, Authored]:
    return {f"{prefix}.{k}": author for k in keys}


AWS_SECURITY_HUB: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITIES,
    # Security Hub's "hostnames" are the affected resources' ARNs/ids, which
    # AWS assigns.
    "entities.hostnames": SENSOR,
    # Account, region, product and resource identifiers are AWS's own.
    "metadata.*": SENSOR,
    "mitre_attack.*": SENSOR,
    **_under(
        "raw_data",
        (
            "Id",
            "AwsAccountId",
            "Region",
            "ProductArn",
            "ProductName",
            "CompanyName",
            "GeneratorId",
            "CreatedAt",
            "UpdatedAt",
            "FirstObservedAt",
            "LastObservedAt",
            "Types",
            "Severity.*",
            "Resources.*",
            "Compliance.*",
            "Workflow.*",
            "WorkflowState",
            "RecordState",
            "Network.SourceIpV4",
            "Network.SourceIpV6",
            "Network.SourcePort",
            "Network.DestinationIpV4",
            "Network.DestinationIpV6",
            "Network.DestinationPort",
            "Network.Protocol",
            "Network.Direction",
        ),
        SENSOR,
    ),
    **_under(
        "raw_data",
        ("Title", "Description", "Network.SourceDomain", "Network.DestinationDomain"),
        ADVERSARY,
    ),
    "raw_data.ThreatIntelIndicators.*": THIRD_PARTY,
}

AZURE_SENTINEL: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITIES,
    "metadata.incident_id": SENSOR,
    "metadata.status": SENSOR,
    "metadata.owner": SENSOR,
    "metadata.labels": SENSOR,
    "metadata.tactics": SENSOR,
    "metadata.alert_count": SENSOR,
    "metadata.last_updated": SENSOR,
    "mitre_attack.*": SENSOR,
    **_under(
        "raw_data",
        (
            "id",
            "severity",
            "status",
            "created_time",
            "last_updated_time",
            "owner",
            "labels",
            "tactics",
            "alert_count",
        ),
        SENSOR,
    ),
    "raw_data.title": ADVERSARY,
    "raw_data.description": ADVERSARY,
}

CROWDSTRIKE: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITY_CONTEXT,
    # The Falcon agent id, assigned by CrowdStrike.
    "entity_context.device_id": SENSOR,
    "mitre_predictions": SENSOR,
    **_under(
        "raw_event",
        (
            "detection_id",
            "created_timestamp",
            "first_behavior",
            "last_behavior",
            "max_severity",
            "max_severity_displayname",
            "max_confidence",
            "status",
            "scenario",
            "device.*",
            "hostinfo.*",
        ),
        SENSOR,
    ),
    # Behaviors carry the command line and file name next to the hashes; a
    # list cannot be split per child, so the whole block stays adversary.
    **_under(
        "raw_event",
        (
            "description",
            "behaviors.*",
            "cmdline",
            "filename",
            "filepath",
            "user_name",
            "device.hostname",
            "device.machine_domain",
            "hostinfo.domain",
        ),
        ADVERSARY,
    ),
}

ELASTIC: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITY_CONTEXT,
    "mitre_predictions": SENSOR,
    "metadata.elastic_alert_id": SENSOR,
    "metadata.rule_id": SENSOR,
    "metadata.index": SENSOR,
    "metadata.kibana_case_ids": SENSOR,
    "metadata.vendor": SENSOR,
    "metadata.rule_name": ADVERSARY,
    "raw_event._id": SENSOR,
    "raw_event._index": SENSOR,
    **_under("raw_event._source", _ECS_SENSOR, SENSOR),
    **_under("raw_event._source", _ECS_ADVERSARY, ADVERSARY),
    "raw_event._source.kibana.alert.uuid": SENSOR,
    "raw_event._source.kibana.alert.severity": SENSOR,
    "raw_event._source.kibana.alert.risk_score": SENSOR,
    "raw_event._source.kibana.alert.rule.uuid": SENSOR,
    "raw_event._source.kibana.alert.rule.rule_id": SENSOR,
    "raw_event._source.kibana.alert.rule.threat.*": SENSOR,
    "raw_event._source.kibana.alert.rule.name": ADVERSARY,
    "raw_event._source.kibana.alert.rule.description": ADVERSARY,
    # Wazuh documents in the same index.
    "raw_event._source.manager.*": SENSOR,
    "raw_event._source.rule.id": SENSOR,
    "raw_event._source.rule.level": SENSOR,
    "raw_event._source.rule.groups": SENSOR,
    "raw_event._source.rule.mitre.*": SENSOR,
    "raw_event._source.rule.description": ADVERSARY,
    "raw_event._source.full_log": ADVERSARY,
    "raw_event._source.data.srcip": SENSOR,
    "raw_event._source.data.dstip": SENSOR,
    "raw_event._source.data.*": ADVERSARY,
    # A syslog relay records whatever host name the sender claimed.
    "raw_event._source.predecoder.*": ADVERSARY,
}

MICROSOFT_DEFENDER: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITY_CONTEXT,
    # Defender's own classification of the alert.
    "entity_context.category": SENSOR,
    "entity_context.threat_family": SENSOR,
    "mitre_predictions": SENSOR,
}

OPENSEARCH: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITY_CONTEXT,
    "mitre_predictions": SENSOR,
    "metadata.opensearch_finding_id": SENSOR,
    "metadata.monitor_id": SENSOR,
    "metadata.triggered_rule_ids": SENSOR,
    "metadata.related_doc_ids": SENSOR,
    "metadata.source_index": SENSOR,
    "metadata.log_type": SENSOR,
    "metadata.index": SENSOR,
    "metadata.detector_name": ADVERSARY,
    "raw_event._id": SENSOR,
    "raw_event._index": SENSOR,
    "raw_event._source.id": SENSOR,
    "raw_event._source.monitor_id": SENSOR,
    "raw_event._source.detector_id": SENSOR,
    "raw_event._source.index": SENSOR,
    "raw_event._source.related_doc_ids": SENSOR,
    "raw_event._source.timestamp": SENSOR,
    "raw_event._source.queries.*": ADVERSARY,
    "raw_event._source.monitor_name": ADVERSARY,
    **_under("raw_event._source", _ECS_SENSOR, SENSOR),
    **_under("raw_event._source", _ECS_ADVERSARY, ADVERSARY),
}

SPLUNK: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITY_CONTEXT,
    "mitre_predictions": SENSOR,
    # Index-time metadata and the CIM network fields the adapter normalizes.
    **_under(
        "raw_event",
        (
            "_time",
            "_indextime",
            "_cd",
            "_serial",
            "index",
            "source",
            "sourcetype",
            "splunk_server",
            "event_id",
            "urgency",
            "severity",
            "search_name",
            "src_ip",
            "src",
            "source_ip",
            "src_port",
            "dest_ip",
            "dest",
            "destination_ip",
            "dest_port",
            "transport",
            "protocol",
            "action",
            "file_hash",
            "md5",
            "sha1",
            "sha256",
        ),
        SENSOR,
    ),
    **_under(
        "raw_event",
        (
            "_raw",
            "description",
            "rule_name",
            "host",
            "hostname",
            "src_host",
            "dest_host",
            "user",
            "username",
            "src_user",
            "http_user_agent",
            "user_agent",
            "url",
            "uri",
            "uri_path",
            "uri_query",
            "http_referrer",
            "process",
            "process_name",
            "CommandLine",
            "cmdline",
            "command",
            "file_name",
            "file_path",
            "query",
            "subject",
            "message_body",
            "sender",
            "recipient",
        ),
        ADVERSARY,
    ),
}

ADAPTER_PROVENANCE: Dict[str, Dict[str, Authored]] = {
    "aws_security_hub": AWS_SECURITY_HUB,
    "azure_sentinel": AZURE_SENTINEL,
    "crowdstrike": CROWDSTRIKE,
    "elastic": ELASTIC,
    "microsoft_defender": MICROSOFT_DEFENDER,
    "opensearch": OPENSEARCH,
    "splunk": SPLUNK,
}

# A known-answer probe (services/daemon/probes.py) is synthetic input written
# by our own code: every field it carries is ours. Its expected answer under
# entity_context.probe never reaches the prompt (see prompt_fields).
PROBE_DATA_SOURCE = "probe"
PROBE_PROVENANCE: Dict[str, Authored] = {
    "severity": SENSOR,
    "timestamp": SENSOR,
    "title": SENSOR,
    "description": SENSOR,
    "entity_context.*": SENSOR,
}

# Webhook pushes and every other source. The pusher is a connector we
# configured and authenticated, so the normalized network observables it
# sends are sensor; its detector's technique guesses are its assertion
# (third party); everything else, free text first, is adversary.
WEBHOOK_PROVENANCE: Dict[str, Authored] = {
    **_COMMON,
    **_ENTITY_CONTEXT,
    "mitre_predictions": THIRD_PARTY,
    "raw_event.*": ADVERSARY,
}


def provenance_for(data_source: Optional[str]) -> ProvenanceMap:
    """The provenance map for a finding's ``data_source``."""
    if data_source in ADAPTER_PROVENANCE:
        return ADAPTER_PROVENANCE[data_source]
    if data_source == PROBE_DATA_SOURCE:
        return PROBE_PROVENANCE
    return WEBHOOK_PROVENANCE


# --------------------------------------------------------------------------
# Flattening a finding into prompt fields
# --------------------------------------------------------------------------

# Sections of a finding shown to the model, in order. Normalized fields come
# first so the field budget is spent on them before raw payloads.
_SECTIONS = (
    "title",
    "description",
    "severity",
    "timestamp",
    "mitre_predictions",
    "entity_context",
    "entities",
    "metadata",
    "mitre_attack",
    "enrichment",
    "raw_event",
    "raw_data",
)
# entity_context keys never shown: the probe's known answer.
_HIDDEN_ENTITY_KEYS = frozenset({"probe"})

MAX_FIELDS = 80
MAX_VALUE_CHARS = 300
MAX_DESCRIPTION_CHARS = 1000
MAX_DEPTH = 6
MAX_LIST_SCALARS = 10
MAX_LIST_OBJECTS = 5

_SEGMENT = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def _scalar(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    return text if text.strip() else None


def _key_segments(key: Any) -> Optional[List[str]]:
    """A dict key as path segments, or None when it cannot be named safely."""
    if not isinstance(key, str):
        key = str(key)
    segments = key.split(".")
    if all(_SEGMENT.fullmatch(s) for s in segments):
        return segments
    return None


class _Collector:
    def __init__(self) -> None:
        self.fields: List[Tuple[str, str]] = []
        self.seen: set = set()
        self.omitted = 0

    @property
    def full(self) -> bool:
        return len(self.fields) >= MAX_FIELDS

    def add(self, name: str, value: str, limit: int = MAX_VALUE_CHARS) -> None:
        if name in self.seen:
            return
        if self.full:
            self.omitted += 1
            return
        self.seen.add(name)
        self.fields.append((name, _clip(value, limit)))

    def walk(self, path: List[str], value: Any, depth: int) -> None:
        if isinstance(value, Mapping):
            if depth >= MAX_DEPTH:
                self.omitted += 1
                return
            for key, child in value.items():
                segments = _key_segments(key)
                if segments is None:
                    self.omitted += 1
                    continue
                self.walk(path + segments, child, depth + 1)
            return
        if isinstance(value, (list, tuple)):
            if any(isinstance(v, (Mapping, list, tuple)) for v in value):
                if depth >= MAX_DEPTH:
                    self.omitted += 1
                    return
                for i, child in enumerate(value[:MAX_LIST_OBJECTS]):
                    self.walk(path + [str(i)], child, depth + 1)
                self.omitted += max(0, len(value) - MAX_LIST_OBJECTS)
                return
            items = [s for v in value if (s := _scalar(v)) is not None]
            if items:
                shown = items[:MAX_LIST_SCALARS]
                text = ", ".join(shown)
                if len(items) > len(shown):
                    text += f", ... (+{len(items) - len(shown)} more)"
                self.add(".".join(path), text)
            return
        text = _scalar(value)
        if text is not None:
            self.add(".".join(path), text)


def prompt_fields(finding: Mapping[str, Any]) -> Tuple[List[Tuple[str, str]], int]:
    """``([(field, value), ...], omitted)`` — what the triage prompt shows.

    Field names are the names :func:`provenance_for` maps resolve. Values are
    plain strings, clipped; rendering (quoting, fencing) is the caller's job.
    ``omitted`` counts fields left out by the budget, the depth limit or an
    unnameable key.
    """
    out = _Collector()
    for section in _SECTIONS:
        value = finding.get(section)
        if value is None:
            continue
        if section == "description":
            text = _scalar(value)
            if text is not None:
                out.add("description", text, MAX_DESCRIPTION_CHARS)
            continue
        if section == "mitre_predictions":
            # {technique: score}: technique ids contain dots, so the keys are
            # one field rather than a path.
            if isinstance(value, Mapping):
                value = list(value.keys())
            out.walk([section], value, 0)
            continue
        if section == "entity_context" and isinstance(value, Mapping):
            value = {k: v for k, v in value.items() if k not in _HIDDEN_ENTITY_KEYS}
        out.walk([section], value, 0)
    return out.fields, out.omitted


def group_fields(
    finding: Mapping[str, Any],
) -> Tuple[Dict[Authored, List[Tuple[str, str]]], int]:
    """:func:`prompt_fields` grouped by author under the finding's map."""
    provenance = provenance_for(finding.get("data_source"))
    fields, omitted = prompt_fields(finding)
    groups: Dict[Authored, List[Tuple[str, str]]] = {a: [] for a in AUTHORED}
    for name, value in fields:
        groups[resolve_authored(name, provenance)].append((name, value))
    return groups, omitted


def presented_provenance(finding: Mapping[str, Any]) -> Dict[str, Authored]:
    """An exact-key map of only the fields :func:`prompt_fields` shows.

    Resolving a verdict's citations against this map instead of the full one
    makes a citation of a field the prompt never showed (an empty
    ``entity_context.src_ips``, a sensor field the finding does not have)
    resolve to ``adversary``: a verdict can only stand on evidence that was
    in front of the model.
    """
    provenance = provenance_for(finding.get("data_source"))
    fields, _ = prompt_fields(finding)
    return {name: resolve_authored(name, provenance) for name, _ in fields}


def check_map(provenance: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` if a map has an unknown author or a malformed key."""
    for key, author in provenance.items():
        if author not in AUTHORED:
            raise ValueError(f"{key!r}: unknown author {author!r}")
        name = key[: -len(CHILDREN_SUFFIX)] if key.endswith(CHILDREN_SUFFIX) else key
        if not all(_SEGMENT.fullmatch(s) for s in name.split(".")):
            raise ValueError(f"{key!r}: not a dotted field name")


__all__ = [
    "ADAPTER_PROVENANCE",
    "ADVERSARY",
    "MAX_FIELDS",
    "PROBE_DATA_SOURCE",
    "PROBE_PROVENANCE",
    "SENSOR",
    "THIRD_PARTY",
    "WEBHOOK_PROVENANCE",
    "check_map",
    "group_fields",
    "presented_provenance",
    "prompt_fields",
    "provenance_for",
]
