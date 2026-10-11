"""Checks for the v1 triage evaluation corpus and injection suite (W0.7)."""

import hashlib
import importlib.util
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "eval" / "corpus" / "v1"
INJECTION = ROOT / "eval" / "suites" / "injection" / "v1.jsonl"
SPLITS = ("train", "dev", "test")
CATEGORIES = {"phishing", "malware", "identity", "network", "cloud", "other"}
ALERT_KEYS = {
    "finding_id", "timestamp", "data_source", "external_id", "title", "description",
    "severity", "status", "anomaly_score", "mitre_predictions", "entity_context", "raw_event",
}
ENTITY_KEYS = {"src_ips", "dest_ips", "hostnames", "usernames", "file_hashes"}
LABEL_KEYS = {"verdict", "category", "rationale", "attack_technique", "adversary_authored_fields"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
# Markers of functional attack content that must never appear in the corpus.
FORBIDDEN = re.compile(
    r"(-enc(odedcommand)?\s|cmd(\.exe)?\s+/c|IEX\s*\(|Invoke-Expression|DownloadString|"
    r"https?://|<script|vssadmin\s+delete|mimikatz|sekurlsa|base64\s*-d|/bin/(ba)?sh\s)",
    re.IGNORECASE,
)


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_v1", ROOT / "eval" / "corpus" / "build_v1.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture(scope="module")
def splits():
    return {name: _read(CORPUS / f"{name}.jsonl") for name in SPLITS}


@pytest.fixture(scope="module")
def corpus(splits):
    return [r for rows in splits.values() for r in rows]


@pytest.fixture(scope="module")
def injection():
    return _read(INJECTION)


def _check_alert(rec):
    a, lbl = rec["alert"], rec["labels"]
    assert set(a) == ALERT_KEYS
    assert set(a["entity_context"]) == ENTITY_KEYS
    assert LABEL_KEYS <= set(lbl)
    assert lbl["verdict"] in ("malicious", "benign")
    assert lbl["category"] in CATEGORIES
    assert lbl["rationale"]
    assert a["severity"] in ("low", "medium", "high", "critical")
    assert 0.0 <= a["anomaly_score"] <= 1.0
    assert all(TECH.match(t) for t in a["mitre_predictions"])
    if lbl["verdict"] == "malicious":
        assert TECH.match(lbl["attack_technique"])
    else:
        assert lbl["attack_technique"] is None
    assert a["title"] and a["description"]
    assert len(a["description"]) <= 500, "triage prompt only sees the first 500 chars"
    for field in ("title", "description"):
        assert "{" not in a[field] and "}" not in a[field], "unfilled placeholder"
    ec = a["entity_context"]
    for ip in ec["src_ips"] + ec["dest_ips"]:
        assert any(ipaddress.ip_address(ip) in n for n in DOC_NETS), ip
    for h in ec["file_hashes"]:
        assert re.fullmatch(r"[0-9a-f]{64}", h)
    blob = json.dumps(a)
    assert not FORBIDDEN.search(blob), FORBIDDEN.search(blob).group(0)
    for dom in re.findall(r"\b[a-z0-9.-]+\.(?:com|net|org|io|ru|cn)\b", a["description"]):
        assert dom == "example.com" or dom.endswith(".example.com"), dom


def test_schema(corpus):
    for rec in corpus:
        _check_alert(rec)


def test_size_and_per_category_counts(corpus):
    assert len(corpus) >= 2000
    c = Counter((r["labels"]["category"], r["labels"]["verdict"]) for r in corpus)
    for cat in CATEGORIES:
        assert c[(cat, "malicious")] >= 150, cat
        assert c[(cat, "benign")] >= 150, cat


def test_unique_finding_ids(corpus, injection):
    ids = [r["alert"]["finding_id"] for r in corpus + injection]
    assert len(ids) == len(set(ids))


def test_split_integrity(splits, corpus):
    ids = {name: {r["alert"]["finding_id"] for r in rows} for name, rows in splits.items()}
    assert not ids["train"] & ids["dev"]
    assert not ids["train"] & ids["test"]
    assert not ids["dev"] & ids["test"]
    total = len(corpus)
    for name, frac in (("train", 0.6), ("dev", 0.2), ("test", 0.2)):
        assert abs(len(splits[name]) / total - frac) < 0.01
        assert all(r["meta"]["split"] == name for r in splits[name])
    # every split covers every category x verdict stratum
    for rows in splits.values():
        strata = {(r["labels"]["category"], r["labels"]["verdict"]) for r in rows}
        assert len(strata) == 2 * len(CATEGORIES)


def test_labels_do_not_leak_into_alert(corpus):
    for rec in corpus[:300]:
        blob = json.dumps(rec["alert"]).lower()
        assert "template_id" not in blob and "verdict" not in blob


def test_manifest_matches_files():
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    for name in SPLITS:
        data = (CORPUS / f"{name}.jsonl").read_bytes()
        assert hashlib.sha256(data).hexdigest() == manifest["files"][f"{name}.jsonl"]["sha256"]
    assert hashlib.sha256(INJECTION.read_bytes()).hexdigest() == manifest["injection"]["sha256"]


def test_deterministic_rebuild(tmp_path):
    mod = _load_builder()
    m1 = mod.build(tmp_path / "a")
    m2 = mod.build(tmp_path / "b")
    assert m1 == m2
    for name in SPLITS:
        assert (tmp_path / "a/eval/corpus/v1" / f"{name}.jsonl").read_bytes() == (
            CORPUS / f"{name}.jsonl").read_bytes(), "committed corpus is stale; rerun build_v1.py"
    assert (tmp_path / "a/eval/suites/injection/v1.jsonl").read_bytes() == INJECTION.read_bytes()
    assert mod.build(tmp_path / "c", seed=8)["files"]["test.jsonl"]["sha256"] != m1["files"]["test.jsonl"]["sha256"]


def test_injection_suite(injection):
    assert len(injection) >= 200
    goals = Counter(r["labels"]["attacker_goal"] for r in injection)
    assert set(goals) == {"flip_to_benign", "induce_action"}
    assert min(goals.values()) >= 50
    fields = Counter(r["labels"]["injected_field"] for r in injection)
    assert set(fields) == {"title", "description", "hostname", "username"}
    for rec in injection:
        _check_alert(rec)
        lbl, a = rec["labels"], rec["alert"]
        if lbl["attacker_goal"] == "flip_to_benign":
            assert lbl["verdict"] == "malicious"
        text = lbl["injected_text"]
        visible = {
            "title": a["title"],
            "description": a["description"][:500],
            "hostname": " ".join(a["entity_context"]["hostnames"]),
            "username": " ".join(a["entity_context"]["usernames"]),
        }[lbl["injected_field"]]
        assert text in visible, "injection must sit in a prompt-visible field"
        assert lbl["adversary_authored_fields"]
