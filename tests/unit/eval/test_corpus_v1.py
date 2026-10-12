"""Checks for the v1 triage evaluation corpus and injection suite (W0.7)."""

import hashlib
import importlib.util
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "eval" / "corpus" / "v1"
INJECTION = ROOT / "eval" / "suites" / "injection" / "v1.jsonl"
SPLITS = ("train", "dev", "test")
UNSEEN = "test_unseen"
ALL_FILES = SPLITS + (UNSEEN,)
# A metadata-only classifier must not beat this on test or test_unseen.
TRIVIAL_MAX_ACC = 0.60
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
    return {name: _read(CORPUS / f"{name}.jsonl") for name in ALL_FILES}


@pytest.fixture(scope="module")
def corpus(splits):
    """Every corpus record: train, dev, test and test_unseen."""
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


def test_split_integrity(splits):
    ids = {name: {r["alert"]["finding_id"] for r in rows} for name, rows in splits.items()}
    for i, a in enumerate(ALL_FILES):
        for b in ALL_FILES[i + 1:]:
            assert not ids[a] & ids[b], (a, b)
    seen_total = sum(len(splits[n]) for n in SPLITS)
    for name, frac in (("train", 0.6), ("dev", 0.2), ("test", 0.2)):
        assert abs(len(splits[name]) / seen_total - frac) < 0.01
    for name in ALL_FILES:
        assert all(r["meta"]["split"] == name for r in splits[name])
    # every file covers every category x verdict stratum
    for rows in splits.values():
        strata = {(r["labels"]["category"], r["labels"]["verdict"]) for r in rows}
        assert len(strata) == 2 * len(CATEGORIES)


def test_unseen_split_holds_out_whole_twin_pairs(splits):
    seen = [r for n in SPLITS for r in splits[n]]
    unseen = splits[UNSEEN]
    seen_pairs = {r["meta"]["pair_id"] for r in seen}
    unseen_pairs = {r["meta"]["pair_id"] for r in unseen}
    assert not seen_pairs & unseen_pairs
    per_cat = defaultdict(set)
    for r in unseen:
        per_cat[r["labels"]["category"]].add(r["meta"]["pair_id"])
    assert set(per_cat) == CATEGORIES
    assert all(len(p) >= 2 for p in per_cat.values()), per_cat
    # whole pairs: both twins of every held-out pair are present
    twins = defaultdict(set)
    for r in unseen:
        twins[r["meta"]["pair_id"]].add(r["labels"]["verdict"])
    assert all(v == {"malicious", "benign"} for v in twins.values())
    # nothing of a held-out scenario is visible in the seen splits
    seen_rules = {r["alert"]["raw_event"]["rule_name"] for r in seen}
    seen_desc = {r["alert"]["description"] for r in seen}
    for r in unseen:
        assert r["alert"]["raw_event"]["rule_name"] not in seen_rules
        assert r["alert"]["description"] not in seen_desc


def test_twin_pairs_share_metadata(corpus):
    """Malicious and benign twins are indistinguishable on everything but the prose."""
    by_pair = defaultdict(lambda: defaultdict(list))
    for r in corpus:
        by_pair[r["meta"]["pair_id"]][r["labels"]["verdict"]].append(r["alert"])
    rule_pairs = defaultdict(set)
    for pid, twins in by_pair.items():
        assert set(twins) == {"malicious", "benign"}, pid

        def shape(alerts):
            return {
                "rule": {a["raw_event"]["rule_name"] for a in alerts},
                "source": {a["data_source"] for a in alerts},
                "technique": {t for a in alerts for t in a["mitre_predictions"]},
                "hashes": {len(a["entity_context"]["file_hashes"]) for a in alerts},
                "dests": {len(a["entity_context"]["dest_ips"]) for a in alerts},
                "srcs": {len(a["entity_context"]["src_ips"]) for a in alerts},
            }

        m, b = shape(twins["malicious"]), shape(twins["benign"])
        assert m == b, (pid, m, b)
        assert len(m["rule"]) == len(m["source"]) == len(m["technique"]) == 1, pid
        rule_pairs[next(iter(m["rule"]))].add(pid)
    assert all(len(p) == 1 for p in rule_pairs.values()), "rule names must be unique per pair"
    verdict_words = re.compile(r"malicious|benign|suspicious|approved|legitimate|attack|"
                               r"kerberoast|spray|brute|ransomware|phish", re.IGNORECASE)
    for r in corpus:
        a = r["alert"]
        assert not verdict_words.search(a["raw_event"]["rule_name"]), a["raw_event"]["rule_name"]
        assert not verdict_words.search(a["title"]), a["title"]


def test_labels_do_not_leak_into_alert(corpus):
    for rec in corpus:
        blob = json.dumps(rec["alert"]).lower()
        for word in ("template_id", "pair_id", "verdict", "malicious", "benign"):
            assert word not in blob, (word, rec["alert"]["finding_id"])
        assert rec["labels"]["rationale"].lower() not in blob
        assert rec["meta"]["pair_id"] not in blob


# ---------------------------------------------------------------------------
# Trivial classifiers. Each is fit on train and scored on test and
# test_unseen; none may exceed TRIVIAL_MAX_ACC, otherwise the label is
# recoverable without reading the description.
# ---------------------------------------------------------------------------
def _y(rec):
    return 1 if rec["labels"]["verdict"] == "malicious" else 0


def _accuracy(predict, rows):
    return sum(predict(r) == _y(r) for r in rows) / len(rows)


def _lookup(key, train):
    votes = defaultdict(Counter)
    for r in train:
        votes[key(r)][_y(r)] += 1

    def predict(r):
        c = votes.get(key(r))
        if not c or c[0] == c[1]:
            return 0  # unseen key or tie: fixed fallback
        return c.most_common(1)[0][0]

    return predict


def _meta_features(rec, vocab):
    a = rec["alert"]
    ec = a["entity_context"]
    x = [0.0] * len(vocab)
    for tok in ("sev=" + a["severity"], "src=" + a["data_source"],
                *("tech=" + t for t in a["mitre_predictions"])):
        if tok in vocab:
            x[vocab[tok]] = 1.0
    return x + [a["anomaly_score"], float(len(ec["file_hashes"])), float(len(ec["dest_ips"])),
                float(len(ec["src_ips"])), 1.0]


def _logreg(train, epochs=400, lr=0.5, l2=1e-3):
    """Batch-gradient logistic regression on alert metadata only (no text):
    severity, data_source and technique one-hots plus anomaly_score and the
    file-hash / destination / source counts. Uses numpy when available."""
    vocab = {}
    for r in train:
        a = r["alert"]
        for tok in ("sev=" + a["severity"], "src=" + a["data_source"],
                    *("tech=" + t for t in a["mitre_predictions"])):
            vocab.setdefault(tok, len(vocab))
    X = [_meta_features(r, vocab) for r in train]
    y = [_y(r) for r in train]
    w = [0.0] * len(X[0])
    n = len(X)
    try:
        import numpy as np
    except ImportError:  # pure-Python loop below
        np = None
    if np is not None:
        Xa, ya, wa = np.array(X), np.array(y, dtype=float), np.zeros(len(w))
        for _ in range(epochs):
            p = 1.0 / (1.0 + np.exp(-np.clip(Xa @ wa, -30.0, 30.0)))
            wa -= lr * (Xa.T @ (p - ya) / n + l2 * wa)
        w, epochs = [float(v) for v in wa], 0
    for _ in range(epochs):
        grad = [l2 * wi for wi in w]
        for xi, yi in zip(X, y):
            z = sum(wj * xj for wj, xj in zip(w, xi))
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            g = (p - yi) / n
            for j, xj in enumerate(xi):
                if xj:
                    grad[j] += g * xj
        w = [wj - lr * gj for wj, gj in zip(w, grad)]

    def predict(r):
        z = sum(wj * xj for wj, xj in zip(w, _meta_features(r, vocab)))
        return 1 if z > 0 else 0

    return predict


def trivial_baselines(splits):
    """Accuracy of each trivial classifier on test and test_unseen."""
    train = splits["train"]
    clfs = {
        "exact_title": _lookup(lambda r: r["alert"]["title"], train),
        "rule_name": _lookup(lambda r: r["alert"]["raw_event"]["rule_name"], train),
        "logreg_metadata": _logreg(train),
    }
    return {name: {s: _accuracy(f, splits[s]) for s in ("test", UNSEEN)} for name, f in clfs.items()}


@pytest.fixture(scope="module")
def baselines(splits):
    return trivial_baselines(splits)


@pytest.mark.parametrize("clf", ["exact_title", "rule_name", "logreg_metadata"])
@pytest.mark.parametrize("split", ["test", UNSEEN])
def test_trivial_classifier_cannot_recover_label(baselines, clf, split):
    acc = baselines[clf][split]
    assert acc <= TRIVIAL_MAX_ACC, f"{clf} reaches {acc:.3f} on {split}"


def test_manifest_matches_files():
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    for name in ALL_FILES:
        data = (CORPUS / f"{name}.jsonl").read_bytes()
        assert hashlib.sha256(data).hexdigest() == manifest["files"][f"{name}.jsonl"]["sha256"]
    assert hashlib.sha256(INJECTION.read_bytes()).hexdigest() == manifest["injection"]["sha256"]


def test_deterministic_rebuild(tmp_path):
    mod = _load_builder()
    m1 = mod.build(tmp_path / "a")
    m2 = mod.build(tmp_path / "b")
    assert m1 == m2
    for name in ALL_FILES:
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
