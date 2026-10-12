"""Signed checkpoints in a real Postgres: write, verify, and what they catch.

Every test writes its checkpoints inside a transaction that is rolled back, so
no committed checkpoint signed by one test's key confronts another test's
trusted key.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import text

from core.audit import verify as verify_cli
from core.audit.chain import walk_audit_chain
from core.audit.checkpoint import (
    append_to_file,
    generate_key,
    load_private_key,
    verify_checkpoints,
    write_checkpoint,
)
from tests.unit.audit.conftest import insert_action

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

AGENT_RUN = "00000000-0000-4000-8000-00000000c4ec"


def _key():
    seed, _ = generate_key()
    return load_private_key(seed)


@pytest.fixture
def conn(audit_db):
    connection = audit_db.engine.connect()
    tx = connection.begin()
    try:
        yield connection
    finally:
        tx.rollback()
        connection.close()


def _agent_event(conn, seq):
    conn.execute(
        text(
            "INSERT INTO agent_events (run_id, seq, run_kind, kind, payload, "
            "schema_version) VALUES (:r, :s, 'hunt', 'note', CAST(:p AS jsonb), 1)"
        ),
        {"r": AGENT_RUN, "s": seq, "p": json.dumps({"n": seq})},
    )


def test_checkpoint_records_both_heads_and_verifies(conn):
    key = _key()
    insert_action(conn, "action-cp-1")
    _agent_event(conn, 1)
    _agent_event(conn, 2)
    first = write_checkpoint(conn, key)
    insert_action(conn, "action-cp-2")
    second = write_checkpoint(conn, key)

    body = json.loads(first.body)
    head = body["audit_chain"]["head"]
    assert (
        head["seq"]
        == conn.execute(
            text("SELECT seq FROM audit_chain WHERE source_id = 'action-cp-1'")
        ).scalar()
    )
    assert body["agent_events"]["heads"][AGENT_RUN]["seq"] == 2
    assert body["prev"] == ""
    assert json.loads(second.body)["prev"] == first.body_hash
    assert second.prev_body_hash == first.body_hash

    report = verify_checkpoints(conn, key.public_key())
    assert report.ok, report.breaks
    assert (report.count, report.trusted) == (2, True)


def test_wrong_trusted_key_is_refused(conn):
    write_checkpoint(conn, _key())
    [found] = verify_checkpoints(conn, _key().public_key()).breaks
    assert found.reason == "checkpoint_key"


def test_without_a_trusted_key_the_report_says_so(conn):
    write_checkpoint(conn, _key())
    report = verify_checkpoints(conn, None)
    assert report.ok
    assert report.trusted is False


def _tamper(conn):
    conn.execute(text("SET LOCAL session_replication_role = replica"))


def test_rewritten_body_is_refused(conn):
    key = _key()
    cp = write_checkpoint(conn, key)
    forged = json.loads(cp.body)
    forged["audit_chain"]["head"]["seq"] = 1
    body = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    _tamper(conn)
    # Body alone: the hash no longer matches.
    conn.execute(
        text("UPDATE audit_checkpoints SET body = :b WHERE id = :id"),
        {"b": body, "id": cp.id},
    )
    [found] = verify_checkpoints(conn, key.public_key()).breaks
    assert found.reason == "checkpoint_body"
    # Body and its hash: the signature no longer verifies.
    conn.execute(
        text(
            "UPDATE audit_checkpoints SET body_hash = encode(sha256(convert_to(body, "
            "'UTF8')), 'hex') WHERE id = :id"
        ),
        {"id": cp.id},
    )
    [found] = verify_checkpoints(conn, key.public_key()).breaks
    assert found.reason == "checkpoint_signature"


def test_deleted_checkpoint_breaks_the_link(conn):
    key = _key()
    first = write_checkpoint(conn, key)
    write_checkpoint(conn, key)
    write_checkpoint(conn, key)
    _tamper(conn)
    conn.execute(
        text("DELETE FROM audit_checkpoints WHERE id = :id"), {"id": first.id + 1}
    )
    [found] = verify_checkpoints(conn, key.public_key()).breaks
    assert found.reason == "checkpoint_link"


def test_truncated_chain_tail_is_caught_by_the_checkpoint(conn):
    # Deleting the newest chain rows leaves a chain that walks clean; only the
    # signed head shows they were there.
    key = _key()
    insert_action(conn, "action-cp-tail")
    write_checkpoint(conn, key)
    _tamper(conn)
    conn.execute(
        text(
            "DELETE FROM audit_chain WHERE seq = (SELECT max(seq) FROM audit_chain)"
        )
    )
    assert walk_audit_chain(conn).ok
    [found] = verify_checkpoints(conn, key.public_key()).breaks
    assert found.reason == "checkpoint_head"
    assert "audit_chain" in found.detail


def test_rewritten_agent_ledger_head_is_caught(conn):
    key = _key()
    _agent_event(conn, 1)
    write_checkpoint(conn, key)
    _tamper(conn)
    conn.execute(text("DELETE FROM agent_events WHERE run_id = :r"), {"r": AGENT_RUN})
    [found] = verify_checkpoints(conn, key.public_key()).breaks
    assert found.reason in {"checkpoint_count", "checkpoint_head"}


def test_file_copy_catches_a_deleted_newest_checkpoint(conn, tmp_path):
    key = _key()
    path = tmp_path / "checkpoints.jsonl"
    for _ in range(2):
        append_to_file(str(path), write_checkpoint(conn, key))
    report = verify_checkpoints(conn, key.public_key(), str(path))
    assert report.ok, report.breaks
    assert report.file_lines == 2

    _tamper(conn)
    conn.execute(
        text(
            "DELETE FROM audit_checkpoints WHERE id = (SELECT max(id) FROM audit_checkpoints)"
        )
    )
    # The database alone still links up...
    assert verify_checkpoints(conn, key.public_key()).ok
    # ...the copy does not.
    [found] = verify_checkpoints(conn, key.public_key(), str(path)).breaks
    assert found.reason == "checkpoint_missing"


def test_tsa_token_is_stored_without_network(conn):
    sent = []

    def fake_post(url, body, timeout):
        sent.append((url, body))
        return 200, bytes.fromhex("30053003020100")  # TimeStampResp, granted

    cp = write_checkpoint(
        conn, _key(), tsa_url="https://tsa.invalid/tsr", tsa_post=fake_post
    )
    assert cp.tsa_token == "MAUwAwIBAA=="
    [(url, body)] = sent
    assert url == "https://tsa.invalid/tsr"
    digest = hashlib.sha256(cp.body.encode("utf-8")).digest()
    assert body.startswith(b"\x30") and digest in body


def test_verify_cli_reports_ok(audit_db, capsys):
    assert verify_cli.main(["--checkpoint-file", "", "--agent-events"]) == 0
    out = capsys.readouterr().out
    assert out.strip().endswith("ok")
    assert verify_cli.main(["--checkpoint-file", "", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_verify_finds_tampering_end_to_end(conn):
    key = _key()
    insert_action(conn, "action-cp-e2e")
    write_checkpoint(conn, key)
    assert verify_cli.verify(conn, public_key=key.public_key())["ok"]
    _tamper(conn)
    conn.execute(
        text(
            "UPDATE audit_chain SET payload = '{}'::jsonb WHERE source_id = 'action-cp-e2e'"
        )
    )
    result = verify_cli.verify(conn, public_key=key.public_key())
    assert not result["ok"]
    assert result["breaks"][0]["reason"] == "hash"
