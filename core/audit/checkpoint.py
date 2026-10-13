"""Ed25519-signed checkpoints of the audit chain heads.

A chain alone cannot show that its newest rows were removed, or that the whole
chain was rebuilt with fresh hashes. A checkpoint can: it records, signed, the
``audit_chain`` head and the heads of the ``agent_events`` runs that
moved since the previous checkpoint, and it links to that previous checkpoint
by the SHA-256 of its body. The verifier then checks that every recorded head is
still in the database with the same hash.

The signed body is canonical JSON (sorted keys, no whitespace), stored verbatim
in ``audit_checkpoints.body``. Optionally each checkpoint is also appended as a
JSON line to ``AUDIT_CHECKPOINT_FILE`` (a copy that survives the database) and
countersigned by an RFC 3161 timestamp authority (``AUDIT_TSA_URL``).

    python -m core.audit.checkpoint run      # write one checkpoint now
    python -m core.audit.checkpoint keygen   # print a new signing key pair
    python -m core.audit.checkpoint rebaseline --table T --reason R
        # after a deliberate DROP / RENAME COLUMN on an audited table

A checkpoint only covers the chain up to the head it records: rows written
after the newest checkpoint can be deleted or rewritten (and rehashed) by a
superuser without a trace, and deleting checkpoints back to an earlier one is
visible only against a copy kept outside the database (the file copy on other
storage, or a TSA token). Keep the interval short and the file off-host.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from core.audit import tsa
from core.audit.chain import (
    Break,
    audit_chain_present,
    check_sources,
    head,
    walk_audit_chain,
)
from core.storage.audit_chain import AUDITED_TABLES
from core.config import get_settings
from core.secrets import get_secret
from core.storage.connection import get_db_manager
from core.time import utcnow

logger = logging.getLogger(__name__)

SIGNING_KEY_SECRET = "AUDIT_CHECKPOINT_SIGNING_KEY"
BODY_VERSION = 1
# agent_events runs are recorded when they had an event since the previous
# checkpoint, less this overlap for transactions that committed late.
AGENT_EVENTS_OVERLAP = timedelta(hours=1)
_LOCK_SQL = text(
    "SELECT pg_advisory_xact_lock(hashtextextended('audit_checkpoints', 0))"
)


class KeyFormatError(ValueError):
    """A key value that is not an Ed25519 key in a format this module reads."""


def _decode_raw(value: str) -> bytes:
    value = value.strip()
    if len(value) == 64:
        try:
            return bytes.fromhex(value)
        except ValueError:
            pass
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise KeyFormatError("not hex, base64 or PEM") from e
    if len(raw) != 32:
        raise KeyFormatError("an Ed25519 key is 32 bytes")
    return raw


def load_private_key(value: str) -> Ed25519PrivateKey:
    """An Ed25519 private key from a PEM block or a 32-byte seed (hex / base64)."""
    value = value.strip()
    if value.startswith("-----BEGIN"):
        key = serialization.load_pem_private_key(value.encode("ascii"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise KeyFormatError("PEM key is not Ed25519")
        return key
    return Ed25519PrivateKey.from_private_bytes(_decode_raw(value))


def load_public_key(value: str) -> Ed25519PublicKey:
    """An Ed25519 public key from a PEM block or 32 raw bytes (hex / base64)."""
    value = value.strip()
    if value.startswith("-----BEGIN"):
        key = serialization.load_pem_public_key(value.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise KeyFormatError("PEM key is not Ed25519")
        return key
    return Ed25519PublicKey.from_public_bytes(_decode_raw(value))


def public_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def key_id(key: Ed25519PublicKey) -> str:
    """First 16 hex digits of sha256 of the raw public key."""
    return hashlib.sha256(bytes.fromhex(public_hex(key))).hexdigest()[:16]


def generate_key() -> Tuple[str, str]:
    """(private seed hex, public key hex) for a new key pair."""
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return seed.hex(), public_hex(private.public_key())


def signing_key_from_secrets() -> Optional[Ed25519PrivateKey]:
    """The configured signing key, or None when the secret is unset or unreadable."""
    value = get_secret(SIGNING_KEY_SECRET)
    if not value:
        return None
    try:
        return load_private_key(value)
    except (ValueError, TypeError) as e:
        logger.error("%s is not a usable Ed25519 key: %s", SIGNING_KEY_SECRET, e)
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _agent_events_state(conn: Connection, since: Optional[datetime]) -> Dict[str, Any]:
    present = conn.execute(
        text(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = "
            "current_schema() AND table_name = 'agent_events' "
            "AND column_name = 'event_hash'"
        )
    ).scalar()
    if not present:
        return {"present": False}
    events, runs = conn.execute(
        text("SELECT count(*), count(DISTINCT run_id) FROM agent_events")
    ).one()
    rows = conn.execute(
        text(
            "SELECT DISTINCT ON (run_id) CAST(run_id AS text), seq, event_hash "
            "FROM agent_events WHERE run_id IN ("
            "  SELECT DISTINCT run_id FROM agent_events "
            "  WHERE CAST(:since AS timestamptz) IS NULL OR ts >= :since) "
            "ORDER BY run_id, seq DESC"
        ),
        {"since": since},
    )
    return {
        "present": True,
        "events": int(events),
        "runs": int(runs),
        "since": _iso(since) if since is not None else None,
        "heads": {run: {"seq": int(seq), "hash": h} for run, seq, h in rows},
    }


@dataclass(frozen=True)
class Checkpoint:
    id: int
    key_id: str
    public_key: str
    body: str
    body_hash: str
    prev_body_hash: str
    signature: str
    tsa_token: Optional[str]

    def as_line(self) -> str:
        return canonical_json(
            {
                "id": self.id,
                "key_id": self.key_id,
                "public_key": self.public_key,
                "body": self.body,
                "body_hash": self.body_hash,
                "prev_body_hash": self.prev_body_hash,
                "signature": self.signature,
                "tsa_token": self.tsa_token,
            }
        )


def write_checkpoint(
    conn: Connection,
    key: Ed25519PrivateKey,
    *,
    tsa_url: str = "",
    tsa_post: Optional[tsa.Poster] = None,
    now: Optional[datetime] = None,
    schema_change: Optional[Dict[str, Any]] = None,
) -> Checkpoint:
    """Sign and insert one checkpoint on ``conn``; the caller commits.

    ``schema_change`` (from :func:`rebaseline`) is signed into the body as
    ``schema_change``: the re-baselined table, the marker's seq and the reason.

    Writers serialize on an advisory lock, so two daemons never link two
    checkpoints to the same predecessor.
    """
    conn.execute(_LOCK_SQL)
    issued = now or utcnow()
    previous = conn.execute(
        text("SELECT body_hash, body FROM audit_checkpoints ORDER BY id DESC LIMIT 1")
    ).first()
    prev_hash = previous[0] if previous else ""
    since: Optional[datetime] = None
    if previous:
        prev_issued = json.loads(previous[1]).get("issued_at")
        if prev_issued:
            since = (
                datetime.strptime(prev_issued, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                    tzinfo=timezone.utc
                )
                - AGENT_EVENTS_OVERLAP
            )
    public = key.public_key()
    kid = key_id(public)
    body_obj = {
        "v": BODY_VERSION,
        "issued_at": _iso(issued),
        "key_id": kid,
        "prev": prev_hash,
        "audit_chain": {"head": head(conn)},
        "agent_events": _agent_events_state(conn, since),
    }
    if schema_change is not None:
        body_obj["schema_change"] = schema_change
    body = canonical_json(body_obj)
    body_bytes = body.encode("utf-8")
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    signature = base64.b64encode(key.sign(body_bytes)).decode("ascii")
    token: Optional[str] = None
    if tsa_url:
        raw = tsa.request_timestamp(
            tsa_url, hashlib.sha256(body_bytes).digest(), post=tsa_post
        )
        token = base64.b64encode(raw).decode("ascii") if raw else None
    new_id = conn.execute(
        text(
            "INSERT INTO audit_checkpoints (key_id, public_key, body, body_hash, "
            "prev_body_hash, signature, tsa_token) VALUES (:kid, :pub, :body, "
            ":bh, :prev, :sig, :tsa) RETURNING id"
        ),
        {
            "kid": kid,
            "pub": public_hex(public),
            "body": body,
            "bh": body_hash,
            "prev": prev_hash,
            "sig": signature,
            "tsa": token,
        },
    ).scalar_one()
    return Checkpoint(
        id=int(new_id),
        key_id=kid,
        public_key=public_hex(public),
        body=body,
        body_hash=body_hash,
        prev_body_hash=prev_hash,
        signature=signature,
        tsa_token=token,
    )


def append_to_file(path: str, checkpoint: Checkpoint) -> None:
    """Append the checkpoint as one JSON line, flushed to disk."""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(checkpoint.as_line() + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def run_checkpoint(
    engine: Engine,
    *,
    key: Optional[Ed25519PrivateKey] = None,
    file_path: Optional[str] = None,
    tsa_url: Optional[str] = None,
    tsa_post: Optional[tsa.Poster] = None,
) -> Optional[Checkpoint]:
    """One checkpoint from settings and secrets; None (logged) when it cannot.

    The file copy is written after the database commit, so a line in the file
    always has its row (barring a later deletion, which is what it catches).
    """
    settings = get_settings()
    key = key if key is not None else signing_key_from_secrets()
    if key is None:
        logger.warning(
            "Audit checkpoint skipped: no %s configured "
            "(python -m core.audit.checkpoint keygen)",
            SIGNING_KEY_SECRET,
        )
        return None
    with engine.begin() as conn:
        if not audit_chain_present(conn):
            logger.warning(
                "Audit checkpoint skipped: audit_chain table missing "
                "(apply infra/database/init/51_audit_chain.sql)"
            )
            return None
        checkpoint = write_checkpoint(
            conn,
            key,
            tsa_url=settings.audit_tsa_url if tsa_url is None else tsa_url,
            tsa_post=tsa_post,
        )
    path = settings.audit_checkpoint_file if file_path is None else file_path
    if path:
        try:
            append_to_file(path, checkpoint)
        except OSError as e:
            logger.error(
                "Audit checkpoint %s not copied to %s: %s", checkpoint.id, path, e
            )
    logger.info(
        "Audit checkpoint %s written (key %s)", checkpoint.id, checkpoint.key_id
    )
    return checkpoint


class RebaselineRefused(RuntimeError):
    """The table is not in a state a re-baseline may record."""


def rebaseline_on(
    conn: Connection,
    table: str,
    reason: str,
    key: Ed25519PrivateKey,
    *,
    tsa_url: str = "",
    tsa_post: Optional[tsa.Poster] = None,
) -> Tuple[int, Checkpoint]:
    """:func:`rebaseline` on ``conn``; the caller commits (or rolls back)."""
    if table not in AUDITED_TABLES:
        raise RebaselineRefused(f"{table} is not an audited table")
    reason = (reason or "").strip()
    if not reason:
        raise RebaselineRefused("a reason is required")
    column = AUDITED_TABLES[table]
    # Identifiers come from AUDITED_TABLES, never from input.
    conn.execute(text(f"LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE"))
    chain = walk_audit_chain(conn)
    if chain.breaks:
        raise RebaselineRefused(f"audit chain is broken: {chain.breaks[0].format()}")
    strict = check_sources(conn, [table])
    if not any(b.reason == "schema_column_missing" for b in strict.breaks):
        raise RebaselineRefused(
            f"{table} has no missing column to re-baseline"
            + (f" ({strict.breaks[0].format()})" if strict.breaks else "")
        )
    lenient = check_sources(conn, [table], ignore_missing_columns=True)
    if lenient.breaks:
        raise RebaselineRefused(
            f"{table} is not clean apart from the schema change: "
            f"{lenient.breaks[0].format()}"
        )
    marker = int(
        conn.execute(
            text(
                "SELECT audit_chain_record_rebaseline(:t, :k, :r, "
                f"(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.{column}), "
                f"'[]'::jsonb) FROM {table} AS s))"  # nosec B608 - fixed names
            ),
            {"t": table, "k": column, "r": reason},
        ).scalar_one()
    )
    after = check_sources(conn, [table])
    if after.breaks:
        raise RebaselineRefused(
            f"re-baseline did not settle {table}: {after.breaks[0].format()}"
        )
    checkpoint = write_checkpoint(
        conn,
        key,
        tsa_url=tsa_url,
        tsa_post=tsa_post,
        schema_change={"table": table, "seq": marker, "reason": reason},
    )
    return marker, checkpoint


def rebaseline(
    engine: Engine,
    table: str,
    reason: str,
    *,
    key: Optional[Ed25519PrivateKey] = None,
    file_path: Optional[str] = None,
    tsa_url: Optional[str] = None,
    tsa_post: Optional[tsa.Poster] = None,
) -> Tuple[int, Checkpoint]:
    """Re-baseline ``table`` after a deliberate DROP / RENAME COLUMN.

    The verifier reports such a change as ``schema_column_missing`` for as long
    as the latest chain rows carry the old column. This writes, in one
    transaction holding a SHARE ROW EXCLUSIVE lock on the table: a
    ``rebaseline`` marker and a ``snapshot`` of every current row (through
    ``audit_chain_record_rebaseline()``, which vigil_app may not call), and a
    signed checkpoint whose body names the marker (``schema_change``). It
    refuses unless a signing key is configured, the chain walks clean, and the
    table is clean apart from the missing column(s), so it cannot launder a
    row changed outside the chain. Returns (marker seq, checkpoint); any
    refusal rolls everything back.
    """
    key = key if key is not None else signing_key_from_secrets()
    if key is None:
        raise RebaselineRefused(
            f"no {SIGNING_KEY_SECRET} configured: a re-baseline must be signed"
        )
    settings = get_settings()
    with engine.begin() as conn:
        marker, checkpoint = rebaseline_on(
            conn,
            table,
            reason,
            key,
            tsa_url=settings.audit_tsa_url if tsa_url is None else tsa_url,
            tsa_post=tsa_post,
        )
    path = settings.audit_checkpoint_file if file_path is None else file_path
    if path:
        try:
            append_to_file(path, checkpoint)
        except OSError as e:
            logger.error(
                "Audit checkpoint %s not copied to %s: %s", checkpoint.id, path, e
            )
    logger.warning(
        "audit_chain: %s re-baselined at seq %s (checkpoint %s): %s",
        table,
        marker,
        checkpoint.id,
        reason.strip(),
    )
    return marker, checkpoint


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass
class CheckpointReport:
    count: int = 0
    key_id: Optional[str] = None
    trusted: bool = False
    file_lines: int = 0
    # seq of each 'rebaseline' marker named by a checkpoint that verified.
    signed_rebaselines: Dict[int, str] = field(default_factory=dict)
    breaks: List[Break] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.breaks


def _verify_signature(public: Ed25519PublicKey, body: str, signature: str) -> bool:
    try:
        public.verify(base64.b64decode(signature, validate=True), body.encode("utf-8"))
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True


def _head_break(conn: Connection, scope: str, body: Dict[str, Any]) -> Optional[Break]:
    chain_head = body.get("audit_chain", {}).get("head")
    if chain_head is not None:
        stored = conn.execute(
            text("SELECT event_hash FROM audit_chain WHERE seq = :s"),
            {"s": chain_head["seq"]},
        ).scalar()
        if stored != chain_head["hash"]:
            what = "is missing" if stored is None else "has a different hash"
            return Break(
                "checkpoints",
                scope,
                chain_head["seq"],
                "checkpoint_head",
                f"audit_chain head {what}",
            )
    agent = body.get("agent_events", {})
    if agent.get("present"):
        events, runs = conn.execute(
            text("SELECT count(*), count(DISTINCT run_id) FROM agent_events")
        ).one()
        if events < agent.get("events", 0) or runs < agent.get("runs", 0):
            return Break(
                "checkpoints",
                scope,
                None,
                "checkpoint_count",
                f"agent_events has {events} events / {runs} runs, "
                f"fewer than the {agent.get('events')} / {agent.get('runs')} recorded",
            )
        for run, run_head in sorted(agent.get("heads", {}).items()):
            stored = conn.execute(
                text(
                    "SELECT event_hash FROM agent_events "
                    "WHERE CAST(run_id AS text) = :r AND seq = :s"
                ),
                {"r": run, "s": run_head["seq"]},
            ).scalar()
            if stored != run_head["hash"]:
                what = "is missing" if stored is None else "has a different hash"
                return Break(
                    "checkpoints",
                    scope,
                    run_head["seq"],
                    "checkpoint_head",
                    f"agent_events run={run} head {what}",
                )
    return None


def verify_checkpoints(
    conn: Connection,
    trusted_key: Optional[Ed25519PublicKey] = None,
    file_path: Optional[str] = None,
) -> CheckpointReport:
    """Signatures, links and recorded heads of every checkpoint; the first break.

    Without ``trusted_key`` each signature is checked against the public key
    stored in its own row, which shows the checkpoints agree with themselves and
    nothing more; the report says so (``trusted`` False).
    """
    report = CheckpointReport(trusted=trusted_key is not None)
    if trusted_key is not None:
        report.key_id = key_id(trusted_key)
    rows = conn.execute(
        text(
            "SELECT id, key_id, public_key, body, body_hash, prev_body_hash, signature "
            "FROM audit_checkpoints ORDER BY id"
        )
    ).all()
    expected_prev = ""
    for cid, kid, pub, body, body_hash, prev_body_hash, signature in rows:
        report.count += 1
        scope = f"checkpoint={cid}"
        found = _check_one(
            trusted_key,
            scope,
            kid,
            pub,
            body,
            body_hash,
            prev_body_hash,
            signature,
            expected_prev,
        )
        parsed = json.loads(body) if found is None else {}
        if found is None:
            found = _head_break(conn, scope, parsed)
        if found is not None:
            report.breaks.append(found)
            return report
        change = parsed.get("schema_change")
        if isinstance(change, dict) and isinstance(change.get("seq"), int):
            report.signed_rebaselines[change["seq"]] = str(change.get("table", ""))
        if report.key_id is None:
            report.key_id = kid
        expected_prev = body_hash
    if file_path:
        found = _verify_file(conn, Path(file_path), trusted_key, report)
        if found is not None:
            report.breaks.append(found)
    return report


def _check_one(
    trusted_key: Optional[Ed25519PublicKey],
    scope: str,
    kid: str,
    pub: str,
    body: str,
    body_hash: str,
    prev_body_hash: str,
    signature: str,
    expected_prev: Optional[str],
) -> Optional[Break]:
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != body_hash:
        return Break(
            "checkpoints",
            scope,
            None,
            "checkpoint_body",
            "body does not match body_hash",
        )
    try:
        parsed = json.loads(body)
    except ValueError:
        return Break("checkpoints", scope, None, "checkpoint_body", "body is not JSON")
    if expected_prev is not None and (
        prev_body_hash != expected_prev or parsed.get("prev") != expected_prev
    ):
        return Break(
            "checkpoints",
            scope,
            None,
            "checkpoint_link",
            "does not link to the previous checkpoint (one was removed or rewritten)",
        )
    if trusted_key is not None:
        if pub != public_hex(trusted_key):
            return Break(
                "checkpoints",
                scope,
                None,
                "checkpoint_key",
                "signed by an untrusted key",
            )
        public = trusted_key
    else:
        try:
            public = load_public_key(pub)
        except (ValueError, TypeError):
            return Break(
                "checkpoints",
                scope,
                None,
                "checkpoint_key",
                "stored public key is unreadable",
            )
    if kid != key_id(public) or parsed.get("key_id") != kid:
        return Break(
            "checkpoints",
            scope,
            None,
            "checkpoint_key",
            "key_id does not match the key",
        )
    if not _verify_signature(public, body, signature):
        return Break(
            "checkpoints",
            scope,
            None,
            "checkpoint_signature",
            "signature does not verify",
        )
    return None


def _verify_file(
    conn: Connection,
    path: Path,
    trusted_key: Optional[Ed25519PublicKey],
    report: CheckpointReport,
) -> Optional[Break]:
    """Every line of the file copy is a valid checkpoint the database still has."""
    if not path.exists():
        return Break(
            "checkpoints", f"file={path}", None, "checkpoint_file", "file not found"
        )
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            scope = f"file={path}:{number}"
            try:
                entry = json.loads(line)
                cid = int(entry["id"])
                fields = (
                    entry["key_id"],
                    entry["public_key"],
                    entry["body"],
                    entry["body_hash"],
                    entry["prev_body_hash"],
                    entry["signature"],
                )
            except (ValueError, KeyError, TypeError):
                return Break(
                    "checkpoints", scope, None, "checkpoint_file", "unreadable line"
                )
            report.file_lines += 1
            found = _check_one(trusted_key, scope, *fields, expected_prev=None)
            if found is not None:
                return found
            stored = conn.execute(
                text("SELECT body_hash FROM audit_checkpoints WHERE id = :id"),
                {"id": cid},
            ).scalar()
            if stored != entry["body_hash"]:
                return Break(
                    "checkpoints",
                    scope,
                    None,
                    "checkpoint_missing",
                    f"checkpoint {cid} is in the file but "
                    + (
                        "not in the database"
                        if stored is None
                        else "differs in the database"
                    ),
                )
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m core.audit.checkpoint",
        description="Write or prepare AutoSecOps signed audit checkpoints.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="write one checkpoint now")
    sub.add_parser(
        "keygen",
        help=f"print a new Ed25519 key pair; store the seed as {SIGNING_KEY_SECRET}",
    )
    rebase = sub.add_parser(
        "rebaseline",
        help="after a deliberate DROP / RENAME COLUMN on an audited table: "
        "re-snapshot it under a signed schema-change marker (run as the schema "
        "owner, not vigil_app)",
    )
    rebase.add_argument("--table", required=True, choices=sorted(AUDITED_TABLES))
    rebase.add_argument(
        "--reason", required=True, help="why the schema changed (signed, kept)"
    )
    args = parser.parse_args(argv)
    if args.command == "keygen":
        seed, public = generate_key()
        print(f"{SIGNING_KEY_SECRET}={seed}")
        print(f"AUDIT_CHECKPOINT_PUBLIC_KEY={public}")
        print(
            "# Keep the first line secret (secrets manager). Give the second to "
            "whoever verifies, outside this database.",
            file=sys.stderr,
        )
        return 0
    manager = get_db_manager()
    manager.initialize()
    if args.command == "rebaseline":
        try:
            marker, checkpoint = rebaseline(manager.engine, args.table, args.reason)
        except RebaselineRefused as e:
            print(f"rebaseline refused: {e}", file=sys.stderr)
            return 1
        print(
            f"rebaseline {args.table}  seq {marker}  checkpoint {checkpoint.id}  "
            f"key {checkpoint.key_id}"
        )
        return 0
    checkpoint = run_checkpoint(manager.engine)
    if checkpoint is None:
        return 1
    print(
        f"checkpoint {checkpoint.id}  key {checkpoint.key_id}  {checkpoint.body_hash}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
