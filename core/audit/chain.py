"""Walk the audit chain and check what it covers.

The hash is recomputed here, in Python, over the canonical text Postgres
renders for each row, rather than by calling ``audit_chain_hash()``: a verifier
that asked the database to grade itself would trust a redefined function.
The canonical text is the same ``jsonb_build_object(...)`` the BEFORE INSERT
trigger hashed (``infra/database/init/51_audit_chain.sql``).

Break reasons:

``gap``             a seq is missing (a row was deleted) or out of order
``prev_hash``       prev_hash is not the previous row's event_hash
``hash``            the row's content no longer matches its event_hash
``not_attached``    an audited table exists but was never attached
``triggers_missing`` an attached table's capture triggers are gone or disabled
``unchained``       a source row has no chain row (written while the triggers
                    were missing, or re-inserted under a deleted key)
``source_modified`` a source row differs from its latest chain row
``source_deleted``  the chain says the row exists and the table does not have it
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy import bindparam, text
from sqlalchemy.engine import Connection

from core.storage.audit_chain import AUDITED_TABLES, triggers_attached

# Must render exactly what audit_chain_hash() renders.
CANONICAL_SQL = (
    "CAST(jsonb_build_object("
    "'created_at', to_char(created_at AT TIME ZONE 'UTC', "
    '\'YYYY-MM-DD"T"HH24:MI:SS.US"Z"\'), '
    "'event', event, 'payload', payload, 'seq', seq, "
    "'source_id', source_id, 'source_table', source_table, "
    "'tenant_id', tenant_id) AS text)"
)

SOURCE_EVENTS = ("insert", "update", "delete", "snapshot")

# Per statement: Connection.execution_options() would change the connection.
_STREAM = {"stream_results": True, "yield_per": 1000}


@dataclass(frozen=True)
class Break:
    """The first thing found wrong in one chain (or one source table)."""

    chain: str  # audit_chain | agent_events | source:<table> | checkpoints
    scope: str  # chain, run_id, table or checkpoint id
    seq: Optional[int]
    reason: str
    detail: str = ""

    def format(self) -> str:
        where = f"{self.chain}  {self.scope}"
        if self.seq is not None:
            where += f"  seq={self.seq}"
        return f"break  {where}  {self.reason}: {self.detail}".rstrip(": ")


@dataclass
class ChainReport:
    rows: int = 0
    scopes: int = 0
    breaks: List[Break] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.breaks


def event_hash(prev_hash: str, canonical: str) -> str:
    """sha256(prev_hash || canonical), hex: the formula of both ledgers."""
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def audit_chain_present(conn: Connection) -> bool:
    return conn.execute(text("SELECT to_regclass('audit_chain')")).scalar() is not None


def walk_audit_chain(conn: Connection) -> ChainReport:
    """Recompute every row's hash and link; the first break.

    There is one chain for the whole database, so it is always walked whole:
    a tenant's rows link to other tenants' rows.
    """
    report = ChainReport()
    rows = conn.execute(
        text(
            "SELECT seq, prev_hash, event_hash, "
            f"{CANONICAL_SQL} AS canonical FROM audit_chain ORDER BY seq"
        ),
        execution_options=_STREAM,
    )
    expected_seq = 1
    expected_prev = ""
    for seq, prev_hash, stored_hash, canonical in rows:
        report.rows += 1
        report.scopes = 1
        if report.breaks:
            continue
        found: Optional[Break] = None
        if seq != expected_seq:
            found = Break(
                "audit_chain",
                "chain",
                seq,
                "gap",
                f"expected seq {expected_seq}, a row is missing",
            )
        elif prev_hash != expected_prev:
            found = Break(
                "audit_chain",
                "chain",
                seq,
                "prev_hash",
                "prev_hash does not follow the previous row",
            )
        elif event_hash(prev_hash, canonical) != stored_hash:
            found = Break(
                "audit_chain",
                "chain",
                seq,
                "hash",
                "row content does not match event_hash",
            )
        if found is not None:
            report.breaks.append(found)
            continue
        expected_seq = seq + 1
        expected_prev = stored_hash
    return report


def walk_agent_events(conn: Connection, run_id: Optional[str] = None) -> ChainReport:
    """The agent ledger, recomputed in Python with 31's formula.

    Same checks as services/agent/ledger/verify.ts: each event's prev_hash is
    the previous seq's event_hash ('' first) and its event_hash is
    sha256(prev_hash || payload text).
    """
    report = ChainReport()
    present = conn.execute(
        text(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = "
            "current_schema() AND table_name = 'agent_events' "
            "AND column_name = 'event_hash'"
        )
    ).scalar()
    if not present:
        return report
    rows = conn.execute(
        text(
            "SELECT CAST(run_id AS text), seq, prev_hash, event_hash, "
            "CAST(payload AS text) FROM agent_events "
            "WHERE (CAST(:run AS text) IS NULL OR CAST(run_id AS text) = :run) "
            "ORDER BY run_id, seq"
        ),
        {"run": run_id},
        execution_options=_STREAM,
    )
    current: Optional[str] = None
    expected_prev = ""
    broken = False
    for run, seq, prev_hash, stored_hash, payload in rows:
        report.rows += 1
        if run != current:
            current, expected_prev, broken = run, "", False
            report.scopes += 1
        if broken:
            continue
        reason = None
        if prev_hash != expected_prev:
            reason = ("prev_hash", "prev_hash does not follow the previous event")
        elif event_hash(prev_hash, payload) != stored_hash:
            reason = ("payload", "payload does not match event_hash")
        if reason is not None:
            report.breaks.append(Break("agent_events", f"run={run}", seq, *reason))
            broken = True
            continue
        expected_prev = stored_hash
    return report


# A source row against its latest chain row; a row chained before the table's
# last TRUNCATE counts as deleted. Only columns both sides have are
# compared, so a column added (or dropped) after the row was chained is not a
# modification. A key re-inserted after a chained delete, or never chained,
# is unchained.
_SOURCE_CHECK = """
WITH truncated AS (
    SELECT coalesce(max(seq), 0) AS seq
      FROM audit_chain
     WHERE source_table = :table AND event = 'truncate'
), latest AS (
    SELECT DISTINCT ON (c.source_id) c.source_id, c.payload -> 'row' AS row,
           CASE WHEN c.seq < tr.seq THEN 'delete' ELSE c.event END AS event
      FROM audit_chain AS c
     CROSS JOIN truncated AS tr
     WHERE c.source_table = :table AND c.event IN :events
     ORDER BY c.source_id, c.seq DESC
), cur AS (
    SELECT CAST(t.{key} AS text) AS source_id, to_jsonb(t) AS row
      FROM {table} AS t
), checked AS (
    SELECT coalesce(cur.source_id, latest.source_id) AS source_id,
           CASE
             WHEN latest.source_id IS NULL
               OR (cur.source_id IS NOT NULL AND latest.event = 'delete')
               THEN 'unchained'
             WHEN cur.source_id IS NULL AND latest.event <> 'delete'
               THEN 'source_deleted'
             WHEN cur.source_id IS NOT NULL
              AND (SELECT coalesce(jsonb_object_agg(k.key, k.value), '{{}}'::jsonb)
                     FROM jsonb_each(cur.row) AS k WHERE latest.row ? k.key)
                  IS DISTINCT FROM
                  (SELECT coalesce(jsonb_object_agg(k.key, k.value), '{{}}'::jsonb)
                     FROM jsonb_each(latest.row) AS k WHERE cur.row ? k.key)
               THEN 'source_modified'
           END AS reason
      FROM cur FULL JOIN latest ON latest.source_id = cur.source_id
)
SELECT source_id, reason, count(*) OVER () AS total
  FROM checked
 WHERE reason IS NOT NULL
 ORDER BY source_id
 LIMIT 1
"""

_SOURCE_DETAIL = {
    "unchained": "row has no chain entry (written while the capture triggers were off)",
    "source_modified": "row differs from its latest chain entry",
    "source_deleted": "row is gone but the chain has no delete for it",
}


def check_sources(conn: Connection) -> ChainReport:
    """Each audited table against the chain: attached, and row for row."""
    report = ChainReport()
    for table, key in AUDITED_TABLES.items():
        exists = conn.execute(text("SELECT to_regclass(:t)"), {"t": table}).scalar()
        if exists is None:
            continue
        report.scopes += 1
        scope = f"table={table}"
        installed = conn.execute(
            text(
                "SELECT 1 FROM audit_chain WHERE source_table = :t "
                "AND event = 'install' LIMIT 1"
            ),
            {"t": table},
        ).scalar()
        if not installed:
            report.breaks.append(
                Break(
                    f"source:{table}",
                    scope,
                    None,
                    "not_attached",
                    "table was never attached to the audit chain",
                )
            )
            continue
        if not triggers_attached(conn, table):
            report.breaks.append(
                Break(
                    f"source:{table}",
                    scope,
                    None,
                    "triggers_missing",
                    "capture triggers are missing or disabled",
                )
            )
        # Identifiers come from AUDITED_TABLES, never from input.
        statement = text(_SOURCE_CHECK.format(table=table, key=key)).bindparams(
            bindparam("events", expanding=True)
        )
        row = conn.execute(
            statement, {"table": table, "events": list(SOURCE_EVENTS)}
        ).first()
        report.rows += conn.execute(
            text(f"SELECT count(*) FROM {table}")  # nosec B608 - fixed table name
        ).scalar()
        if row is not None:
            source_id, reason, total = row
            report.breaks.append(
                Break(
                    f"source:{table}",
                    f"{scope} {key}={source_id}",
                    None,
                    reason,
                    f"{_SOURCE_DETAIL[reason]} ({total} row(s) affected)",
                )
            )
    return report


def head(conn: Connection) -> Optional[Dict[str, object]]:
    """The chain's last seq and event_hash, or None while it is empty."""
    row = conn.execute(
        text("SELECT seq, event_hash FROM audit_chain ORDER BY seq DESC LIMIT 1")
    ).first()
    return {"seq": int(row[0]), "hash": row[1]} if row is not None else None
