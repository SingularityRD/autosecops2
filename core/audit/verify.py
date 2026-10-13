"""Verify the AutoSecOps audit trail: ``python -m core.audit.verify``.

Walks ``audit_chain`` (every hash and link of the one chain), checks every signed
checkpoint (signature, link to the previous one, recorded heads still present)
and the file copy of the checkpoints when there is one, and checks the audited
source tables row for row against the chain. ``--agent-events`` also walks the
agent ledger, as ``services/agent/ledger/verify.ts`` does.

``--require-signature`` turns the signature from best effort into a
requirement: the run is broken (``signature_required``) when no trusted public
key is available (neither ``--public-key``, ``AUDIT_CHECKPOINT_PUBLIC_KEY`` nor
the ``AUDIT_CHECKPOINT_SIGNING_KEY`` secret) or when no signed checkpoint has
been written yet. Without it, checkpoints are checked against the key stored
in their own rows and the output says UNTRUSTED.

Prints one line per check and the first break of each; exits 0 when nothing is
broken, 1 when something is, 2 when it could not run.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.engine import Connection

from core.audit.chain import (
    Break,
    audit_chain_present,
    check_sources,
    walk_agent_events,
    walk_audit_chain,
)
from core.audit.checkpoint import (
    load_public_key,
    signing_key_from_secrets,
    verify_checkpoints,
)
from core.config import get_settings
from core.storage.connection import get_db_manager


def trusted_public_key(explicit: Optional[str]) -> Optional[Ed25519PublicKey]:
    """--public-key, else AUDIT_CHECKPOINT_PUBLIC_KEY, else the signing key's."""
    value = explicit or get_settings().audit_checkpoint_public_key
    if value:
        return load_public_key(value)
    private = signing_key_from_secrets()
    return private.public_key() if private is not None else None


def verify(
    conn: Connection,
    *,
    public_key: Optional[Ed25519PublicKey] = None,
    checkpoint_file: Optional[str] = None,
    agent_events: bool = False,
    sources: bool = True,
    require_signature: bool = False,
) -> Dict[str, Any]:
    """Run every check on ``conn``; a dict the CLI prints, ``ok`` overall."""
    result: Dict[str, Any] = {}
    breaks: List[Break] = []

    chain = walk_audit_chain(conn)
    result["audit_chain"] = {"rows": chain.rows}
    breaks += chain.breaks

    checkpoints = verify_checkpoints(conn, public_key, checkpoint_file)
    result["checkpoints"] = {
        "count": checkpoints.count,
        "key_id": checkpoints.key_id,
        "trusted": checkpoints.trusted,
        "file_lines": checkpoints.file_lines,
    }
    breaks += checkpoints.breaks
    if require_signature:
        if public_key is None:
            breaks.append(
                Break(
                    "checkpoints",
                    "signature",
                    None,
                    "signature_required",
                    "no trusted public key: pass --public-key or set "
                    "AUDIT_CHECKPOINT_PUBLIC_KEY (or the AUDIT_CHECKPOINT_SIGNING_KEY "
                    "secret)",
                )
            )
        elif not checkpoints.count:
            breaks.append(
                Break(
                    "checkpoints",
                    "signature",
                    None,
                    "signature_required",
                    "no signed checkpoint has been written",
                )
            )

    if sources:
        source = check_sources(conn)
        result["sources"] = {"tables": source.scopes, "rows": source.rows}
        breaks += source.breaks

    if agent_events:
        ledger = walk_agent_events(conn)
        result["agent_events"] = {"events": ledger.rows, "runs": ledger.scopes}
        breaks += ledger.breaks

    result["breaks"] = [
        {
            "chain": b.chain,
            "scope": b.scope,
            "seq": b.seq,
            "reason": b.reason,
            "detail": b.detail,
        }
        for b in breaks
    ]
    result["ok"] = not breaks
    result["_breaks"] = breaks
    return result


def format_result(result: Dict[str, Any]) -> List[str]:
    lines = []
    chain = result["audit_chain"]
    lines.append(f"audit_chain  {chain['rows']} rows")
    cp = result["checkpoints"]
    if cp["count"]:
        trust = (
            "trusted key"
            if cp["trusted"]
            else (
                "UNTRUSTED: checked against the key stored in the database; "
                "pass --public-key"
            )
        )
        line = f"checkpoints  {cp['count']}  key {cp['key_id']}  {trust}"
        if cp["file_lines"]:
            line += f"  file copy {cp['file_lines']} line(s)"
        lines.append(line)
    else:
        lines.append("checkpoints  none written yet")
    if "sources" in result:
        lines.append(
            f"sources      {result['sources']['tables']} table(s)  "
            f"{result['sources']['rows']} rows"
        )
    if "agent_events" in result:
        ae = result["agent_events"]
        lines.append(f"agent_events {ae['events']} events  {ae['runs']} run(s)")
    for b in result["_breaks"]:
        lines.append(b.format())
    lines.append("ok" if result["ok"] else "BROKEN")
    return lines


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m core.audit.verify",
        description="Verify the AutoSecOps tamper-evident audit trail.",
    )
    parser.add_argument(
        "--public-key",
        help="trusted Ed25519 public key (hex, base64 or PEM); "
        "default AUDIT_CHECKPOINT_PUBLIC_KEY",
    )
    parser.add_argument(
        "--checkpoint-file",
        help="file copy of the checkpoints to check; default AUDIT_CHECKPOINT_FILE",
    )
    parser.add_argument(
        "--agent-events", action="store_true", help="also walk the agent ledger"
    )
    parser.add_argument(
        "--no-sources",
        action="store_true",
        help="skip the row-by-row check of the audited tables",
    )
    parser.add_argument(
        "--require-signature",
        action="store_true",
        help="fail unless a trusted public key is configured and at least one "
        "signed checkpoint exists",
    )
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)

    try:
        public_key = trusted_public_key(args.public_key)
    except (ValueError, TypeError) as e:
        print(f"unusable public key: {e}", file=sys.stderr)
        return 2
    checkpoint_file = (
        args.checkpoint_file
        if args.checkpoint_file is not None
        else get_settings().audit_checkpoint_file
    ) or None

    try:
        manager = get_db_manager()
        manager.initialize()
        with manager.engine.connect() as conn:
            if not audit_chain_present(conn):
                print(
                    "audit_chain table not found: apply "
                    "infra/database/init/51_audit_chain.sql",
                    file=sys.stderr,
                )
                return 2
            result = verify(
                conn,
                public_key=public_key,
                checkpoint_file=checkpoint_file,
                agent_events=args.agent_events,
                sources=not args.no_sources,
                require_signature=args.require_signature,
            )
    except Exception as e:  # noqa: BLE001
        print(f"could not verify: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    if args.json:
        printable = {k: v for k, v in result.items() if not k.startswith("_")}
        print(json.dumps(printable, indent=2, sort_keys=True))
    else:
        print("\n".join(format_result(result)))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
