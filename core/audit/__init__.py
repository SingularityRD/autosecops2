"""Tamper-evident audit: the audit_chain walk, signed checkpoints, the verifier.

- :mod:`core.audit.chain` walks ``audit_chain`` (and optionally the
  ``agent_events`` ledger) and checks the audited source tables against it.
- :mod:`core.audit.checkpoint` writes and verifies Ed25519-signed checkpoints
  of the chain heads (``python -m core.audit.checkpoint``).
- :mod:`core.audit.verify` is the operator CLI (``python -m core.audit.verify``).

The schema is ``infra/database/init/50_audit_chain.sql``.
"""
