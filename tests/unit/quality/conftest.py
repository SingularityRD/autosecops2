"""qa_samples is SQL-owned: create_all does not build it, so apply its init file."""

from pathlib import Path

import pytest
from sqlalchemy import text

from tests.unit.quality._factory import PREFIX

INIT_SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "46_eval_qa_canary.sql"
)


@pytest.fixture
def qa_db(throwaway_database):
    from core.storage.connection import get_db_manager
    from core.storage.models import AIDecisionLog
    from core.storage.unit_of_work import unit_of_work

    with get_db_manager().engine.begin() as conn:
        conn.execute(text(INIT_SQL.read_text(encoding="utf-8")))
    # The file also creates canary_injections; drop a cached "absent".
    from core.storage.canary_exclusion import forget_table_presence

    forget_table_presence()

    def purge():
        with unit_of_work() as session:
            session.execute(text("DELETE FROM qa_samples"))
            session.query(AIDecisionLog).filter(
                AIDecisionLog.decision_id.like(f"{PREFIX}%")
            ).delete(synchronize_session=False)

    purge()
    yield
    purge()
