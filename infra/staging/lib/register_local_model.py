"""Make the in-cluster Ollama model the default LLM provider. Runs INSIDE the
backend pod (project python, project imports), fed on stdin by nightly.sh:

    kubectl exec -i deploy/<backend> -- env STAGING_LOCAL_MODEL=qwen2.5:1.5b python - < this

Same steps as scripts/local_model.sh `mirror` (Bifrost catalog sync, then the
``bifrost-ollama`` row must exist and be active), plus: that row's
``default_model`` is the staging model and it is the default provider, so the
daemon's triage target (ai_model_configs -> default provider) resolves to it on
an instance with no other provider. Idempotent.
"""

import os
import sys

from core.llm.bifrost.admin import sync_after_ollama_start
from core.storage.connection import get_db_manager
from core.storage.models import LLMProviderConfig

PROVIDER_ID = "bifrost-ollama"
model = os.environ.get("STAGING_LOCAL_MODEL", "").strip()
if not model:
    print("STAGING_LOCAL_MODEL is empty", file=sys.stderr)
    sys.exit(2)

result = sync_after_ollama_start()
if not result.get("bifrost_synced"):
    print(f"bifrost sync did not finish: {result}", file=sys.stderr)
    sys.exit(1)

db = get_db_manager()
if db._engine is None:
    db.initialize()
with db.session_scope() as session:
    row = session.get(LLMProviderConfig, PROVIDER_ID)
    if row is None:
        print(f"sync finished but llm_provider_configs has no {PROVIDER_ID} row", file=sys.stderr)
        sys.exit(1)
    for other in session.query(LLMProviderConfig).filter(
        LLMProviderConfig.is_default.is_(True), LLMProviderConfig.provider_id != PROVIDER_ID
    ):
        other.is_default = False
    row.is_active = True
    row.is_default = True
    row.default_model = model
print(f"{PROVIDER_ID} default_model={model}")
