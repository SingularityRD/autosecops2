-- Secrets saved in the console when SECRETS_BACKEND=database (the Helm default).
--
-- On Helm the State Directory is an emptyDir in each of two backend replicas, so
-- a secret written there lived in one pod until it restarted. A row here is seen
-- by every replica and survives restarts and upgrades.
--
-- Never plaintext: `ciphertext` is a Fernet token under the data key
-- (VIGIL_DATA_KEY, core/crypto/data_key.py), which the database does not hold.
-- A dump of this table without that key reveals the names, not the values.
-- core/secrets_manager.py DatabaseBackend reads and writes it; the start-up
-- rekey (core/crypto/rekey.py) moves rows under a previous key to the current one.

CREATE TABLE IF NOT EXISTS platform_secrets (
    -- The secrets-store key, e.g. SPLUNK_PASSWORD or OIDC_CLIENT_SECRET_<ID>.
    name VARCHAR(200) PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
