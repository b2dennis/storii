-- +goose Up
-- storii v2. The v1 tables (users, stored_passwords) are left alone, so v2 can run on the same database and
-- `storii migrate --legacy-db` can read them.
CREATE TABLE accounts (
    id          BIGSERIAL PRIMARY KEY,
    username    TEXT NOT NULL,
    kdf         JSONB NOT NULL,          -- vault.KDF, public
    auth_hash   BYTEA NOT NULL,          -- SHA-256 of the client's auth key
    wrapped_key TEXT NOT NULL,           -- vault key, encrypted by the client
    revision    BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX accounts_username ON accounts (lower(username));

CREATE TABLE sessions (
    token_hash   BYTEA PRIMARY KEY,
    account_id   BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_name  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_account ON sessions (account_id);

-- Secrets and contexts alike: the server can't tell them apart.
CREATE TABLE items (
    account_id BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    id         UUID NOT NULL,
    data       TEXT,                     -- NULL once deleted (tombstone)
    revision   BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);
CREATE INDEX items_revision ON items (account_id, revision);

-- +goose Down
DROP TABLE items;
DROP TABLE sessions;
DROP TABLE accounts;
