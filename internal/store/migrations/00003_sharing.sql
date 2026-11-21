-- +goose Up
-- Sharing: an X25519 key pair per account (the private key sealed by the client), and shares whose key is wrapped
-- for each member. Names and items are encrypted with the share's key.
ALTER TABLE accounts ADD COLUMN public_key TEXT, ADD COLUMN sealed_private_key TEXT;

CREATE TABLE shares (
    id         UUID PRIMARY KEY,
    owner_id   BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    meta       TEXT NOT NULL,            -- encrypted name
    revision   BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE share_members (
    share_id    UUID NOT NULL REFERENCES shares (id) ON DELETE CASCADE,
    account_id  BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,           -- the share key, encrypted for this member's public key
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (share_id, account_id)
);
CREATE INDEX share_members_account ON share_members (account_id);

CREATE TABLE share_items (
    share_id     UUID NOT NULL REFERENCES shares (id) ON DELETE CASCADE,
    id           UUID NOT NULL,
    data         TEXT,                   -- NULL once deleted (tombstone)
    revision     BIGINT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_data TEXT,
    deleted_at   TIMESTAMPTZ,
    PRIMARY KEY (share_id, id)
);
CREATE INDEX share_items_revision ON share_items (share_id, revision);
CREATE INDEX share_items_trash ON share_items (deleted_at) WHERE deleted_at IS NOT NULL;

-- +goose Down
DROP TABLE share_items;
DROP TABLE share_members;
DROP TABLE shares;
ALTER TABLE accounts DROP COLUMN public_key, DROP COLUMN sealed_private_key;
