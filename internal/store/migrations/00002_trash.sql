-- +goose Up
-- The trash: a deleted item keeps its last ciphertext for TrashDays, so a client can put it back.
ALTER TABLE items ADD COLUMN deleted_data TEXT, ADD COLUMN deleted_at TIMESTAMPTZ;
CREATE INDEX items_trash ON items (deleted_at) WHERE deleted_at IS NOT NULL;

-- +goose Down
DROP INDEX items_trash;
ALTER TABLE items DROP COLUMN deleted_data, DROP COLUMN deleted_at;
