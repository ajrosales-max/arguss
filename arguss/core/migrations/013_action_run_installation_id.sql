-- GitHub App installation id for Mode C background merge (nullable; legacy rows stay NULL).
ALTER TABLE action_run ADD COLUMN installation_id TEXT;
