-- Version scan_response rows for payload / candidate_id invalidation.
ALTER TABLE api_cache ADD COLUMN scan_response_schema_version INTEGER NOT NULL DEFAULT 0;
