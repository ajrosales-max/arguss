-- Mode C auto-merge registry: action runs and per-candidate merge lifecycle.

CREATE TABLE IF NOT EXISTS action_run (
    id                 TEXT PRIMARY KEY,
    scan_hash          TEXT NOT NULL,
    scan_ref           TEXT,
    mode               TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    state              TEXT NOT NULL,
    wizard_action_id   TEXT
);

CREATE INDEX IF NOT EXISTS idx_action_run_scan_hash ON action_run(scan_hash);
CREATE INDEX IF NOT EXISTS idx_action_run_wizard_action_id ON action_run(wizard_action_id);

CREATE TABLE IF NOT EXISTS action_run_candidate (
    id                   TEXT PRIMARY KEY,
    action_run_id        TEXT NOT NULL,
    candidate_id         TEXT NOT NULL,
    package              TEXT NOT NULL,
    from_version         TEXT NOT NULL,
    to_version           TEXT NOT NULL,
    pr_number            INTEGER,
    head_sha             TEXT,
    state                TEXT NOT NULL,
    state_detail         TEXT,
    merge_authorization  TEXT NOT NULL DEFAULT 'engine',
    updated_at           TEXT NOT NULL,
    FOREIGN KEY (action_run_id) REFERENCES action_run(id)
);

CREATE INDEX IF NOT EXISTS idx_action_run_candidate_run_id
    ON action_run_candidate(action_run_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_action_run_candidate_run_and_cid
    ON action_run_candidate(action_run_id, candidate_id);
