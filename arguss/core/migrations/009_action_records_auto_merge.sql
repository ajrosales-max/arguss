-- Persist user opt-in for post-CI auto-merge on wizard action records.
CREATE TABLE IF NOT EXISTS action_records (
    action_id              TEXT PRIMARY KEY,
    scan_hash              TEXT NOT NULL,
    repo_display           TEXT NOT NULL,
    status                 TEXT NOT NULL,
    started_at             TEXT NOT NULL,
    completed_at           TEXT,
    selected_candidate_ids TEXT NOT NULL,
    pr_outcomes            TEXT NOT NULL DEFAULT '[]',
    failure_reason         TEXT,
    auto_merge_after_ci    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_action_records_scan_hash ON action_records(scan_hash);
