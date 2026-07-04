-- Per-candidate auto-merge opt-in on action records (wizard_sessions via _ensure_wizard_table).
ALTER TABLE action_records ADD COLUMN auto_merge_candidate_ids TEXT NOT NULL DEFAULT '[]';
