-- Merge authorization metadata captured at registry population time.
ALTER TABLE action_run_candidate ADD COLUMN engine_score INTEGER;
ALTER TABLE action_run_candidate ADD COLUMN veto_signals TEXT NOT NULL DEFAULT '[]';
ALTER TABLE action_run_candidate ADD COLUMN pr_authorization_appended INTEGER NOT NULL DEFAULT 0;
