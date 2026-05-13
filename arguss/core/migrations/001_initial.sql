-- Initial schema: API response cache, AI explanation cache, scan history.

CREATE TABLE IF NOT EXISTS api_cache (
    key TEXT PRIMARY KEY,
    response_json TEXT NOT NULL,
    source TEXT NOT NULL,           -- 'osv', 'npm', 'deps_dev', 'scorecard', 'epss', 'kev'
    cached_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_cache_expires ON api_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_cache_source ON api_cache(source);

CREATE TABLE IF NOT EXISTS ai_explanations (
    cache_key TEXT PRIMARY KEY,     -- hash of (package, from_v, to_v, findings_hash, prompt_v)
    package_name TEXT NOT NULL,
    from_version TEXT NOT NULL,
    to_version TEXT NOT NULL,
    findings_hash TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    explanation_json TEXT NOT NULL,
    model TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_explanations_expires ON ai_explanations(expires_at);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,            -- UUID
    project_identifier TEXT,        -- repo URL or filename hash
    overall_score REAL NOT NULL,
    lens_scores_json TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'  -- 'pending', 'complete', 'failed'
);

CREATE INDEX IF NOT EXISTS idx_scan_history_scanned ON scan_history(scanned_at DESC);
