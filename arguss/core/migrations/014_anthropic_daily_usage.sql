-- Global daily Anthropic call counter (per UTC day). Backs the spend ceiling;
-- lives in SQLite on the persistent volume so it survives restarts/deploys.
CREATE TABLE IF NOT EXISTS anthropic_daily_usage (
    day   TEXT PRIMARY KEY,  -- UTC date, YYYY-MM-DD
    calls INTEGER NOT NULL DEFAULT 0
);
