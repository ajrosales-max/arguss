-- Precomputed OSV vulnerability sweep for the download-ranked top-1000 npm list.

CREATE TABLE IF NOT EXISTS top_packages (
    rank INTEGER NOT NULL,
    name TEXT PRIMARY KEY,
    historical_advisory_count INTEGER NOT NULL,
    historical_advisory_ids TEXT NOT NULL,
    latest_version TEXT,
    latest_vulnerable INTEGER,
    latest_advisories TEXT,
    swept_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_top_packages_rank ON top_packages(rank);
