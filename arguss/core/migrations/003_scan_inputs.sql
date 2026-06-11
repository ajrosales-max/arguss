CREATE TABLE IF NOT EXISTS scan_inputs (
    scan_hash  TEXT PRIMARY KEY,
    mode       TEXT NOT NULL,
    url        TEXT NOT NULL,
    ref        TEXT,
    created_at TEXT NOT NULL
);
