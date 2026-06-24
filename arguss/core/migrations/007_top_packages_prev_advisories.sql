-- Previously-vulnerable advisory summaries for the top-1000 npm sweep.

ALTER TABLE top_packages ADD COLUMN previously_vulnerable_advisories TEXT;
