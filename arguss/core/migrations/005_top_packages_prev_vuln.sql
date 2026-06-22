-- Previously-vulnerable version and EPSS for the top-1000 npm sweep.

ALTER TABLE top_packages ADD COLUMN previously_vulnerable_version TEXT;
ALTER TABLE top_packages ADD COLUMN patched_advisory_ids TEXT;
ALTER TABLE top_packages ADD COLUMN max_epss REAL;
