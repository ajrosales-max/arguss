-- Historical advisory summaries + last advisory date for top-packages dashboard.

ALTER TABLE top_packages ADD COLUMN historical_advisory_summaries TEXT;
ALTER TABLE top_packages ADD COLUMN last_advisory_date TEXT;
