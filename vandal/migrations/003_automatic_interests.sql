ALTER TABLE interests ADD COLUMN source_key TEXT;
CREATE UNIQUE INDEX interest_source_key ON interests(engagement_id,source_key);
