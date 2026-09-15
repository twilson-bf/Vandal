ALTER TABLE engagements ADD COLUMN scope_mode TEXT NOT NULL DEFAULT 'open'
  CHECK(scope_mode IN ('open', 'included'));

ALTER TABLE scope_rules ADD COLUMN tag TEXT NOT NULL DEFAULT '';
ALTER TABLE scope_rules ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0
  CHECK(hidden IN (0, 1));

-- Preserve the meaning of existing installations while moving the old free-form
-- reason into the group label. Existing exclusions were globally hidden, so they
-- remain hidden until an operator explicitly changes the group.
UPDATE scope_rules
SET tag = CASE WHEN trim(reason) = '' THEN 'untagged' ELSE trim(reason) END;

UPDATE scope_rules SET hidden = 1 WHERE action = 'exclude';

CREATE INDEX idx_scope_rules_group
  ON scope_rules(engagement_id, tag, action, hidden);
