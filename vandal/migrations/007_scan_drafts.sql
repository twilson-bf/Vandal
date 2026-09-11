CREATE TABLE scan_drafts (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id),
 title TEXT NOT NULL, profile TEXT NOT NULL, revision INTEGER NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE scan_draft_revisions (
 draft_id INTEGER NOT NULL REFERENCES scan_drafts(id), revision INTEGER NOT NULL,
 payload TEXT NOT NULL, command TEXT NOT NULL, notes TEXT NOT NULL,
 warnings TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(draft_id,revision)
);
CREATE INDEX scan_drafts_project ON scan_drafts(engagement_id,updated_at);
