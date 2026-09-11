CREATE TABLE web_captures (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id),
 job_id INTEGER NOT NULL REFERENCES jobs(id), asset_id INTEGER REFERENCES assets(id),
 url TEXT NOT NULL, host TEXT NOT NULL, ips TEXT NOT NULL DEFAULT '[]',
 status TEXT NOT NULL, status_code INTEGER, title TEXT NOT NULL DEFAULT '',
 final_url TEXT NOT NULL DEFAULT '', technologies TEXT NOT NULL DEFAULT '[]',
 screenshot TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
 validation TEXT NOT NULL DEFAULT '{}', report TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
 UNIQUE(job_id,url)
);
CREATE INDEX web_capture_project ON web_captures(engagement_id,url,id);
CREATE TABLE job_steps (
 id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id), name TEXT NOT NULL,
 command TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT, exit_code INTEGER
);
