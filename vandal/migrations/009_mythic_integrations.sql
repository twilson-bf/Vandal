CREATE TABLE integration_sources(
    id INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    public_url TEXT NOT NULL,
    operation_id INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_sync_at TEXT,
    UNIQUE(engagement_id, kind, name)
);

CREATE TABLE mythic_callbacks(
    id INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    source_id INTEGER NOT NULL REFERENCES integration_sources(id),
    external_id TEXT NOT NULL,
    display_id INTEGER NOT NULL,
    operation_id INTEGER,
    operation_name TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    user TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    external_ip TEXT NOT NULL DEFAULT '',
    ips TEXT NOT NULL DEFAULT '[]',
    os TEXT NOT NULL DEFAULT '',
    architecture TEXT NOT NULL DEFAULT '',
    payload_type TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    present INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    source_url TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    received_at TEXT NOT NULL,
    UNIQUE(source_id, external_id)
);
CREATE INDEX mythic_callbacks_engagement ON mythic_callbacks(engagement_id, last_seen);

CREATE TABLE mythic_callback_assets(
    callback_id INTEGER NOT NULL REFERENCES mythic_callbacks(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    match_basis TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    PRIMARY KEY(callback_id, asset_id, match_basis)
);
CREATE INDEX mythic_callback_asset ON mythic_callback_assets(asset_id, callback_id);
