PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY,
    member_code TEXT NOT NULL UNIQUE,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','inactive','blocked')),
    max_devices INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    member_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_name TEXT,
    token_hash TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','blocked')),
    paired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT,
    FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE,
    UNIQUE(member_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_member
ON devices(member_id);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    member_id TEXT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_member
ON messages(member_id, expires_at);

CREATE TABLE IF NOT EXISTS app_config (
    config_key TEXT PRIMARY KEY,
    config_value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS catalog_releases (
    id TEXT PRIMARY KEY,
    version TEXT NOT NULL UNIQUE,
    manifest_url TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    total_bytes INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK(status IN ('draft','published','retired')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TEXT
);

CREATE TABLE IF NOT EXISTS download_jobs (
    id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL,
    batch_no INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK(status IN ('queued','running','completed','failed','cancelled')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(release_id) REFERENCES catalog_releases(id) ON DELETE CASCADE,
    UNIQUE(release_id, batch_no)
);

CREATE INDEX IF NOT EXISTS idx_jobs_status
ON download_jobs(status, created_at);

CREATE TABLE IF NOT EXISTS device_downloads (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK(status IN ('queued','authorized','downloading','completed','failed')),
    authorized_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(release_id) REFERENCES catalog_releases(id)
);

CREATE INDEX IF NOT EXISTS idx_device_downloads_status
ON device_downloads(status, updated_at);
