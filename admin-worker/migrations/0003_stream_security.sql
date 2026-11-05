PRAGMA foreign_keys = ON;

-- =========================================================
-- YAYIN KAYNAKLARI
-- Gerçek kaynak adresleri yalnızca sunucu tarafında tutulur.
-- Üye API yanıtlarında source_url kesinlikle gösterilmez.
-- =========================================================

CREATE TABLE IF NOT EXISTS stream_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT 'hls',
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive', 'blocked')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_stream_sources_status
ON stream_sources(status);

-- =========================================================
-- CANLI YAYINLAR
-- audience:
--   all      = yayının başlatıldığı andaki tüm aktif üyeler
--   selected = yalnızca seçilmiş üyeler
-- =========================================================

CREATE TABLE IF NOT EXISTS broadcasts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    message TEXT DEFAULT '',
    stream_source_id TEXT NOT NULL,
    audience TEXT NOT NULL
        CHECK (audience IN ('all', 'selected')),
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'live', 'stopped')),
    created_by TEXT,
    started_at TEXT,
    stopped_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (stream_source_id)
        REFERENCES stream_sources(id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_broadcasts_status
ON broadcasts(status);

CREATE INDEX IF NOT EXISTS idx_broadcasts_created
ON broadcasts(created_at);

CREATE INDEX IF NOT EXISTS idx_broadcasts_source
ON broadcasts(stream_source_id);

-- =========================================================
-- YAYIN ALICILARI
-- Yayın başlatılırken hedef üyeler burada sabitlenir.
-- Böylece sonradan eklenen üyeler eski yayına otomatik katılmaz.
-- =========================================================

CREATE TABLE IF NOT EXISTS broadcast_recipients (
    id TEXT PRIMARY KEY,
    broadcast_id TEXT NOT NULL,
    member_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'targeted'
        CHECK (
            status IN (
                'targeted',
                'authorized',
                'denied',
                'ended'
            )
        ),
    authorized_at TEXT,
    ended_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (broadcast_id)
        REFERENCES broadcasts(id)
        ON DELETE CASCADE,

    FOREIGN KEY (member_id)
        REFERENCES members(id)
        ON DELETE CASCADE,

    UNIQUE (broadcast_id, member_id)
);

CREATE INDEX IF NOT EXISTS idx_broadcast_recipients_member
ON broadcast_recipients(member_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_recipients_broadcast
ON broadcast_recipients(broadcast_id);

CREATE INDEX IF NOT EXISTS idx_broadcast_recipients_status
ON broadcast_recipients(status);

-- =========================================================
-- GÜVENLİ YAYIN OTURUMLARI
-- Gerçek kaynak URL'si istemciye verilmez.
-- ticket_hash yalnızca sunucu tarafında tutulur.
-- =========================================================

CREATE TABLE IF NOT EXISTS playback_sessions (
    id TEXT PRIMARY KEY,
    member_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    stream_source_id TEXT NOT NULL,
    broadcast_id TEXT,
    ticket_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'expired')),
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT,

    FOREIGN KEY (member_id)
        REFERENCES members(id)
        ON DELETE CASCADE,

    FOREIGN KEY (stream_source_id)
        REFERENCES stream_sources(id)
        ON DELETE RESTRICT,

    FOREIGN KEY (broadcast_id)
        REFERENCES broadcasts(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_playback_member
ON playback_sessions(member_id);

CREATE INDEX IF NOT EXISTS idx_playback_device
ON playback_sessions(device_id);

CREATE INDEX IF NOT EXISTS idx_playback_status
ON playback_sessions(status);

CREATE INDEX IF NOT EXISTS idx_playback_expiry
ON playback_sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_playback_broadcast
ON playback_sessions(broadcast_id);

-- =========================================================
-- HLS ALT KAYNAK TOKENLARI
-- Segment, anahtar, harita ve alt oynatma listeleri için.
-- =========================================================

-- HLS kaynak tokenları D1'e yazılmaz.
-- Şifreli ve süreli tokenlar Worker tarafından doğrulanır.


-- =========================================================
-- YÖNETİM VE GÜVENLİK KAYITLARI
-- =========================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_actor
ON audit_logs(actor_type, actor_id);

CREATE INDEX IF NOT EXISTS idx_audit_action
ON audit_logs(action);

CREATE INDEX IF NOT EXISTS idx_audit_created
ON audit_logs(created_at);

-- =========================================================
-- ÜYE MESAJLARI
-- Mevcut messages tablosu korunur.
-- member_id NULL: tüm üyelere gönderilen mesaj.
-- Belirli member_id: yalnızca o üyeye gönderilen mesaj.
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_messages_member_expiry
ON messages(member_id, expires_at);

-- =========================================================
-- CİHAZ VE ÜYELİK SORGULARI
-- Mevcut cihaz ve üye kayıtları korunur.
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_devices_member_device_status
ON devices(member_id, device_id, status);

CREATE INDEX IF NOT EXISTS idx_members_status_expiry
ON members(status, expires_at);

