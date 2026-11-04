ALTER TABLE members ADD COLUMN password_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_members_member_code
ON members(member_code);

CREATE INDEX IF NOT EXISTS idx_devices_member_status
ON devices(member_id, status);

CREATE INDEX IF NOT EXISTS idx_messages_expiry
ON messages(expires_at);
