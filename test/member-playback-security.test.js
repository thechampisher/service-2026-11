import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import worker from "../src/index.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const SECRET = "local-member-test-secret-with-more-than-32-characters";
const encoder = new TextEncoder();

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

async function makeJwt(payload) {
  const header = b64url(JSON.stringify({
    alg: "HS256",
    typ: "JWT"
  }));

  const body = b64url(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  }));

  const input = `${header}.${body}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(input)
  );

  return `${input}.${b64url(new Uint8Array(signature))}`;
}

function fakeEnvironment(options = {}) {
  const stats = {
    queries: [],
    inserts: [],
    updates: []
  };

  const DB = {
    prepare(sql) {
      const query = {
        sql: sql.replace(/\s+/g, " ").trim(),
        args: []
      };

      stats.queries.push(query);

      return {
        bind(...args) {
          query.args = args;
          return this;
        },

        async first() {
          if (query.sql.includes("FROM members")) {
            return {
              id: "member-1",
              member_code: "TEST-001",
              display_name: "Test Member",
              status: "active",
              max_devices: 2,
              expires_at: null
            };
          }

          if (query.sql.includes("FROM devices")) {
            return {
              id: "device-record-1",
              status: "active",
              token_hash: options.tokenHash
            };
          }

          if (query.sql.includes("FROM broadcasts")) {
            if (options.broadcastMissing) return null;

            return {
              id: "broadcast-1",
              stream_source_id: "source-1",
              audience: options.audience || "all",
              source_id: "source-1",
              source_url: "https://example.test/live.m3u8",
              source_status: options.sourceStatus || "active"
            };
          }

          if (query.sql.includes("FROM broadcast_recipients")) {
            return options.authorized
              ? { id: "recipient-1" }
              : null;
          }

          return null;
        },

        async run() {
          if (query.sql.includes("INSERT INTO playback_sessions")) {
            stats.inserts.push(query);
          }

          if (query.sql.includes("UPDATE broadcast_recipients")) {
            stats.updates.push(query);
          }

          return { success: true };
        },

        async all() {
          return { results: [] };
        }
      };
    }
  };

  return {
    stats,
    env: {
      DB,
      TOKEN_SIGNING_SECRET: SECRET,
      STREAM_ALLOWED_HOSTS: "example.test"
    }
  };
}

async function requestPlayback(options = {}) {
  const token = await makeJwt({
    role: "member",
    member_id: "member-1",
    device_id: "device-1"
  });

  const tokenHash = b64url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(token)
      )
    )
  );

  const setup = fakeEnvironment({
    ...options,
    tokenHash
  });

  const response = await worker.fetch(
    new Request("https://worker.example/member/playback", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(options.body || {
        broadcast_id: "broadcast-1"
      })
    }),
    setup.env
  );

  return {
    response,
    data: await response.json(),
    stats: setup.stats
  };
}

test("Doğrudan stream_id ile oynatma engellenir", async () => {
  const result = await requestPlayback({
    body: { stream_id: "source-1" }
  });

  assert.equal(result.response.status, 400);
  assert.equal(result.data.ok, false);
  assert.equal(result.stats.inserts.length, 0);

  assert.equal(
    result.stats.queries.some(x =>
      x.sql.includes("FROM stream_sources")
    ),
    false
  );
});

test("broadcast_id olmadan oynatma engellenir", async () => {
  const result = await requestPlayback({
    body: {}
  });

  assert.equal(result.response.status, 400);
  assert.equal(result.stats.inserts.length, 0);
});

test("Seçilmiş yayında yetkisiz üye reddedilir", async () => {
  const result = await requestPlayback({
    audience: "selected",
    authorized: false
  });

  assert.equal(result.response.status, 403);
  assert.equal(result.data.error, "Not authorized for broadcast");
  assert.equal(result.stats.inserts.length, 0);
});

test("Seçilmiş yayında yetkili üye oynatma oturumu alır", async () => {
  const result = await requestPlayback({
    audience: "selected",
    authorized: true
  });

  assert.equal(result.response.status, 200);
  assert.equal(result.data.ok, true);
  assert.ok(result.data.playback_url.startsWith("/play/"));
  assert.equal(result.stats.inserts.length, 1);
  assert.equal(result.stats.updates.length, 1);
});

test("Tüm üyelere açık yayında kayıtlı alıcı oynatma oturumu alır", async () => {
  const result = await requestPlayback({
    audience: "all",
    authorized: true
  });

  assert.equal(result.response.status, 200);
  assert.equal(result.data.ok, true);
  assert.equal(result.stats.inserts.length, 1);
});

test("Durdurulmuş yayın için oynatma oturumu oluşturulmaz", async () => {
  const result = await requestPlayback({
    broadcastMissing: true
  });

  assert.equal(result.response.status, 404);
  assert.equal(result.stats.inserts.length, 0);
});

test("Pasif yayın kaynağı oynatılamaz", async () => {
  const result = await requestPlayback({
    sourceStatus: "inactive"
  });

  assert.equal(result.response.status, 404);
  assert.equal(result.stats.inserts.length, 0);
});


test("Tüm üyelere açık yayında alıcı kaydı olmayan üye reddedilir", async () => {
  const result = await requestPlayback({
    audience: "all",
    authorized: false
  });

  assert.equal(result.response.status, 403);
  assert.equal(result.data.error, "Not authorized for broadcast");
  assert.equal(result.stats.inserts.length, 0);
});
