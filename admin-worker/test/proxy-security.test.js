import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

const SECRET = "local-test-secret-with-more-than-32-characters";
const encoder = new TextEncoder();

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function makeToken(payload, lifetime = 120) {
  const raw = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(SECRET + "|media-token-v1")
  );

  const key = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const data = encoder.encode(JSON.stringify({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + lifetime,
    ver: 1
  }));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return `${b64url(iv)}.${b64url(new Uint8Array(encrypted))}`;
}

function fakeEnvironment(sessionState = "active", failDb = false) {
  const stats = { queries: 0 };

  const DB = {
    prepare(sql) {
      stats.queries++;

      return {
        bind(...args) {
          this.args = args;
          return this;
        },
        async first() {
          if (failDb) throw new Error("Simulated D1 failure");

          if (sessionState === "active") {
            return { id: "session-test" };
          }

          return null;
        }
      };
    }
  };

  return {
    env: {
      DB,
      TOKEN_SIGNING_SECRET: SECRET,
      STREAM_ALLOWED_HOSTS: "example.test"
    },
    stats
  };
}

async function requestProxy(payload, contentType, body = "MEDIA", state = "active", failDb = false) {
  const { env, stats } = fakeEnvironment(state, failDb);

  const token = await makeToken(payload);

  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () => new Response(body, {
    status: 200,
    headers: { "Content-Type": contentType }
  });

  try {
    const response = await worker.fetch(
      new Request(`https://worker.example/play/${token}`),
      env
    );

    return {
      response,
      stats
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

const base = {
  sid: "session-test",
  member_id: "member-test",
  device_id: "device-test"
};

test("Aktif ana manifest oynatılabilir ve oturum kontrol edilir", async () => {
  const result = await requestProxy({
    ...base,
    kind: "play",
    url: "https://example.test/master.m3u8"
  }, "application/vnd.apple.mpegurl", "#EXTM3U\nsegment.ts");

  assert.equal(result.response.status, 200);
  assert.equal(result.response.headers.get("Access-Control-Allow-Origin"), "*");
  assert.equal(result.stats.queries, 1);

  const text = await result.response.text();
  assert.match(text, /\/p\//);
  assert.doesNotMatch(text, /https:\/\/example\.test/);
});

test("İptal edilmiş ana oturum 403 ile reddedilir", async () => {
  const result = await requestProxy({
    ...base,
    kind: "play",
    url: "https://example.test/master.m3u8"
  }, "application/vnd.apple.mpegurl", "#EXTM3U", "revoked");

  assert.equal(result.response.status, 403);
  assert.equal(result.response.headers.get("Access-Control-Allow-Origin"), "*");
  assert.equal(result.stats.queries, 1);
});

test("Engellenmiş cihazın manifest isteği reddedilir", async () => {
  const result = await requestProxy({
    ...base,
    kind: "manifest",
    url: "https://example.test/child.m3u8"
  }, "application/vnd.apple.mpegurl", "#EXTM3U", "blocked-device");

  assert.equal(result.response.status, 403);
  assert.equal(result.stats.queries, 1);
});

test("Uzantısız alt manifest için D1 iptal kontrolü yapılır", async () => {
  const result = await requestProxy({
    ...base,
    kind: "resource",
    url: "https://example.test/playlist?id=123"
  }, "application/vnd.apple.mpegurl", "#EXTM3U\nsegment.ts", "revoked");

  assert.equal(result.response.status, 403);
  assert.equal(result.stats.queries, 1);
});

test("Video segmenti için hiçbir D1 sorgusu yapılmaz", async () => {
  const result = await requestProxy({
    ...base,
    kind: "resource",
    url: "https://example.test/segment001.ts"
  }, "video/mp2t", "FAKE-VIDEO-SEGMENT", "active");

  assert.equal(result.response.status, 200);
  assert.equal(result.response.headers.get("Access-Control-Allow-Origin"), "*");
  assert.equal(result.stats.queries, 0);
});

test("D1 erişilemiyorsa manifest güvenli biçimde reddedilir", async () => {
  const result = await requestProxy({
    ...base,
    kind: "play",
    url: "https://example.test/master.m3u8"
  }, "application/vnd.apple.mpegurl", "#EXTM3U", "active", true);

  assert.equal(result.response.status, 503);
  assert.equal(result.stats.queries, 1);
});
