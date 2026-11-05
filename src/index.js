const encoder = new TextEncoder();
const decoder = new TextDecoder();

const VERSION = "2.0.0";
const MEMBER_TOKEN_SECONDS = 10 * 365 * 24 * 60 * 60;
const ADMIN_TOKEN_SECONDS = 8 * 60 * 60;
const PLAYBACK_TOKEN_SECONDS = 120;
const PLAYBACK_SESSION_SECONDS = 12 * 60 * 60;
const PLAYBACK_TICKET_SECONDS = PLAYBACK_SESSION_SECONDS;
const MAX_SELECTED_MEMBERS = 250;
const MAX_GITHUB_FILE_BYTES = 900000;
const MAX_GITHUB_CHUNK_BYTES = 24 * 1024 * 1024;
const MAX_GITHUB_REQUEST_BYTES = 36 * 1024 * 1024;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function randomToken(bytes = 32) {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return b64url(value);
}

function b64url(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function unb64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    typeof value === "string" ? encoder.encode(value) : value
  );
  return b64url(new Uint8Array(result));
}

function equalText(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}

function bearer(request) {
  const value = request.headers.get("Authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : "";
}

async function readJson(request) {
  try {
    const length = Number(request.headers.get("Content-Length") || 0);
    if (length > MAX_GITHUB_REQUEST_BYTES) return null;

    const raw = await request.text();
    if (encoder.encode(raw).length > MAX_GITHUB_REQUEST_BYTES) return null;

    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function uuid() {
  return crypto.randomUUID();
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function normalizeExpiry(value) {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

async function signingKey(env) {
  if (!env.TOKEN_SIGNING_SECRET || env.TOKEN_SIGNING_SECRET.length < 32) {
    throw new Error("TOKEN_SIGNING_SECRET must contain at least 32 characters");
  }

  return crypto.subtle.importKey(
    "raw",
    encoder.encode(env.TOKEN_SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createJwt(payload, env, lifetime) {
  const header = b64url(encoder.encode(JSON.stringify({
    alg: "HS256",
    typ: "JWT"
  })));

  const body = b64url(encoder.encode(JSON.stringify({
    ...payload,
    iat: nowSeconds(),
    exp: nowSeconds() + lifetime
  })));

  const input = `${header}.${body}`;
  const signature = await crypto.subtle.sign(
    "HMAC",
    await signingKey(env),
    encoder.encode(input)
  );

  return `${input}.${b64url(new Uint8Array(signature))}`;
}

async function verifyJwt(token, env) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const input = `${parts[0]}.${parts[1]}`;
    const signature = unb64url(parts[2]);

    const valid = await crypto.subtle.verify(
      "HMAC",
      await signingKey(env),
      signature,
      encoder.encode(input)
    );

    if (!valid) return null;

    const payload = JSON.parse(decoder.decode(unb64url(parts[1])));
    if (!payload.exp || payload.exp <= nowSeconds()) return null;

    return payload;
  } catch {
    return null;
  }
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);

  return `pbkdf2$100000$${b64url(salt)}$${b64url(new Uint8Array(result))}`;
}

async function checkPassword(password, stored) {
  try {
    const parts = stored.split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

    const iterations = Number(parts[1]);
    if (!Number.isInteger(iterations) ||
        iterations < 100000 ||
        iterations > 100000) return false;

    const salt = unb64url(parts[2]);
    const expected = unb64url(parts[3]);

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const actual = new Uint8Array(await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    }, key, 256));

    if (actual.length !== expected.length) return false;

    let diff = 0;
    for (let i = 0; i < actual.length; i++) {
      diff |= actual[i] ^ expected[i];
    }

    return diff === 0;
  } catch {
    return false;
  }
}

async function adminAuth(request, env) {
  const token = bearer(request);
  if (!token) return null;

  if (env.ADMIN_API_KEY && equalText(token, env.ADMIN_API_KEY)) {
    return { role: "admin", id: "api-key" };
  }

  const payload = await verifyJwt(token, env);
  return payload?.role === "admin" ? payload : null;
}

async function memberAuth(request, env) {
  const token = bearer(request);
  if (!token) return null;

  const payload = await verifyJwt(token, env);
  if (!payload || payload.role !== "member") return null;

  const member = await env.DB.prepare(`
    SELECT id, member_code, display_name, status, max_devices, expires_at
    FROM members
    WHERE id = ?
    LIMIT 1
  `).bind(payload.member_id).first();

  if (!member || member.status !== "active") return null;

  const expiry = normalizeExpiry(member.expires_at);
  if (expiry && expiry <= Date.now()) return null;

  const device = await env.DB.prepare(`
    SELECT id, status, token_hash
    FROM devices
    WHERE member_id = ? AND device_id = ?
    LIMIT 1
  `).bind(member.id, payload.device_id).first();

  if (!device || device.status !== "active") return null;

  const tokenHash = await sha256(token);
  if (!equalText(device.token_hash || "", tokenHash)) return null;

  return {
    member,
    deviceId: payload.device_id,
    deviceRecordId: device.id
  };
}

function allowedSource(raw, env) {
  try {
    const url = new URL(raw);

    if (!["http:", "https:"].includes(url.protocol)) return false;
    if (url.username || url.password) return false;

    const host = url.hostname.toLowerCase();

    if (!host || host === "localhost" ||
        host.endsWith(".localhost") ||
        host.endsWith(".local") ||
        host.endsWith(".internal")) return false;

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      const parts = host.split(".").map(Number);
      if (parts.some(x => x < 0 || x > 255)) return false;

      const [a, b, c, d] = parts;

      if (
        a === 0 || a === 10 || a === 127 ||
        a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 192 && b === 0 && c === 0) ||
        (a === 192 && b === 0 && c === 2) ||
        (a === 198 && (b === 18 || b === 19)) ||
        (a === 198 && b === 51 && c === 100) ||
        (a === 203 && b === 0 && c === 113) ||
        (a === 255 && b === 255 && c === 255 && d === 255)
      ) return false;

      return true;
    }

    // IPv6 adresleri şimdilik kabul edilmez.
    if (host.includes(":")) return false;

    // Özel alan adları ve yerel ağ adları kabul edilmez.
    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host.endsWith(".internal")
    ) return false;

    // Önceden tanımlı izin listesi olmadan genel DNS alan adlarını kabul et.
    // URL uzantısı ve query parametreleri burada filtrelenmez.
    if (host.length > 253) return false;

    const labels = host.split(".");
    if (labels.length < 2) return false;

    return labels.every(label =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
    );
  } catch {
    return false;
  }
}

async function audit(env, action, targetId = null, details = null, actor = "admin") {
  try {
    await env.DB.prepare(`
      INSERT INTO audit_logs
        (id, actor_type, actor_id, action, target_type, target_id, details)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      uuid(),
      actor,
      actor === "admin" ? "admin" : actor,
      action,
      null,
      targetId,
      details ? JSON.stringify(details) : null
    ).run();
  } catch {
    // Audit failure must not expose secrets or break media delivery.
  }
}

/* =========================================================
   ENCRYPTED STATELESS MEDIA TOKENS

   HLS resources are encrypted in the token itself.
   No D1 query or write occurs for individual video segments.
   ========================================================= */

async function mediaKey(env) {
  if (!env.TOKEN_SIGNING_SECRET || env.TOKEN_SIGNING_SECRET.length < 32) {
    throw new Error("TOKEN_SIGNING_SECRET missing");
  }

  const raw = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(env.TOKEN_SIGNING_SECRET + "|media-token-v1")
  );

  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function createMediaToken(payload, env, lifetime) {
  const data = encoder.encode(JSON.stringify({
    ...payload,
    exp: nowSeconds() + lifetime,
    ver: 1
  }));

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await mediaKey(env),
    data
  );

  return `${b64url(iv)}.${b64url(new Uint8Array(encrypted))}`;
}

async function readMediaToken(token, env) {
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64url(parts[0]) },
      await mediaKey(env),
      unb64url(parts[1])
    );

    const payload = JSON.parse(decoder.decode(decrypted));

    if (payload.ver !== 1 ||
        !payload.exp ||
        payload.exp <= nowSeconds()) return null;

    return payload;
  } catch {
    return null;
  }
}

async function makeResourceUrl(sourceUrl, env, session) {
  if (!allowedSource(sourceUrl, env)) {
    throw new Error("Source host is not allowed");
  }

  // Playlist kaynakları oturum kontrolünden geçer.
  // Segment ve medya kaynakları stateless kalır.
  const kind = isManifest(sourceUrl, "")
    ? "manifest"
    : "resource";

  const token = await createMediaToken({
    kind,
    url: sourceUrl,
    sid: session.sid,
    member_id: session.member_id,
    device_id: session.device_id
  }, env, PLAYBACK_TOKEN_SECONDS);

  return `/p/${token}`;
}

function isManifest(url, contentType) {
  return /\.m3u8?($|\?)/i.test(url) ||
    /mpegurl|vnd\.apple\.mpegurl/i.test(contentType || "");
}

async function rewriteManifest(text, baseUrl, env, session) {
  const lines = text.split(/\r?\n/);
  const output = [];

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed) {
      output.push(line);
      continue;
    }

    if (trimmed.startsWith("#")) {
      const rewritten = await rewriteUriAttributes(
        line, baseUrl, env, session
      );
      output.push(rewritten);
      continue;
    }

    const absolute = new URL(trimmed, baseUrl).toString();
    output.push(await makeResourceUrl(absolute, env, session));
  }

  return output.join("\n");
}

async function rewriteUriAttributes(line, baseUrl, env, session) {
  const regex = /URI="([^"]+)"/g;
  let result = line;
  const matches = [...line.matchAll(regex)];

  for (const match of matches) {
    const original = match[1];
    const absolute = new URL(original, baseUrl).toString();
    const replacement = await makeResourceUrl(absolute, env, session);
    result = result.replace(
      `URI="${original}"`,
      `URI="${replacement}"`
    );
  }

  return result;
}

function mediaResponseHeaders(upstream, manifest = false, cors = {}) {
  const headers = new Headers(cors);

  const type = upstream.headers.get("Content-Type");
  if (type) headers.set("Content-Type", type);

  for (const name of [
    "Content-Range",
    "Accept-Ranges",
    "Content-Length"
  ]) {
    const value = upstream.headers.get(name);
    if (value && !manifest) headers.set(name, value);
  }

  headers.set("Cache-Control", "private, no-store");
  headers.set("X-Content-Type-Options", "nosniff");

  return headers;
}

async function activePlaybackSession(env, payload) {
  if (!payload?.sid || !payload?.member_id || !payload?.device_id) {
    return false;
  }

  // Bu sorgu yalnızca ana/alt oynatma listelerinde çalışır.
  // Video segmentleri bu fonksiyona uğramaz.
  const session = await env.DB.prepare(`
    SELECT ps.id
    FROM playback_sessions ps
    JOIN members m
      ON m.id = ps.member_id
    JOIN devices d
      ON d.member_id = ps.member_id
     AND d.device_id = ps.device_id
    LEFT JOIN broadcasts b
      ON b.id = ps.broadcast_id
    WHERE ps.id = ?
      AND ps.member_id = ?
      AND ps.device_id = ?
      AND ps.status = 'active'
      AND ps.expires_at > ?
      AND m.status = 'active'
      AND d.status = 'active'
      AND (
        m.expires_at IS NULL
        OR m.expires_at = ''
        OR julianday(m.expires_at) > julianday('now')
      )
      AND (
        ps.broadcast_id IS NULL
        OR b.status = 'live'
      )
    LIMIT 1
  `).bind(
    payload.sid,
    payload.member_id,
    payload.device_id,
    nowSeconds()
  ).first();

  return Boolean(session);
}

async function proxyMedia(request, env, token, cors = {}) {
  const respondJson = (data, status) => json(data, status, cors);
  const payload = await readMediaToken(token, env);

  if (!payload ||
      !["play", "manifest", "resource"].includes(payload.kind) ||
      !payload.url ||
      !payload.sid ||
      !allowedSource(payload.url, env)) {
    return respondJson({ ok: false, error: "Invalid or expired playback token" }, 403);
  }

  // Ana ve alt oynatma listelerinde iptal kontrolü.
  // Segment tokenlarında D1 sorgusu kesinlikle yapılmaz.
  if (payload.kind === "play" || payload.kind === "manifest") {
    let active = false;

    try {
      active = await activePlaybackSession(env, payload);
    } catch {
      return respondJson({ ok: false, error: "Playback authorization unavailable" }, 503);
    }

    if (!active) {
      return respondJson({ ok: false, error: "Playback session revoked or expired" }, 403);
    }
  }

  const headers = new Headers({
    "Accept": request.headers.get("Accept") || "*/*",
    "User-Agent": "MediaProxy/2.0"
  });

  try {
    const sourceHost = new URL(payload.url).hostname.toLowerCase();
    if (sourceHost === "andro.evrenesoglu101.click") {
      headers.set("Referer", "https://taraftarium24.xyz/");
      headers.set("Origin", "https://taraftarium24.xyz");
    }
  } catch (_) {}


  const range = request.headers.get("Range");
  if (range) headers.set("Range", range);

  let upstream;
  let currentUrl = payload.url;

  // Yönlendirmeleri kontrollü takip et.
  // Her yeni adres yeniden doğrulanır.
  for (let redirectCount = 0; redirectCount <= 5; redirectCount++) {
    if (!allowedSource(currentUrl, env)) {
      return respondJson({
        ok: false,
        error: "Redirect source is not permitted"
      }, 502);
    }

    try {
      upstream = await fetch(currentUrl, {
        method: "GET",
        headers,
        redirect: "manual"
      });
    } catch {
      return respondJson({
        ok: false,
        error: "Upstream unavailable"
      }, 502);
    }

    if (upstream.status < 300 || upstream.status >= 400) {
      break;
    }

    const location = upstream.headers.get("Location");

    if (!location || redirectCount === 5) {
      return respondJson({
        ok: false,
        error: "Redirect limit exceeded"
      }, 502);
    }

    try {
      currentUrl = new URL(location, currentUrl).toString();
    } catch {
      return respondJson({
        ok: false,
        error: "Invalid redirect address"
      }, 502);
    }
  }

  if (!upstream || (upstream.status >= 300 && upstream.status < 400)) {
    return respondJson({
      ok: false,
      error: "Upstream redirect failed"
    }, 502);
  }

  if (!upstream.ok && upstream.status !== 206) {
    return respondJson({ ok: false, error: "Upstream request failed" }, 502);
  }

  const contentType = upstream.headers.get("Content-Type") || "";
  const manifest = isManifest(currentUrl, contentType);

  if (manifest) {
    // Uzantısı tanınmayan alt oynatma listeleri ancak upstream
    // Content-Type yanıtından sonra anlaşılabilir.
    // Bu kontrol manifest başına yapılır; segmentlere uygulanmaz.
    if (payload.kind === "resource") {
      let active = false;

      try {
        active = await activePlaybackSession(env, payload);
      } catch {
        return respondJson({
          ok: false,
          error: "Playback authorization unavailable"
        }, 503);
      }

      if (!active) {
        return respondJson({
          ok: false,
          error: "Playback session revoked or expired"
        }, 403);
      }
    }

    const sourceText = await upstream.text();

    if (sourceText.length > 2 * 1024 * 1024) {
      return respondJson({ ok: false, error: "Manifest too large" }, 502);
    }

    let rewritten;

    try {
      rewritten = await rewriteManifest(
        sourceText,
        currentUrl,
        env,
        {
          sid: payload.sid,
          member_id: payload.member_id,
          device_id: payload.device_id
        }
      );
    } catch {
      return respondJson({ ok: false, error: "Manifest rewrite failed" }, 502);
    }

    return new Response(rewritten, {
      status: 200,
      headers: mediaResponseHeaders(upstream, true, cors)
    });
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: mediaResponseHeaders(upstream, false, cors)
  });
}

async function issuePlayback(env, member, deviceId, source, broadcastId = null) {
  if (!source || source.status !== "active") {
    return { error: "Stream unavailable" };
  }

  if (!allowedSource(source.source_url, env)) {
    return { error: "Stream source is not permitted" };
  }

  const sid = uuid();
  const ticket = await createMediaToken({
    kind: "play",
    url: source.source_url,
    sid,
    member_id: member.id,
    device_id: deviceId,
    broadcast_id: broadcastId
  }, env, PLAYBACK_TICKET_SECONDS);

  const ticketHash = await sha256(ticket);

  // Oynatma bileti ve oturum aynı 12 saatlik süreyi kullanır.
  const expiry = nowSeconds() + PLAYBACK_SESSION_SECONDS;

  await env.DB.prepare(`
    INSERT INTO playback_sessions
      (id, member_id, device_id, stream_source_id, broadcast_id,
       ticket_hash, status, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
  `).bind(
    sid,
    member.id,
    deviceId,
    source.id,
    broadcastId,
    ticketHash,
    expiry
  ).run();

  return {
    playback_url: `/play/${ticket}`,
    expires_in: PLAYBACK_TICKET_SECONDS
  };
}

/* =========================================================
   LOGIN
   ========================================================= */

async function handleLogin(request, env, path) {
  const body = await readJson(request);
  if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

  if (path === "/auth/admin/login") {
    const password = String(body.password || "");

    if (!env.ADMIN_LOGIN_PASSWORD ||
        !equalText(password, env.ADMIN_LOGIN_PASSWORD)) {
      return json({ ok: false, error: "Invalid credentials" }, 401);
    }

    const token = await createJwt({
      role: "admin",
      id: "admin"
    }, env, ADMIN_TOKEN_SECONDS);

    return json({
      ok: true,
      token,
      expires_in: ADMIN_TOKEN_SECONDS
    });
  }

  if (path === "/auth/member/login") {
    const code = String(body.member_code || "").trim();
    const password = String(body.password || "");
    const deviceId = String(body.device_id || "").trim();
    const deviceName = String(body.device_name || "Android").slice(0, 120);

    if (!code || !password || !deviceId || deviceId.length > 180) {
      return json({ ok: false, error: "Missing login fields" }, 400);
    }

    const member = await env.DB.prepare(`
      SELECT *
      FROM members
      WHERE member_code = ?
      LIMIT 1
    `).bind(code).first();

    if (!member ||
        member.status !== "active" ||
        !member.password_hash) {
      return json({ ok: false, error: "Invalid credentials" }, 401);
    }

    const expiry = normalizeExpiry(member.expires_at);
    if (expiry && expiry <= Date.now()) {
      return json({ ok: false, error: "Membership expired" }, 403);
    }

    if (!await checkPassword(password, member.password_hash)) {
      return json({ ok: false, error: "Invalid credentials" }, 401);
    }

    const existing = await env.DB.prepare(`
      SELECT id, status
      FROM devices
      WHERE member_id = ? AND device_id = ?
      LIMIT 1
    `).bind(member.id, deviceId).first();

    if (existing?.status === "blocked") {
      return json({ ok: false, error: "Device blocked" }, 403);
    }

    const count = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM devices
      WHERE member_id = ? AND status = 'active'
    `).bind(member.id).first();

    if (!existing && Number(count?.total || 0) >= Number(member.max_devices || 1)) {
      return json({ ok: false, error: "Device limit reached" }, 403);
    }

    const token = await createJwt({
      role: "member",
      member_id: member.id,
      device_id: deviceId
    }, env, MEMBER_TOKEN_SECONDS);

    const tokenHash = await sha256(token);
    const deviceRecordId = existing?.id || uuid();

    if (existing) {
      await env.DB.prepare(`
        UPDATE devices
        SET device_name = ?, token_hash = ?, status = 'active',
            last_seen = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(deviceName, tokenHash, deviceRecordId).run();
    } else {
      await env.DB.prepare(`
        INSERT INTO devices
          (id, member_id, device_id, device_name, token_hash,
           status, paired_at, last_seen)
        VALUES (?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `).bind(
        deviceRecordId,
        member.id,
        deviceId,
        deviceName,
        tokenHash
      ).run();
    }

    return json({
      ok: true,
      token,
      expires_in: MEMBER_TOKEN_SECONDS,
      member: {
        id: member.id,
        member_code: member.member_code,
        display_name: member.display_name,
        expires_at: member.expires_at,
        max_devices: member.max_devices
      }
    });
  }

  return json({ ok: false, error: "Not found" }, 404);
}

/* =========================================================
   ADMIN API
   ========================================================= */

async function handleAdmin(request, env, path, method) {
  if (method === "GET" && path === "/admin/members") {
    const result = await env.DB.prepare(`
      SELECT id, member_code, display_name, status,
             max_devices, expires_at, created_at
      FROM members
      ORDER BY created_at DESC
      LIMIT 1000
    `).all();

    return json({ ok: true, members: result.results || [] });
  }

  if (method === "POST" && path === "/admin/members") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const name = String(body.display_name || "").trim();
    const password = String(body.password || "");
    const maxDevices = Math.min(20, Math.max(1, Number(body.max_devices || 1)));

    if (!name || name.length > 120 || password.length < 6 || password.length > 256) {
      return json({ ok: false, error: "Invalid member data" }, 400);
    }

    if (body.expires_at && !normalizeExpiry(body.expires_at)) {
      return json({ ok: false, error: "Invalid expiration date" }, 400);
    }

    const id = uuid();
    const code = `MBR-${randomToken(9).toUpperCase()}`;
    const passwordHash = await hashPassword(password);

    await env.DB.prepare(`
      INSERT INTO members
        (id, member_code, display_name, status,
         max_devices, expires_at, password_hash)
      VALUES (?, ?, ?, 'active', ?, ?, ?)
    `).bind(
      id,
      code,
      name,
      maxDevices,
      body.expires_at || null,
      passwordHash
    ).run();

    await audit(env, "member_created", id);

    return json({
      ok: true,
      member: {
        id,
        member_code: code,
        display_name: name,
        status: "active"
      }
    }, 201);
  }


  // MEMBER_DELETE_ROUTE_V1
  const memberDelete = path.match(/^\/admin\/members\/([^/]+)\/delete$/);

  if (method === "POST" && memberDelete) {
    const id = memberDelete[1];

    const member = await env.DB.prepare(
      "SELECT id FROM members WHERE id = ? LIMIT 1"
    ).bind(id).first();

    if (!member) {
      return json({ ok: false, error: "Member not found" }, 404);
    }

    await audit(env, "member_deleted", id);

    await env.DB.batch([
      env.DB.prepare(
        "DELETE FROM playback_sessions WHERE member_id = ?"
      ).bind(id),
      env.DB.prepare(
        "DELETE FROM broadcast_recipients WHERE member_id = ?"
      ).bind(id),
      env.DB.prepare(
        "DELETE FROM messages WHERE member_id = ?"
      ).bind(id),
      env.DB.prepare(
        "DELETE FROM devices WHERE member_id = ?"
      ).bind(id),
      env.DB.prepare(
        "DELETE FROM members WHERE id = ?"
      ).bind(id)
    ]);

    return json({ ok: true, deleted: true });
  }

  const memberStatus = path.match(/^\/admin\/members\/([^/]+)\/status$/);

  if (method === "PATCH" && memberStatus) {
    const body = await readJson(request);
    const status = body?.status;

    if (!["active", "inactive", "blocked"].includes(status)) {
      return json({ ok: false, error: "Invalid status" }, 400);
    }

    await env.DB.prepare(`
      UPDATE members SET status = ? WHERE id = ?
    `).bind(status, memberStatus[1]).run();

    if (status !== "active") {
      await env.DB.prepare(`
        UPDATE playback_sessions
        SET status = 'revoked'
        WHERE member_id = ? AND status = 'active'
      `).bind(memberStatus[1]).run();
    }

    await audit(env, "member_status_changed", memberStatus[1], { status });
    return json({ ok: true });
  }

  if (method === "GET" && path === "/admin/devices") {
    const result = await env.DB.prepare(`
      SELECT d.id, d.member_id, d.device_id, d.device_name,
             d.status, d.paired_at, d.last_seen,
             m.member_code, m.display_name
      FROM devices d
      LEFT JOIN members m ON m.id = d.member_id
      ORDER BY d.last_seen DESC
      LIMIT 2000
    `).all();

    return json({ ok: true, devices: result.results || [] });
  }

  const deviceStatus = path.match(/^\/admin\/devices\/([^/]+)\/status$/);

  if (method === "PATCH" && deviceStatus) {
    const body = await readJson(request);
    const status = body?.status;

    if (!["active", "blocked"].includes(status)) {
      return json({ ok: false, error: "Invalid status" }, 400);
    }

    await env.DB.prepare(`
      UPDATE devices SET status = ? WHERE id = ?
    `).bind(status, deviceStatus[1]).run();

    if (status === "blocked") {
      await env.DB.prepare(`
        UPDATE playback_sessions
        SET status = 'revoked'
        WHERE device_id = (
          SELECT device_id FROM devices WHERE id = ?
        )
        AND member_id = (
          SELECT member_id FROM devices WHERE id = ?
        )
        AND status = 'active'
      `).bind(deviceStatus[1], deviceStatus[1]).run();
    }

    await audit(env, "device_status_changed", deviceStatus[1], { status });
    return json({ ok: true });
  }

  const messageDelete = path.match(/^\/admin\/messages\/([^/]+)\/delete$/);
  if (method === "POST" && messageDelete) {
    const id = messageDelete[1];

    const message = await env.DB.prepare(
      "SELECT id FROM messages WHERE id = ? LIMIT 1"
    ).bind(id).first();

    if (!message) {
      return json({ ok: false, error: "Message not found" }, 404);
    }

    await env.DB.prepare(
      "DELETE FROM messages WHERE id = ?"
    ).bind(id).run();

    await audit(env, "message_deleted", id);
    return json({ ok: true, deleted: true });
  }

  if (method === "GET" && path === "/admin/messages") {
    const result = await env.DB.prepare(`
      SELECT id, member_id, title, body, created_at, expires_at
      FROM messages
      ORDER BY created_at DESC
      LIMIT 1000
    `).all();

    return json({ ok: true, messages: result.results || [] });
  }

  if (method === "POST" && path === "/admin/messages") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const title = String(body.title || "").trim();
    const message = String(body.body || "").trim();
    const audience = body.audience || (body.member_id ? "selected" : "all");

    if (!title || !message ||
        title.length > 180 ||
        message.length > 10000 ||
        !["all", "selected"].includes(audience)) {
      return json({ ok: false, error: "Invalid message" }, 400);
    }

    const expiry = body.expires_at || null;
    if (expiry && !normalizeExpiry(expiry)) {
      return json({ ok: false, error: "Invalid expiration date" }, 400);
    }

    if (audience === "all") {
      await env.DB.prepare(`
        INSERT INTO messages (id, member_id, title, body, expires_at)
        VALUES (?, NULL, ?, ?, ?)
      `).bind(uuid(), title, message, expiry).run();

      await audit(env, "message_sent_all");
      return json({ ok: true, audience: "all" }, 201);
    }

    const ids = Array.isArray(body.member_ids)
      ? [...new Set(body.member_ids.map(String))]
      : body.member_id ? [String(body.member_id)] : [];

    if (!ids.length || ids.length > MAX_SELECTED_MEMBERS) {
      return json({ ok: false, error: "Invalid member selection" }, 400);
    }

    const placeholders = ids.map(() => "?").join(",");
    const members = await env.DB.prepare(`
      SELECT id FROM members
      WHERE status = 'active' AND id IN (${placeholders})
    `).bind(...ids).all();

    const validIds = (members.results || []).map(x => x.id);
    if (!validIds.length) {
      return json({ ok: false, error: "No active recipients" }, 400);
    }

    const statements = validIds.map(id =>
      env.DB.prepare(`
        INSERT INTO messages (id, member_id, title, body, expires_at)
        VALUES (?, ?, ?, ?, ?)
      `).bind(uuid(), id, title, message, expiry)
    );

    await env.DB.batch(statements);
    await audit(env, "message_sent_selected", null, {
      recipient_count: validIds.length
    });

    return json({
      ok: true,
      audience: "selected",
      recipient_count: validIds.length
    }, 201);
  }

  if (method === "POST" && path === "/admin/streams") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const name = String(body.name || "").trim();
    const sourceUrl = String(body.source_url || "").trim();
    const sourceType = String(body.source_type || "hls");

    if (!name || name.length > 180 ||
        !allowedSource(sourceUrl, env) ||
        !["hls"].includes(sourceType)) {
      return json({ ok: false, error: "Invalid stream source or host" }, 400);
    }

    const id = uuid();

    await env.DB.prepare(`
      INSERT INTO stream_sources
        (id, name, source_url, source_type, status)
      VALUES (?, ?, ?, ?, 'active')
    `).bind(id, name, sourceUrl, sourceType).run();

    await audit(env, "stream_created", id);

    return json({
      ok: true,
      stream: { id, name, source_type: sourceType, status: "active" }
    }, 201);
  }

  if (method === "GET" && path === "/admin/streams") {
    const result = await env.DB.prepare(`
      SELECT id, name, source_type, status, created_at, updated_at
      FROM stream_sources
      ORDER BY created_at DESC
      LIMIT 500
    `).all();

    return json({ ok: true, streams: result.results || [] });
  }

  const streamRoute = path.match(/^\/admin\/streams\/([^/]+)$/);

  if (method === "PATCH" && streamRoute) {
    const body = await readJson(request);
    const id = streamRoute[1];

    if (body?.status && ["active", "inactive", "blocked"].includes(body.status)) {
      await env.DB.prepare(`
        UPDATE stream_sources SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(body.status, id).run();

      await audit(env, "stream_status_changed", id, {
        status: body.status
      });

      return json({ ok: true });
    }

    if (body?.source_url) {
      const sourceUrl = String(body.source_url);
      if (!allowedSource(sourceUrl, env)) {
        return json({ ok: false, error: "Source host not allowed" }, 400);
      }

      await env.DB.prepare(`
        UPDATE stream_sources
        SET source_url = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(sourceUrl, id).run();

      await audit(env, "stream_source_updated", id);
      return json({ ok: true });
    }

    return json({ ok: false, error: "No valid update" }, 400);
  }

  if (method === "POST" && path === "/admin/broadcast/start") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const title = String(body.title || "").trim();
    const message = String(body.message || "");
    const streamId = String(body.stream_id || "");
    const audience = body.audience || "all";

    if (!title || title.length > 180 ||
        message.length > 5000 ||
        !streamId ||
        !["all", "selected"].includes(audience)) {
      return json({ ok: false, error: "Invalid broadcast" }, 400);
    }

    const source = await env.DB.prepare(`
      SELECT id, status FROM stream_sources WHERE id = ? LIMIT 1
    `).bind(streamId).first();

    if (!source || source.status !== "active") {
      return json({ ok: false, error: "Stream unavailable" }, 400);
    }

    const broadcastId = uuid();

    const statements = [
      env.DB.prepare(`
        INSERT INTO broadcasts
          (id, title, message, stream_source_id, audience,
           status, created_by, started_at)
        VALUES (?, ?, ?, ?, ?, 'live', 'admin', CURRENT_TIMESTAMP)
      `).bind(broadcastId, title, message, streamId, audience)
    ];

    let recipientCount = 0;

    if (audience === "all") {
      // Yayın başladığı andaki aktif üyeleri sabitle.
      // Sonradan eklenen üyeler bu yayına otomatik katılamaz.
      statements.push(env.DB.prepare(`
        INSERT INTO broadcast_recipients
          (id, broadcast_id, member_id, status)
        SELECT lower(hex(randomblob(16))), ?, id, 'targeted'
        FROM members
        WHERE status = 'active'
      `).bind(broadcastId));

      const count = await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM members
        WHERE status = 'active'
      `).first();

      recipientCount = Number(count?.total || 0);

      if (!recipientCount) {
        return json({ ok: false, error: "No active recipients" }, 400);
      }
    } else {
      const ids = Array.isArray(body.member_ids)
        ? [...new Set(body.member_ids.map(String))]
        : [];

      if (!ids.length || ids.length > MAX_SELECTED_MEMBERS) {
        return json({ ok: false, error: "Invalid recipient selection" }, 400);
      }

      const placeholders = ids.map(() => "?").join(",");
      const members = await env.DB.prepare(`
        SELECT id FROM members
        WHERE status = 'active' AND id IN (${placeholders})
      `).bind(...ids).all();

      const validIds = (members.results || []).map(x => x.id);

      if (!validIds.length) {
        return json({ ok: false, error: "No active recipients" }, 400);
      }

      recipientCount = validIds.length;

      for (const memberId of validIds) {
        statements.push(env.DB.prepare(`
          INSERT INTO broadcast_recipients
            (id, broadcast_id, member_id, status)
          VALUES (?, ?, ?, 'targeted')
        `).bind(uuid(), broadcastId, memberId));
      }
    }

    await env.DB.batch(statements);
    await audit(env, "broadcast_started", broadcastId, {
      audience,
      recipient_count: recipientCount
    });

    return json({
      ok: true,
      broadcast_id: broadcastId,
      audience,
      recipient_count: audience === "all" ? "all-active-members" : recipientCount
    }, 201);
  }

  if (method === "POST" && path === "/admin/broadcast/stop") {
    const body = await readJson(request);
    const requestedId = String(body?.broadcast_id || "").trim();

    const active = requestedId
      ? await env.DB.prepare(`
          SELECT id FROM broadcasts
          WHERE id = ? AND status = 'live'
          LIMIT 1
        `).bind(requestedId).first()
      : await env.DB.prepare(`
          SELECT id FROM broadcasts
          WHERE status = 'live'
          ORDER BY started_at DESC, created_at DESC
          LIMIT 1
        `).first();

    if (!active) {
      return json({ ok: false, error: "Aktif yayın bulunamadı." }, 404);
    }

    const id = active.id;

    await env.DB.batch([
      env.DB.prepare(`
        UPDATE broadcasts
        SET status = 'stopped',
            stopped_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'live'
      `).bind(id),

      env.DB.prepare(`
        UPDATE playback_sessions
        SET status = 'revoked'
        WHERE broadcast_id = ? AND status = 'active'
      `).bind(id),

      env.DB.prepare(`
        UPDATE broadcast_recipients
        SET status = 'ended', ended_at = CURRENT_TIMESTAMP
        WHERE broadcast_id = ? AND status IN ('targeted', 'authorized')
      `).bind(id)
    ]);

    await audit(env, "broadcast_stopped", id);
    return json({ ok: true, broadcast_id: id, stopped: true });
  }

  if (method === "GET" && path === "/admin/broadcast") {
    const result = await env.DB.prepare(`
      SELECT b.id, b.title, b.message, b.audience, b.status,
             b.started_at, b.stopped_at, b.created_at,
             s.name AS stream_name
      FROM broadcasts b
      LEFT JOIN stream_sources s ON s.id = b.stream_source_id
      ORDER BY b.created_at DESC
      LIMIT 100
    `).all();

    return json({ ok: true, broadcasts: result.results || [] });
  }

  if (method === "GET" && path === "/admin/audit") {
    const result = await env.DB.prepare(`
      SELECT id, actor_type, actor_id, action,
             target_type, target_id, details, created_at
      FROM audit_logs
      ORDER BY created_at DESC
      LIMIT 500
    `).all();

    return json({ ok: true, logs: result.results || [] });
  }

  return json({ ok: false, error: "Admin endpoint not found" }, 404);
}

/* =========================================================
   PRIVATE GITHUB API
   Token is read only from Worker environment secrets.
   APK and member responses never receive the token.
   ========================================================= */

function allowedGithubRepos(env) {
  return (env.GITHUB_ALLOWED_REPOS || "")
    .split(",")
    .map(x => x.trim())
    .filter(x => /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(x));
}

function checkGithubRepo(repo, env) {
  return allowedGithubRepos(env).includes(repo);
}

function cleanGithubPath(path) {
  const value = String(path || "").replace(/^\/+/, "");

  if (!value ||
      value.split("/").some(part =>
        !part || part === "." || part === ".." ||
        part.includes("\\")
      )) return null;

  return value;
}

function isGithubPathWritable(path) {
  if (!path) return false;

  const parts = path.split("/").map(x => x.toLowerCase());
  const filename = parts[parts.length - 1];

  if (parts.some(x => x === ".github" || x === ".git")) {
    return false;
  }

  const protectedFiles = new Set([
    "codeowners",
    ".gitmodules",
    "security.md",
    "dependabot.yml",
    "dependabot.yaml"
  ]);

  if (protectedFiles.has(filename)) return false;

  return true;
}

async function githubRequest(env, path, options = {}) {
  if (!env.GITHUB_TOKEN) {
    throw new Error("GitHub token is not configured");
  }

  const response = await fetch(`https://api.github.com${path}`, {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Private-Content-Manager",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let data;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(`GitHub API error ${response.status}`);
  }

  return data;
}

async function handleGithub(request, env, url, method) {
  if (method === "GET" && url.pathname === "/admin/github/repos") {
    const repos = [];

    for (const repo of allowedGithubRepos(env)) {
      try {
        const info = await githubRequest(env, `/repos/${repo}`);
        repos.push({
          name: info.full_name,
          private: info.private,
          default_branch: info.default_branch
        });
      } catch {
        repos.push({ name: repo, error: "Repository unavailable" });
      }
    }

    return json({ ok: true, repos });
  }

  if (url.pathname === "/admin/github/file" && method === "GET") {
    const repo = url.searchParams.get("repo") || "";
    const path = cleanGithubPath(url.searchParams.get("path"));
    const ref = url.searchParams.get("ref") || "";

    if (!checkGithubRepo(repo, env) || !path) {
      return json({ ok: false, error: "Invalid repository or path" }, 400);
    }

    try {
      const query = ref ? `?ref=${encodeURIComponent(ref)}` : "";
      const file = await githubRequest(
        env,
        `/repos/${repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}${query}`
      );

      if (Array.isArray(file) || file.type !== "file" || !file.content) {
        return json({ ok: false, error: "Not a regular file" }, 400);
      }

      const content = decoder.decode(unb64url(
        b64url(Uint8Array.from(atob(file.content.replace(/\n/g, "")), c => c.charCodeAt(0)))
      ));

      return json({
        ok: true,
        repository: repo,
        path,
        sha: file.sha,
        size: file.size,
        content
      });
    } catch {
      return json({ ok: false, error: "GitHub file read failed" }, 502);
    }
  }

  if (url.pathname === "/admin/github/chunk" && method === "PUT") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const repo = String(body.repo || "");
    const path = cleanGithubPath(body.path);
    const contentBase64 = String(body.contentBase64 || "");
    const message = String(body.message || "Upload file part");

    if (!checkGithubRepo(repo, env) ||
        !path ||
        !isGithubPathWritable(path) ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(contentBase64) ||
        Math.floor(contentBase64.length * 3 / 4) > MAX_GITHUB_CHUNK_BYTES) {
      return json({ ok: false, error: "Invalid chunk or size" }, 400);
    }

    try {
      const encodedPath = path.split("/").map(encodeURIComponent).join("/");
      let sha;

      try {
        const existing = await githubRequest(
          env,
          `/repos/${repo}/contents/${encodedPath}`
        );
        sha = existing.sha;
      } catch {
        sha = undefined;
      }

      const payload = { message, content: contentBase64 };
      if (sha) payload.sha = sha;

      const result = await githubRequest(
        env,
        `/repos/${repo}/contents/${encodedPath}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        }
      );

      await audit(env, "github_chunk_uploaded", path, { repo });

      return json({
        ok: true,
        repository: repo,
        path,
        sha: result.content?.sha || null
      });
    } catch {
      return json({ ok: false, error: "GitHub part upload failed" }, 502);
    }
  }

  if (url.pathname === "/admin/github/file" && method === "PUT") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const repo = String(body.repo || "");
    const path = cleanGithubPath(body.path);
    const content = String(body.content ?? "");
    const message = String(body.message || "Update managed content");

    if (!checkGithubRepo(repo, env) ||
        !path ||
        !isGithubPathWritable(path) ||
        encoder.encode(content).length > MAX_GITHUB_FILE_BYTES) {
      return json({ ok: false, error: "Invalid repository, protected path or file size" }, 400);
    }

    try {
      const encodedPath = path.split("/").map(encodeURIComponent).join("/");
      let sha;

      try {
        const existing = await githubRequest(
          env,
          `/repos/${repo}/contents/${encodedPath}`
        );
        sha = existing.sha;
      } catch {
        sha = undefined;
      }

      const payload = {
        message,
        content: btoa(Array.from(
          encoder.encode(content),
          byte => String.fromCharCode(byte)
        ).join(""))
      };

      if (sha) payload.sha = sha;
      // GitHub API varsayılan branch'i kullanır.
      // İstemciden branch seçimi kabul edilmez.

      const result = await githubRequest(
        env,
        `/repos/${repo}/contents/${encodedPath}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        }
      );

      await audit(env, "github_file_updated", path, { repo });

      return json({
        ok: true,
        repository: repo,
        path,
        sha: result.content?.sha || null
      });
    } catch {
      return json({ ok: false, error: "GitHub file update failed" }, 502);
    }
  }

  return json({ ok: false, error: "GitHub endpoint not found" }, 404);
}

/* =========================================================
   MEMBER API
   ========================================================= */

async function handleMember(request, env, path, method, auth) {
  const member = auth.member;

  if (method === "GET" && path === "/member/profile") {
    return json({
      ok: true,
      member: {
        id: member.id,
        member_code: member.member_code,
        display_name: member.display_name,
        status: member.status,
        expires_at: member.expires_at,
        max_devices: member.max_devices
      }
    });
  }

  if (method === "GET" && path === "/member/messages") {
    const result = await env.DB.prepare(`
      SELECT id, title, body, created_at, expires_at
      FROM messages
      WHERE (member_id IS NULL OR member_id = ?)
        AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
      ORDER BY created_at DESC
      LIMIT 100
    `).bind(member.id).all();

    return json({ ok: true, messages: result.results || [] });
  }

  if (method === "GET" && path === "/member/streams") {
    const result = await env.DB.prepare(`
      SELECT id, name, source_type
      FROM stream_sources
      WHERE status = 'active'
      ORDER BY name
      LIMIT 500
    `).all();

    return json({ ok: true, streams: result.results || [] });
  }

  if (method === "GET" && path === "/member/broadcast") {
    const result = await env.DB.prepare(`
      SELECT b.id, b.title, b.message, b.started_at,
             s.name AS stream_name
      FROM broadcasts b
      JOIN stream_sources s ON s.id = b.stream_source_id
      WHERE b.status = 'live'
        AND s.status = 'active'
        AND EXISTS (
          SELECT 1
          FROM broadcast_recipients r
          WHERE r.broadcast_id = b.id
            AND r.member_id = ?
            AND r.status IN ('targeted', 'authorized')
        )
      ORDER BY b.started_at DESC
      LIMIT 20
    `).bind(member.id).all();

    return json({ ok: true, broadcasts: result.results || [] });
  }

  if (method === "POST" && path === "/member/playback") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    if (!body.broadcast_id) {
      return json({
        ok: false,
        error: "An active broadcast is required"
      }, 400);
    }

    let source;
    const broadcastId = String(body.broadcast_id).trim();

    if (!broadcastId || broadcastId.length > 180) {
      return json({ ok: false, error: "Invalid broadcast ID" }, 400);
    }

    {

      const broadcast = await env.DB.prepare(`
        SELECT b.id, b.stream_source_id, b.audience,
               s.id AS source_id, s.source_url, s.status AS source_status
        FROM broadcasts b
        JOIN stream_sources s ON s.id = b.stream_source_id
        WHERE b.id = ? AND b.status = 'live'
        LIMIT 1
      `).bind(broadcastId).first();

      if (!broadcast || broadcast.source_status !== "active") {
        return json({ ok: false, error: "Broadcast unavailable" }, 404);
      }

      const recipient = await env.DB.prepare(`
        SELECT id
        FROM broadcast_recipients
        WHERE broadcast_id = ?
          AND member_id = ?
          AND status IN ('targeted', 'authorized')
        LIMIT 1
      `).bind(broadcastId, member.id).first();

      if (!recipient) {
        return json({ ok: false, error: "Not authorized for broadcast" }, 403);
      }

      await env.DB.prepare(`
        UPDATE broadcast_recipients
        SET status = 'authorized', authorized_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(recipient.id).run();

      source = {
        id: broadcast.source_id,
        source_url: broadcast.source_url,
        status: broadcast.source_status
      };
    }

    if (!source) {
      return json({ ok: false, error: "Stream not found" }, 404);
    }

    const playback = await issuePlayback(
      env,
      member,
      auth.deviceId,
      source,
      broadcastId
    );

    if (playback.error) {
      return json({ ok: false, error: playback.error }, 403);
    }

    return json({ ok: true, ...playback });
  }

  return json({ ok: false, error: "Member endpoint not found" }, 404);
}

/* =========================================================
   MAIN ROUTER
   ========================================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    const configuredOrigins = (env.APP_ORIGINS || "")
      .split(",")
      .map(x => x.trim())
      .filter(Boolean);

    const origin = request.headers.get("Origin") || "";
    const allowOrigin = configuredOrigins.length
      ? (configuredOrigins.includes(origin) ? origin : "")
      : "*";

    const cors = {
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type, Range",
      "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges",
      "Vary": "Origin"
    };

    if (allowOrigin) cors["Access-Control-Allow-Origin"] = allowOrigin;

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors
      });
    }

    try {
      if (path === "/health" && method === "GET") {
        return json({
          ok: true,
          version: VERSION,
          service: "stream-access-service"
        }, 200, cors);
      }

      if (path.startsWith("/play/") && method === "GET") {
        const ticket = path.slice("/play/".length);
        return proxyMedia(request, env, ticket, cors);
      }

      if (path.startsWith("/p/") && method === "GET") {
        const ticket = path.slice("/p/".length);
        return proxyMedia(request, env, ticket, cors);
      }

      if (path.startsWith("/auth/") && method === "POST") {
        return handleLogin(request, env, path);
      }

      if (path.startsWith("/admin/")) {
        const admin = await adminAuth(request, env);
        if (!admin) {
          return json({ ok: false, error: "Unauthorized" }, 401, cors);
        }

        if (path.startsWith("/admin/github/")) {
          return handleGithub(request, env, url, method);
        }

        return handleAdmin(request, env, path, method);
      }

      if (path.startsWith("/member/")) {
        const auth = await memberAuth(request, env);
        if (!auth) {
          return json({ ok: false, error: "Unauthorized" }, 401, cors);
        }

        return handleMember(request, env, path, method, auth);
      }

      return json({ ok: false, error: "Not found" }, 404, cors);
    } catch (error) {
      // Safe diagnostics: never log request bodies, passwords or tokens.
      console.error("WORKER_REQUEST_ERROR", JSON.stringify({
        path,
        method,
        name: error?.name || "Error",
        message: String(error?.message || error).slice(0, 1000)
      }));

      return json({
        ok: false,
        error: "Internal server error"
      }, 500, cors);
    }
  }
};
