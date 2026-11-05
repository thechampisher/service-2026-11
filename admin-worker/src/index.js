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


async function handleAdminLogin(request, env) {
  const body = await readJson(request);
  if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

  const password = String(body.password || "");

  if (!env.ADMIN_LOGIN_PASSWORD ||
      !equalText(password, env.ADMIN_LOGIN_PASSWORD)) {
    return json({ ok: false, error: "Invalid credentials" }, 401);
  }

  const token = await createJwt(
    { role: "admin", id: "admin" },
    env,
    ADMIN_TOKEN_SECONDS
  );

  return json({
    ok: true,
    token,
    expires_in: ADMIN_TOKEN_SECONDS
  });
}


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


const SOURCE_REPO = "thechampisher/content-data";
const SOURCE_ROOT = "sources";
const SOURCE_PART_LIMIT = 700000;

async function sourceRead(env, path) {
  const file = await githubRequest(
    env,
    `/repos/${SOURCE_REPO}/contents/${path.split("/").map(encodeURIComponent).join("/")}`
  );
  if (Array.isArray(file) || file.type !== "file" || !file.content) {
    throw new Error("Source file unavailable");
  }
  const bytes = Uint8Array.from(
    atob(file.content.replace(/\n/g, "")),
    c => c.charCodeAt(0)
  );
  return JSON.parse(decoder.decode(bytes));
}

async function sourceWrite(env, path, value, message) {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  let sha;
  try {
    const old = await githubRequest(
      env, `/repos/${SOURCE_REPO}/contents/${encodedPath}`
    );
    sha = old.sha;
  } catch {}

  const bytes = encoder.encode(
    typeof value === "string" ? value : JSON.stringify(value)
  );
  const content = btoa(Array.from(bytes, b => String.fromCharCode(b)).join(""));
  const payload = { message, content };
  if (sha) payload.sha = sha;

  return githubRequest(
    env,
    `/repos/${SOURCE_REPO}/contents/${encodedPath}`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }
  );
}

async function sourceGetCurrent(env) {
  const pointer = await sourceRead(env, `${SOURCE_ROOT}/current.json`);
  if (!pointer.generation) throw new Error("Invalid source pointer");
  const base = `${SOURCE_ROOT}/generations/${pointer.generation}`;
  const manifest = await sourceRead(env, `${base}/manifest.json`);
  if (!Array.isArray(manifest.parts)) throw new Error("Invalid source manifest");
  return { pointer, manifest, base };
}

async function sourceReadRecords(env, current) {
  const records = [];
  for (const part of current.manifest.parts) {
    const rows = await sourceRead(env, `${current.base}/${part}`);
    if (!Array.isArray(rows)) throw new Error("Invalid source part");
    records.push(...rows);
  }
  return records;
}

async function sourcePublishRecords(env, records) {
  const generation = crypto.randomUUID().replace(/-/g, "");
  const base = `${SOURCE_ROOT}/generations/${generation}`;
  const parts = [];
  let batch = [];

  async function flush() {
    if (!batch.length) return;
    const name = `part-${String(parts.length).padStart(5, "0")}.json`;
    await sourceWrite(env, `${base}/${name}`, batch, "Save source generation part");
    parts.push(name);
    batch = [];
  }

  for (const row of records) {
    const test = [...batch, row];
    if (encoder.encode(JSON.stringify(test)).length > SOURCE_PART_LIMIT && batch.length) {
      await flush();
    }
    batch.push(row);
    if (encoder.encode(JSON.stringify(batch)).length > SOURCE_PART_LIMIT) {
      throw new Error("A single source record is too large");
    }
  }
  await flush();

  const manifest = {
    generation,
    parts,
    count: records.length,
    createdAt: new Date().toISOString()
  };

  await sourceWrite(env, `${base}/manifest.json`, manifest, "Publish source manifest");
  await sourceWrite(
    env,
    `${SOURCE_ROOT}/current.json`,
    { generation, updatedAt: new Date().toISOString() },
    "Activate source generation"
  );
  return manifest;
}


// XTREAM_MAG_SOURCE_V1
function validateExternalSourceHost(value) {
  let u;
  try { u = new URL(String(value || "").trim()); }
  catch { throw new Error("Geçerli sunucu adresi girilmedi."); }

  if (!["http:", "https:"].includes(u.protocol) ||
      u.username || u.password || u.search || u.hash) {
    throw new Error("Sunucu adresi geçersiz.");
  }

  const host=u.hostname.toLowerCase();
  if (!host || host==="localhost" || host.endsWith(".localhost") ||
      host.endsWith(".local") || host.endsWith(".internal") ||
      host.endsWith(".test")) {
    throw new Error("Yerel sunucu adreslerine izin verilmiyor.");
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    const a=host.split(".").map(Number);
    if (a.some(x=>x<0||x>255) ||
        a[0]===10 || a[0]===127 || a[0]===0 ||
        a[0]>=224 || (a[0]===169&&a[1]===254) ||
        (a[0]===172&&a[1]>=16&&a[1]<=31) ||
        (a[0]===192&&a[1]===168) ||
        (a[0]===100&&a[1]>=64&&a[1]<=127)) {
      throw new Error("Özel ağ adreslerine izin verilmiyor.");
    }
  }

  u.pathname=u.pathname.replace(/\/+$/,"");
  return u;
}

async function externalJson(url, headers={}) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),25000);
  try {
    const response=await fetch(url,{
      method:"GET",
      headers,
      redirect:"manual",
      signal:controller.signal
    });
    if(!response.ok) throw new Error("Kaynak sunucu HTTP "+response.status);
    const text=await response.text();
    if(text.length>12*1024*1024) throw new Error("Kaynak yanıtı çok büyük.");
    try { return JSON.parse(text); }
    catch { throw new Error("Kaynak sunucu geçerli JSON döndürmedi."); }
  } finally {
    clearTimeout(timer);
  }
}

function sourceCredentials(body) {
  const host=validateExternalSourceHost(body.host);
  const user=String(body.username||"").trim();
  const pass=String(body.password||"");
  if(!user||!pass||user.length>256||pass.length>256)
    throw new Error("Kullanıcı adı ve şifre gerekli.");
  return {host,user,pass};
}

async function xtreamAction(info,action,categoryId=null,seriesId=null) {
  const endpoint=new URL(info.host.href);
  if(!endpoint.pathname.toLowerCase().endsWith("/player_api.php"))
    endpoint.pathname=endpoint.pathname.replace(/\/+$/,"")+"/player_api.php";

  endpoint.searchParams.set("username",info.user);
  endpoint.searchParams.set("password",info.pass);
  endpoint.searchParams.set("action",action);
  if(categoryId!==null) endpoint.searchParams.set("category_id",String(categoryId));
  if(seriesId!==null) endpoint.searchParams.set("series_id",String(seriesId));

  return externalJson(endpoint.href,{
    "Accept":"application/json",
    "User-Agent":"Mozilla/5.0"
  });
}

function arrayValue(value) {
  return Array.isArray(value)?value:[];
}

function xtreamStreamRecord(info,row,type,group) {
  const id=String(row.stream_id||row.series_id||row.id||"");
  if(!id) return null;
  const ext=String(row.container_extension||(
    type==="live"?"ts":type==="movie"?"mp4":"mkv"
  )).toLowerCase().replace(/[^a-z0-9]/g,"").slice(0,8) ||
    (type==="live"?"ts":type==="movie"?"mp4":"mkv");

  const path=type==="live"?"live":type==="movie"?"movie":"series";
  const url=info.host.origin+info.host.pathname.replace(/\/player_api\.php$/i,"")+
    "/"+path+"/"+encodeURIComponent(info.user)+"/"+
    encodeURIComponent(info.pass)+"/"+encodeURIComponent(id)+"."+ext;

  return {
    id:uuid(),
    source:"xtream",
    type,
    name:String(row.name||row.title||"İsimsiz"),
    url,
    logo:String(row.stream_icon||row.cover||row.movie_image||""),
    group:String(group||"Diğer"),
    tvgId:String(row.epg_channel_id||""),
    streamId:id
  };
}

async function handleXtreamCategories(body) {
  const info=sourceCredentials(body);
  const specs=[
    ["live","get_live_categories"],
    ["vod","get_vod_categories"],
    ["series","get_series_categories"]
  ];
  const categories=[];
  for(const [type,action] of specs) {
    const rows=arrayValue(await xtreamAction(info,action));
    for(const row of rows) {
      categories.push({
        type,
        id:String(row.category_id||row.id||""),
        name:String(row.category_name||row.name||"Diğer")
      });
    }
  }
  return categories;
}

function xtreamCredentialsFromPlaylistUrl(value) {
  let playlist;
  try {
    playlist = new URL(String(value || ""));
  } catch {
    throw new Error("M3U/Xtream adresi geçerli değil.");
  }

  if (playlist.protocol !== "https:" && playlist.protocol !== "http:") {
    throw new Error("Xtream adresi HTTPS olmalı.");
  }

  const user = String(playlist.searchParams.get("username") || "").trim();
  const pass = String(playlist.searchParams.get("password") || "");

  if (!user || !pass) {
    throw new Error("URL içinde username ve password bilgileri bulunamadı.");
  }

  playlist.pathname = playlist.pathname.replace(
    /\/(?:get|playlist|player_api)\.php$/i, ""
  ).replace(/\/+$/, "") || "/";

  playlist.search = "";
  playlist.hash = "";

  const host = validateExternalSourceHost(playlist.href);
  return sourceCredentials({
    host: host.href,
    username: user,
    password: pass
  });
}

async function handleXtreamImportFromUrl(body) {
  const info = xtreamCredentialsFromPlaylistUrl(body.playlistUrl);
  const credentials = {
    host: info.host.href,
    username: info.user,
    password: info.pass
  };

  const categories = await handleXtreamCategories(credentials);

  if (!categories.length) {
    throw new Error("Xtream sunucusunda kategori bulunamadı.");
  }

  if (categories.length > 800) {
    throw new Error("Kategori sayısı 800 sınırını aşıyor.");
  }

  return handleXtreamImport({
    ...credentials,
    categories
  });
}

async function handleXtreamImport(body) {
  const info=sourceCredentials(body);
  const selected=Array.isArray(body.categories)?body.categories:[];
  if(!selected.length||selected.length>800)
    throw new Error("En fazla 800 kategori aktarılabilir.");

  const records=[];
  for(const category of selected) {
    const type=String(category.type||"");
    const id=String(category.id||"");
    const name=String(category.name||"Diğer");
    if(!["live","vod","series"].includes(type)||!id) continue;

    const action=type==="live"?"get_live_streams":
      type==="vod"?"get_vod_streams":"get_series";
    const rows=arrayValue(await xtreamAction(info,action,id));

    if(type!=="series") {
      for(const row of rows) {
        const record=xtreamStreamRecord(
          info,row,type==="live"?"live":"movie",name
        );
        if(record) records.push(record);
        if(records.length>=12000) break;
      }
    } else {
      if(rows.length>150) throw new Error("Bir dizin kategorisinde 150'den fazla dizi var. Kategorileri bölerek aktar.");
      for(const series of rows) {
        const sid=String(series.series_id||series.id||"");
        if(!sid) continue;
        const detail=await xtreamAction(info,"get_series_info",null,sid);
        const seasons=detail.episodes||{};
        let found=0;

        for(const seasonKey of Object.keys(seasons)) {
          for(const ep of arrayValue(seasons[seasonKey])) {
            const eid=String(ep.id||ep.episode_id||"");
            if(!eid) continue;
            const ext=String(ep.container_extension||"mkv")
              .toLowerCase().replace(/[^a-z0-9]/g,"").slice(0,8)||"mkv";
            const epNo=ep.episode_num||ep.episode_number||"";
            const title=String(ep.title||ep.name||"Bölüm");
            records.push({
              id:uuid(),
              source:"xtream",
              type:"episode",
              name:String(series.name||"Dizi")+" - S"+
                String(seasonKey)+" E"+String(epNo)+" - "+title,
              seriesName:String(series.name||""),
              season:String(seasonKey),
              episode:String(epNo),
              url:info.host.origin+
                info.host.pathname.replace(/\/player_api\.php$/i,"")+
                "/series/"+encodeURIComponent(info.user)+"/"+
                encodeURIComponent(info.pass)+"/"+
                encodeURIComponent(eid)+"."+ext,
              logo:String(ep.info?.movie_image||series.cover||""),
              group:name,
              seriesId:sid
            });
            found++;
            if(records.length>=12000) break;
          }
          if(records.length>=12000) break;
        }
        if(!found) {
          records.push({
            id:uuid(),source:"xtream",type:"series",
            name:String(series.name||"İsimsiz"),
            url:"",logo:String(series.cover||""),
            group:name,seriesId:sid
          });
        }
        if(records.length>=12000) break;
      }
    }
    if(records.length>=12000) break;
  }
  return records;
}


// XTREAM_BATCH_IMPORT_V1
// Her çağrıda bir kategori ve en fazla 8 dizi ayrıntısı işlenir.
async function handleXtreamImportPart(body) {
  const info = sourceCredentials(body);
  const category = body.category || {};
  const type = String(category.type || "");
  const id = String(category.id || "");
  const name = String(category.name || "Diğer");

  if (!["live", "vod", "series"].includes(type) || !id) {
    throw new Error("Geçersiz Xtream kategorisi.");
  }

  const action = type === "live" ? "get_live_streams" :
    type === "vod" ? "get_vod_streams" : "get_series";

  const rows = arrayValue(await xtreamAction(info, action, id));

  if (type !== "series") {
    const items = [];
    for (const row of rows) {
      const record = xtreamStreamRecord(
        info, row, type === "live" ? "live" : "movie", name
      );
      if (record) items.push(record);
    }
    return { items, total: rows.length, nextOffset: rows.length, done: true };
  }

  const offset = Math.max(0, Number(body.offset) || 0);
  const batchSize = Math.min(8, Math.max(1, Number(body.batchSize) || 8));
  const batch = rows.slice(offset, offset + batchSize);
  const items = [];

  for (const series of batch) {
    const sid = String(series.series_id || series.id || "");
    if (!sid) continue;

    const detail = await xtreamAction(info, "get_series_info", null, sid);
    const seasons = detail?.episodes || {};
    let found = 0;

    for (const seasonKey of Object.keys(seasons)) {
      for (const ep of arrayValue(seasons[seasonKey])) {
        const eid = String(ep.id || ep.episode_id || "");
        if (!eid) continue;

        const ext = String(ep.container_extension || "mkv")
          .toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 8) || "mkv";
        const epNo = ep.episode_num || ep.episode_number || "";
        const title = String(ep.title || ep.name || "Bölüm");

        items.push({
          id: uuid(),
          source: "xtream",
          type: "episode",
          name: String(series.name || "Dizi") + " - S" +
            String(seasonKey) + " E" + String(epNo) + " - " + title,
          seriesName: String(series.name || ""),
          season: String(seasonKey),
          episode: String(epNo),
          url: info.host.origin +
            info.host.pathname.replace(/\/player_api\.php$/i, "") +
            "/series/" + encodeURIComponent(info.user) + "/" +
            encodeURIComponent(info.pass) + "/" +
            encodeURIComponent(eid) + "." + ext,
          logo: String(ep.info?.movie_image || series.cover || ""),
          group: name,
          seriesId: sid
        });
        found++;
      }
    }

    if (!found) {
      items.push({
        id: uuid(),
        source: "xtream",
        type: "series",
        name: String(series.name || "İsimsiz"),
        url: "",
        logo: String(series.cover || ""),
        group: name,
        seriesId: sid
      });
    }
  }

  const nextOffset = offset + batch.length;
  return {
    items,
    total: rows.length,
    nextOffset,
    done: nextOffset >= rows.length
  };
}

function magUnwrap(value) {
  let x=value?.js??value;
  if(typeof x==="string") {
    try { x=JSON.parse(x); } catch {}
  }
  return x;
}

async function magSession(hostValue,macValue) {
  const host=validateExternalSourceHost(hostValue);
  const mac=String(macValue||"").trim().toUpperCase();
  if(!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac))
    throw new Error("MAC adresi 00:11:22:33:44:55 biçiminde olmalı.");

  const portal=new URL(host.href);
  if(!portal.pathname.toLowerCase().endsWith("portal.php"))
    portal.pathname=portal.pathname.replace(/\/+$/,"")+"/portal.php";

  const cookie="mac="+mac+"; stb_lang=en; timezone=Europe%2FIstanbul";
  const u=new URL(portal.href);
  u.searchParams.set("type","stb");
  u.searchParams.set("action","handshake");
  u.searchParams.set("token","");
  u.searchParams.set("JsHttpRequest","1-xml");

  const response=await fetch(u.href,{
    headers:{
      "Cookie":cookie,
      "User-Agent":"Mozilla/5.0 (QtEmbedded; Linux; U; Linux armv7l) AppleWebKit/533.3",
      "X-User-Agent":"Model: MAG250; Link: Ethernet",
      "Referer":portal.origin+"/c/"
    },
    redirect:"manual"
  });
  if(!response.ok) throw new Error("MAG handshake HTTP "+response.status);
  const text=await response.text();
  let data;
  try { data=JSON.parse(text); }
  catch { throw new Error("MAG portal yanıtı JSON değil."); }

  const js=magUnwrap(data);
  const token=String(js?.token||data?.token||"");
  if(!token) throw new Error("MAG portal token vermedi.");

  const setCookie=response.headers.get("set-cookie")||"";
  const php=(setCookie.match(/PHPSESSID=[^;]+/i)||[])[0]||"";
  return {portal,mac,token,cookie:cookie+(php?"; "+php:"")};
}

async function magCall(session,params) {
  const u=new URL(session.portal.href);
  for(const [k,v] of Object.entries({
    ...params,JsHttpRequest:"1-xml"
  })) u.searchParams.set(k,String(v));

  const response=await fetch(u.href,{
    headers:{
      "Cookie":session.cookie,
      "Authorization":"Bearer "+session.token,
      "User-Agent":"Mozilla/5.0 (QtEmbedded; Linux; U; Linux armv7l) AppleWebKit/533.3",
      "X-User-Agent":"Model: MAG250; Link: Ethernet",
      "Referer":session.portal.origin+"/c/"
    },
    redirect:"manual"
  });
  if(!response.ok) throw new Error("MAG portal HTTP "+response.status);
  const text=await response.text();
  try { return JSON.parse(text); }
  catch { throw new Error("MAG portal yanıtı okunamadı."); }
}

function magArray(value) {
  const x=magUnwrap(value);
  if(Array.isArray(x)) return x;
  if(Array.isArray(x?.data)) return x.data;
  if(Array.isArray(x?.channels)) return x.channels;
  return [];
}

async function magGetChannels(session) {
  const result=await magCall(session,{type:"itv",action:"get_all_channels"});
  return magArray(result);
}

function magChannelId(row) {
  return String(row.id||row.ch_id||row.channel_id||"");
}

async function handleMagCategories(body) {
  const session=await magSession(body.host,body.mac);
  const result=await magCall(session,{type:"itv",action:"get_genres"});
  return magArray(result).map(x=>({
    id:String(x.id||x.genre_id||""),
    name:String(x.title||x.name||"Diğer")
  })).filter(x=>x.id);
}

async function handleMagChannels(body) {
  const session=await magSession(body.host,body.mac);
  const genre=String(body.categoryId||"");
  const channels=await magGetChannels(session);
  return channels.filter(x=>
    !genre || String(x.tv_genre_id||x.genre_id||x.category_id||"")===genre
  ).slice(0,1000).map(x=>({
    id:magChannelId(x),
    name:String(x.name||x.title||"İsimsiz"),
    logo:String(x.logo||x.screenshot_uri||""),
    group:String(x.tv_genre_name||x.genre_name||"MAG"),
    number:String(x.number||"")
  })).filter(x=>x.id);
}

async function handleMagImport(body) {
  const ids=Array.isArray(body.ids)?[...new Set(body.ids.map(String))]:[];
  if(!ids.length||ids.length>200)
    throw new Error("Bir aktarımda 1-200 kanal seç.");

  const session=await magSession(body.host,body.mac);
  const channels=await magGetChannels(session);
  const wanted=new Set(ids);
  const selected=channels.filter(x=>wanted.has(magChannelId(x)));
  if(selected.length!==ids.length)
    throw new Error("Seçilen kanalların bir kısmı portalda bulunamadı.");

  const records=[];
  for(const channel of selected) {
    const cmd=String(channel.cmd||"");
    if(!cmd) continue;

    const result=await magCall(session,{
      type:"itv",action:"create_link",cmd,
      series:"0",forced_storage:"0",
      disable_ad:"0",download:"0"
    });
    const js=magUnwrap(result);
    const raw=String(js?.cmd||js?.url||js?.link||"");
    const match=raw.match(/https?:\/\/[^\s"'<>]+/i);
    if(!match) continue;

    records.push({
      id:uuid(),
      source:"mag",
      type:"live",
      name:String(channel.name||"İsimsiz"),
      url:match[0],
      logo:String(channel.logo||channel.screenshot_uri||""),
      group:String(channel.tv_genre_name||channel.genre_name||"MAG"),
      channelId:magChannelId(channel),
      number:String(channel.number||"")
    });
  }
  return records;
}

async function handleSources(request, env, url, method) {
  // XTREAM_MAG_ROUTES_V1

  if (method === "POST" && url.pathname === "/admin/sources/xtream/categories") {
    try {
      const body=await readJson(request);
      if(!body) return json({ok:false,error:"Invalid JSON"},400);
      return json({ok:true,categories:await handleXtreamCategories(body)});
    } catch(e) {
      return json({ok:false,error:String(e.message||"Xtream category request failed")},502);
    }
  }
  if (method === "POST" && url.pathname === "/admin/sources/xtream/import-url") {
    try {
      const body = await readJson(request);
      if (!body) return json({ok:false,error:"Invalid JSON"},400);
      const items = await handleXtreamImportFromUrl(body);
      return json({ok:true,count:items.length,items});
    } catch(e) {
      return json({ok:false,error:String(e.message||"Xtream URL import failed")},502);
    }
  }

  if (method === "POST" && url.pathname === "/admin/sources/xtream/import-part") {
    try {
      const body = await readJson(request);
      if (!body) return json({ok:false,error:"Invalid JSON"},400);
      const result = await handleXtreamImportPart(body);
      return json({ok:true,...result});
    } catch(e) {
      return json({ok:false,error:String(e.message || "Xtream batch import failed")},502);
    }
  }

  if (method === "POST" && url.pathname === "/admin/sources/xtream/import") {
    try {
      const body=await readJson(request);
      if(!body) return json({ok:false,error:"Invalid JSON"},400);
      const items=await handleXtreamImport(body);
      return json({ok:true,count:items.length,items});
    } catch(e) {
      return json({ok:false,error:String(e.message||"Xtream import failed")},502);
    }
  }
  if (method === "POST" && url.pathname === "/admin/sources/mag/categories") {
    try {
      const body=await readJson(request);
      if(!body) return json({ok:false,error:"Invalid JSON"},400);
      return json({ok:true,categories:await handleMagCategories(body)});
    } catch(e) {
      return json({ok:false,error:String(e.message||"MAG category request failed")},502);
    }
  }
  if (method === "POST" && url.pathname === "/admin/sources/mag/channels") {
    try {
      const body=await readJson(request);
      if(!body) return json({ok:false,error:"Invalid JSON"},400);
      return json({ok:true,items:await handleMagChannels(body)});
    } catch(e) {
      return json({ok:false,error:String(e.message||"MAG channel request failed")},502);
    }
  }
  if (method === "POST" && url.pathname === "/admin/sources/mag/import") {
    try {
      const body=await readJson(request);
      if(!body) return json({ok:false,error:"Invalid JSON"},400);
      const items=await handleMagImport(body);
      return json({ok:true,count:items.length,items});
    } catch(e) {
      return json({ok:false,error:String(e.message||"MAG import failed")},502);
    }
  }

  if (method === "GET" && url.pathname === "/admin/sources") {
    try {
      const current = await sourceGetCurrent(env);
      const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 100)));
      const records = await sourceReadRecords(env, current);
      return json({
        ok: true,
        generation: current.manifest.generation,
        total: records.length,
        offset,
        items: records.slice(offset, offset + limit)
      });
    } catch {
      return json({ ok: false, error: "Source repository could not be read" }, 502);
    }
  }

  if (method === "POST" && url.pathname === "/admin/sources/begin") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const expectedParts = Number(body.expectedParts);
    const sourceCount = Number(body.sourceCount);
    if (!Number.isInteger(expectedParts) || expectedParts < 1 || expectedParts > 500 ||
        !Number.isInteger(sourceCount) || sourceCount < 0 || sourceCount > 1000000) {
      return json({ ok: false, error: "Invalid upload metadata" }, 400);
    }

    const generation = crypto.randomUUID().replace(/-/g, "");
    try {
      await sourceWrite(env, `${SOURCE_ROOT}/uploads/${generation}/meta.json`, {
        generation, expectedParts, sourceCount,
        createdAt: new Date().toISOString()
      }, "Begin source upload");
      return json({ ok: true, generation, expectedParts });
    } catch {
      return json({ ok: false, error: "Could not begin source upload" }, 502);
    }
  }

  if (method === "PUT" && url.pathname === "/admin/sources/chunk") {
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400);

    const generation = String(body.generation || "");
    const index = Number(body.index);
    const contentBase64 = String(body.contentBase64 || "");
    if (!/^[a-f0-9]{32}$/.test(generation) ||
        !Number.isInteger(index) || index < 0 || index >= 500 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(contentBase64) ||
        Math.floor(contentBase64.length * 3 / 4) > SOURCE_PART_LIMIT) {
      return json({ ok: false, error: "Invalid source chunk" }, 400);
    }

    try {
      const meta = await sourceRead(env, `${SOURCE_ROOT}/uploads/${generation}/meta.json`);
      if (index >= meta.expectedParts) {
        return json({ ok: false, error: "Chunk index out of range" }, 400);
      }
      const raw = decoder.decode(Uint8Array.from(
        atob(contentBase64), c => c.charCodeAt(0)
      ));
      const rows = JSON.parse(raw);
      if (!Array.isArray(rows)) throw new Error("Chunk must contain an array");

      await sourceWrite(
        env,
        `${SOURCE_ROOT}/uploads/${generation}/part-${String(index).padStart(5, "0")}.json`,
        raw,
        "Upload source chunk"
      );
      return json({ ok: true, generation, index, count: rows.length });
    } catch {
      return json({ ok: false, error: "Source chunk upload failed" }, 502);
    }
  }

  if (method === "POST" && url.pathname === "/admin/sources/complete") {
    const body = await readJson(request);
    const generation = String(body?.generation || "");
    if (!/^[a-f0-9]{32}$/.test(generation)) {
      return json({ ok: false, error: "Invalid generation" }, 400);
    }

    try {
      const meta = await sourceRead(env, `${SOURCE_ROOT}/uploads/${generation}/meta.json`);
      const base = `${SOURCE_ROOT}/uploads/${generation}`;
      const parts = [];
      let total = 0;

      for (let i = 0; i < meta.expectedParts; i++) {
        const name = `part-${String(i).padStart(5, "0")}.json`;
        const rows = await sourceRead(env, `${base}/${name}`);
        if (!Array.isArray(rows)) throw new Error("Invalid part");
        total += rows.length;
        parts.push(name);
      }

      if (total !== meta.sourceCount) {
        return json({ ok: false, error: "Source count does not match", expected: meta.sourceCount, actual: total }, 409);
      }

      const manifest = {
        generation, parts, count: total,
        createdAt: new Date().toISOString()
      };
      const finalBase = `${SOURCE_ROOT}/generations/${generation}`;

      for (const name of parts) {
        const rows = await sourceRead(env, `${base}/${name}`);
        await sourceWrite(env, `${finalBase}/${name}`, rows, "Copy verified source part");
      }

      await sourceWrite(env, `${finalBase}/manifest.json`, manifest, "Publish verified source manifest");
      await sourceWrite(
        env, `${SOURCE_ROOT}/current.json`,
        { generation, updatedAt: new Date().toISOString() },
        "Activate verified source generation"
      );

      await audit(env, "sources_generation_published", generation, { count: total });
      return json({ ok: true, generation, count: total });
    } catch {
      return json({ ok: false, error: "Upload verification or publication failed" }, 502);
    }
  }

  if (method === "POST" && url.pathname === "/admin/sources/delete-all") {
    try {
      const current = await sourceGetCurrent(env);
      const records = await sourceReadRecords(env, current);
      const removed = records.length;

      if (!removed) {
        return json({ ok: true, deleted: 0, total: 0 });
      }

      const manifest = await sourcePublishRecords(env, []);
      await audit(env, "sources_all_deleted", manifest.generation, {
        deleted: removed
      });

      return json({
        ok: true,
        deleted: removed,
        total: 0,
        generation: manifest.generation
      });
    } catch (error) {
      return json({
        ok: false,
        error: "All source deletion failed"
      }, 502);
    }
  }

  if (method === "POST" && url.pathname === "/admin/sources/delete") {
    const body = await readJson(request);
    const ids = Array.isArray(body?.ids)
      ? [...new Set(body.ids.map(x => String(x)).filter(x => x && x.length <= 200))]
      : [];

    if (!ids.length) return json({ ok: false, error: "No source selected" }, 400);
    if (ids.length > 10000) return json({ ok: false, error: "Too many selected sources" }, 400);

    try {
      const current = await sourceGetCurrent(env);
      const records = await sourceReadRecords(env, current);
      const selected = new Set(ids);
      const kept = records.filter(row => !selected.has(String(row.id || "")));
      const removed = records.length - kept.length;

      if (!removed) return json({ ok: true, deleted: 0, total: records.length });

      const manifest = await sourcePublishRecords(env, kept);
      await audit(env, "sources_selected_deleted", manifest.generation, { deleted: removed });
      return json({ ok: true, deleted: removed, total: kept.length, generation: manifest.generation });
    } catch {
      return json({ ok: false, error: "Selected source deletion failed" }, 502);
    }
  }

  return json({ ok: false, error: "Source endpoint not found" }, 404);
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
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Vary": "Origin"
    };

    if (allowOrigin) cors["Access-Control-Allow-Origin"] = allowOrigin;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      if (path === "/health" && method === "GET") {
        return json({
          ok: true,
          version: "1.0.0",
          service: "admin-control-service"
        }, 200, cors);
      }

      if (path === "/auth/admin/login" && method === "POST") {
        const response = await handleAdminLogin(request, env);
        const headers = new Headers(response.headers);
        for (const [key, value] of Object.entries(cors)) {
          headers.set(key, value);
        }
        return new Response(response.body, {
          status: response.status,
          headers
        });
      }

      if (path.startsWith("/admin/")) {
        const admin = await adminAuth(request, env);

        if (!admin) {
          return json({ ok: false, error: "Unauthorized" }, 401, cors);
        }

        const response = path.startsWith("/admin/github/")
          ? await handleGithub(request, env, url, method)
          : (path === "/admin/sources" || path.startsWith("/admin/sources/"))
            ? await handleSources(request, env, url, method)
            : await handleAdmin(request, env, path, method);

        const headers = new Headers(response.headers);
        for (const [key, value] of Object.entries(cors)) {
          headers.set(key, value);
        }

        return new Response(response.body, {
          status: response.status,
          headers
        });
      }

      return json({ ok: false, error: "Not found" }, 404, cors);
    } catch (error) {
      console.error("ADMIN_WORKER_ERROR", JSON.stringify({
        path,
        method,
        name: error?.name || "Error",
        message: String(error?.message || error).slice(0, 500)
      }));

      return json({
        ok: false,
        error: "Internal server error"
      }, 500, cors);
    }
  }
};

