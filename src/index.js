const SERVER_SECRET = "Wmfd2893gb7";
const ACCOUNT_SECRET = "Wmfv3899gc9";
const HASH_SALT = "xI25fpAapCQg";
const GJP2_SALT = "mI29fmAnxgTs";
const MAX_BODY_BYTES = 1_000_000;
const MAX_LEVEL_BYTES = 700_000;

const reply = (body, status = 200, headers = {}) => new Response(body, {
  status,
  headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", ...headers },
});

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean);
  if (!origin || !allowed.includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "POST, GET, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "access-control-max-age": "86400",
    "vary": "Origin",
  };
}

async function readForm(request) {
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared > MAX_BODY_BYTES) throw new RangeError("body-too-large");
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength > MAX_BODY_BYTES) throw new RangeError("body-too-large");
  const params = new URLSearchParams(new TextDecoder().decode(bytes));
  return Object.fromEntries(params.entries());
}

function safeText(value, max = 80) {
  return String(value ?? "").replace(/[|:#\u0000-\u001f]/g, " ").trim().slice(0, max);
}

function intParam(form, key, fallback = 0, min = 0, max = 2_147_483_647) {
  const value = form[key];
  if (value == null || value === "") return fallback;
  if (!/^-?\d{1,10}$/.test(value)) return fallback;
  return Math.max(min, Math.min(max, Number(value)));
}

function decodeBase64(value) {
  try {
    const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0)));
  } catch {
    return "";
  }
}

function encodeBase64(value) {
  const bytes = new TextEncoder().encode(String(value));
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

async function sha1(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function constantTimeEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  let diff = a.length ^ b.length;
  const size = Math.max(a.length, b.length);
  for (let i = 0; i < size; i++) diff |= (a[i] || 0) ^ (b[i] || 0);
  return diff === 0;
}

function validGjp2(value) {
  return /^[a-f0-9]{40}$/i.test(String(value || ""));
}

function randomSalt() {
  return [...crypto.getRandomValues(new Uint8Array(16))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function passwordDigest(gjp2, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(gjp2), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100_000, hash: "SHA-256" }, key, 256);
  return [...new Uint8Array(bits)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function rateLimit(request, env, action, maximum, intervalMs = 60_000) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const keyHash = await sha1(`${env.RATE_LIMIT_SALT || "local-only"}:${action}:${ip}`);
  const now = Date.now();
  const windowStart = Math.floor(now / intervalMs) * intervalMs;
  const row = await env.DB.prepare(`
    INSERT INTO rate_limits (key_hash, window_start, request_count)
    VALUES (?, ?, 1)
    ON CONFLICT(key_hash) DO UPDATE SET
      request_count = CASE WHEN rate_limits.window_start < excluded.window_start THEN 1 ELSE rate_limits.request_count + 1 END,
      window_start = excluded.window_start
    RETURNING request_count
  `).bind(keyHash, windowStart).first();
  if (Number(row?.request_count || 0) > maximum) return false;
  return true;
}

async function authenticatedUser(form, env) {
  const accountID = intParam(form, "accountID", -1, 1);
  const gjp2 = form.gjp2 || "";
  if (accountID < 1 || !validGjp2(gjp2)) return null;
  const user = await env.DB.prepare("SELECT id, username, password_hash, password_salt FROM users WHERE id = ?")
    .bind(accountID).first();
  if (!user || !(await constantTimeEqual(user.password_hash, await passwordDigest(gjp2, user.password_salt)))) return null;
  return user;
}

function levelFields(level, includeString = false) {
  const values = [
    "1", level.id,
    "2", safeText(level.name, 100),
    "3", encodeBase64(level.description),
  ];
  if (includeString) values.push("4", level.level_string);
  values.push(
    "5", level.version,
    "6", level.creator_id,
    "8", 10,
    "9", level.difficulty,
    "10", level.downloads,
    "11", 1,
    "12", level.audio_track,
    "13", 22,
    "14", level.likes,
    "17", level.demon,
    "43", level.demon_difficulty,
    "25", level.auto,
    "18", level.stars,
    "19", level.featured,
    "42", level.epic,
    "45", Math.min(65535, level.object_count),
    "15", level.length,
    "30", level.original_id,
    "31", level.two_player,
    "28", "now",
    "29", "now",
    "35", level.song_id,
    "36", 0,
    "37", level.coins,
    "38", level.verified_coins,
    "39", 0,
    "40", level.ldm,
    "27", level.copy_password,
  );
  return values.join(":");
}

async function levelsHash(levels) {
  let value = "";
  for (const level of levels) {
    const id = String(level.id);
    value += `${id[0]}${id.at(-1)}${level.stars}${level.verified_coins ? 1 : 0}`;
  }
  return sha1(value + HASH_SALT);
}

async function searchLevels(form, env) {
  if (form.secret !== SERVER_SECRET) return reply("-1");
  const type = intParam(form, "type", 2, 0, 34);
  const page = intParam(form, "page", 0, 0, 100_000);
  const query = safeText(form.str, 100);
  const conditions = [];
  const params = [];
  if (type === 0 && query) {
    conditions.push("l.name LIKE ? COLLATE NOCASE");
    params.push(`%${query}%`);
  } else if (type === 5) {
    const userId = intParam(form, "str", -1, 1);
    if (userId < 1) return reply("-1");
    conditions.push("l.creator_id = ?");
    params.push(userId);
  }
  const diff = String(form.diff || "-");
  if (diff && diff !== "-") {
    const diffValues = diff.split(",").map((item) => Number(item)).filter((item) => Number.isInteger(item) && item >= -3 && item <= 10);
    if (diffValues.length) {
      conditions.push(`l.difficulty IN (${diffValues.map(() => "?").join(",")})`);
      params.push(...diffValues);
    }
  }
  const length = intParam(form, "len", -1, -1, 5);
  if (length >= 0) {
    conditions.push("l.length = ?");
    params.push(length);
  }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const count = await env.DB.prepare(`SELECT COUNT(*) AS n FROM levels l ${where}`).bind(...params).first();
  let order = "l.uploaded_at DESC, l.id DESC";
  if (type === 1) order = "l.downloads DESC, l.id DESC";
  if (type === 2) order = "l.likes DESC, l.id DESC";
  const rows = await env.DB.prepare(`
    SELECT l.*, u.username AS creator_name FROM levels l
    JOIN users u ON u.id = l.creator_id ${where}
    ORDER BY ${order} LIMIT 10 OFFSET ?
  `).bind(...params, page * 10).all();
  const levels = rows.results || [];
  if (!levels.length) return reply("-1");
  const objects = levels.map((level) => levelFields(level)).join("|");
  const creatorMap = new Map(levels.map((level) => [level.creator_id, `${level.creator_id}:${safeText(level.creator_name, 20)}:${level.creator_id}`]));
  const creators = [...creatorMap.values()].join("|");
  const offset = page * 10;
  const result = `${objects}#${creators}##${Number(count?.n || 0)}:${offset}:${levels.length}#${await levelsHash(levels)}`;
  return reply(result);
}

async function downloadLevelHash(levelString) {
  if (levelString.length < 41) return sha1(`${levelString}${HASH_SALT}`);
  const step = Math.floor(levelString.length / 40);
  let sample = "?".repeat(40);
  for (let i = 39; i >= 0; i--) sample = sample.slice(0, i) + levelString[i * step] + sample.slice(i + 1);
  return sha1(`${sample}${HASH_SALT}`);
}

function copyPasswordHashValue(value) {
  const password = Number(value || 0);
  if (!Number.isSafeInteger(password) || password <= 1) return Math.max(0, password || 0);
  return password < 1_000_000 ? password + 1_000_000 : password;
}

async function downloadLevel(form, env) {
  if (form.secret !== SERVER_SECRET) return reply("-1");
  const id = intParam(form, "levelID", -1, 1);
  if (id < 1) return reply("-1");
  const level = await env.DB.prepare(`
    SELECT l.*, u.username AS creator_name FROM levels l JOIN users u ON u.id = l.creator_id WHERE l.id = ?
  `).bind(id).first();
  if (!level) return reply("-1");
  const details = levelFields(level, true);
  const hash1 = await downloadLevelHash(level.level_string);
  const hash2 = await sha1(`${level.creator_id}${level.stars}${level.demon ? 1 : 0}${level.id}${level.verified_coins ? 1 : 0}${level.featured}${copyPasswordHashValue(level.copy_password)}0${HASH_SALT}`);
  await env.DB.prepare("UPDATE levels SET downloads = downloads + 1 WHERE id = ?").bind(id).run();
  return reply(`${details}#${hash1}#${hash2}`);
}

async function createAccount(form, request, env) {
  if (form.secret !== ACCOUNT_SECRET || env.REGISTRATION_OPEN !== "true") return reply("-1");
  if (!(await rateLimit(request, env, "register", 4))) return reply("-1", 429);
  const username = safeText(form.userName, 20);
  const gjp2 = String(form.password || "");
  if (username.length < 3) return reply("-9");
  if (username.length > 20) return reply("-4");
  if (!validGjp2(gjp2)) return reply("-5");
  const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
  if (existing) return reply("-2");
  const salt = randomSalt();
  const passwordHash = await passwordDigest(gjp2, salt);
  try {
    await env.DB.prepare("INSERT INTO users (username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)")
      .bind(username, passwordHash, salt, Math.floor(Date.now() / 1000)).run();
  } catch {
    return reply("-1");
  }
  return reply("1");
}

async function loginAccount(form, request, env) {
  if (form.secret !== ACCOUNT_SECRET) return reply("-1");
  if (!(await rateLimit(request, env, "login", 12))) return reply("-1", 429);
  const username = safeText(form.userName, 20);
  const gjp2 = String(form.gjp2 || "");
  if (username.length < 3) return reply("-9");
  if (!validGjp2(gjp2)) return reply("-11");
  const user = await env.DB.prepare("SELECT id, username, password_hash, password_salt FROM users WHERE username = ? COLLATE NOCASE")
    .bind(username).first();
  if (!user || !(await constantTimeEqual(user.password_hash, await passwordDigest(gjp2, user.password_salt)))) return reply("-11");
  return reply(`${user.id},${user.id}`);
}

async function uploadLevel(form, request, env) {
  if (form.secret !== SERVER_SECRET) return reply("-1");
  if (!(await rateLimit(request, env, "upload", 10))) return reply("-1", 429);
  const user = await authenticatedUser(form, env);
  if (!user) return reply("-1");
  const levelString = String(form.levelString || "");
  if (!levelString || new TextEncoder().encode(levelString).byteLength > MAX_LEVEL_BYTES) return reply("-1");
  if (!/^[A-Za-z0-9+/_=-]+$/.test(levelString)) return reply("-1");
  const name = safeText(form.levelName, 100);
  if (!name) return reply("-1");
  const description = decodeBase64(form.levelDesc || "").slice(0, 250);
  const levelId = intParam(form, "levelID", 0, 0);
  const now = Math.floor(Date.now() / 1000);
  const columns = [
    safeText(form.levelLength, 10), safeText(form.objects, 8), safeText(form.songID, 10),
    safeText(form.audioTrack, 10), safeText(form.coins, 2), safeText(form.password, 12),
  ];
  const [length, objects, songID, audioTrack, coins, copyPassword] = columns.map((value, index) => {
    const parsed = Number(value || 0);
    return Number.isInteger(parsed) && parsed >= 0 ? Math.min(parsed, index === 1 ? 1_000_000 : 1_000_000_000) : 0;
  });
  if (levelId > 0) {
    const existing = await env.DB.prepare("SELECT creator_id FROM levels WHERE id = ?").bind(levelId).first();
    if (!existing || existing.creator_id !== user.id) return reply("-1");
    await env.DB.prepare(`UPDATE levels SET name=?, description=?, level_string=?, version=version+1,
      length=?, object_count=?, song_id=?, audio_track=?, coins=?, copy_password=?, updated_at=? WHERE id=?`)
      .bind(name, description, levelString, length, objects, songID, audioTrack, coins, copyPassword, now, levelId).run();
    return reply(String(levelId));
  }
  const result = await env.DB.prepare(`INSERT INTO levels
    (name, description, level_string, creator_id, length, object_count, song_id, audio_track, coins, copy_password, uploaded_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(name, description, levelString, user.id, length, objects, songID, audioTrack, coins, copyPassword, now, now).run();
  return reply(String(result.meta?.last_row_id || "-1"));
}

async function apiRegister(request, env, headers) {
  if (env.REGISTRATION_OPEN !== "true") return Response.json({ error: "registration_closed" }, { status: 403, headers });
  if (!(await rateLimit(request, env, "register", 4))) return Response.json({ error: "rate_limited" }, { status: 429, headers });
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared > MAX_BODY_BYTES) return Response.json({ error: "body_too_large" }, { status: 413, headers });
  let body;
  try {
    const bytes = await request.arrayBuffer();
    if (bytes.byteLength > MAX_BODY_BYTES) return Response.json({ error: "body_too_large" }, { status: 413, headers });
    body = JSON.parse(new TextDecoder().decode(bytes));
  } catch { return Response.json({ error: "invalid_json" }, { status: 400, headers }); }
  const username = safeText(body.username, 20);
  const credential = String(body.gjp2 || "");
  if (username.length < 3 || !validGjp2(credential)) return Response.json({ error: "invalid_fields" }, { status: 400, headers });
  const exists = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
  if (exists) return Response.json({ error: "username_taken" }, { status: 409, headers });
  const salt = randomSalt();
  const passwordHash = await passwordDigest(credential, salt);
  try {
    await env.DB.prepare("INSERT INTO users (username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)")
      .bind(username, passwordHash, salt, Math.floor(Date.now() / 1000)).run();
  } catch { return Response.json({ error: "registration_failed" }, { status: 400, headers }); }
  return Response.json({ created: true }, { headers });
}

export default {
  async fetch(request, env) {
    const headers = corsHeaders(request, env);
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (url.pathname === "/health" && request.method === "GET") {
      return Response.json({ status: "ok", service: "geometry-dash-gdps", registrationOpen: env.REGISTRATION_OPEN === "true" }, { headers });
    }
    if (url.pathname === "/api/register" && request.method === "POST") {
      const origin = request.headers.get("Origin");
      const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean);
      if (origin && !allowed.includes(origin)) return Response.json({ error: "origin_not_allowed" }, { status: 403 });
      return apiRegister(request, env, headers);
    }
    if (!url.pathname.startsWith("/database/") || request.method !== "POST") return reply("-1", 404, headers);
    let form;
    try { form = await readForm(request); }
    catch (error) { return reply(error instanceof RangeError ? "-1" : "-1", error instanceof RangeError ? 413 : 400, headers); }
    try {
      let response;
      switch (url.pathname) {
        case "/database/getGJLevels21.php": response = await searchLevels(form, env); break;
        case "/database/downloadGJLevel22.php": response = await downloadLevel(form, env); break;
        case "/database/uploadGJLevel21.php": response = await uploadLevel(form, request, env); break;
        case "/database/accounts/loginGJAccount.php": response = await loginAccount(form, request, env); break;
        case "/database/accounts/registerGJAccount.php": response = await createAccount(form, request, env); break;
        default: response = reply("-1", 404);
      }
      const merged = new Headers(response.headers);
      for (const [key, value] of Object.entries(headers)) merged.set(key, value);
      return new Response(response.body, { status: response.status, headers: merged });
    } catch (error) {
      console.error("GDPS request failed", { path: url.pathname, error: String(error) });
      return reply("-1", 500, headers);
    }
  },
};

export { decodeBase64, encodeBase64, levelFields, levelsHash, safeText, validGjp2 };

