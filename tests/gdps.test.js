import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Miniflare } from "miniflare";

const migration = await readFile(new URL("../migrations/0001_init.sql", import.meta.url), "utf8");
const mf = new Miniflare({
  modules: true,
  scriptPath: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/index.js"),
  d1Databases: { DB: "gdps-integration" },
  bindings: {
    REGISTRATION_OPEN: "true",
    ALLOWED_ORIGINS: "https://game.example,http://localhost:8080",
    RATE_LIMIT_SALT: "test-only-random-salt",
  },
});
const db = await mf.getD1Database("DB");
await db.batch(migration.split(";").map((sql) => sql.trim()).filter(Boolean).map((sql) => db.prepare(sql)));
const base = "http://localhost";
const serverSecret = "Wmfd2893gb7";
const accountSecret = "Wmfv3899gc9";

function form(values) {
  return new URLSearchParams(values).toString();
}

async function register(username, password) {
  const raw = new TextEncoder().encode(password + "mI29fmAnxgTs");
  const hash = await crypto.subtle.digest("SHA-1", raw);
  const gjp2 = [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const response = await mf.dispatchFetch(`${base}/api/register`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://game.example" },
    body: JSON.stringify({ username, gjp2 }),
  });
  return { response, gjp2 };
}

test("health is available and reports the registration gate", async () => {
  const response = await mf.dispatchFetch(`${base}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok", service: "geometry-dash-gdps", registrationOpen: true });
});

test("CORS only grants the configured game origin", async () => {
  const allowed = await mf.dispatchFetch(`${base}/health`, { headers: { origin: "https://game.example" } });
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://game.example");
  const denied = await mf.dispatchFetch(`${base}/health`, { headers: { origin: "https://evil.example" } });
  assert.equal(denied.headers.get("access-control-allow-origin"), null);
});

test("register, login, upload, search, and download round trip", async () => {
  const { response: created, gjp2 } = await register("DashTester", "local-test-password");
  assert.equal(created.status, 200);
  assert.equal(created.headers.get("access-control-allow-origin"), "https://game.example");
  assert.deepEqual(await created.json(), { created: true });
  const stored = await db.prepare("SELECT password_hash, password_salt FROM users WHERE username = ?").bind("DashTester").first();
  assert.notEqual(stored.password_hash, gjp2);
  assert.equal(stored.password_salt.length, 32);

  const login = await mf.dispatchFetch(`${base}/database/accounts/loginGJAccount.php`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ userName: "DashTester", gjp2, secret: accountSecret, udid: "test-device" }),
  });
  assert.equal(await login.text(), "1,1");

  const upload = await mf.dispatchFetch(`${base}/database/uploadGJLevel21.php`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({
      secret: serverSecret, accountID: "1", gjp2,
      levelName: "Test level", levelDesc: "VGVzdCBkZXNj", levelString: "QUJDREVGR0g=",
      levelLength: "2", objects: "25", songID: "0", audioTrack: "1", coins: "0", password: "0",
    }),
  });
  const levelId = await upload.text();
  assert.equal(levelId, "1");

  const search = await mf.dispatchFetch(`${base}/database/getGJLevels21.php`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ secret: serverSecret, type: "4", page: "0", str: "" }),
  });
  const searchBody = await search.text();
  assert.match(searchBody, /^1:1:2:Test level:3:VGVzdCBkZXNj/);
  assert.match(searchBody, /#1:DashTester:1##1:0:1#[a-f0-9]{40}$/);

  const download = await mf.dispatchFetch(`${base}/database/downloadGJLevel22.php`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ secret: serverSecret, levelID: levelId }),
  });
  const downloaded = await download.text();
  assert.match(downloaded, /:4:QUJDREVGR0g=/);
  assert.match(downloaded, /#[a-f0-9]{40}#[a-f0-9]{40}$/);

  const longLevel = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
  await db.prepare("UPDATE levels SET level_string = ? WHERE id = 1").bind(longLevel).run();
  const longDownload = await mf.dispatchFetch(`${base}/database/downloadGJLevel22.php`, {
    method: "POST", body: form({ secret: serverSecret, levelID: "1" }),
  });
  const longHash = (await longDownload.text()).split("#")[1];
  let sample = "?".repeat(40);
  const stride = Math.floor(longLevel.length / 40);
  for (let i = 39; i >= 0; i--) sample = sample.slice(0, i) + longLevel[i * stride] + sample.slice(i + 1);
  const expected = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(`${sample}xI25fpAapCQg`));
  const expectedHex = [...new Uint8Array(expected)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  assert.equal(longHash, expectedHex);
});

test("invalid server secrets and invalid accounts are rejected", async () => {
  const badSecret = await mf.dispatchFetch(`${base}/database/getGJLevels21.php`, {
    method: "POST", body: form({ secret: "wrong", type: "4" }),
  });
  assert.equal(await badSecret.text(), "-1");
  const badLogin = await mf.dispatchFetch(`${base}/database/accounts/loginGJAccount.php`, {
    method: "POST", body: form({ userName: "missing", gjp2: "0".repeat(40), secret: accountSecret }),
  });
  assert.equal(await badLogin.text(), "-11");
});

test("duplicate account registration is rejected", async () => {
  const { gjp2 } = await register("OneUser", "another-password");
  const duplicate = await mf.dispatchFetch(`${base}/api/register`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "oneuser", gjp2 }),
  });
  assert.equal(duplicate.status, 409);
});

test("browser registration rejects an unlisted Origin", async () => {
  const response = await mf.dispatchFetch(`${base}/api/register`, {
    method: "POST", headers: { "content-type": "application/json", origin: "https://outside.example" },
    body: JSON.stringify({ username: "NopeUser", gjp2: "0".repeat(40) }),
  });
  assert.equal(response.status, 403);
});

test.after(async () => { await mf.dispose(); });



