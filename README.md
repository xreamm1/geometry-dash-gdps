# Xreamm GDPS

A small, independently operated Geometry Dash private server (GDPS) backend. It is separate from RobTop's official servers and stores content only in this project's D1 database. It does not proxy official traffic or use official account credentials.

## Current scope

Implemented in this first server slice:

- Cloudflare Worker + D1 schema.
- Health endpoint.
- Optional account creation and Geometry Dash login using the documented GJP2 credential format. Passwords are not stored; account email is accepted by the old game endpoint but discarded.
- Search, upload, update and download for user levels using the game's form-encoded endpoint format.
- CORS allowlist, body/level size limits, fixed query bounds, prepared D1 statements, and per-IP mutation/login rate limits.

Not implemented: the rest of the GD server API (comments, ratings, lists, songs, cloud saves, social features, leaderboards, rewards, moderation UI, multiplayer). This is a prototype GDPS core, not full server compatibility. It is not connected to the browser game client yet.

## Deploy on Cloudflare

Requirements: Node.js 20+, a Cloudflare account, Wrangler login, and a D1 database. Never commit API tokens or account credentials.

1. Install dependencies: `npm ci`.
2. Create D1: `npx wrangler d1 create xreamm1-geometry-dash-gdps`.
3. Put the returned database ID into `wrangler.toml`.
4. Add a random private salt: `npx wrangler secret put RATE_LIMIT_SALT`.
5. Apply schema: `npm run db:remote`.
6. Set `REGISTRATION_OPEN=true` only when ready to accept players and moderate uploads. Keep it `false` while configuring.
7. Deploy: `npm run deploy`.
8. Confirm `https://<worker>.workers.dev/health` returns JSON with `status: "ok"`.

The static status/account page can be hosted on GitHub Pages. Add its exact origin to `ALLOWED_ORIGINS` before deployment. A GitHub Pages site cannot host or execute this backend itself.

## Local development

`npm run dev` starts a local Worker. Apply the local D1 migration with `npm run db:local`. Use a separate local origin listed in `ALLOWED_ORIGINS` for frontend testing.

## Endpoint status

| Endpoint | Status |
| --- | --- |
| `GET /health` | Implemented |
| `POST /api/register` | Implemented; closed unless `REGISTRATION_OPEN=true` |
| `POST /database/accounts/loginGJAccount.php` | Implemented |
| `POST /database/accounts/registerGJAccount.php` | Implemented; gated and rate-limited |
| `POST /database/getGJLevels21.php` | Partial search: name, recent, popular, creator, basic difficulty/length |
| `POST /database/uploadGJLevel21.php` | Implemented for create/update of own levels |
| `POST /database/downloadGJLevel22.php` | Implemented |

An unsupported endpoint returns `-1`/404. The browser client must be explicitly configured to use this GDPS URL; there is no automatic redirect to RobTop or any other server.

## Data and security notes

- User-generated levels are public to all users of this GDPS.
- Registration is closed by default. Open it only when moderation and abuse handling are ready.
- The server never stores email addresses, the original password, or the reusable GJP2 credential. It stores a random per-account salt and a PBKDF2-SHA-256 digest derived from the credential. The GJP2 credential must still be transmitted only over HTTPS.
- D1 rate limits are per Cloudflare-observed IP; request IPs are stored only as a salted SHA-1 key, not in plain text. Set `RATE_LIMIT_SALT` before production.
- This project does not fetch from, tunnel to, or modify RobTop's servers.

## Protocol references

Endpoint and response layouts are based on the public community protocol documentation at [GD Docs](https://boomlings.dev/). The implementation is independent and does not include game binaries, assets, or level payloads.

## License

This project's original source is MIT licensed. Any game protocol names remain the property of their respective owners. This project is unofficial and not affiliated with RobTop Games.

