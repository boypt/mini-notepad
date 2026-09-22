# AGENTS.md

Web Notepad on Cloudflare Workers + D1. One Worker, one D1 database, one Cron
Trigger. No runtime dependencies; `wrangler` is the only dev dependency.

## Repo shape

- `src/index.js` is the entire app (~1150 lines). It holds the router
  (`export default.fetch`), the `scheduled` GC handler, the D1 store, the zstd
  codec, and the whole HTML/CSS/editor as one template literal returned by
  `renderPage(id, text, meta)`. There is no bundler, framework, or separate
  frontend — editing the UI means editing that template string.
- The inline browser JS in `renderPage` is deliberately ES5 (`var`, function
  declarations) for old-browser support. Don't modernize it.
- Inside that template literal, client-side backticks and `${...}` must be
  escaped, or they will break the Worker at parse time.
- `migrations/0001_init.sql` is the only migration. `public/` is Workers Static
  Assets; requests that don't match a file fall through to the Worker.
- `README.md` (usage) and `DEPLOY.md` (full production guide) are authoritative.

## Verify changes

- There is **no test runner** (`npm test` does not exist). Minimum check:
  `node --check src/index.js`, then run the smoke test below or DEPLOY.md §9
  against a running Worker.
- Helpers are exported specifically so they can be imported and exercised by
  plain Node: `randomNoteId`, `compress`, `encodeForStorage`,
  `resolveExpiryToken`, `parseExpiryDuration`, `decompress`, `renderPage`.

## Commands

```sh
npm run db:migrate:local   # apply migrations to the local D1
npm run dev                # local server, http://127.0.0.1:8787
npm run db:migrate         # apply migrations to the remote D1
npm run deploy             # wrangler deploy
npm run db:gc              # one-off remote GC of expired notes
```

## Deploy gotchas

- `wrangler.toml` intentionally commits
  `database_id = "REPLACE_WITH_YOUR_DATABASE_ID"`. The real id is
  account-specific: set it locally to deploy, then restore the placeholder.
  Never commit a real id.
- Keep `compatibility_flags = ["nodejs_compat"]` and a `compatibility_date`
  of `2024-09-23` or newer. zstd comes from `node:zlib`; the Workers
  `CompressionStream` API has no zstd.
- Browser form saves require the per-note CSRF token (blind POST → 403). Raw
  CLI writes are limited to the `curl`/`wget` user agents. `CSRF_SECRET`
  overrides the built-in dev fallback.

## Conventions

- README.md and DEPLOY.md are written on purpose in short, simple "Easy
  English". Match that style when editing docs.
- The product is "Web Notepad (Cloudflare Workers Mod)", Worker `web-notepad`.
  Do not reintroduce the old `minimalist-web-notepad` name.
- Only commit or deploy when the user explicitly asks.

## Storage

- Bodies under 128 bytes are stored as `identity`; larger bodies use zstd.
  `decompress` also reads `gzip`/`identity`, so codec or rollback changes need
  no backfill.
- `is_protected` / `password_hash` / `password_salt` / `password_algo` columns
  enforce the password lock (`POST /:note/password`, PBKDF2-SHA256, 100k
  rounds). Reads take `X-Note-Password` or `?pw=`; writes take only the
  header; a bad or missing password returns 401. A write to an unprotected
  note can set the password in one step (raw header or form `new`); on a
  locked note form `new` returns 400.

## HTTP behavior

- A note ID may be any length and uses only `a-z`, `A-Z`, `0-9`, `_`, and `-`
  (`NOTE_ID_RE`). A browser `GET /` and a CLI `POST /` generate a 5-character
  ID from the unambiguous alphabet `234579abcdefghjkmnpqrstwxyz`.
- A browser form save needs the per-note CSRF token (blind POST → 403). Raw CLI
  writes are limited to the `curl`/`wget` user agents; on GET they receive the
  raw body instead of the HTML editor.
- Every response sets `Cache-Control: no-store` and
  `X-Robots-Tag: noindex, nofollow`.
- A form save and `POST /:note/expire` return JSON
  `{ created_at, updated_at, expires_at }` (`expires_at` may be `null`). An
  empty `text` delete returns `{ "deleted": true }`. A password change returns
  `{ protected, updated_at }`. CLI writes get a plain-text
  receipt instead. An unknown file suffix (for example `/index.jsp`) returns
  `400`.

## Smoke test

```sh
BASE=http://127.0.0.1:8787

curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "$BASE/"
echo hello | curl --data-binary @- "$BASE/"          # new random ID; receipt shows it
echo hello | curl --data-binary @- "$BASE/cli-test"
curl "$BASE/cli-test"            # hello
curl "$BASE/cli-test.txt"        # hello
curl "$BASE/cli-test.base64"     # aGVsbG8=
echo " world" | curl --data-binary @- "$BASE/cli-test/append"
curl "$BASE/cli-test"            # hello world
```
