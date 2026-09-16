# Deploy guide — Cloudflare Workers + D1

This guide shows how to put the notepad on Cloudflare. It covers local
development, the D1 database, deployment, custom domains, rollback, garbage
collection, and common problems.

See [README.md](./README.md) for a short overview.

---

## 1. What you need

| Item | Requirement |
| --- | --- |
| Node.js | Version 18 or newer. Version 20+ is better. This repo was tested on Node 24. |
| Package manager | npm. The repo uses `package.json` and `npx wrangler`. |
| Cloudflare account | You need Workers and D1 permission. |
| Login | Use `wrangler login` on your computer. Use an API token in CI. |
| Compat flag | `wrangler.toml` already sets `nodejs_compat`. zstd needs `node:zlib`. |

Install the tools:

```sh
npm install
```

---

## 2. How it works

```
Browser / curl
   │
   ▼
Cloudflare Worker  (src/index.js)
   ├── static file  public/favicon.ico  → Workers Static Assets
   ├── note routes  /:note, /:note.txt, /:note.base64  → Worker fetch
   └── D1 binding   env.DB              → notes table (BLOB)
             ▲
Cron Trigger └─ runs at 03:00 UTC every day to delete expired notes
```

- The app uses one Worker, one D1 database, and one Cron Trigger. Nothing else.
- The Worker saves the note body in `content` (a BLOB).
  - A body under 128 bytes is saved as plain text
    (`content_encoding = 'identity'`).
  - A bigger body is compressed with zstd (`content_encoding = 'zstd'`).
- The table has `created_at`, `updated_at`, and `expires_at`. It also has
  password columns: `is_protected`, `password_hash`, `password_salt`, and
  `password_algo`. A locked note stores only a PBKDF2 hash, never the
  password.
- The app must run at the root of a site. It uses `/<id>` and `/favicon.ico`.

---

## 3. Log in to Cloudflare

```sh
# Log in on your computer. This opens a browser.
npx wrangler login

# Check who you are.
npx wrangler whoami
```

For CI or a computer without a browser, use an API token. See section 8.

---

## 4. Create the D1 database

```sh
npx wrangler d1 create web-notepad
```

The command prints the database details. Example:

```
[[d1_databases]]
binding = "DB"
database_name = "web-notepad"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Put the `database_id` in `wrangler.toml`. Replace
`REPLACE_WITH_YOUR_DATABASE_ID`.

Optional flags:

- `--location apac` — sets the primary location. Values: `weur`, `eeur`,
  `apac`, `oc`, `wnam`, `enam`.
- `--jurisdiction eu|fedramp|us` — limits where the data lives. If you set
  this, `--location` is ignored.
- `--update-config` — writes the binding into the wrangler config for you.

> Note: You can only create a D1 database in the cloud. Local development uses
> a local database made by Miniflare. The two databases are separate.

---

## 5. Local development

```sh
# 1. Apply the schema to the local database.
npx wrangler d1 migrations apply web-notepad --local

# 2. Start the local dev server (default http://127.0.0.1:8787).
npm run dev
```

Local checks:

```sh
# The root path should redirect (302) to a random 5-character ID.
curl -s -D - -o /dev/null http://127.0.0.1:8787/

# CLI write to the root. The Worker makes a random ID and prints it in the
# receipt. The output looks like:
#   Saved.
#   Note:    7k2ma
#   Saved:   2026-01-31 12:00:00 UTC
#   Expires: 2026-03-02 12:00:00 UTC
#   Plain:   http://127.0.0.1:8787/7k2ma.txt
#   Base64:  http://127.0.0.1:8787/7k2ma.base64
#   Editor:  http://127.0.0.1:8787/7k2ma
echo hello | curl --data-binary @- http://127.0.0.1:8787/

# CLI write and read. A curl user agent gets the raw text.
echo hello | curl --data-binary @- http://127.0.0.1:8787/cli-test
curl http://127.0.0.1:8787/cli-test            # hello

# Output by file suffix.
curl http://127.0.0.1:8787/cli-test.txt        # hello
curl http://127.0.0.1:8787/cli-test.base64     # aGVsbG8=
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/index.jsp   # 400

# Append.
echo " world" | curl --data-binary @- http://127.0.0.1:8787/cli-test/append
curl http://127.0.0.1:8787/cli-test            # hello world

# Change only the expiry from the command line. POST to /:note/expire, so the
# body stays the same. The receipt starts with "Expiry set." and shows the new
# Expires. It accepts 24h, 72h, 1w, or never.
curl -d 'expires=24h'   http://127.0.0.1:8787/cli-test/expire
curl -d 'expires=never' http://127.0.0.1:8787/cli-test/expire

# Or save a new body and set the expiry in one call.
curl -d 'text=hello&expires=24h' http://127.0.0.1:8787/cli-test
```

Look at the local database:

```sh
npx wrangler d1 execute web-notepad --local \
  --command "SELECT id, content_encoding, size_raw, size_stored, expires_at FROM notes"
```

Local state is in `.wrangler/`. `.gitignore` ignores it.

---

## 6. Apply the production schema

Apply the schema to the cloud database **before** you deploy the code:

```sh
npx wrangler d1 migrations apply web-notepad --remote
```

- Migration files are in `migrations/`. They run in file-name order. Applied
  files are skipped.
- The first run creates the `notes` table and the `idx_notes_expires_at` index.
- The command shows the migrations it will run. It may ask you to confirm. In
  CI it runs without a prompt.

> Code and data stay compatible. The reader knows `zstd`, `gzip`, and
> `identity`. So you can add fields or change the default codec without
> backfilling existing rows.

---

## 7. Deploy

```sh
npm run deploy        # same as: npx wrangler deploy
```

After the deploy, Wrangler prints the Worker URL:

- Default: `https://web-notepad.<your-subdomain>.workers.dev`
- Run the smoke test in section 9 right after the deploy.

The deploy includes:

- `src/index.js`
- `public/` as static files (the favicon)
- the `[[d1_databases]]` binding `env.DB`
- the `[triggers]` Cron
- the `[vars]` value `NOTE_TTL_DAYS`

Show live logs:

```sh
npx wrangler tail
```

---

## 8. CI / deploy without a browser

Set these environment variables, then deploy from a pipeline:

| Variable | Meaning |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | A token with Workers Scripts:Edit and D1:Edit permission. |
| `CLOUDFLARE_ACCOUNT_ID` | Your account ID. Find it on the right side of the dashboard. |

```sh
npm ci
npx wrangler d1 migrations apply web-notepad --remote
npx wrangler deploy
```

Set a secret for the CSRF token (recommended):

```sh
npx wrangler secret put CSRF_SECRET
```

If you need another secret later (for example, for passwords), use:

```sh
npx wrangler secret put SOME_SECRET
```

---

## 9. Check the deploy

```sh
BASE=https://<your-worker-domain>

# 1. Root redirect.
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "$BASE/"

# 1b. CLI write to the root. It saves under a new random ID. The receipt shows
#     the ID and the read URLs.
echo hello | curl --data-binary @- "$BASE/"

# 2. Write, read, and output.
echo hello | curl --data-binary @- "$BASE/smoke"
curl "$BASE/smoke"          # hello
curl "$BASE/smoke.txt"      # hello
curl "$BASE/smoke.base64"   # aGVsbG8=
curl -s -o /dev/null -w '%{http_code}\n' "$BASE/index.jsp"   # 400
curl -s -o /dev/null -w '%{content_type}\n' "$BASE/smoke/json"   # application/json

# 3. Form save (the web autosave uses this).
curl -s -d 'text=from+form' "$BASE/smoke"
curl "$BASE/smoke"          # from form

# 4. An empty form save deletes the note.
curl -s -d 'text=' "$BASE/smoke"
curl -s -o /dev/null -w '%{http_code}\n' "$BASE/smoke/plain"     # 302 -> /smoke

# 5. Static file.
curl -s -o /dev/null -w '%{http_code}\n' "$BASE/favicon.ico"     # 200

# 6. Check the stored encoding and expiry.
npx wrangler d1 execute web-notepad --remote \
  --command "SELECT id, content_encoding, size_raw, size_stored, expires_at FROM notes LIMIT 5"

# 7. Password lock (uses a separate note).
echo hello | curl --data-binary @- "$BASE/smoke-pw"
curl -s -d 'new=pw123' "$BASE/smoke-pw/password"
curl -s -o /dev/null -w '%{http_code}\n' "$BASE/smoke-pw.txt"   # 401
curl -H 'X-Note-Password: pw123' "$BASE/smoke-pw.txt"           # hello
curl "$BASE/smoke-pw.txt?pw=pw123"                              # hello
curl -s -d 'current=pw123&new=' "$BASE/smoke-pw/password"       # remove lock
curl "$BASE/smoke-pw.txt"                                       # hello
```

In a browser: the home page redirects to a random ID. Type some text. The note
saves after about 60 seconds. You can also click the Save button. Reload the
page. The note is still there.

---

## 10. Settings

All settings are in `wrangler.toml`:

| Setting | Where | Meaning |
| --- | --- | --- |
| `NOTE_TTL_DAYS` | `[vars]` | Default life (in days) for a new note and for saves without an `expires` value. Default `30`. Set `0` to never expire. An existing note keeps the expiry you set before; the web page uses the expiry you pick. |
| `crons` | `[triggers]` | GC schedule. Default `["0 3 * * *"]` (03:00 UTC every day). |
| `compatibility_flags` | top level | Keep `nodejs_compat`. zstd needs `node:zlib`. |
| `compatibility_date` | top level | Must be `2024-09-23` or newer for `nodejs_compat` v2. |
| `database_id` | `[[d1_databases]]` | Fill this in after step 4. |

Run `npm run deploy` to apply changes. Note: after you change `crons`, you must
deploy once so Cloudflare updates the trigger.

### Garbage collection

- Automatic: the Cron Trigger calls `scheduled` every day. It deletes rows
  where `expires_at < now`.
- Manual: `npm run db:gc` runs one DELETE on the cloud database.
- Lazy: when a read finds an expired row, the Worker deletes it with
  `ctx.waitUntil` and treats it as missing.

### How expiry works

The user picks an expiry in the status bar: `24h`, `72h`, `1w`, or `never`. The
page sends it in the `expires` field when it creates a note and when the menu
changes. An explicit choice sets `expires_at = now + the choice`; a normal
content save keeps the current expiry. So a note expires after the chosen
period from the last menu change or creation. A CLI `POST /:note/expire`
(`curl -d 'expires=24h' .../my-note/expire`) changes the expiry only; the body
and `updated_at` stay the same. A raw-body CLI save (`curl --data-binary ...`)
keeps the note's current expiry. A new note uses `NOTE_TTL_DAYS`. If you want a
fixed expiry from the creation time, change the migration or the `saveNote`
code.

---

## 11. Custom domain / routes

In the dashboard: Workers & Pages → choose `web-notepad` →
Settings → Domains & Routes → add a custom domain. You can also set it in
`wrangler.toml`:

```toml
routes = [
  { pattern = "notes.example.com", custom_domain = true },
]
```

The app uses root paths (`/<id>`, `/favicon.ico`). Use a separate subdomain. Do
not put it under a sub-path of another site. If you must use a sub-path, you
need a reverse proxy that rewrites the path, or a `<base href>` solution.

---

## 12. Canary and rollback

```sh
# List past deploys.
npx wrangler deployments list

# Show the current state.
npx wrangler deployments status

# Roll back to the previous version.
npx wrangler rollback --message "revert bad deploy"
```

Important: **A rollback changes the Worker code only. It does not change D1
data.** The reader knows `zstd`, `gzip`, and `identity`. So a code rollback
between codecs is safe. But a delete is permanent. Check before you roll back.

---

## 13. Common problems

**`database_id` is still the placeholder / binding error**
You did not replace `REPLACE_WITH_YOUR_DATABASE_ID` in `wrangler.toml`. Run
`npx wrangler d1 list` to find the real ID, then fill it in.

**It works locally but the cloud says "no such table: notes"**
The cloud database has no schema yet. Run
`npx wrangler d1 migrations apply web-notepad --remote`.

**`zstdCompressSync is not a function`**
The `nodejs_compat` flag is missing, or `compatibility_date` is too old. Check
that `wrangler.toml` has `compatibility_flags = ["nodejs_compat"]` and a date
of `2024-09-23` or newer. Then deploy again.

**Build or size warning about zstd / node:zlib**
`nodejs_compat` adds polyfills, so the bundle is a bit bigger. This Worker is
about 15 KiB (about 5 KiB gzip). You can ignore the warning.

**`wrangler dev` does not start / workerd download fails**
This is usually a network or proxy problem. Check that you can reach
`*.workers.dev` and the npm registry. Set a proxy if needed, or update
wrangler.

**"No migrations to apply!" but the table is missing**
You may have used `--local` but you want the cloud database (or the opposite).
Use `--local` for your computer. Use `--remote` for the cloud. The data is
separate.

**The Cron does not run GC**
Check that you deployed and that `[triggers] crons` is not empty. In the
dashboard, open Worker → Triggers. You can also run `npm run db:gc` to test the
SQL by hand.

**Limits for large text or high traffic**
Workers have a CPU time limit. D1 has database size and query limits. This
Worker uses synchronous zstd. A very large note uses CPU. If you hit a limit,
use async or streaming compression, or store very large notes as `identity`.

**favicon 404**
Check that `public/favicon.ico` exists and that `[assets]` in `wrangler.toml`
points to `./public`. Static files and Worker routes share the domain. Only
requests that do not match a file go to the Worker.

---

## 14. Security and privacy

- Every response has `Cache-Control: no-store` and
  `X-Robots-Tag: noindex, nofollow`.
- A browser form save needs a per-note CSRF token. The page embeds the token.
  A blind POST returns `403`. This stops crawlers from creating notes.
- A raw CLI write is allowed only for whitelisted user agents: `curl` and
  `wget`. Set a strong token secret with
  `npx wrangler secret put CSRF_SECRET`. Without it, the Worker uses a
  built-in default.
- A note can be locked with a password. The lock button in the status bar
  sets, changes, or removes it. The Worker stores only a PBKDF2-SHA256 hash
  (100,000 rounds), never the password.
- A locked note needs the password on reads and writes. Reads accept the
  `X-Note-Password` header or `?pw=`. Writes accept only the header. A
  missing or wrong password returns `401`.
- The browser asks for the password one time. It then remembers the password
  in localStorage for that note.
- Note passwords protect single notes, not the whole site. For site-wide
  control, use Cloudflare Access.
- A new note gets a 5-character random ID (about 17 million combinations).
  You can also pick your own ID of any length. Either way, the ID is **not**
  strong access control. Do not rely on the ID to hide secret content.
