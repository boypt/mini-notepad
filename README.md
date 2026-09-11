# Web Notepad (Cloudflare Workers + D1)

A Pastebin-like notebook. It runs on
[Cloudflare Workers](https://developers.cloudflare.com/workers/) and stores
every note in a [D1](https://developers.cloudflare.com/d1/) database.

The main job is simple:

- **Paste** code or text in the browser.
- **Share** it with a short link.
- **Use** it again as `.txt` or `.base64`, or from the command line.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/boypt/mini-notepad)

Click the button to copy this project and deploy it to your own Cloudflare
account. Cloudflare makes the D1 database for you. After the first deploy,
apply the database schema once (see [Setup](#setup)).

## Features

- Paste code or plain text in the browser. No login, no setup.
- Share a note with a short link. A note ID is 5 random characters.
- Read a note as plain text (`/<id>.txt`) or Base64 (`/<id>.base64`).
- Read, write, and append from the command line (`curl`, `wget`). See
  [Command line](#command-line).
- Auto-save, line numbers, font size, copy/paste buttons, and an expiry choice.
- Made for IT maintenance and programmers who need to share code or text
  quickly.

## Routes

| Route | What it does |
| --- | --- |
| `GET /` | Sends a `302` redirect to a new random note ID. |
| `GET /:note` | Shows the HTML editor. |
| `GET /:note.txt` | Shows the note as plain text. |
| `GET /:note.base64` | Shows the note as Base64. |
| `POST /:note` (form field `text`) | Saves the note. An empty `text` deletes it. |
| `POST /:note` (raw body) | CLI save. |
| `POST /:note/append` (raw body) | CLI append. |

Notes:

- A note ID uses only these characters: `a-z`, `A-Z`, `0-9`, `_`, and `-`.
- A file suffix we do not know (for example `/index.jsp`) returns `400`.
- A browser form save must include the per-note CSRF token from the page. A
  blind POST returns `403`.
- `curl` and `wget` user agents may save without a token. On GET they get the
  raw note body, not HTML.
- All responses use `no-store` and `X-Robots-Tag: noindex, nofollow`.

## Output modes

The output menu opens a file name:

- `/<id>.txt` gives plain text.
- `/<id>.base64` gives Base64.

## Command line

The Worker speaks plain HTTP, so you can use `curl` or any HTTP client.

Save a note with a raw body:

```sh
echo "hello" | curl --data-binary @- https://<your-worker>/my-note
```

The save prints a receipt with the time and the read URLs:

```text
Saved.
Note:    my-note
Saved:   2026-01-31 12:00:00 UTC
Expires: 2026-03-02 12:00:00 UTC
Plain:   https://<your-worker>/my-note.txt
Base64:  https://<your-worker>/my-note.base64
Editor:  https://<your-worker>/my-note
```

Read it back:

```sh
curl https://<your-worker>/my-note
```

Append to it:

```sh
echo " world" | curl --data-binary @- https://<your-worker>/my-note/append
```

Read plain text or Base64:

```sh
curl https://<your-worker>/my-note.txt
curl https://<your-worker>/my-note.base64
```

A `curl` user agent gets the raw note text, not the HTML page.

## Security

- A browser form save needs the per-note CSRF token. The page embeds it.
- A raw CLI write is allowed only for whitelisted user agents: `curl` and
  `wget`.
- In production, set a secret for the CSRF token:
  ```sh
  npx wrangler secret put CSRF_SECRET
  ```
  If you do not set it, the Worker uses a built-in default.

## Storage and compression

- A note shorter than 128 bytes is saved as plain UTF-8 text.
  `content_encoding` is `identity`.
- A longer note is compressed with zstd and saved as a BLOB.
  `content_encoding` is `zstd`.
- The table stores `size_raw` and `size_stored`.
- On read, the code can decode `zstd`, `gzip`, and `identity`.

Why `node:zlib`? In Workers, the Web `CompressionStream` API supports only
`gzip`, `deflate`, and `deflate-raw`. It does not support zstd or brotli.
`node:zlib` gives us zstd. It needs the `nodejs_compat` flag. That flag is
already in `wrangler.toml`.

## Expiry and garbage collection

- The web editor sends an `expires` value: `24h`, `72h`, `1w`, or `never`.
- The Worker sets `expires_at = now + expires`.
- A CLI save has no `expires` value. Then the Worker keeps the note's current
  expiry. A new note starts with `NOTE_TTL_DAYS` (default `30`). Set
  `NOTE_TTL_DAYS = "0"` to never expire.
- `created_at` is set one time. `updated_at` changes on every save.
- A Cron Trigger runs at `0 3 * * *` (03:00 UTC every day). It deletes notes
  that are past `expires_at`.
- A read also deletes an expired note. It uses `ctx.waitUntil`.

## Save response

A form save returns JSON:

```json
{ "created_at": 0, "updated_at": 0, "expires_at": 0 }
```

`expires_at` can be `null`. A delete returns `{ "deleted": true }`.

## Password columns (not used yet)

The `notes` table has `is_protected`, `password_hash`, `password_salt`, and
`password_algo`. The Worker writes `is_protected = 0` and does not check a
password. A future version can add the check. PBKDF2 with `crypto.subtle` is a
good choice. Store `password_algo = "pbkdf2-sha256"`.

## Files

```
src/index.js              # router, D1 store, compression, HTML page
migrations/0001_init.sql  # D1 schema
public/favicon.ico        # static asset
wrangler.toml             # bindings, cron, vars
package.json              # dev and deploy scripts
README.md                 # this file
DEPLOY.md                 # deployment guide
```

## Setup

See [DEPLOY.md](./DEPLOY.md) for the full production steps.

```sh
npm install

# 1. Create the D1 database. Copy the printed database_id into wrangler.toml.
npx wrangler d1 create web-notepad

# 2. Apply the schema. Use --local for local dev.
npx wrangler d1 migrations apply web-notepad --remote

# 3. Run local, or deploy.
npx wrangler dev
npx wrangler deploy
```

## Smoke test

```sh
BASE=http://127.0.0.1:8787

curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "$BASE/"
echo hello | curl --data-binary @- "$BASE/cli-test"
curl "$BASE/cli-test"            # hello
curl "$BASE/cli-test.txt"        # hello
curl "$BASE/cli-test.base64"     # aGVsbG8=
echo " world" | curl --data-binary @- "$BASE/cli-test/append"
curl "$BASE/cli-test"            # hello world
```
