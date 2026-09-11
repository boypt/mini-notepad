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
apply the database schema once. See [DEPLOY.md](./DEPLOY.md) for the full
steps.

## Features

- Paste code or plain text in the browser. No login, no setup.
- Share a note with a short link. The app makes a short random ID, or you can
  pick your own ID. An ID can be any length, using `a-z`, `A-Z`, `0-9`, `_`, and
  `-`.
- Read a note as plain text (`/<id>.txt`) or Base64 (`/<id>.base64`).
- Read, write, and append from the command line (`curl`, `wget`). See
  [Command line](#command-line).
- Auto-save, line numbers, font size, copy/paste buttons, and an expiry choice.
- Made for IT maintenance and programmers who need to share code or text
  quickly.

## Output modes

The output menu opens a file name:

- `/<id>.txt` gives plain text.
- `/<id>.base64` gives Base64.

## Command line

The Worker speaks plain HTTP, so you can use `curl` or any HTTP client.

Save with your own ID:

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

Save with a random ID. Post to `/`. The Worker makes a short random ID and
prints it in the receipt:

```sh
echo "hello" | curl --data-binary @- https://<your-worker>/
```

Append, read, and get other output:

```sh
echo " world" | curl --data-binary @- https://<your-worker>/my-note/append
curl https://<your-worker>/my-note            # raw text
curl https://<your-worker>/my-note.txt        # plain text
curl https://<your-worker>/my-note.base64     # Base64
```

A `curl` or `wget` user agent gets the raw note text, not the HTML page.

### Set the expiry

Post to `/:note/expire` with `expires`. The body does not change:

```sh
curl -d 'expires=24h'   https://<your-worker>/my-note/expire
curl -d 'expires=never' https://<your-worker>/my-note/expire
```

`expires` accepts `24h`, `72h`, `1w`, or `never`. A new note lives for
`NOTE_TTL_DAYS` (default `30` days).

You can also save a new body and set the expiry in one call:

```sh
curl -d 'text=hello&expires=24h' https://<your-worker>/my-note
```

## Routes (reference)

| Route | What it does |
| --- | --- |
| `GET /` | Redirects to a new random note ID. |
| `GET /:note` | Shows the HTML editor. |
| `GET /:note.txt` | Shows the note as plain text. |
| `GET /:note.base64` | Shows the note as Base64. |
| `POST /:note` (form field `text`) | Saves the note. An empty `text` deletes it. |
| `POST /:note/expire` (form field `expires`) | Changes the expiry only. Keeps the body. |
| `POST /:note` (raw body) | CLI save. |
| `POST /:note/append` (raw body) | CLI append. |
| `POST /` (raw body) | CLI save to a new random ID. |

Notes:

- A note ID uses only these characters: `a-z`, `A-Z`, `0-9`, `_`, and `-`.
  Any length is allowed.
- A file suffix we do not know (for example `/index.jsp`) returns `400`.

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
