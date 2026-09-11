/**
 * Minimalist Web Notepad — Cloudflare Workers Mod
 *
 * A module Worker backed by D1.
 *
 * Routes:
 *   - GET  /                     -> 302 redirect to a random 5-char note id
 *   - GET  /:note                -> HTML editor
 *   - GET  /:note.txt            -> stored note as plain text
 *   - GET  /:note.base64         -> stored note as base64
 *   - GET  /:note/:mode          -> stored note in that mode (legacy; plain,
 *                                    base64, mtime, html, css, js, json;
 *                                    unknown == raw)
 *   - unknown file suffix        -> 400
 *   - POST /:note  (form `text`) -> save; empty `text` deletes
 *   - POST /:note  (raw body)    -> CLI save
 *   - POST /:note/append         -> CLI append
 *   - CLI user-agent             -> raw body, no HTML wrapper
 *
 * Security:
 *   - A browser form save must carry the per-note CSRF token from the page.
 *   - A raw CLI write is allowed only for whitelisted user agents (curl, wget).
 *
 * Storage:
 *   - Bodies are zstd-compressed (node:zlib) before they are written to D1;
 *     bodies shorter than 128 bytes are stored as plain UTF-8 instead
 *     (content_encoding = 'identity').
 *   - Every row carries created_at / updated_at / expires_at; a Cron
 *     Trigger garbage-collects expired rows. Reads also lazily delete.
 *   - The web editor offers a per-note expiry choice; CLI writes fall back
 *     to NOTE_TTL_DAYS.
 *   - Password columns (password_hash / password_salt / password_algo /
 *     is_protected) are reserved for a future password-protected view.
 *     They are stored but not yet enforced.
 *
 * The helper exports below are exported so they can be unit-tested with
 * plain Node; the Worker entrypoint is the default export.
 */

import zlib from 'node:zlib';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';

const NOTE_ID_RE = /^[a-zA-Z0-9_-]+$/;
const MODE_RE = /^[a-z0-9]*$/;
const ID_ALPHABET = '234579abcdefghjkmnpqrstwxyz';
const DEFAULT_TTL_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;
/** Codec recorded in notes.content_encoding. */
const CODEC = 'zstd';
/** Bodies shorter than this many UTF-8 bytes are stored uncompressed. */
const PLAINTEXT_MAX_BYTES = 128;
/** Expiry options offered by the web UI, as durations in milliseconds. */
const EXPIRY_TOKENS = {
  '24h': DAY_MS,
  '72h': 3 * DAY_MS,
  '1w': 7 * DAY_MS,
};
/** User agents allowed to use the raw command-line write path. */
const CLI_USER_AGENTS = ['curl', 'wget'];
/** Fallback CSRF secret for local/dev; set CSRF_SECRET in production. */
const DEFAULT_CSRF_SECRET = 'minimalist-notepad-dev-secret';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------------------------------------------------------------------------
// Shared response helpers
// ---------------------------------------------------------------------------

/** Cache headers shared by every response. */
function noStore(extra) {
  return {
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    Pragma: 'no-cache',
    Expires: '0',
    'X-Robots-Tag': 'noindex, nofollow',
    ...extra,
  };
}

function redirect(location) {
  return new Response(null, { status: 302, headers: noStore({ Location: location }) });
}

function emptyOk() {
  return new Response('', {
    status: 200,
    headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
  });
}

function jsonOk(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: noStore({ 'Content-Type': 'application/json; charset=utf-8' }),
  });
}

function notFound() {
  return new Response('Not found', {
    status: 404,
    headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
  });
}

function badRequest() {
  return new Response('Bad request', {
    status: 400,
    headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
  });
}

function forbidden() {
  return new Response('Forbidden', {
    status: 403,
    headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
  });
}

// ---------------------------------------------------------------------------
// Encoding / compression
// ---------------------------------------------------------------------------

/** Random note id from an unambiguous alphabet. */
export function randomNoteId(length = 5) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let id = '';
  for (let i = 0; i < length; i++) id += ID_ALPHABET[bytes[i] % ID_ALPHABET.length];
  return id;
}

/**
 * zstd-compress a UTF-8 string, returning the raw compressed bytes.
 *
 * The Web Compression Streams API only supports gzip/deflate/deflate-raw in
 * Workers, so zstd comes from node:zlib (requires the `nodejs_compat` flag).
 */
export function compress(text) {
  return new Uint8Array(zlib.zstdCompressSync(encoder.encode(text)));
}

/**
 * Pick the storage codec for a body: plain UTF-8 for short notes, zstd for the
 * rest. Returns the bytes plus the metadata recorded in the notes row.
 */
export function encodeForStorage(text) {
  const raw = encoder.encode(text);
  if (raw.length < PLAINTEXT_MAX_BYTES) {
    return { bytes: raw, encoding: 'identity', rawSize: raw.length };
  }
  return { bytes: new Uint8Array(zlib.zstdCompressSync(raw)), encoding: CODEC, rawSize: raw.length };
}

/**
 * Map a web-UI expiry token to an `expires` argument for saveNote.
 * `undefined` means "use NOTE_TTL_DAYS"; `null` means "never expires".
 */
export function resolveExpiryToken(token) {
  if (token == null || token === '') return undefined;
  if (token === 'never') return null;
  return Object.prototype.hasOwnProperty.call(EXPIRY_TOKENS, token)
    ? EXPIRY_TOKENS[token]
    : undefined;
}

/**
 * Decompress bytes back to a UTF-8 string. `encoding` is the value stored in
 * notes.content_encoding; `gzip` is still decoded so data written by an
 * earlier gzip build remains readable.
 */
export function decompress(bytes, encoding = CODEC) {
  const input = toBytes(bytes);
  if (encoding === 'gzip') return decoder.decode(zlib.gunzipSync(input));
  if (encoding === 'identity' || encoding === 'none') return decoder.decode(input);
  return decoder.decode(zlib.zstdDecompressSync(input));
}

/**
 * D1 returns BLOB columns as an Array of byte values (despite the docs
 * saying ArrayBuffer). Normalise every accepted shape to Uint8Array.
 */
function toBytes(value) {
  if (value == null) return new Uint8Array(0);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value)) return Uint8Array.from(value);
  return new Uint8Array(0);
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default: return '&#39;';
    }
  });
}

// ---------------------------------------------------------------------------
// D1 note store
// ---------------------------------------------------------------------------

async function deleteNote(env, id) {
  await env.DB.prepare('DELETE FROM notes WHERE id = ?').bind(id).run();
}

/**
 * Load a note and decompress its body.
 * Returns null when missing, or { expired: true } when past expires_at
 * (the caller schedules the delete).
 */
async function loadNote(env, id) {
  const row = await env.DB.prepare(
    `SELECT id, content, content_encoding, created_at, updated_at, expires_at, is_protected
       FROM notes WHERE id = ? LIMIT 1`,
  ).bind(id).first();

  if (!row) return null;
  if (row.expires_at != null && row.expires_at < Date.now()) return { expired: true, row };

  let text = '';
  if (row.content != null) {
    const bytes = toBytes(row.content);
    text = decompress(bytes, row.content_encoding || CODEC);
  }
  return { expired: false, row, text };
}

/**
 * Insert or update a note. Short bodies are stored as plain UTF-8; larger ones
 * are zstd-compressed. expires_at is (re)computed on every write:
 *   - `expires` as a number  -> now + that many ms
 *   - `expires === null`     -> never expires
 *   - `expires` undefined    -> NOTE_TTL_DAYS default (0 = never expires)
 */
async function saveNote(env, id, text, { append = false, expires } = {}) {
  const now = Date.now();

  let expiresAt;
  if (expires === null) {
    expiresAt = null;
  } else if (typeof expires === 'number') {
    expiresAt = now + expires;
  } else {
    const ttlDays = Number(env.NOTE_TTL_DAYS ?? DEFAULT_TTL_DAYS);
    expiresAt = ttlDays > 0 ? now + ttlDays * DAY_MS : null;
  }

  let body = text;
  if (append) {
    const existing = await loadNote(env, id);
    const base = existing && !existing.expired ? existing.text : '';
    body = base + text;
  }

  const { bytes, encoding, rawSize } = encodeForStorage(body);

  await env.DB.prepare(
    `INSERT INTO notes
       (id, content, content_encoding, size_raw, size_stored,
        created_at, updated_at, expires_at, is_protected)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
     ON CONFLICT(id) DO UPDATE SET
       content          = excluded.content,
       content_encoding = excluded.content_encoding,
       size_raw         = excluded.size_raw,
       size_stored      = excluded.size_stored,
       updated_at       = excluded.updated_at,
       expires_at       = excluded.expires_at`,
  ).bind(id, bytes, encoding, rawSize, bytes.byteLength, now, now, expiresAt).run();
}

/** Delete every row whose expiry has passed (used by the Cron Trigger). */
async function gcExpired(env) {
  await env.DB.prepare(
    'DELETE FROM notes WHERE expires_at IS NOT NULL AND expires_at < ?',
  ).bind(Date.now()).run();
}

// ---------------------------------------------------------------------------
// Request security
// ---------------------------------------------------------------------------

/** True for user agents we allow to use the raw command-line write path. */
function isCliUserAgent(userAgent) {
  const ua = (userAgent || '').trim().toLowerCase();
  return CLI_USER_AGENTS.some((name) => ua.startsWith(name));
}

/** Per-note CSRF token: HMAC-SHA256 of the note id. */
function csrfToken(env, id) {
  const secret = env.CSRF_SECRET || DEFAULT_CSRF_SECRET;
  return createHmac('sha256', secret).update(id).digest('hex');
}

/** Constant-time check of a form CSRF token against the expected value. */
function verifyCsrf(env, id, token) {
  if (typeof token !== 'string') return false;
  const expected = csrfToken(env, id);
  if (token.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(token, 'utf8'), Buffer.from(expected, 'utf8'));
  } catch (err) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async function handlePost(request, env, id, mode) {
  const contentType = request.headers.get('content-type') || '';
  const userAgent = request.headers.get('user-agent') || '';
  const cli = isCliUserAgent(userAgent);
  const raw = await request.text();

  // Web (form) save path: the autosave XHR posts `text=...` (and `expires=...`).
  // A browser must send the per-note CSRF token from the page. Whitelisted CLI
  // tools may skip it so `curl -d 'text=...'` keeps working.
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(raw);
    if (params.has('text')) {
      if (!cli && !verifyCsrf(env, id, params.get('csrf'))) return forbidden();
      const text = params.get('text') ?? '';
      if (text.length === 0) {
        await deleteNote(env, id);
        return jsonOk({ deleted: true });
      }
      const expires = resolveExpiryToken(params.get('expires'));
      await saveNote(env, id, text, { expires });
      const row = await env.DB.prepare(
        'SELECT created_at, updated_at, expires_at FROM notes WHERE id = ? LIMIT 1',
      ).bind(id).first();
      return jsonOk({
        created_at: row?.created_at ?? null,
        updated_at: row?.updated_at ?? null,
        expires_at: row?.expires_at ?? null,
      });
    }
  }

  // CLI path: raw request body. Only whitelisted CLI user agents may use it.
  if (!cli) return forbidden();
  if (mode === 'append') await saveNote(env, id, raw, { append: true });
  else await saveNote(env, id, raw);
  return emptyOk();
}

function modeResponse(loaded, mode) {
  const text = loaded.text;
  const headers = (contentType) => noStore({ 'Content-Type': contentType });
  const plain = 'text/plain; charset=utf-8';

  switch (mode) {
    case 'plain':
      return new Response(text, { headers: headers(plain) });
    case 'base64':
      return new Response(bytesToBase64(encoder.encode(text)), { headers: headers(plain) });
    case 'mtime':
      return new Response(String(Math.floor(loaded.row.updated_at / 1000)), {
        headers: headers(plain),
      });
    case 'html':
      return new Response(text, { headers: headers('text/html; charset=utf-8') });
    case 'css':
      return new Response(text, { headers: headers('text/css; charset=utf-8') });
    case 'js':
      return new Response(text, { headers: headers('text/javascript; charset=utf-8') });
    case 'json':
      return new Response(text, { headers: headers('application/json; charset=utf-8') });
    default:
      return new Response(text, { headers: headers(plain) });
  }
}

async function handleGet(request, env, ctx, id, mode) {
  let loaded = await loadNote(env, id);
  if (loaded && loaded.expired) {
    ctx.waitUntil(deleteNote(env, id));
    loaded = null;
  }

  if (mode) {
    if (!loaded) return redirect('/' + id);
    return modeResponse(loaded, mode);
  }

  const userAgent = request.headers.get('user-agent') || '';
  if (isCliUserAgent(userAgent)) {
    return new Response(loaded ? loaded.text : '', {
      status: 200,
      headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
    });
  }

  const meta = loaded
    ? {
        createdAt: loaded.row.created_at ?? null,
        updatedAt: loaded.row.updated_at ?? null,
        expiresAt: loaded.row.expires_at ?? null,
      }
    : { createdAt: null, updatedAt: null, expiresAt: null };
  meta.csrf = csrfToken(env, id);
  return new Response(renderPage(id, loaded ? loaded.text : '', meta), {
    status: 200,
    headers: noStore({ 'Content-Type': 'text/html; charset=utf-8' }),
  });
}

// ---------------------------------------------------------------------------
// HTML template (CSS + JS inlined)
// ---------------------------------------------------------------------------

export function renderPage(id, text, meta = {}) {
  return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="Minimalist Web Notepad Workers Mod">
    <title>${escapeHtml(id)}</title>
    <link rel="shortcut icon" href="/favicon.ico">
    <style>
/*! Minimalist Web Notepad Workers Mod */

*, *::before, *::after {
    box-sizing: border-box;
}
html, body {
    height: 100%;
}
body {
    margin: 0;
    min-height: 100vh;
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
    background: #ebeef1;
    color: #222;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.toolbar,
.statusbar {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
}
.statusbar {
    padding-bottom: calc(8px + env(safe-area-inset-bottom, 0px));
    font-size: 12px;
    color: #66707a;
}
.grow {
    flex: 1 1 auto;
}
button.icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    padding: 0;
    font-size: 18px;
    line-height: 1;
    color: inherit;
    background: #fff;
    border: 1px solid #d3d8de;
    border-radius: 6px;
    cursor: pointer;
}
button.icon:not(:disabled):hover {
    background: #f2f4f7;
}
button.icon:not(:disabled):active {
    transform: translateY(1px);
}
button.icon:disabled {
    color: #b3b9c0;
    background: #f0f2f4;
    border-color: #e0e4e8;
    cursor: not-allowed;
    opacity: 0.5;
    filter: grayscale(1);
}
#save-note:not(:disabled) {
    color: #1f6feb;
    border-color: #1f6feb;
    background: #eaf2ff;
}
#save-note:not(:disabled):hover {
    background: #dcebff;
}
button.icon:focus-visible,
select:focus-visible,
#content:focus-visible {
    outline: 2px solid #5b8def;
    outline-offset: 1px;
}
select {
    font: inherit;
    font-size: 13px;
    color: inherit;
    background: #fff;
    border: 1px solid #d3d8de;
    border-radius: 6px;
    padding: 6px 8px;
    max-width: 45vw;
}
main {
    flex: 1 1 auto;
    min-height: 0;
    display: flex;
    padding: 0 12px;
}
#content {
    flex: 1 1 auto;
    width: 100%;
    margin: 0;
    padding: 16px;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    font-size: 100%;
    line-height: 1.5;
    tab-size: 4;
    overflow-y: auto;
    resize: none;
    border: 1px solid #d3d8de;
    border-radius: 6px;
    outline: none;
}
#printable {
    display: none;
}

@media (prefers-color-scheme: dark) {
    body {
        background: #383934;
        color: #f8f8f2;
    }
    button.icon,
    select {
        background: #282923;
        border-color: #4a4b45;
    }
    button.icon:not(:disabled):hover {
        background: #33342d;
    }
    button.icon:disabled {
        color: #6b6d66;
        background: #23241f;
        border-color: #3a3b35;
        opacity: 0.5;
        filter: grayscale(1);
    }
    #save-note:not(:disabled) {
        color: #7cb0ff;
        border-color: #7cb0ff;
        background: #1d2a3f;
    }
    #save-note:not(:disabled):hover {
        background: #253652;
    }
    #content {
        background: #282923;
        color: #f8f8f2;
        border-color: #4a4b45;
    }
    .statusbar {
        color: #b6b7ae;
    }
}

@media print {
    body {
        display: block;
        min-height: 0;
        background: #fff;
    }
    .toolbar,
    .statusbar,
    main {
        display: none;
    }
    #printable {
        display: block;
        white-space: pre-wrap;
        word-break: break-word;
        font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    }
}
    </style>
</head>
<body>
    <script id="note-meta" type="application/json">${JSON.stringify(meta).replace(/</g, '\\u003c')}</script>
    <header class="toolbar">
        <button type="button" class="icon" id="new-note" title="New note" aria-label="New note">🗋</button>
        <button type="button" class="icon" id="save-note" title="Save" aria-label="Save" disabled>💾</button>
        <span class="grow"></span>
        <select id="output-mode" aria-label="Output format">
            <option value="" selected disabled>Output&hellip;</option>
            <option value=".txt">Plain text</option>
            <option value=".base64">Base64</option>
        </select>
    </header>
    <main>
        <textarea id="content" autocomplete="off" autocapitalize="off">${escapeHtml(text)}</textarea>
    </main>
    <footer class="statusbar">
        <span id="saved-at">Not saved yet</span>
        <span class="grow"></span>
        <label for="expiry">Expires
            <select id="expiry" aria-label="Expiry">
                <option value="24h">24 hours</option>
                <option value="72h">72 hours</option>
                <option value="1w">1 week</option>
                <option value="never">Never</option>
            </select>
        </label>
    </footer>
    <pre id="printable"></pre>
    <script>
/*! Minimalist Web Notepad Workers Mod */
(function () {
    'use strict';

    var AUTOSAVE_MS = 60000;
    var DAY_MS = 24 * 60 * 60 * 1000;
    var NOTE_ID = ${JSON.stringify(id)};

    var textarea = document.getElementById('content');
    var printable = document.getElementById('printable');
    var outputMode = document.getElementById('output-mode');
    var expiry = document.getElementById('expiry');
    var savedAtEl = document.getElementById('saved-at');
    var saveButton = document.getElementById('save-note');

    var meta;
    try {
        meta = JSON.parse(document.getElementById('note-meta').textContent || '{}') || {};
    } catch (err) {
        meta = {};
    }

    var content = textarea.value;
    var saving = false;
    var dirty = false;

    // Make the content available to print.
    printable.appendChild(document.createTextNode(content));

    function pad(n) {
        return String(n).padStart(2, '0');
    }

    function showSavedAt(ms) {
        if (ms == null) {
            savedAtEl.textContent = 'Not saved yet';
            return;
        }
        var d = new Date(ms);
        savedAtEl.textContent = 'Saved ' + d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
            ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
    }

    function pickExpiry() {
        // A brand-new note (no created_at yet) starts on the 24-hour default.
        if (meta.createdAt == null) {
            expiry.value = '24h';
            return;
        }
        if (meta.expiresAt == null) {
            expiry.value = 'never';
            return;
        }
        var span = meta.expiresAt - (meta.updatedAt != null ? meta.updatedAt : meta.expiresAt);
        if (span === DAY_MS) expiry.value = '24h';
        else if (span === 3 * DAY_MS) expiry.value = '72h';
        else if (span === 7 * DAY_MS) expiry.value = '1w';
        else expiry.value = '24h';
    }

    function updateSaveState() {
        saveButton.disabled = textarea.value === content;
    }

    function send(body, onDone) {
        var request = new XMLHttpRequest();
        request.open('POST', window.location.href, true);
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        request.onload = function () {
            if (request.readyState === 4 && request.status >= 200 && request.status < 300) {
                try {
                    var data = JSON.parse(request.responseText);
                    if (data && data.updated_at != null) {
                        meta.createdAt = data.created_at;
                        meta.updatedAt = data.updated_at;
                        meta.expiresAt = data.expires_at;
                        showSavedAt(data.updated_at);
                    }
                } catch (err) {
                    // Non-JSON responses (for example a delete) are expected.
                }
            }
            if (onDone) onDone();
        };
        request.onerror = function () {
            if (onDone) onDone();
        };
        request.send(body);
    }

    function payload(value) {
        return 'text=' + encodeURIComponent(value) +
            '&expires=' + encodeURIComponent(expiry.value) +
            '&csrf=' + encodeURIComponent(meta.csrf || '');
    }

    function save(force) {
        var temp = textarea.value;

        if (!force && temp === content) return;
        if (!force && temp.length === 0 && meta.createdAt == null) return;
        if (saving) {
            dirty = true;
            return;
        }

        saving = true;

        // Make the content available to print.
        printable.removeChild(printable.firstChild);
        printable.appendChild(document.createTextNode(temp));

        send(payload(temp), function () {
            saving = false;
            content = temp;
            updateSaveState();
            if (dirty) {
                dirty = false;
                save(true);
            }
        });
    }

    function autosave() {
        save(false);
        setTimeout(autosave, AUTOSAVE_MS);
    }

    saveButton.addEventListener('click', function () {
        save(true);
    });

    textarea.addEventListener('input', updateSaveState);

    document.getElementById('new-note').addEventListener('click', function () {
        var input = window.prompt('Note ID', '');
        if (input === null) return;

        // Keep only characters a note id accepts.
        var id = input.replace(/[^a-zA-Z0-9_-]/g, '');
        if (id.length === 0) {
            window.alert('Enter a valid note ID: letters, digits, "-" and "_".');
            return;
        }

        var go = function () {
            window.location.href = '/' + id;
        };
        var temp = textarea.value;
        if (temp.length === 0) {
            go();
            return;
        }
        send(payload(temp), go);
    });

    expiry.addEventListener('change', function () {
        save(true);
    });

    outputMode.addEventListener('change', function () {
        if (outputMode.value) {
            window.location.href = '/' + NOTE_ID + outputMode.value;
        }
    });

    showSavedAt(meta.updatedAt);
    pickExpiry();
    updateSaveState();
    textarea.focus();
    autosave();
})();
    </script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Worker entrypoint
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const segments = url.pathname.split('/').filter(Boolean);

    if (segments.length === 0) {
      return redirect('/' + randomNoteId());
    }

    // Output is addressed by file suffix: /<id>.txt and /<id>.base64.
    // Any other suffix is an illegal file request.
    const filename = segments[0];
    let id = filename;
    let suffixMode = '';
    const dot = filename.lastIndexOf('.');
    if (dot !== -1) {
      const ext = filename.slice(dot + 1);
      id = filename.slice(0, dot);
      if (ext === 'txt') suffixMode = 'plain';
      else if (ext === 'base64') suffixMode = 'base64';
      else return badRequest();
      if (!NOTE_ID_RE.test(id)) return badRequest();
    }

    const pathMode = segments[1] ?? '';
    if (
      segments.length > 2 ||
      !NOTE_ID_RE.test(id) ||
      (segments.length === 2 && !MODE_RE.test(pathMode))
    ) {
      return notFound();
    }

    const mode = suffixMode || pathMode || url.searchParams.get('mode') || '';

    if (request.method === 'POST') return handlePost(request, env, id, mode);
    if (request.method !== 'GET' && request.method !== 'HEAD') return notFound();

    return handleGet(request, env, ctx, id, mode);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(gcExpired(env));
  },
};
