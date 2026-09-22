/**
 * Web Notepad — Cloudflare Workers Mod
 *
 * A module Worker backed by D1.
 *
 * Routes:
 *   - GET  /                     -> 302 redirect to a random 5-char note id
 *   - GET  /:note                -> HTML editor shell (empty body + meta/csrf);
 *                                    the body is then fetched by XHR
 *                                    GET /:note.txt
 *   - GET  /:note.txt            -> stored note as plain text
 *   - GET  /:note.base64         -> stored note as base64
 *   - GET  /:note.page           -> empty Markdown shell; the browser
 *                                    fetches /:note.txt by XHR and renders it
 *   - GET  /:note/:mode          -> stored note in that mode (legacy; plain,
 *                                    base64, mtime, html, css, js, json;
 *                                    unknown == raw)
 *   - unknown file suffix        -> 400
 *   - XHR GET missing .txt       -> 404 plain text (no redirect, so the
 *                                    loader can tell a new note apart)
 *   - POST /:note  (form `text`) -> save; empty `text` deletes; optional
 *                                    `new` locks an unlocked note in one step
 *   - POST /:note/expire (form `expires`) -> change expiry, keep the body
 *   - POST /:note/password (form `csrf` + `current` + `new`) -> set/change/
 *                                    cancel the password; `new` empty cancels
 *   - POST /:note  (raw body)    -> CLI save; a non-empty `X-Note-Password`
 *                                    header locks an unlocked note in one step
 *   - POST /:note/append         -> CLI append
 *   - POST /       (CLI)         -> CLI save to a new random id; receipt shows id
 *   - CLI user-agent             -> raw body, no HTML wrapper
 *   - POST /mcp                  -> MCP (Streamable HTTP, stateless, no auth);
 *                                    JSON-RPC tools: read_note, write_note,
 *                                    append_note, delete_note, set_expiry,
 *                                    set_password
 *   - GET/DELETE /mcp            -> 405
 *
 * Security:
 *   - The MCP endpoint has no authentication (same as the public notebook).
 *     To add an API key later, check a header in mcpAuthHook and return 401;
 *     tool handlers stay unchanged. MCP tools skip the browser CSRF and CLI
 *     user-agent checks (there is no browser); a locked note still needs its
 *     password, passed as a tool argument instead of a header.
 *   - A browser form save must carry the per-note CSRF token from the page.
 *   - A raw CLI write is allowed only for whitelisted user agents (curl, wget).
 *   - GET /:note returns only the empty shell (meta/csrf, no body text);
 *     the body is loaded via XHR GET /:note.txt. An XHR for a missing
 *     note gets 404; a direct navigation to a missing .txt redirects
 *     back to the editor.
 *   - Password lock: a note with is_protected=1 (plus hash/salt/algo) needs
 *     its password for every read (all modes + CLI bare GET) and every
 *     write (save/delete/append/expire). Reads take the password from the
 *     `X-Note-Password` header or the `?pw=` query (either one passing is
 *     enough); writes only take the header, never `?pw=`, so a mutated URL
 *     cannot leak into history or logs. `POST /:note/password` takes the
 *     current password from the form `current` field instead.
 *   - One-step lock: a content write may carry a new password (raw header or
 *     form `new`) only for an unlocked note; a locked note rejects form
 *     `new` with 400 (use POST /:note/password) and keeps header-as-auth.
 *   - 401 means "Password required" (plain text); 403 means bad CSRF;
 *     404 means missing/expired. Passwords never appear in bodies,
 *     receipts, JSON, or logs.
 *
 * Storage:
 *   - Bodies are zstd-compressed (node:zlib) before they are written to D1;
 *     bodies shorter than 128 bytes are stored as plain UTF-8 instead
 *     (content_encoding = 'identity').
 *   - Every row carries created_at / updated_at / expires_at; a Cron
 *     Trigger garbage-collects expired rows. Reads also lazily delete.
 *   - The web editor offers a per-note expiry choice; a CLI write that sends
 *     no choice keeps the note's existing expiry (NOTE_TTL_DAYS is only the
 *     default for a brand-new note).
 *   - Password columns (password_hash / password_salt / password_algo /
 *     is_protected) enforce the password lock: PBKDF2-SHA256 (100k
 *     iterations), 16-byte salt, 32-byte derived key, all base64. Content
 *     saves never touch the password columns, so saving keeps the lock;
 *     only POST /:note/password, a one-step write password, or a full
 *     delete changes it.
 *
 * The helper exports below are exported so they can be unit-tested with
 * plain Node; the Worker entrypoint is the default export.
 */

import zlib from 'node:zlib';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { McpServer, WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/server';
import { z } from 'zod';

const NOTE_ID_RE = /^[a-zA-Z0-9_-]+$/;
const MODE_RE = /^[a-z0-9]*$/;
const ID_ALPHABET = '234579abcdefghjkmnpqrstwxyz';
const DEFAULT_TTL_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;
/** Codec recorded in notes.content_encoding. */
const CODEC = 'zstd';
/** Bodies shorter than this many UTF-8 bytes are stored uncompressed. */
const PLAINTEXT_MAX_BYTES = 128;
/** Expiry choices shown by the web UI select; the API accepts more (see below). */
const EXPIRY_TOKENS = {
  '24h': DAY_MS,
  '72h': 3 * DAY_MS,
  '1w': 7 * DAY_MS,
};
/** Longest expiry the API accepts (10 years); longer values are rejected. */
const MAX_EXPIRY_MS = 10 * 365 * DAY_MS;
/** Unit words accepted in an expiry duration, mapped to milliseconds. */
const EXPIRY_UNIT_MS = {
  s: 1000, sec: 1000, secs: 1000, second: 1000, seconds: 1000,
  m: 60 * 1000, min: 60 * 1000, mins: 60 * 1000, minute: 60 * 1000, minutes: 60 * 1000,
  h: 60 * 60 * 1000, hr: 60 * 60 * 1000, hrs: 60 * 60 * 1000, hour: 60 * 60 * 1000, hours: 60 * 60 * 1000,
  d: DAY_MS, day: DAY_MS, days: DAY_MS,
  w: 7 * DAY_MS, week: 7 * DAY_MS, weeks: 7 * DAY_MS,
  mo: 30 * DAY_MS, mos: 30 * DAY_MS, mon: 30 * DAY_MS, month: 30 * DAY_MS, months: 30 * DAY_MS,
  y: 365 * DAY_MS, yr: 365 * DAY_MS, yrs: 365 * DAY_MS, year: 365 * DAY_MS, years: 365 * DAY_MS,
};
/** Shared hint text for expiry arguments. */
const EXPIRY_HINT = "Use 'never', or a duration like '90m', '36h', '30d', '1w2d', '6mo', '1y'.";
/** PBKDF2 iteration count for note passwords. */
const PBKDF2_ITERATIONS = 100000;
/** Algorithm tag stored in notes.password_algo; only this value is accepted. */
const PASSWORD_ALGO = 'pbkdf2-sha256-100k';
/** Salt length (bytes) and derived-key length (bits) for note passwords. */
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_KEY_BITS = 256;
/** Longest accepted new password (characters); '' on the password route cancels. */
const PASSWORD_MAX_LENGTH = 256;
/** User agents allowed to use the raw command-line write path. */
const CLI_USER_AGENTS = ['curl', 'wget'];
/** Fallback CSRF secret for local/dev; set CSRF_SECRET in production. */
const DEFAULT_CSRF_SECRET = 'web-notepad-dev-secret';

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

function textOk(body) {
  return new Response(body, {
    status: 200,
    headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
  });
}

/** Format epoch milliseconds as "YYYY-MM-DD HH:MM:SS UTC"; null means never. */
function formatUtc(ms) {
  if (ms == null) return 'never';
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

function jsonOk(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: noStore({ 'Content-Type': 'application/json; charset=utf-8' }),
  });
}

/** Pretty-printed JSON response for command-line (curl/wget) writes. */
function prettyJsonOk(value) {
  return new Response(JSON.stringify(value, null, 2) + '\n', {
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
 * Parse a free-form expiry duration like '90m', '36h', '30d', '1w2d',
 * '6mo', or '1y' into milliseconds. Returns undefined for anything that
 * is not a positive duration of at most 10 years. A bare number with no
 * unit is rejected, so '3600' never means seconds or milliseconds by
 * accident. The web UI only offers a few choices, but the API takes any
 * value this function accepts.
 */
export function parseExpiryDuration(raw) {
  if (typeof raw !== 'string') return undefined;
  const text = raw.trim().toLowerCase();
  if (!text) return undefined;
  const re =
    /\s*(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|months?|mos?|mon|m|hours?|hrs?|hr|h|days?|d|weeks?|w|years?|yrs?|yr|y)/gy;
  let total = 0;
  let count = 0;
  let pos = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    const unit = EXPIRY_UNIT_MS[m[2]];
    if (unit === undefined) return undefined;
    total += parseFloat(m[1]) * unit;
    count++;
    if (count > 16) return undefined;
    pos = re.lastIndex;
  }
  // Note: a failed exec resets re.lastIndex to 0, so the end position is
  // kept in pos instead.
  if (!count || !/^\s*$/.test(text.slice(pos))) return undefined;
  if (!Number.isFinite(total)) return undefined;
  const ms = Math.round(total);
  if (ms <= 0 || ms > MAX_EXPIRY_MS) return undefined;
  return ms;
}

/**
 * Map an expiry argument to a `saveNote`/`setNoteExpiry` `expires` value.
 * `undefined` means "no choice" (keep the note's current expiry, or use
 * NOTE_TTL_DAYS for a new note); `null` means "never expires". Besides the
 * web-UI tokens ('24h', '72h', '1w') and 'never', any duration that
 * `parseExpiryDuration` accepts works too ('90m', '36h', '30d', ...).
 * Anything else is also `undefined`, so callers that need to tell "bad
 * value" apart from "no choice" must check the raw input first.
 */
export function resolveExpiryToken(token) {
  if (token == null) return undefined;
  const text = String(token).trim();
  if (text === '') return undefined;
  if (text === 'never') return null;
  if (Object.prototype.hasOwnProperty.call(EXPIRY_TOKENS, text)) return EXPIRY_TOKENS[text];
  return parseExpiryDuration(text);
}

/**
 * Decompress bytes back to a UTF-8 string. `encoding` is the value stored in
 * notes.content_encoding. `zstd` is current; `gzip` and `identity` (or the
 * legacy `none`) are still decoded so older rows stay readable. Any other
 * value is rejected instead of being guessed.
 */
export function decompress(bytes, encoding = CODEC) {
  const input = toBytes(bytes);
  switch (encoding) {
    case 'gzip':
      return decoder.decode(zlib.gunzipSync(input));
    case 'identity':
    case 'none':
      return decoder.decode(input);
    case 'zstd':
      return decoder.decode(zlib.zstdDecompressSync(input));
    default:
      throw new Error(`Unknown content_encoding: ${encoding}`);
  }
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
    `SELECT id, content, content_encoding, created_at, updated_at, expires_at, is_protected,
            password_hash, password_salt, password_algo
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
 * Load only a note's metadata (no body BLOB, no decompression) for the HTML
 * shell. Returns null when missing, or { expired: true, row } when past
 * expires_at (the caller schedules the delete and treats it as null),
 * matching loadNote's expiry semantics.
 */
async function loadNoteMeta(env, id) {
  const row = await env.DB.prepare(
    `SELECT id, created_at, updated_at, expires_at, is_protected,
            password_hash, password_salt, password_algo
       FROM notes WHERE id = ? LIMIT 1`,
  ).bind(id).first();

  if (!row) return null;
  if (row.expires_at != null && row.expires_at < Date.now()) return { expired: true, row };

  return { expired: false, row };
}

/**
 * Insert or update a note. Short bodies are stored as plain UTF-8; larger ones
 * are zstd-compressed. expires_at rules:
 *   - `expires` as a number  -> now + that many ms (an explicit choice wins)
 *   - `expires === null`     -> never expires (an explicit "never" wins)
 *   - `expires` undefined    -> keep the current expiry on update; a new note
 *                               falls back to NOTE_TTL_DAYS (0 = never expires)
 */
async function saveNote(env, id, text, { append = false, expires } = {}) {
  const now = Date.now();
  const explicitExpiry = expires !== undefined;

  let base = '';
  if (append) {
    const existing = await loadNote(env, id);
    if (existing && !existing.expired) base = existing.text;
  }

  let expiresAt;
  if (expires === null) {
    expiresAt = null;
  } else if (typeof expires === 'number') {
    expiresAt = now + expires;
  } else {
    const ttlDays = Number(env.NOTE_TTL_DAYS ?? DEFAULT_TTL_DAYS);
    expiresAt = ttlDays > 0 ? now + ttlDays * DAY_MS : null;
  }

  const body = append ? base + text : text;

  const { bytes, encoding, rawSize } = encodeForStorage(body);

  // Only write expires_at on an explicit choice. Otherwise the UPDATE leaves the
  // stored expiry alone, so a content save cannot clobber a concurrent
  // expiry-only change (no read-modify-write race). The INSERT value is the
  // default TTL, used only when this creates a brand-new note.
  const assignments = [
    'content          = excluded.content',
    'content_encoding = excluded.content_encoding',
    'size_raw         = excluded.size_raw',
    'size_stored      = excluded.size_stored',
    'updated_at       = excluded.updated_at',
  ];
  if (explicitExpiry) assignments.push('expires_at       = excluded.expires_at');

  await env.DB.prepare(
    `INSERT INTO notes
       (id, content, content_encoding, size_raw, size_stored,
        created_at, updated_at, expires_at, is_protected)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
     ON CONFLICT(id) DO UPDATE SET
       ${assignments.join(',\n       ')}`,
  ).bind(id, bytes, encoding, rawSize, bytes.byteLength, now, now, expiresAt).run();

  if (!explicitExpiry) {
    // Report the expiry the row actually has now, not the insert default.
    const row = await env.DB.prepare(
      'SELECT expires_at FROM notes WHERE id = ? LIMIT 1',
    ).bind(id).first();
    return { updatedAt: now, expiresAt: row ? (row.expires_at ?? null) : null };
  }
  return { updatedAt: now, expiresAt };
}

/**
 * Change only a note's expiry. Content and updated_at are left untouched.
 * `expires` is a number of ms from now, or `null` for "never". Returns null
 * when the note does not exist.
 */
async function setNoteExpiry(env, id, expires) {
  const now = Date.now();
  const row = await env.DB.prepare(
    'SELECT created_at, updated_at, expires_at FROM notes WHERE id = ? LIMIT 1',
  ).bind(id).first();
  if (!row) return null;
  // Treat an already-expired note as missing, matching loadNote, so an expired
  // note cannot be revived by extending its expiry.
  if (row.expires_at != null && row.expires_at < now) return null;
  const expiresAt = expires === null ? null : now + expires;
  await env.DB.prepare('UPDATE notes SET expires_at = ? WHERE id = ?')
    .bind(expiresAt, id).run();
  return {
    createdAt: row.created_at ?? null,
    updatedAt: row.updated_at ?? null,
    expiresAt,
  };
}

/**
 * Pick a random note id that is not already taken. Used by the root POST path so
 * a CLI upload cannot silently overwrite an existing note. Retries a few times;
 * a collision after that is vanishingly unlikely.
 */
async function freshNoteId(env) {
  for (let i = 0; i < 5; i++) {
    const id = randomNoteId();
    const row = await env.DB.prepare('SELECT id FROM notes WHERE id = ? LIMIT 1')
      .bind(id).first();
    if (!row) return id;
  }
  return randomNoteId();
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

/**
 * True for link-preview crawlers (Telegram, X/Twitter, Facebook, LinkedIn,
 * Discord, Slack, WhatsApp). They never run the `.page` loader JS, so any
 * 200 shell they fetch becomes a saved preview. Locked notes must 401 them
 * instead — otherwise a link pasted to chat generates a preview entry for a
 * note the chat cannot open.
 */
const PREVIEW_BOT_RE =
  /telegrambot|twitterbot|facebookexternalhit|facebot|linkedinbot|discordbot|slackbot|whatsapp/i;
function isPreviewBot(userAgent) {
  return PREVIEW_BOT_RE.test(userAgent || '');
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
// Note passwords (PBKDF2-SHA256, WebCrypto subtle; no new dependencies)
// ---------------------------------------------------------------------------

/**
 * Hash a password with a fresh random salt. Returns base64 strings plus the
 * algorithm tag, ready for the notes columns.
 */
export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(PASSWORD_SALT_BYTES));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    key,
    PASSWORD_KEY_BITS,
  );
  return {
    hash_b64: Buffer.from(bits).toString('base64'),
    salt_b64: Buffer.from(salt).toString('base64'),
    algo: PASSWORD_ALGO,
  };
}

/**
 * Check a password against a notes row. Only our own algorithm tag is
 * accepted; any malformed row fails closed (returns false, never throws).
 */
export async function verifyPassword(password, row) {
  try {
    if (!row || row.password_algo !== PASSWORD_ALGO) return false;
    if (typeof row.password_hash !== 'string' || typeof row.password_salt !== 'string') {
      return false;
    }
    if (!row.password_hash || !row.password_salt) return false;
    const expected = Buffer.from(row.password_hash, 'base64');
    const salt = new Uint8Array(Buffer.from(row.password_salt, 'base64'));
    if (expected.length === 0 || salt.length === 0) return false;
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, [
      'deriveBits',
    ]);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      key,
      PASSWORD_KEY_BITS,
    );
    const actual = Buffer.from(bits);
    if (actual.length !== expected.length) return false;
    return timingSafeEqual(actual, expected);
  } catch (err) {
    return false;
  }
}

/**
 * True only when the row is locked: is_protected=1 AND the hash, salt, and
 * algorithm columns are all present. Anything else reads/writes as public.
 */
function isProtectedRow(row) {
  return (
    !!row &&
    row.is_protected === 1 &&
    !!row.password_hash &&
    !!row.password_salt &&
    !!row.password_algo
  );
}

/**
 * Read credential: the `X-Note-Password` header wins when non-empty,
 * otherwise the `?pw=` query value (not trimmed). Both missing means ''.
 */
function getReadPassword(request, url) {
  const header = request.headers.get('X-Note-Password');
  if (header != null && header !== '') return header;
  const query = url.searchParams.get('pw');
  if (query != null && query !== '') return query;
  return '';
}

/** Uniform 401 for a locked note: plain text, no password anywhere in it. */
function passwordRequired() {
  return new Response('Password required', {
    status: 401,
    headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
  });
}

/**
 * Read gate for a loaded row. Returns a 401 Response when the row is locked
 * and neither credential passes; null when the read may proceed (public
 * notes ignore any credential). Header and query are OR: a wrong header
 * never shadows a correct ?pw=, and vice versa.
 */
async function checkReadPassword(request, url, row) {
  if (!isProtectedRow(row)) return null;
  const first = getReadPassword(request, url);
  if (first && (await verifyPassword(first, row))) return null;
  const header = request.headers.get('X-Note-Password') || '';
  const query = url.searchParams.get('pw') || '';
  const second = first === header ? query : header;
  if (second && second !== first && (await verifyPassword(second, row))) return null;
  return passwordRequired();
}

/**
 * Write gate for POST /:note, /:note/append, and /:note/expire. Only the
 * `X-Note-Password` header counts (never `?pw=`). Returns a 401 Response on
 * failure, null when the write may proceed. Missing rows pass (creation is
 * always allowed); a wrong password never reveals more than the 401.
 */
async function checkWritePassword(env, request, id) {
  const found = await loadNoteMeta(env, id);
  const row = found ? found.row : null;
  if (!isProtectedRow(row)) return null;
  const password = request.headers.get('X-Note-Password') || '';
  if (!password) return passwordRequired();
  return (await verifyPassword(password, row)) ? null : passwordRequired();
}

/**
 * Lock a note with a fresh password (new salt + hash). Only touches the
 * password columns plus updated_at; content/expiry/created_at are left
 * alone. The caller must have validated length and lock state. Returns the
 * updated_at timestamp written. Never logs or returns the password itself.
 */
async function setNotePassword(env, id, newPw) {
  const secret = await hashPassword(newPw);
  const now = Date.now();
  await env.DB.prepare(
    `UPDATE notes SET is_protected = 1, password_hash = ?,
                      password_salt = ?, password_algo = ?, updated_at = ?
       WHERE id = ?`,
  ).bind(secret.hash_b64, secret.salt_b64, secret.algo, now, id).run();
  return now;
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/**
 * Pretty JSON receipt for a command-line write (curl/wget): confirms the
 * save, prints the save time, and lists the read URLs.
 */
function cliReceipt(url, id, verb, updatedAt, expiresAt) {
  return prettyJsonOk({
    status: verb.toLowerCase(),
    note: id,
    saved: formatUtc(updatedAt),
    expires: formatUtc(expiresAt),
    plain: `${url.origin}/${id}.txt`,
    base64: `${url.origin}/${id}.base64`,
    page: `${url.origin}/${id}.page`,
    editor: `${url.origin}/${id}`,
  });
}

function cliDeleted(id) {
  return prettyJsonOk({ status: 'deleted', note: id });
}

async function handlePost(request, env, ctx, id, mode) {
  const contentType = request.headers.get('content-type') || '';
  const userAgent = request.headers.get('user-agent') || '';
  const cli = isCliUserAgent(userAgent);
  const raw = await request.text();
  const url = new URL(request.url);

  // Password set/change/cancel: `POST /:note/password` with form fields
  // `csrf`, `current` (needed only when locked), and `new` (`''` cancels).
  // Order: missing/expired -> 404, wrong current -> 401, bad CSRF -> 403.
  if (mode === 'password') {
    let found = await loadNoteMeta(env, id);
    if (found && found.expired) {
      ctx.waitUntil(deleteNote(env, id));
      found = null;
    }
    if (!found) return notFound();
    const params = new URLSearchParams(raw);
    if (!params.has('new')) return badRequest();
    const updated = params.get('new') ?? '';
    if (updated.length > PASSWORD_MAX_LENGTH) return badRequest();
    if (isProtectedRow(found.row)) {
      const current = params.get('current') ?? '';
      if (!(await verifyPassword(current, found.row))) return passwordRequired();
    }
    if (!cli && !verifyCsrf(env, id, params.get('csrf'))) return forbidden();
    const now = Date.now();
    let locked;
    let stamp = now;
    if (updated === '') {
      await env.DB.prepare(
        `UPDATE notes SET is_protected = 0, password_hash = NULL,
                          password_salt = NULL, password_algo = NULL, updated_at = ?
           WHERE id = ?`,
      ).bind(now, id).run();
      locked = false;
    } else {
      stamp = await setNotePassword(env, id, updated);
      locked = true;
    }
    if (cli) {
      return prettyJsonOk({
        status: locked ? 'password set' : 'protection removed',
        note: id,
        protected: locked,
      });
    }
    return jsonOk({ protected: locked, updated_at: stamp });
  }

  // Write gate: a locked note needs the right `X-Note-Password` header for
  // every content/expiry write (?pw= never counts here).
  const writeDeny = await checkWritePassword(env, request, id);
  if (writeDeny) return writeDeny;

  // Expiry-only update: `POST /:note/expire` with form `expires`. The body is
  // left untouched. This is a dedicated route so a raw CLI body that happens to
  // start with `expires=` is still stored as text.
  if (mode === 'expire') {
    const params = new URLSearchParams(raw);
    if (!cli && !verifyCsrf(env, id, params.get('csrf'))) return forbidden();
    const expires = resolveExpiryToken(params.get('expires'));
    if (expires === undefined) return badRequest();
    const saved = await setNoteExpiry(env, id, expires);
    if (!saved) return notFound();
    if (cli) return cliReceipt(url, id, 'Expiry set', saved.updatedAt, saved.expiresAt);
    return jsonOk({
      created_at: saved.createdAt,
      updated_at: saved.updatedAt,
      expires_at: saved.expiresAt,
    });
  }

  // Web (form) save path: the autosave XHR posts `text=...` (and `expires=...`).
  // A browser must send the per-note CSRF token from the page. Whitelisted CLI
  // tools may skip it so `curl -d 'text=...'` keeps working. Optional `new`
  // sets a password in the same write, but only on an unlocked note; on a
  // locked note any `new` is rejected (use POST /:note/password instead).
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(raw);
    if (params.has('text')) {
      const formRow = (await loadNoteMeta(env, id))?.row ?? null;
      const formLocked = isProtectedRow(formRow);
      if (formLocked && params.has('new')) return badRequest();
      if (!cli && !verifyCsrf(env, id, params.get('csrf'))) return forbidden();
      const text = params.get('text') ?? '';
      if (text.length === 0) {
        // Delete ignores `new` on an unlocked note; a locked note already
        // passed the 401 gate above and rejects any `new` with 400.
        await deleteNote(env, id);
        return cli ? cliDeleted(id) : jsonOk({ deleted: true });
      }
      let setPw = '';
      if (!formLocked && params.has('new')) {
        setPw = params.get('new') ?? '';
        if (setPw.length > PASSWORD_MAX_LENGTH) return badRequest();
      }
      const expires = resolveExpiryToken(params.get('expires'));
      const saved = await saveNote(env, id, text, { expires });
      if (setPw !== '') await setNotePassword(env, id, setPw);
      if (cli) return cliReceipt(url, id, 'Saved', saved.updatedAt, saved.expiresAt);
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
  // One-step lock: on an unlocked note a non-empty `X-Note-Password` header
  // becomes the password after the content is saved (overlong -> 400, nothing
  // saved). On a locked note the header was already consumed as auth above.
  if (!cli) return forbidden();
  const append = mode === 'append';
  const rawRow = (await loadNoteMeta(env, id))?.row ?? null;
  let rawPw = '';
  if (!isProtectedRow(rawRow)) {
    rawPw = request.headers.get('X-Note-Password') || '';
    if (rawPw.length > PASSWORD_MAX_LENGTH) return badRequest();
  }
  const saved = append
    ? await saveNote(env, id, raw, { append: true })
    : await saveNote(env, id, raw);
  if (rawPw !== '') await setNotePassword(env, id, rawPw);
  return cliReceipt(url, id, append ? 'Appended' : 'Saved', saved.updatedAt, saved.expiresAt);
}

function modeResponse(loaded, mode, extra) {
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
    case 'page': {
      // Body-free shell: the text is never loaded for `.page`. Only the row
      // metadata (id, dates) feeds the shell. Locked notes get the same shell;
      // the browser loader prompts for the password when `.txt` 401s.
      const row = loaded.row || {};
      const origin = (extra && extra.origin) || '';
      const userAgent = (extra && extra.userAgent) || '';
      const headers = noStore({ 'Content-Type': 'text/html; charset=utf-8' });
      // TelegramBot honours a remembered noindex as "no preview", so omit
      // X-Robots-Tag only for its .page fetches (case-insensitive UA sniff);
      // browsers and search crawlers keep the noindex default. The preview
      // carries only the id-based title/description (crawlers do not run the
      // loader JS, so no body excerpt is possible). Cache-Control: no-store
      // is always kept.
      if (/telegrambot/i.test(userAgent)) delete headers['X-Robots-Tag'];
      return new Response(
        renderPageView(row.id, { createdAt: row.created_at, updatedAt: row.updated_at, expiresAt: row.expires_at }, origin),
        { headers },
      );
    }
    default:
      return new Response(text, { headers: headers(plain) });
  }
}

async function handleGet(request, env, ctx, id, mode) {
  const url = new URL(request.url);
  if (mode === 'page') {
    // Shell-only path: existence check only, no body BLOB is fetched or
    // decompressed. Missing notes keep the `.txt` semantics (XHR 404 for the
    // loader, 302 back to the editor for a direct navigation). Locked notes
    // get the same empty shell (200); the loader fetches `.txt` and prompts
    // for the password on 401, mirroring the editor flow. The one exception
    // is link-preview crawlers: they never run JS, so a 200 shell would be
    // saved as a preview entry for a note the chat cannot open — a locked
    // note 401s them instead (a valid `?pw=` still passes, same as `.txt`).
    let found = await loadNoteMeta(env, id);
    if (found && found.expired) {
      ctx.waitUntil(deleteNote(env, id));
      found = null;
    }
    if (!found) {
      if (request.headers.get('X-Requested-With') === 'XMLHttpRequest') return notFound();
      return redirect('/' + id);
    }
    if (isProtectedRow(found.row) && isPreviewBot(request.headers.get('user-agent'))) {
      const botDeny = await checkReadPassword(request, url, found.row);
      if (botDeny) return botDeny;
    }
    return modeResponse({ row: found.row, text: '' }, mode, {
      origin: url.origin,
      userAgent: request.headers.get('user-agent') || '',
    });
  }
  if (mode) {
    let loaded = await loadNote(env, id);
    if (loaded && loaded.expired) {
      ctx.waitUntil(deleteNote(env, id));
      loaded = null;
    }

    if (!loaded) {
      // XHR content loads need a 404 to tell "new note" apart; a direct
      // navigation to a missing .txt goes back to the editor instead.
      if (request.headers.get('X-Requested-With') === 'XMLHttpRequest') return notFound();
      return redirect('/' + id);
    }
    const readDeny = await checkReadPassword(request, url, loaded.row);
    if (readDeny) return readDeny;
    return modeResponse(loaded, mode, {
      origin: url.origin,
      userAgent: request.headers.get('user-agent') || '',
    });
  }

  const userAgent = request.headers.get('user-agent') || '';
  if (isCliUserAgent(userAgent)) {
    let loaded = await loadNote(env, id);
    if (loaded && loaded.expired) {
      ctx.waitUntil(deleteNote(env, id));
      loaded = null;
    }
    if (loaded) {
      const readDeny = await checkReadPassword(request, url, loaded.row);
      if (readDeny) return readDeny;
    }
    return new Response(loaded ? loaded.text : '', {
      status: 200,
      headers: noStore({ 'Content-Type': 'text/plain; charset=utf-8' }),
    });
  }

  // Browser shell: metadata only, no body BLOB decompression. The body is
  // fetched after page load via XHR GET /:note.txt. The shell is always 200;
  // meta only says whether the note is protected (never any hash material).
  let metaLoaded = await loadNoteMeta(env, id);
  if (metaLoaded && metaLoaded.expired) {
    ctx.waitUntil(deleteNote(env, id));
    metaLoaded = null;
  }

  const meta = metaLoaded
    ? {
        createdAt: metaLoaded.row.created_at ?? null,
        updatedAt: metaLoaded.row.updated_at ?? null,
        expiresAt: metaLoaded.row.expires_at ?? null,
        protected: isProtectedRow(metaLoaded.row),
      }
    : { createdAt: null, updatedAt: null, expiresAt: null, protected: false };
  meta.csrf = csrfToken(env, id);
  return new Response(renderPage(id, '', meta), {
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
    <meta name="generator" content="Web Notepad Workers Mod">
    <title>${escapeHtml(id)}</title>
    <link rel="shortcut icon" href="/favicon.ico">
    <style>
/*! Web Notepad Workers Mod */

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
.toolbar {
    flex-wrap: wrap;
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
    width: 28px;
    height: 28px;
    padding: 0;
    font-size: 15px;
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
select:focus-visible {
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
select:disabled {
    color: #b3b9c0;
    background: #f0f2f4;
    cursor: not-allowed;
    opacity: 0.6;
}
/* Keep every toolbar control on the same 28px baseline as button.icon and
   #font-size. Scoped to .toolbar so the status bar select is untouched. */
.toolbar select {
    height: 28px;
    padding-top: 0;
    padding-bottom: 0;
}
#lock-note {
    font: inherit;
    font-size: 12px;
    color: inherit;
    background: #fff;
    border: 1px solid #d3d8de;
    border-radius: 6px;
    padding: 4px 8px;
    cursor: pointer;
    white-space: nowrap;
}
#lock-note:hover {
    background: #f2f4f7;
}
#lock-note:focus-visible {
    outline: 2px solid #5b8def;
    outline-offset: 1px;
}
.sep {
    width: 1px;
    align-self: stretch;
    background: #d3d8de;
    margin: 2px 4px;
}
.fontsize {
    display: inline-flex;
    align-items: center;
    gap: 4px;
}
#font-size {
    width: 3.5em;
    height: 28px;
    padding: 0 2px;
    text-align: center;
    font: inherit;
    font-size: 13px;
    color: inherit;
    background: #fff;
    border: 1px solid #d3d8de;
    border-radius: 6px;
}
main {
    flex: 1 1 auto;
    min-height: 0;
    display: flex;
    padding: 0 12px;
}
.editor {
    flex: 1 1 auto;
    min-height: 0;
    display: flex;
    overflow: hidden;
    background: #fff;
    border: 1px solid #d3d8de;
    border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    font-size: 100%;
    line-height: 1.5;
}
.editor:focus-within {
    border-color: #5b8def;
}
.gutter {
    flex: 0 0 auto;
    overflow: hidden;
    padding: 16px 8px;
    background: #f6f8fa;
    border-right: 1px solid #e6e9ed;
    color: #9aa4af;
    text-align: right;
    user-select: none;
}
.gutter-lines {
    margin: 0;
    font: inherit;
    line-height: inherit;
    white-space: pre;
    text-align: right;
    will-change: transform;
}
#content {
    flex: 1 1 auto;
    width: 100%;
    margin: 0;
    padding: 16px;
    background: transparent;
    font: inherit;
    tab-size: 4;
    white-space: pre;
    overflow: auto;
    resize: none;
    border: 0;
    outline: none;
}
#printable {
    display: none;
}

/* Command-line help overlay */
.modal-overlay {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    z-index: 20;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
    background: rgba(20, 24, 30, 0.55);
}
.modal-overlay[hidden] {
    display: none;
}
.modal-card {
    display: flex;
    flex-direction: column;
    width: 100%;
    max-width: 560px;
    max-height: 85vh;
    overflow: hidden;
    background: #fff;
    color: #222;
    border: 1px solid #d3d8de;
    border-radius: 10px;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.28);
}
.modal-head {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    border-bottom: 1px solid #e6e9ed;
}
.modal-head h2 {
    flex: 1 1 auto;
    margin: 0;
    font-size: 15px;
    font-weight: 600;
}
.modal-hint {
    flex: 0 0 auto;
    margin: 0;
    padding: 10px 14px 0;
    font-size: 12px;
    color: #66707a;
}
#cli-help-code {
    flex: 1 1 auto;
    margin: 0;
    padding: 12px 14px 16px;
    overflow: auto;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    font-size: 12px;
    line-height: 1.6;
    white-space: pre;
}

@media (prefers-color-scheme: dark) {
    body {
        background: #383934;
        color: #f8f8f2;
    }
    button.icon,
    select,
    #font-size {
        background: #282923;
        border-color: #4a4b45;
    }
    select:disabled {
        color: #6b6d66;
        background: #23241f;
    }
    #lock-note {
        background: #282923;
        border-color: #4a4b45;
    }
    #lock-note:hover {
        background: #33342d;
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
    .editor {
        background: #282923;
        border-color: #4a4b45;
    }
    .gutter {
        background: #23241f;
        border-right-color: #3a3b35;
        color: #6b6d66;
    }
    .sep {
        background: #4a4b45;
    }
    #content {
        color: #f8f8f2;
    }
    .statusbar {
        color: #b6b7ae;
    }
    .modal-card {
        background: #282923;
        color: #f8f8f2;
        border-color: #4a4b45;
    }
    .modal-head {
        border-bottom-color: #3a3b35;
    }
    .modal-hint {
        color: #b6b7ae;
    }
}

@media (max-width: 560px) {
    .gutter {
        display: none;
    }
    .modal-overlay {
        padding: 10px;
    }
    .modal-card {
        max-height: 90vh;
    }
    #cli-help-code {
        font-size: 11px;
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
    .modal-overlay,
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
        <span class="sep" role="separator" aria-orientation="vertical"></span>
        <button type="button" class="icon" id="copy-note" title="Copy" aria-label="Copy">🗐</button>
        <button type="button" class="icon" id="paste-note" title="Paste" aria-label="Paste">📋</button>
        <span class="sep" role="separator" aria-orientation="vertical"></span>
        <div class="fontsize" role="group" aria-label="Font size">
            <button type="button" class="icon" id="font-decrease" title="Smaller text" aria-label="Smaller text">−</button>
            <input type="text" id="font-size" inputmode="numeric" maxlength="2" value="16" aria-label="Font size">
            <button type="button" class="icon" id="font-increase" title="Larger text" aria-label="Larger text">+</button>
        </div>
        <span class="grow"></span>
        <select id="output-mode" aria-label="Output format"${meta.createdAt == null ? ' disabled' : ''}>
            <option value="" selected disabled>Output&hellip;</option>
            <option value=".txt">Plain text</option>
            <option value=".base64">Base64</option>
            <option value=".page">Markdown page</option>
        </select>
        <button type="button" class="icon" id="cli-help" title="Command-line help" aria-label="Command-line help">⌨</button>
    </header>
    <main>
        <div class="editor" id="editor">
            <div class="gutter" id="gutter" aria-hidden="true"><pre class="gutter-lines" id="gutter-lines">1</pre></div>
            <textarea id="content" wrap="off" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" placeholder="Loading…" disabled></textarea>
        </div>
    </main>
    <footer class="statusbar">
        <span id="saved-at">Loading…</span>
        <button type="button" id="lock-note" title="Password protection" aria-label="Password protection">${meta.protected ? '🔒 Protected' : '○ Public'}</button>
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
    <div class="modal-overlay" id="cli-help-overlay" hidden>
        <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="cli-help-title">
            <div class="modal-head">
                <h2 id="cli-help-title">Command line</h2>
                <button type="button" class="icon" id="cli-help-close" title="Close" aria-label="Close">×</button>
            </div>
            <p class="modal-hint">Use <code>curl</code> with this note URL. A <code>curl</code> or <code>wget</code> user agent gets the raw text.</p>
            <pre id="cli-help-code"></pre>
        </div>
    </div>
    <script>
/*! Web Notepad Workers Mod */
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
    var gutter = document.getElementById('gutter');
    var gutterLines = document.getElementById('gutter-lines');
    var editor = document.getElementById('editor');
    var fontSizeInput = document.getElementById('font-size');
    var fontDecrease = document.getElementById('font-decrease');
    var fontIncrease = document.getElementById('font-increase');
    var copyButton = document.getElementById('copy-note');
    var pasteButton = document.getElementById('paste-note');
    var lockButton = document.getElementById('lock-note');
    var helpButton = document.getElementById('cli-help');
    var helpOverlay = document.getElementById('cli-help-overlay');
    var helpClose = document.getElementById('cli-help-close');
    var helpCode = document.getElementById('cli-help-code');

    var meta;
    try {
        meta = JSON.parse(document.getElementById('note-meta').textContent || '{}') || {};
    } catch (err) {
        meta = {};
    }

    var content = textarea.value;
    var saving = false;
    var dirty = false;
    var contentLoading = true;

    // Make the content available to print.
    printable.appendChild(document.createTextNode(content));

    function updatePrintable(value) {
        while (printable.firstChild) printable.removeChild(printable.firstChild);
        printable.appendChild(document.createTextNode(value));
    }

    // Password lock state. The cleartext password lives in memory; a copy
    // goes to localStorage only after the server accepts it (HTTP 200).
    // A 401/403 wipes the stored copy.
    var notePw = '';
    var pwFromUrl = false;
    var pwPrompted = false;
    var pwLocked = false;

    function pwKey() {
        return 'web-notepad-pw-' + NOTE_ID;
    }

    function storePw(pw) {
        try {
            window.localStorage.setItem(pwKey(), pw);
        } catch (err) {
            // Storage can be blocked; the memory copy still works.
        }
    }

    function clearStoredPw() {
        try {
            window.localStorage.removeItem(pwKey());
        } catch (err) {
            // Nothing to clean up.
        }
    }

    // Read ?pw= with a hand-rolled parser (no modern query helper, so old
    // browsers work): manual parse of location.search, first pw key wins,
    // %-decoded.
    function queryPw() {
        try {
            var s = window.location.search || '';
            if (s.charAt(0) === '?') s = s.slice(1);
            var parts = s.split('&');
            for (var i = 0; i < parts.length; i++) {
                var kv = parts[i];
                var eq = kv.indexOf('=');
                var k = eq === -1 ? kv : kv.slice(0, eq);
                if (k === 'pw') {
                    var v = eq === -1 ? '' : kv.slice(eq + 1);
                    if (!v) return '';
                    try {
                        return decodeURIComponent(v.replace(/\\+/g, ' '));
                    } catch (err2) {
                        return v;
                    }
                }
            }
        } catch (err) {
            // No query string available.
        }
        return '';
    }

    // Drop ?pw= from the address bar after it proved valid (success path).
    function stripQueryPw() {
        pwFromUrl = false;
        try {
            if (window.history && window.history.replaceState) {
                window.history.replaceState(null, '', '/' + NOTE_ID);
            }
        } catch (err) {
            // History may be unavailable; the ?pw= simply stays.
        }
    }

    function updateLockUI() {
        if (!lockButton) return;
        if (meta.protected) {
            lockButton.textContent = '🔒 Protected';
            lockButton.title = 'Password protected — click to change';
        } else {
            lockButton.textContent = '○ Public';
            lockButton.title = 'No password — click to set one';
        }
    }

    // Park the editor in "locked" state: no editing until the lock is
    // clicked again with the right password.
    function lockForPassword() {
        pwLocked = true;
        textarea.disabled = true;
        textarea.placeholder = 'Password required — click lock to retry';
        savedAtEl.textContent = 'Password required';
        saveButton.disabled = true;
        contentLoading = false;
        updateLockUI();
    }

    try {
        notePw = window.localStorage.getItem(pwKey()) || '';
    } catch (err) {
        notePw = '';
    }
    var urlPw = queryPw();
    if (!notePw && urlPw) {
        notePw = urlPw;
        pwFromUrl = true;
    }

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
        if (contentLoading) {
            saveButton.disabled = true;
            return;
        }
        saveButton.disabled = textarea.value === content;
    }

    function updateOutputState() {
        outputMode.disabled = meta.createdAt == null;
    }

    var gutterLineHeight = 0;

    // Draw only the line numbers near the viewport, then shift them to match
    // the textarea scroll position.
    function updateGutter() {
        if (!gutter || !gutterLines || !window.getComputedStyle) return;
        if (!gutterLineHeight) {
            var measured = parseFloat(window.getComputedStyle(gutterLines).lineHeight);
            gutterLineHeight = measured > 0 ? measured : 24;
        }

        var value = textarea.value;
        var total = 1;
        for (var i = 0; i < value.length; i++) {
            if (value.charCodeAt(i) === 10) total++;
        }
        gutter.style.width = 'calc(' + Math.max(2, String(total).length) + 'ch + 18px)';

        var lineHeight = gutterLineHeight;
        var first = Math.max(0, Math.floor(textarea.scrollTop / lineHeight));
        var rows = Math.ceil((textarea.clientHeight || 0) / lineHeight) + 1;
        var last = Math.min(total, first + rows);

        var numbers = [];
        for (var n = first + 1; n <= last; n++) numbers.push(n);
        gutterLines.textContent = numbers.join('\\n');
        gutterLines.style.transform = 'translateY(' + (first * lineHeight - textarea.scrollTop) + 'px)';
    }

    var FONT_MIN = 10;
    var FONT_MAX = 40;
    var FONT_KEY = 'web-notepad-font-size';

    function applyFontSize(px) {
        var size = Math.max(FONT_MIN, Math.min(FONT_MAX, Math.round(px) || 16));
        editor.style.fontSize = size + 'px';
        fontSizeInput.value = String(size);
        gutterLineHeight = 0; // line height changed; re-measure the gutter
        updateGutter();
        try {
            window.localStorage.setItem(FONT_KEY, String(size));
        } catch (err) {
            // Storage can be blocked; the size still applies for this page.
        }
    }

    function stepFontSize(delta) {
        var current = parseInt(fontSizeInput.value, 10);
        if (isNaN(current)) current = 16;
        applyFontSize(current + delta);
    }

    function initFontSize() {
        var saved = null;
        try {
            saved = window.localStorage.getItem(FONT_KEY);
        } catch (err) {
            saved = null;
        }
        applyFontSize(saved ? parseInt(saved, 10) : 16);
    }

    function insertAtCursor(text) {
        var start = textarea.selectionStart || 0;
        var end = textarea.selectionEnd || 0;
        var value = textarea.value;
        textarea.value = value.slice(0, start) + text + value.slice(end);
        var caret = start + text.length;
        textarea.selectionStart = caret;
        textarea.selectionEnd = caret;
        updateSaveState();
        updateGutter();
        textarea.focus();
    }

    function copyFromEditor() {
        var value = textarea.value;
        var start = textarea.selectionStart || 0;
        var end = textarea.selectionEnd || 0;
        if (end > start) value = value.slice(start, end);

        var clipboard = window.navigator && window.navigator.clipboard;
        if (clipboard && clipboard.writeText) {
            clipboard.writeText(value).catch(function () {});
            return;
        }
        // Fallback for browsers without the async Clipboard API.
        textarea.focus();
        textarea.select();
        try {
            document.execCommand('copy');
        } catch (err) {
            // Nothing else we can do here.
        }
    }

    function pasteIntoEditor() {
        var clipboard = window.navigator && window.navigator.clipboard;
        if (!clipboard || !clipboard.readText) {
            window.alert('Paste is not supported here. Use Ctrl/Cmd+V.');
            return;
        }
        clipboard.readText().then(function (text) {
            if (text) insertAtCursor(text);
        }).catch(function () {
            window.alert('Could not read the clipboard. Use Ctrl/Cmd+V.');
        });
    }

    function send(body, onDone, url) {
        var request = new XMLHttpRequest();
        request.open('POST', url || window.location.href, true);
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        if (notePw) request.setRequestHeader('X-Note-Password', notePw);
        request.onload = function () {
            var ok = request.readyState === 4 && request.status >= 200 && request.status < 300;
            if (ok) {
                try {
                    var data = JSON.parse(request.responseText);
                    if (data && data.deleted) {
                        meta.createdAt = null;
                        meta.updatedAt = null;
                        meta.expiresAt = null;
                        meta.protected = false;
                        notePw = '';
                        pwFromUrl = false;
                        clearStoredPw();
                        updateLockUI();
                        showSavedAt(null);
                        updateOutputState();
                    } else if (data && data.updated_at != null) {
                        meta.createdAt = data.created_at;
                        meta.updatedAt = data.updated_at;
                        meta.expiresAt = data.expires_at;
                        showSavedAt(data.updated_at);
                        updateOutputState();
                    }
                } catch (err) {
                    // Non-JSON responses are ignored.
                }
                if (notePw) storePw(notePw);
                if (pwFromUrl) stripQueryPw();
            }
            if (request.status === 401 || request.status === 403) {
                notePw = '';
                clearStoredPw();
            }
            if (onDone) onDone(ok);
        };
        request.onerror = function () {
            if (onDone) onDone(false);
        };
        request.send(body);
    }

    function payload(value) {
        var body = 'text=' + encodeURIComponent(value) +
            '&csrf=' + encodeURIComponent(meta.csrf || '');
        // A brand-new note only gets an expiry when the first save creates it.
        if (meta.createdAt == null) {
            body += '&expires=' + encodeURIComponent(expiry.value);
        }
        return body;
    }

    // Change only the expiry of an existing note; the body is left untouched.
    function expiryPayload() {
        return 'expires=' + encodeURIComponent(expiry.value) +
            '&csrf=' + encodeURIComponent(meta.csrf || '');
    }

    function unlockEditor() {
        textarea.disabled = false;
        textarea.placeholder = '';
        contentLoading = false;
        updateSaveState();
        updateGutter();
    }

    function loadContent() {
        var request = new XMLHttpRequest();
        request.open('GET', '/' + NOTE_ID + '.txt', true);
        request.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        if (notePw) request.setRequestHeader('X-Note-Password', notePw);
        request.onreadystatechange = function () {
            if (request.readyState !== 4) return;
            var status = request.status;
            if (status === 200) {
                var contentType = request.getResponseHeader('Content-Type') || '';
                if (contentType.indexOf('text/html') !== -1) {
                    content = '';
                    updatePrintable(textarea.value);
                    unlockEditor();
                    showSavedAt(meta.updatedAt);
                    return;
                }
                var fetched = request.responseText;
                if (textarea.value === '') {
                    textarea.value = fetched;
                }
                content = fetched;
                updatePrintable(textarea.value);
                unlockEditor();
                showSavedAt(meta.updatedAt);
                pwLocked = false;
                if (notePw) storePw(notePw);
                if (pwFromUrl) stripQueryPw();
            } else if (status === 404) {
                content = '';
                updatePrintable(textarea.value);
                unlockEditor();
                showSavedAt(meta.updatedAt);
            } else if (status === 401) {
                // Locked note, password missing or wrong: ask exactly once.
                // A typed password retries the load a single time; a second
                // 401 (or cancel) parks the editor on the lock button.
                notePw = '';
                clearStoredPw();
                if (!pwPrompted) {
                    pwPrompted = true;
                    var attempt = null;
                    try {
                        attempt = window.prompt('This note is protected. Enter the password:', '');
                    } catch (err) {
                        attempt = null;
                    }
                    if (attempt !== null && attempt !== '') {
                        notePw = attempt;
                        loadContent();
                        return;
                    }
                }
                lockForPassword();
            } else if (status === 403) {
                notePw = '';
                clearStoredPw();
                lockForPassword();
            } else {
                content = '';
                textarea.disabled = false;
                textarea.placeholder = '';
                contentLoading = false;
                savedAtEl.textContent = 'Load failed — you can still edit';
                updateSaveState();
                updateGutter();
            }
        };
        request.onerror = function () {
            content = '';
            textarea.disabled = false;
            textarea.placeholder = '';
            contentLoading = false;
            savedAtEl.textContent = 'Load failed — you can still edit';
            updateSaveState();
            updateGutter();
        };
        request.send(null);
    }

    function save(force) {
        if (contentLoading) return;
        var temp = textarea.value;

        if (!force && temp === content) return;
        if (!force && temp.length === 0 && meta.createdAt == null) return;
        if (saving) {
            dirty = true;
            return;
        }

        saving = true;

        updatePrintable(temp);

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
    textarea.addEventListener('input', updateGutter);

    var gutterTicking = false;
    textarea.addEventListener('scroll', function () {
        if (gutterTicking) return;
        gutterTicking = true;
        if (window.requestAnimationFrame) {
            window.requestAnimationFrame(function () {
                gutterTicking = false;
                updateGutter();
            });
        } else {
            gutterTicking = false;
            updateGutter();
        }
    }, { passive: true });

    window.addEventListener('resize', function () {
        gutterLineHeight = 0;
        updateGutter();
    });
    if (window.ResizeObserver) {
        new window.ResizeObserver(updateGutter).observe(textarea);
    }

    fontDecrease.addEventListener('click', function () {
        stepFontSize(-1);
    });
    fontIncrease.addEventListener('click', function () {
        stepFontSize(1);
    });
    fontSizeInput.addEventListener('change', function () {
        stepFontSize(0);
    });
    fontSizeInput.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') fontSizeInput.blur();
    });

    copyButton.addEventListener('click', copyFromEditor);
    pasteButton.addEventListener('click', pasteIntoEditor);

    document.getElementById('new-note').addEventListener('click', function () {
        var input = window.prompt(
            'Enter a note ID for the new note.\\n\\n' +
            'Allowed characters: letters (A-Z, a-z), digits (0-9), hyphen (-) and underscore (_).\\n' +
            'No spaces or other symbols.\\n\\n' +
            'For example: project-notes-2026',
            ''
        );
        if (input === null) return;

        // Keep only characters a note id accepts.
        var id = input.replace(/[^a-zA-Z0-9_-]/g, '');
        if (id.length === 0) {
            window.alert(
                'That note ID has no valid characters.\\n\\n' +
                'Use letters (A-Z, a-z), digits (0-9), hyphen (-) or underscore (_).\\n' +
                'Spaces and other symbols are not allowed.'
            );
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
        // An unsaved note gets its expiry on the first content save.
        if (meta.createdAt == null) return;

        send(expiryPayload(), function (ok) {
            if (ok) {
                savedAtEl.textContent = 'Expiry saved';
                window.setTimeout(function () {
                    showSavedAt(meta.updatedAt);
                }, 1500);
            } else {
                // Put the select back to match what the server still has.
                pickExpiry();
            }
        }, '/' + NOTE_ID + '/expire');
    });

    outputMode.addEventListener('change', function () {
        if (outputMode.value) {
            window.location.href = '/' + NOTE_ID + outputMode.value;
        }
    });

    function postPassword(current, next) {
        var request = new XMLHttpRequest();
        request.open('POST', '/' + NOTE_ID + '/password', true);
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        request.onreadystatechange = function () {
            if (request.readyState !== 4) return;
            if (request.status >= 200 && request.status < 300) {
                var data = null;
                try {
                    data = JSON.parse(request.responseText);
                } catch (err) {
                    data = null;
                }
                meta.protected = !!(data && data.protected);
                if (meta.protected) {
                    notePw = next;
                    storePw(next);
                } else {
                    notePw = '';
                    clearStoredPw();
                }
                pwFromUrl = false;
                updateLockUI();
            } else if (request.status === 401) {
                notePw = '';
                clearStoredPw();
                window.alert('Wrong password. Nothing changed.');
            } else if (request.status === 403) {
                notePw = '';
                clearStoredPw();
                window.alert('Forbidden. Reload the page and try again.');
            } else {
                window.alert('Could not change the password. Try again.');
            }
        };
        request.onerror = function () {
            window.alert('Could not change the password. Try again.');
        };
        request.send('csrf=' + encodeURIComponent(meta.csrf || '') +
            '&current=' + encodeURIComponent(current) +
            '&new=' + encodeURIComponent(next));
    }

    function changePassword() {
        var current, next, fresh;
        if (meta.protected) {
            current = window.prompt('Enter the current password (empty = cancel):', '');
            if (current === null || current === '') return;
            next = window.prompt('Enter the new password (empty = remove protection):', '');
            if (next === null) return;
            if (next === '' && !window.confirm('Remove password protection from this note?')) return;
            postPassword(current, next);
        } else {
            fresh = window.prompt('Set a password for this note (empty = cancel):', '');
            if (fresh === null || fresh === '') return;
            postPassword('', fresh);
        }
    }

    // The lock button doubles as the retry entry: when parked on 401 it
    // reloads with a fresh password, otherwise it runs the change flow.
    function onLockClick() {
        if (pwLocked) {
            var attempt = null;
            try {
                attempt = window.prompt('Enter the password:', '');
            } catch (err) {
                attempt = null;
            }
            if (attempt === null || attempt === '') return;
            notePw = attempt;
            pwPrompted = true;
            pwLocked = false;
            contentLoading = true;
            textarea.disabled = true;
            textarea.placeholder = 'Loading…';
            savedAtEl.textContent = 'Loading…';
            saveButton.disabled = true;
            loadContent();
            return;
        }
        changePassword();
    }

    if (lockButton) lockButton.addEventListener('click', onLockClick);

    // Command-line help overlay. The note URL is built at runtime so the
    // examples point at this deployment and this note ID.
    function noteUrl() {
        var loc = window.location;
        var origin = loc.origin;
        if (!origin) origin = loc.protocol + '//' + loc.host;
        return origin + '/' + NOTE_ID;
    }

    function buildHelp() {
        if (!helpCode) return;
        var u = noteUrl();
        var lines = [
            '# save raw text (a new ID is created if the note does not exist)',
            'echo "hello" | curl --data-binary @- ' + u,
            '',
            '# read the note',
            'curl ' + u,
            'curl ' + u + '.txt',
            'curl ' + u + '.base64',
            'curl ' + u + '.page',
            '',
            '# append',
            'echo " world" | curl --data-binary @- ' + u + '/append',
            '',
            '# change the expiry (24h, 72h, 1w, never)',
            "curl -d 'expires=24h' " + u + '/expire',
            "curl -d 'expires=never' " + u + '/expire',
            '',
            '# set, change or remove the password',
            "curl -d 'new=secret' " + u + '/password',
            "curl -d 'current=secret&new=new-secret' " + u + '/password',
            "curl -d 'current=secret&new=' " + u + '/password',
            '',
            '# read a protected note',
            "curl -H 'X-Note-Password: secret' " + u + '.txt',
            'curl ' + u + '.txt?pw=secret',
            '',
            '# save and set a password in one step',
            "echo hello | curl --data-binary @- -H 'X-Note-Password: secret' " + u
        ];
        helpCode.textContent = lines.join(String.fromCharCode(10));
    }

    function onHelpKeydown(event) {
        var isEsc = event.key === 'Escape' || event.key === 'Esc' || event.keyCode === 27;
        if (isEsc) {
            event.preventDefault();
            closeHelp();
        }
    }

    function openHelp() {
        if (!helpOverlay) return;
        buildHelp();
        helpOverlay.hidden = false;
        document.addEventListener('keydown', onHelpKeydown, true);
        if (helpClose) helpClose.focus();
    }

    function closeHelp() {
        if (!helpOverlay || helpOverlay.hidden) return;
        helpOverlay.hidden = true;
        document.removeEventListener('keydown', onHelpKeydown, true);
        if (helpButton) helpButton.focus();
    }

    if (helpButton) helpButton.addEventListener('click', openHelp);
    if (helpClose) helpClose.addEventListener('click', closeHelp);
    if (helpOverlay) helpOverlay.addEventListener('click', function (event) {
        if (event.target === helpOverlay) closeHelp();
    });

    savedAtEl.textContent = 'Loading…';
    pickExpiry();
    updateOutputState();
    updateLockUI();
    textarea.disabled = true;
    saveButton.disabled = true;
    loadContent();
    updateGutter();
    initFontSize();
    textarea.focus();
    autosave();
})();
    </script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Markdown page shell (`.page` suffix; body rendered in the browser)
// ---------------------------------------------------------------------------

/**
 * Empty read-only shell for `.page` in a minimal Telegraph-like frame:
 * centred 732px column, header (title + Created/Expires dates), article,
 * and a back-to-editor footer. The body is never rendered on the server: a small inline ES5 script
 * (same XHR style as the editor — `XMLHttpRequest` with `X-Requested-With`,
 * so a missing note reads as 404) fetches `/<id>.txt` and renders Markdown
 * in the browser with markdown-it from a CDN (cdnjs primary with SRI,
 * jsdelivr fallback on script error, plain <pre> downgrade when both fail).
 *
 * Password reuse: the loader mirrors the editor flow — the stored
 * `localStorage` password first, then `?pw=`, then one `prompt()` retry on
 * 401. A 401 never renders body text, only a "protected" placeholder.
 * `meta` takes `{ createdAt, updatedAt, expiresAt }` (a notes row with
 * `created_at` / `updated_at` / `expires_at` works too); `origin` builds the
 * absolute og:url. Header dates print as UTC text server-side and are
 * rewritten to the browser's local time by a small inline script
 * (`data-stamp` holds the epoch milliseconds); without JS the UTC text
 * stays readable. The title
 * and description fall back to the note id: crawlers (Telegram included) do
 * not run the loader JS, so no body excerpt can be offered server-side
 * without rendering the body there. `text` is accepted as a legacy second
 * argument and ignored.
 */
export function renderPageView(id, textOrMeta, metaOrOrigin, maybeOrigin) {
  const safeId = String(id == null ? '' : id);
  let meta = {};
  let origin = '';
  if (textOrMeta && typeof textOrMeta === 'object') {
    meta = textOrMeta;
    origin = metaOrOrigin || '';
  } else {
    meta = metaOrOrigin || {};
    origin = maybeOrigin || '';
  }
  const m = meta || {};
  const createdAt = m.createdAt !== undefined ? m.createdAt : m.created_at;
  const updatedAt = m.updatedAt !== undefined ? m.updatedAt : m.updated_at;
  const expiresAt = m.expiresAt !== undefined ? m.expiresAt : m.expires_at;
  const createdHtml = createdAt != null
    ? '<address data-label="Created" data-stamp="' + createdAt + '">Created: '
      + escapeHtml(formatUtc(createdAt)) + '</address>'
    : '';
  // formatUtc(null) is 'never', so a note that never expires reads
  // "Expires: never". An undefined expiry (legacy callers) shows nothing.
  // data-stamp lets the inline script below rewrite the UTC fallback into
  // the browser's local time; without JS the UTC text stays readable.
  const expiresHtml = expiresAt !== undefined
    ? (expiresAt == null
      ? '<address>Expires: never</address>'
      : '<address data-label="Expires" data-stamp="' + expiresAt + '">Expires: '
        + escapeHtml(formatUtc(expiresAt)) + '</address>')
    : '';
  const addressHtml = createdHtml + (createdHtml && expiresHtml ? '\n' : '') + expiresHtml;
  const plainDesc = 'Web Notepad — ' + safeId;
  let createdISO = '';
  let updatedISO = '';
  try {
    if (createdAt != null) createdISO = new Date(createdAt).toISOString();
    if (updatedAt != null) updatedISO = new Date(updatedAt).toISOString();
  } catch (err) {
    createdISO = '';
    updatedISO = '';
  }
  let pageUrl = '';
  try {
    if (origin) pageUrl = new URL('/' + safeId + '.page', origin).href;
  } catch (err) {
    pageUrl = '';
  }
  return '<!DOCTYPE html>\n'
    + '<html lang="en">\n'
    + '<head>\n'
    + '<meta charset="utf-8">\n'
    + '<title>' + escapeHtml(safeId) + '</title>\n'
    + '<meta name="description" content="' + escapeHtml(plainDesc) + '">\n'
    + '<meta property="og:title" content="' + escapeHtml(safeId) + '">\n'
    + '<meta property="og:description" content="' + escapeHtml(plainDesc) + '">\n'
    + '<meta property="og:type" content="article">\n'
    + (createdISO ? '<meta property="article:published_time" content="' + createdISO + '">\n' : '')
    + (updatedISO ? '<meta property="article:modified_time" content="' + updatedISO + '">\n' : '')
    + (pageUrl ? '<meta property="og:url" content="' + escapeHtml(pageUrl) + '">\n' : '')
    + '<meta property="og:site_name" content="Web Notepad">\n'
    + '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    + '<meta name="robots" content="noindex, nofollow">\n'
    + '<style>\n'
    + '*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;background:#fff;color:#222;font-family:Georgia,Cambria,"Times New Roman",serif;font-size:18px;line-height:1.58}\n'
    + '.wrap{max-width:732px;margin:0 auto;padding:1.17em 1.17em 3.34em}main{display:block}\n'
    + 'h1{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:32px;line-height:1.25;font-weight:700;margin:0.66em 0 0.38em;overflow-wrap:break-word}\n'
    + 'header{margin:0 0 1.4em}\n'
    + 'address{font-style:normal;font-size:15px;color:#79828B;margin:0}\n'
    + 'address+address{margin-top:0.3em}\n'
    + '.content p{margin:0 0 0.67em;overflow-wrap:break-word}\n'
    + '.content h2{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:28px;line-height:1.3;font-weight:700;margin:0.93em 0 0.43em}\n'
    + '.content h3{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:24px;line-height:1.35;font-weight:700;margin:1em 0 0.42em}\n'
    + '.content h4{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:21px;line-height:1.4;font-weight:700;margin:1.05em 0 0.48em}\n'
    + '.content a{color:inherit;text-decoration:underline}\n'
    + '.content code{font-family:Menlo,Consolas,monospace;font-size:16px;background:#F5F8FC;padding:0.13em 0.25em;border-radius:3px;overflow-wrap:break-word}\n'
    + '.content pre{background:#F5F8FC;padding:0.78em 1.17em;margin:0 0 0.78em;overflow-x:auto}\n'
    + '.content pre code{background:none;padding:0;border-radius:0}\n'
    + '.content blockquote{margin:0 0 0.78em;padding:0 0 0 0.89em;border-left:3px solid #000;font-style:italic}\n'
    + '.content blockquote p{margin:0}\n'
    + '.content ul,.content ol{margin:0 0 0.78em;padding:0;list-style:none}\n'
    + '.content ul li{position:relative;padding-left:1.33em;margin-bottom:0.44em}\n'
    + '.content ul li:before{content:"•";position:absolute;left:8px}\n'
    + '.content ol{counter-reset:pageol}.content ol li{position:relative;padding-left:1.67em;margin-bottom:0.44em;counter-increment:pageol}\n'
    + '.content ol li:before{content:counter(pageol) ".";position:absolute;left:8px}\n'
    + '.content img{max-width:100%;height:auto;display:block}\n'
    + '.content figure{margin:0 0 0.89em;text-align:center}\n'
    + '.content figure img{margin:0 auto}\n'
    + '.content figcaption{font-size:15px;color:#79828B;margin-top:0.53em;padding:0}\n'
    + '.content hr{border:none;border-top:1px solid #c9cdd1;width:50%;margin:1.33em auto}\n'
    + '.content table{margin:0 0 0.89em;border-collapse:collapse;width:100%;display:block;overflow-x:auto}\n'
    + '.content th,.content td{border:1px solid #ddd;padding:0.5em 0.75em;text-align:left;font-size:16px;overflow-wrap:break-word}\n'
    + '.content th{background:#F5F8FC;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-weight:700}\n'
    + '.content tbody tr:nth-child(even) td{background:#fafbfc}\n'
    + '.content .empty{color:#79828B;font-style:italic}\n'
    + 'footer{margin:2.13em 0 0;font-size:15px;color:#79828B;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}\n'
    + 'footer a{color:inherit}\n'
    + '@media(max-width:480px){.wrap{padding:0.89em 0.89em 2.22em}h1{font-size:28px;margin:0.57em 0 0.36em}}\n'
    + '</style>\n'
    + '</head>\n'
    + '<body>\n'
    + '<div class="wrap">\n'
    + '<main>\n'
    + '<header>\n'
    + '<h1 id="page-title">' + escapeHtml(safeId) + '</h1>\n'
    + addressHtml + (addressHtml ? '\n' : '')
    + '</header>\n'
    + '<article class="content" id="page-content">\n'
    + '<p class="empty">Loading…</p>\n'
    + '</article>\n'
    + '<footer><a href="/' + escapeHtml(safeId) + '">Edit this note</a></footer>\n'
    + '</main>\n'
    + '</div>\n'
    + '<script src="https://cdnjs.cloudflare.com/ajax/libs/markdown-it/13.0.2/markdown-it.min.js" integrity="sha512-ohlWmsCxOu0bph1om5eDL0jm/83eH09fvqLDhiEdiqfDeJbEvz4FSbeY0gLJSVJwQAp0laRhTXbUQG+ZUuifUQ==" crossorigin="anonymous" onerror="(function(){var s=document.createElement(\'script\');s.src=\'https://cdn.jsdelivr.net/npm/markdown-it@14.1.0/dist/markdown-it.min.js\';document.head.appendChild(s);})()">\n'
    + '</script>\n'
    + '<script>\n'
    + '/* header dates: the server prints UTC as a fallback; rewrite to browser local time when JS runs */\n'
    + '(function () {\n'
    + '"use strict";\n'
    + 'function fmtLocal(ms) {\n'
    + '    var d = new Date(ms);\n'
    + '    try { return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }\n'
    + '    catch (err) { return d.toLocaleString(); }\n'
    + '}\n'
    + 'try {\n'
    + '    var els = document.querySelectorAll("address[data-stamp]");\n'
    + '    for (var i = 0; i < els.length; i++) {\n'
    + '        var ms = parseInt(els[i].getAttribute("data-stamp"), 10);\n'
    + '        if (isNaN(ms)) continue;\n'
    + '        var label = els[i].getAttribute("data-label") || "";\n'
    + '        els[i].textContent = label + ": " + fmtLocal(ms);\n'
    + '    }\n'
    + '} catch (err) {}\n'
    + '})();\n'
    + '</script>\n'
    + '<script>\n'
    + '/* page loader: fetch the raw text, then render Markdown with markdown-it */\n'
    + '(function () {\n'
    + '"use strict";\n'
    + 'var NOTE_ID = ' + JSON.stringify(safeId) + ';\n'
    + 'var MAX_CHARS = 1000000;\n'
    + 'var MD_WAIT_MS = 5000;\n'
    + 'var MD_POLL_MS = 100;\n'
    + 'var titleEl = document.getElementById("page-title");\n'
    + 'var article = document.getElementById("page-content");\n'
    + 'var notePw = "";\n'
    + 'var pwFromUrl = false;\n'
    + 'var pwPrompted = false;\n'
    + 'function pwKey() { return "web-notepad-pw-" + NOTE_ID; }\n'
    + 'function storePw(pw) { try { window.localStorage.setItem(pwKey(), pw); } catch (err) {} }\n'
    + 'function clearStoredPw() { try { window.localStorage.removeItem(pwKey()); } catch (err) {} }\n'
    + 'function queryPw() {\n'
    + '    try {\n'
    + '        var s = window.location.search || "";\n'
    + '        if (s.charAt(0) === "?") s = s.slice(1);\n'
    + '        var parts = s.split("&");\n'
    + '        for (var i = 0; i < parts.length; i++) {\n'
    + '            var kv = parts[i];\n'
    + '            var eq = kv.indexOf("=");\n'
    + '            var k = eq === -1 ? kv : kv.slice(0, eq);\n'
    + '            if (k === "pw") {\n'
    + '                var v = eq === -1 ? "" : kv.slice(eq + 1);\n'
    + '                if (!v) return "";\n'
    + '                try { return decodeURIComponent(v.split("+").join(" ")); } catch (err2) { return v; }\n'
    + '            }\n'
    + '        }\n'
    + '    } catch (err) {}\n'
    + '    return "";\n'
    + '}\n'
    + 'function stripQueryPw() {\n'
    + '    pwFromUrl = false;\n'
    + '    try {\n'
    + '        if (window.history && window.history.replaceState) {\n'
    + '            window.history.replaceState(null, "", "/" + NOTE_ID + ".page");\n'
    + '        }\n'
    + '    } catch (err) {}\n'
    + '}\n'
    + 'try { notePw = window.localStorage.getItem(pwKey()) || ""; } catch (err) { notePw = ""; }\n'
    + 'var urlPw = queryPw();\n'
    + 'if (!notePw && urlPw) { notePw = urlPw; pwFromUrl = true; }\n'
    + 'function headTag(tag) {\n'
    + '    if (tag === "h3") return "h3";\n'
    + '    if (tag === "h4" || tag === "h5" || tag === "h6") return "h4";\n'
    + '    return "h2";\n'
    + '}\n'
    + 'function makeMd() {\n'
    + '    if (!window.markdownit) return null;\n'
    + '    var md = window.markdownit("commonmark", { html: false, linkify: false, typographer: false });\n'
    + '    md.enable("table");\n'
    + '    var defaultLinkOpen = md.renderer.rules.link_open || function (tokens, idx, options, env, self) { return self.renderToken(tokens, idx, options); };\n'
    + '    var defaultImage = md.renderer.rules.image || function (tokens, idx, options, env, self) { return self.renderToken(tokens, idx, options); };\n'
    + '    md.renderer.rules.link_open = function (tokens, idx, options, env, self) {\n'
    + '        tokens[idx].attrPush(["rel", "noopener"]);\n'
    + '        return defaultLinkOpen(tokens, idx, options, env, self);\n'
    + '    };\n'
    + '    md.renderer.rules.image = function (tokens, idx, options, env, self) {\n'
    + '        tokens[idx].attrPush(["loading", "lazy"]);\n'
    + '        return defaultImage(tokens, idx, options, env, self);\n'
    + '    };\n'
    + '    md.renderer.rules.fence = function (tokens, idx) {\n'
    + '        return "<pre><code>" + md.utils.escapeHtml(tokens[idx].content) + "</code></pre>\\n";\n'
    + '    };\n'
    + '    md.renderer.rules.heading_open = function (tokens, idx, options, env, self) {\n'
    + '        if (env && idx === env.skipOpen) return "";\n'
    + '        return "<" + headTag(tokens[idx].tag) + ">";\n'
    + '    };\n'
    + '    md.renderer.rules.heading_close = function (tokens, idx, options, env, self) {\n'
    + '        if (env && idx === env.skipClose) return "";\n'
    + '        return "</" + headTag(tokens[idx].tag) + ">";\n'
    + '    };\n'
    + '    return md;\n'
    + '}\n'
    + 'function figureHtml(html) {\n'
    + '    return String(html).replace(/<p><img([^<>]*)><\\/p>/g, function (m, attrs) {\n'
    + '        var altm = attrs.match(/alt="([^"]*)"/);\n'
    + '        var alt = altm ? altm[1] : "";\n'
    + '        var cap = /\\S/.test(alt.replace(/&#?\\w+;/g, "")) ? "<figcaption>" + alt + "</figcaption>" : "";\n'
    + '        return "<figure><img" + attrs + ">" + cap + "</figure>";\n'
    + '    });\n'
    + '}\n'
    + 'function titleFromInline(token) {\n'
    + '    var kids = (token && token.children) || [];\n'
    + '    var parts = [];\n'
    + '    for (var k = 0; k < kids.length; k++) {\n'
    + '        if (kids[k].type === "text" || kids[k].type === "code_inline") parts.push(kids[k].content);\n'
    + '    }\n'
    + '    return parts.join("").replace(/\\s+/g, " ").replace(/^\\s+|\\s+$/g, "");\n'
    + '}\n'
    + 'function renderMdText(src) {\n'
    + '    var md = makeMd();\n'
    + '    if (!md) return null;\n'
    + '    var text = String(src == null ? "" : src);\n'
    + '    if (text.length > MAX_CHARS) text = text.slice(0, MAX_CHARS);\n'
    + '    var tokens = md.parse(text, {});\n'
    + '    var titleText = "";\n'
    + '    var skipOpen = -1;\n'
    + '    var skipClose = -1;\n'
    + '    var i;\n'
    + '    for (i = 0; i < tokens.length; i++) {\n'
    + '        if (tokens[i].type === "heading_open" && tokens[i].tag === "h1") {\n'
    + '            skipOpen = i;\n'
    + '            if (i + 1 < tokens.length && tokens[i + 1].type === "inline") titleText = titleFromInline(tokens[i + 1]);\n'
    + '            break;\n'
    + '        }\n'
    + '    }\n'
    + '    if (skipOpen !== -1) {\n'
    + '        for (i = skipOpen + 1; i < tokens.length; i++) {\n'
    + '            if (tokens[i].type === "heading_close") { skipClose = i; break; }\n'
    + '        }\n'
    + '    }\n'
    + '    var html = figureHtml(md.renderer.render(tokens, md.options, { skipOpen: skipOpen, skipClose: skipClose }));\n'
    + '    if (!/\\S/.test(html.replace(/<[^<>]*>/g, " "))) html = "<p class=\\"empty\\">Empty note.</p>\\n";\n'
    + '    return { titleText: titleText, html: html };\n'
    + '}\n'
    + 'function setArticle(html) { article.innerHTML = html; }\n'
    + 'function showLocked() { setArticle("<p class=\\"empty\\">This note is protected.</p>"); }\n'
    + 'function showPre(text) {\n'
    + '    article.innerHTML = "";\n'
    + '    var pre = document.createElement("pre");\n'
    + '    pre.appendChild(document.createTextNode(String(text == null ? "" : text)));\n'
    + '    article.appendChild(pre);\n'
    + '}\n'
    + 'function showRendered(fetched) {\n'
    + '    var out = null;\n'
    + '    try {\n'
    + '        out = renderMdText(fetched);\n'
    + '    } catch (err) {\n'
    + '        out = null;\n'
    + '    }\n'
    + '    if (!out) {\n'
    + '        showPre(fetched);\n'
    + '        return;\n'
    + '    }\n'
    + '    if (/\\S/.test(out.titleText)) {\n'
    + '        titleEl.textContent = out.titleText;\n'
    + '        try { document.title = out.titleText; } catch (err2) {}\n'
    + '    }\n'
    + '    setArticle(out.html);\n'
    + '}\n'
    + 'function waitMd(done) {\n'
    + '    if (window.markdownit) { done(true); return; }\n'
    + '    var waited = 0;\n'
    + '    var timer = window.setInterval(function () {\n'
    + '        waited += MD_POLL_MS;\n'
    + '        if (window.markdownit) { window.clearInterval(timer); done(true); }\n'
    + '        else if (waited >= MD_WAIT_MS) { window.clearInterval(timer); done(false); }\n'
    + '    }, MD_POLL_MS);\n'
    + '}\n'
    + 'function onText(fetched) {\n'
    + '    if (notePw) storePw(notePw);\n'
    + '    if (pwFromUrl) stripQueryPw();\n'
    + '    waitMd(function (ok) {\n'
    + '        if (ok) showRendered(fetched);\n'
    + '        else showPre(fetched);\n'
    + '    });\n'
    + '}\n'
    + 'function load() {\n'
    + '    var req = new XMLHttpRequest();\n'
    + '    req.open("GET", "/" + NOTE_ID + ".txt", true);\n'
    + '    req.setRequestHeader("X-Requested-With", "XMLHttpRequest");\n'
    + '    if (notePw) req.setRequestHeader("X-Note-Password", notePw);\n'
    + '    req.onreadystatechange = function () {\n'
    + '        if (req.readyState !== 4) return;\n'
    + '        var status = req.status;\n'
    + '        if (status === 200) {\n'
    + '            var ct = req.getResponseHeader("Content-Type") || "";\n'
    + '            if (ct.indexOf("text/html") !== -1) {\n'
    + '                setArticle("<p class=\\"empty\\">Empty note.</p>");\n'
    + '                return;\n'
    + '            }\n'
    + '            var fetched = req.responseText;\n'
    + '            onText(fetched);\n'
    + '        } else if (status === 404) {\n'
    + '            setArticle("<p class=\\"empty\\">Empty note.</p>");\n'
    + '        } else if (status === 401) {\n'
    + '            notePw = "";\n'
    + '            clearStoredPw();\n'
    + '            if (!pwPrompted) {\n'
    + '                pwPrompted = true;\n'
    + '                var attempt = null;\n'
    + '                try { attempt = window.prompt("This note is protected. Enter the password:", ""); } catch (err) { attempt = null; }\n'
    + '                if (attempt !== null && attempt !== "") {\n'
    + '                    notePw = attempt;\n'
    + '                    load();\n'
    + '                    return;\n'
    + '                }\n'
    + '            }\n'
    + '            showLocked();\n'
    + '        } else {\n'
    + '            setArticle("<p class=\\"empty\\">Could not load the note.</p>");\n'
    + '        }\n'
    + '    };\n'
    + '    req.onerror = function () {\n'
    + '        setArticle("<p class=\\"empty\\">Could not load the note.</p>");\n'
    + '    };\n'
    + '    req.send(null);\n'
    + '}\n'
    + 'load();\n'
    + '})();\n'
    + '</script>\n'
    + '</body>\n'
    + '</html>';
}

// ---------------------------------------------------------------------------
// MCP (Model Context Protocol) — Streamable HTTP, stateless, no auth
//
//   POST /mcp          -> JSON-RPC handled here (one fresh McpServer plus one
//                         fresh transport per request, never reused)
//   GET /mcp, DELETE /mcp -> 405
//
// Six tools (all snake_case): read_note, write_note, append_note,
// delete_note, set_expiry, set_password. Tools reuse the note store above
// (loadNote / loadNoteMeta / saveNote / deleteNote / setNoteExpiry /
// setNotePassword / verifyPassword / isProtectedRow) and mirror the HTTP
// route semantics: expired notes read as missing, locked notes need their
// password (passed as a tool argument), an empty write deletes, and only an
// unlocked note can be locked in one step. No note listing, no .page/editor
// HTML, no Resources/Prompts, no .well-known/OAuth, no Durable Objects.
// ---------------------------------------------------------------------------

/**
 * Auth choke point for the MCP endpoint. It currently allows every request:
 * this service ships without authentication, like the public notebook.
 * To add an API key later, check a header here and return a 401 Response
 * (about ten lines of middleware); return null to allow. Tool handlers
 * below stay unchanged.
 */
function mcpAuthHook(request) {
  return null;
}

/** Note id rule shared by every MCP tool (same as NOTE_ID_RE). */
const MCP_NOTE_ID_RE = /^[A-Za-z0-9_-]+$/;
/** Default and upper bound for read_note maxChars (in text characters). */
const MCP_DEFAULT_MAX_CHARS = 25000;
const MCP_MAX_CHARS_LIMIT = 1000000;

const mcpIdInput = z
  .string()
  .regex(MCP_NOTE_ID_RE, 'Note id may only use a-z, A-Z, 0-9, _ and -.')
  .describe('Note id. Only a-z, A-Z, 0-9, _ and - are allowed.');
const mcpPasswordInput = z
  .string()
  .default('')
  .describe(
    'Note password. Needed only when the note is locked with a password; leave it empty for a public note.',
  );
const mcpStamp = (name) =>
  z
    .number()
    .nullable()
    .describe(`${name}, as milliseconds since the Unix epoch, or null when never.`);
/** Shareable read URLs returned with every read/write/append result. */
const mcpUrlsOutput = z
  .object({
    plain: z.string().describe('Plain-text read URL.'),
    base64: z.string().describe('Base64 read URL.'),
    page: z.string().describe('Markdown article page URL. Share this link.'),
    editor: z.string().describe('Browser editor URL.'),
  })
  .describe('Shareable read URLs for the note.');
function mcpUrls(origin, id) {
  const base = `${origin}/${id}`;
  return { plain: `${base}.txt`, base64: `${base}.base64`, page: `${base}.page`, editor: base };
}

/** Success result: human-readable text plus machine-readable structured data. */
function mcpOk(text, structuredContent) {
  return { content: [{ type: 'text', text }], structuredContent };
}

/** Tool-level failure (missing note, wrong password, bad id): never throws. */
function mcpFail(text) {
  return { content: [{ type: 'text', text }], isError: true };
}

function mcpMissingText(id) {
  return (
    `Note '${id}' was not found. ` +
    'It may never have existed, or it may have expired and been deleted.'
  );
}

function mcpLockedText(id) {
  return `Note '${id}' is locked with a password. Call again with the 'password' argument.`;
}

function mcpWrongPasswordText(id) {
  return `Wrong password for note '${id}'. Nothing changed.`;
}

/**
 * Build a fresh McpServer with the six note tools bound to this request's
 * env/ctx. Called once per HTTP request; the instance is never reused.
 * `origin` (e.g. https://note.example.com) prefixes the shareable urls.
 */
function createMcpServer(env, ctx, origin) {
  const server = new McpServer({ name: 'web-notepad', version: '1.0.0' });

  server.registerTool(
    'read_note',
    {
      title: 'Read note',
      description:
        'Read a saved note by id. Use when the user wants to open, read, show, or fetch a note. ' +
        'A locked note needs its password in the password argument; without it the call fails with a hint instead of the text. ' +
        'Long notes are cut at maxChars; the result tells you how to read the rest.',
      inputSchema: z.object({
        id: mcpIdInput,
        format: z
          .enum(['text', 'base64'])
          .default('text')
          .describe("Output shape: 'text' for plain text, 'base64' for Base64 of the UTF-8 text."),
        password: mcpPasswordInput,
        maxChars: z
          .number()
          .int()
          .min(1)
          .max(MCP_MAX_CHARS_LIMIT)
          .default(MCP_DEFAULT_MAX_CHARS)
          .describe(
            'Longest text to return, in characters. Longer notes are cut and marked truncated:true; ' +
              'call again with a bigger maxChars to read the rest.',
          ),
      }),
      outputSchema: z.object({
        id: mcpIdInput.describe('Note id that was read.'),
        format: z.enum(['text', 'base64']).describe('Output shape that was returned.'),
        text: z.string().describe('Note text (or its Base64), cut at maxChars when truncated.'),
        truncated: z.boolean().describe('True when the text was cut at maxChars.'),
        totalChars: z
          .number()
          .int()
          .describe('Full note length in text characters, counted before Base64 encoding.'),
        created_at: mcpStamp('When the note was created'),
        updated_at: mcpStamp('When the note was last changed'),
        expires_at: mcpStamp('When the note expires'),
        urls: mcpUrlsOutput,
      }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ id, format, password, maxChars }) => {
      let loaded = await loadNote(env, id);
      if (loaded && loaded.expired) {
        ctx.waitUntil(deleteNote(env, id));
        loaded = null;
      }
      if (!loaded) return mcpFail(mcpMissingText(id));
      if (isProtectedRow(loaded.row)) {
        if (!password) return mcpFail(mcpLockedText(id));
        if (!(await verifyPassword(password, loaded.row))) {
          return mcpFail(mcpWrongPasswordText(id));
        }
      }
      const totalChars = loaded.text.length;
      let text = loaded.text;
      let truncated = false;
      if (text.length > maxChars) {
        text = text.slice(0, maxChars);
        truncated = true;
      }
      const out = format === 'base64' ? bytesToBase64(encoder.encode(text)) : text;
      const head = truncated
        ? `Note '${id}' was cut to ${maxChars} of ${totalChars} characters. ` +
          `To read more, call read_note again with a bigger maxChars (at least ${totalChars}).\n\n`
        : '';
      return mcpOk(head + out, {
        id,
        format,
        text: out,
        truncated,
        totalChars,
        created_at: loaded.row.created_at ?? null,
        updated_at: loaded.row.updated_at ?? null,
        expires_at: loaded.row.expires_at ?? null,
        urls: mcpUrls(origin, id),
      });
    },
  );

  server.registerTool(
    'write_note',
    {
      title: 'Write note',
      description:
        'Create a new note or replace a saved one. Use when the user wants to save, write, or overwrite a note. ' +
        'Omit id to create a note with a fresh random id. An empty text deletes the note. ' +
        'A locked note needs its password; a new password can only lock a note that has none yet. ' +
        'Omit expires to keep the current expiry.',
      inputSchema: z.object({
        id: mcpIdInput
          .optional()
          .describe(
            'Note id to write. Omit it to create a note with a fresh random id (the result tells you the id).',
          ),
        text: z
          .string()
          .describe('Full new note text. An empty string deletes the note instead of saving.'),
        password: mcpPasswordInput,
        newPassword: z
          .string()
          .optional()
          .describe(
            'Lock the note with this password in the same write. Works only for a note with no password yet; ' +
              'a locked note rejects it (use set_password to change a password).',
          ),
        expires: z
          .string()
          .optional()
          .describe(
            'Note expiry in the same write. ' +
              EXPIRY_HINT +
              ' Omit it to keep the current expiry (a new note uses the server default).',
          ),
      }),
      outputSchema: z.object({
        id: mcpIdInput.describe('Note id that was written.'),
        deleted: z.boolean().describe('True when an empty text deleted the note.'),
        created: z.boolean().describe('True when this write created a new note.'),
        updated_at: mcpStamp('When the note was written'),
        expires_at: mcpStamp('When the note expires'),
        protected: z.boolean().describe('True when the note is now locked with a password.'),
        urls: mcpUrlsOutput,
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ id, text, password, newPassword, expires }) => {
      const noteId = id ?? (await freshNoteId(env));
      const found = await loadNoteMeta(env, noteId);
      const row = found ? found.row : null;
      const locked = isProtectedRow(row);
      if (locked && newPassword !== undefined) {
        return mcpFail(
          `Note '${noteId}' is already locked. A write cannot change its password; ` +
            'call set_password to change or remove it.',
        );
      }
      if (locked) {
        if (!password) return mcpFail(mcpLockedText(noteId));
        if (!(await verifyPassword(password, row))) return mcpFail(mcpWrongPasswordText(noteId));
      }
      if (text.length === 0) {
        await deleteNote(env, noteId);
        return mcpOk(`Note '${noteId}' was deleted (empty text).`, {
          id: noteId,
          deleted: true,
          created: false,
          updated_at: null,
          expires_at: null,
          protected: false,
          urls: mcpUrls(origin, noteId),
        });
      }
      if (!locked && newPassword !== undefined && newPassword.length > PASSWORD_MAX_LENGTH) {
        return mcpFail(
          `The new password is too long (longest ${PASSWORD_MAX_LENGTH} characters). Nothing was saved.`,
        );
      }
      let resolvedExpiry;
      if (expires !== undefined) {
        resolvedExpiry = resolveExpiryToken(expires);
        if (resolvedExpiry === undefined) {
          return mcpFail(
            `Unknown expiry '${expires}'. ${EXPIRY_HINT} Nothing was saved.`,
          );
        }
      }
      const isNew = !row || !!(found && found.expired);
      const saved = await saveNote(env, noteId, text, { expires: resolvedExpiry });
      let prot = locked;
      if (!locked && newPassword) {
        await setNotePassword(env, noteId, newPassword);
        prot = true;
      }
      return mcpOk(
        (isNew
          ? `Note '${noteId}' was created.${prot ? ' It is locked with a password.' : ''}`
          : `Note '${noteId}' was saved.${prot && !locked ? ' It is now locked with a password.' : ''}`) +
          ` Page: ${origin}/${noteId}.page`,
        {
          id: noteId,
          deleted: false,
          created: isNew,
          updated_at: saved.updatedAt,
          expires_at: saved.expiresAt,
          protected: prot,
          urls: mcpUrls(origin, noteId),
        },
      );
    },
  );

  server.registerTool(
    'append_note',
    {
      title: 'Append to note',
      description:
        'Add text to the end of a note. Use when the user wants to add, append, or continue a note ' +
        'without replacing it. A locked note needs its password. Appending to a missing id creates it. ' +
        'Omit expires to keep the current expiry.',
      inputSchema: z.object({
        id: mcpIdInput,
        text: z.string().describe('Text to add to the end of the note.'),
        password: mcpPasswordInput,
        expires: z
          .string()
          .optional()
          .describe(
            'Note expiry in the same write. ' +
              EXPIRY_HINT +
              ' Omit it to keep the current expiry (a new note uses the server default).',
          ),
      }),
      outputSchema: z.object({
        id: mcpIdInput.describe('Note id that was appended to.'),
        created: z.boolean().describe('True when the note did not exist and was created.'),
        updated_at: mcpStamp('When the note was written'),
        expires_at: mcpStamp('When the note expires'),
        protected: z.boolean().describe('True when the note is locked with a password.'),
        urls: mcpUrlsOutput,
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ id, text, password, expires }) => {
      const found = await loadNoteMeta(env, id);
      const row = found ? found.row : null;
      if (isProtectedRow(row)) {
        if (!password) return mcpFail(mcpLockedText(id));
        if (!(await verifyPassword(password, row))) return mcpFail(mcpWrongPasswordText(id));
      }
      let resolvedExpiry;
      if (expires !== undefined) {
        resolvedExpiry = resolveExpiryToken(expires);
        if (resolvedExpiry === undefined) {
          return mcpFail(
            `Unknown expiry '${expires}'. ${EXPIRY_HINT} Nothing was saved.`,
          );
        }
      }
      const isNew = !row || !!(found && found.expired);
      const saved = await saveNote(env, id, text, {
        append: true,
        expires: resolvedExpiry,
      });
      return mcpOk(
        (isNew
          ? `Note '${id}' was created with the appended text.`
          : `Text was appended to note '${id}'.`) + ` Page: ${origin}/${id}.page`,
        {
          id,
          created: isNew,
          updated_at: saved.updatedAt,
          expires_at: saved.expiresAt,
          protected: isProtectedRow(row),
          urls: mcpUrls(origin, id),
        },
      );
    },
  );

  server.registerTool(
    'delete_note',
    {
      title: 'Delete note',
      description:
        'Delete a note forever. Use only when the user clearly wants to delete or remove a note. ' +
        'A locked note needs its password.',
      inputSchema: z.object({
        id: mcpIdInput,
        password: mcpPasswordInput,
      }),
      outputSchema: z.object({
        id: mcpIdInput.describe('Note id that was deleted.'),
        deleted: z.boolean().describe('Always true when the call succeeds.'),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ id, password }) => {
      const found = await loadNoteMeta(env, id);
      const row = found ? found.row : null;
      if (!row || (found && found.expired)) return mcpFail(mcpMissingText(id));
      if (isProtectedRow(row)) {
        if (!password) return mcpFail(mcpLockedText(id));
        if (!(await verifyPassword(password, row))) return mcpFail(mcpWrongPasswordText(id));
      }
      await deleteNote(env, id);
      return mcpOk(`Note '${id}' was deleted.`, { id, deleted: true });
    },
  );

  server.registerTool(
    'set_expiry',
    {
      title: 'Set note expiry',
      description:
        'Change only when a note expires, keeping its text. A locked note needs its password.',
      inputSchema: z.object({
        id: mcpIdInput,
        token: z.string().describe(`New expiry. ${EXPIRY_HINT}`),
        password: mcpPasswordInput,
      }),
      outputSchema: z.object({
        id: mcpIdInput.describe('Note id whose expiry changed.'),
        created_at: mcpStamp('When the note was created'),
        updated_at: mcpStamp('When the note was last changed'),
        expires_at: mcpStamp('When the note now expires'),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ id, token, password }) => {
      const found = await loadNoteMeta(env, id);
      const row = found ? found.row : null;
      if (!row) return mcpFail(mcpMissingText(id));
      if (isProtectedRow(row)) {
        if (!password) return mcpFail(mcpLockedText(id));
        if (!(await verifyPassword(password, row))) return mcpFail(mcpWrongPasswordText(id));
      }
      const expires = resolveExpiryToken(token);
      if (expires === undefined) {
        return mcpFail(
          `Unknown expiry '${token}'. ${EXPIRY_HINT} Nothing changed.`,
        );
      }
      const saved = await setNoteExpiry(env, id, expires);
      if (!saved) return mcpFail(mcpMissingText(id));
      return mcpOk(
        saved.expiresAt == null
          ? `Note '${id}' will never expire now.`
          : `Note '${id}' now expires at ${formatUtc(saved.expiresAt)}.`,
        {
          id,
          created_at: saved.createdAt,
          updated_at: saved.updatedAt,
          expires_at: saved.expiresAt,
        },
      );
    },
  );

  server.registerTool(
    'set_password',
    {
      title: 'Set note password',
      description:
        'Set, change, or remove a note password. Use when the user wants to lock, protect, unlock, ' +
        'or change the password of a note. A locked note needs its current password; ' +
        'pass an empty newPassword to remove protection.',
      inputSchema: z.object({
        id: mcpIdInput,
        currentPassword: z
          .string()
          .default('')
          .describe('Current password. Needed only when the note is already locked.'),
        newPassword: z
          .string()
          .optional()
          .describe('New password. An empty string removes protection from the note.'),
      }),
      outputSchema: z.object({
        id: mcpIdInput.describe('Note id whose password changed.'),
        protected: z.boolean().describe('True when the note is now locked with a password.'),
        updated_at: mcpStamp('When the password changed'),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ id, currentPassword, newPassword }) => {
      if (newPassword === undefined) {
        return mcpFail(
          `'newPassword' is required. Pass a new password to set it, or an empty string ` +
            `to remove protection from note '${id}'.`,
        );
      }
      if (newPassword.length > PASSWORD_MAX_LENGTH) {
        return mcpFail(
          `The new password is too long (longest ${PASSWORD_MAX_LENGTH} characters). Nothing changed.`,
        );
      }
      const found = await loadNoteMeta(env, id);
      const row = found ? found.row : null;
      if (!row || (found && found.expired)) return mcpFail(mcpMissingText(id));
      if (isProtectedRow(row)) {
        if (!currentPassword) {
          return mcpFail(
            `Note '${id}' is locked. Pass the current password in 'currentPassword'. Nothing changed.`,
          );
        }
        if (!(await verifyPassword(currentPassword, row))) {
          return mcpFail(`Wrong current password for note '${id}'. Nothing changed.`);
        }
      }
      let stamp;
      let prot;
      if (newPassword === '') {
        stamp = Date.now();
        await env.DB.prepare(
          `UPDATE notes SET is_protected = 0, password_hash = NULL,
                            password_salt = NULL, password_algo = NULL, updated_at = ?
             WHERE id = ?`,
        ).bind(stamp, id).run();
        prot = false;
      } else {
        stamp = await setNotePassword(env, id, newPassword);
        prot = true;
      }
      return mcpOk(
        prot
          ? `Note '${id}' is now locked with a password.`
          : `Password protection was removed from note '${id}'.`,
        { id, protected: prot, updated_at: stamp },
      );
    },
  );

  return server;
}

/**
 * MCP endpoint handler (Streamable HTTP, stateless). Only POST is allowed.
 * Every request gets a fresh McpServer plus a fresh transport — instances
 * are never reused across requests. Any Mcp-Session-Id the client sends is
 * dropped: stateless mode issues no sessions and performs no validation.
 */
async function handleMcp(request, env, ctx) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: noStore({
        'Content-Type': 'text/plain; charset=utf-8',
        Allow: 'POST',
      }),
    });
  }
  const deny = mcpAuthHook(request);
  if (deny) return deny;
  const cleanHeaders = new Headers(request.headers);
  cleanHeaders.delete('mcp-session-id');
  const cleanRequest = new Request(request, { headers: cleanHeaders });
  const server = createMcpServer(env, ctx, new URL(request.url).origin);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  await server.connect(transport);
  const res = await transport.handleRequest(cleanRequest);
  // Keep the product promise: every response carries no-store + noindex.
  const headers = new Headers(res.headers);
  for (const [name, value] of Object.entries(noStore())) headers.set(name, value);
  return new Response(res.body, { status: res.status, headers });
}

// ---------------------------------------------------------------------------
// Worker entrypoint
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // MCP endpoint (Streamable HTTP, stateless). Exact path only: /mcp.txt
    // and friends stay normal notes.
    if (url.pathname === '/mcp') return handleMcp(request, env, ctx);

    const segments = url.pathname.split('/').filter(Boolean);

    if (segments.length === 0) {
      // Root write: a CLI upload (curl/wget) to `/` gets a fresh random id and
      // is saved there. The plain-text receipt prints the generated id and its
      // read URLs. Browsers still get the random-note redirect.
      if (request.method === 'POST') {
        const userAgent = request.headers.get('user-agent') || '';
        if (!isCliUserAgent(userAgent)) return forbidden();
        return handlePost(request, env, ctx, await freshNoteId(env), '');
      }
      return redirect('/' + randomNoteId());
    }

    // Output is addressed by file suffix: /<id>.txt, /<id>.base64, /<id>.page.
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
      else if (ext === 'page') suffixMode = 'page';
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

    if (request.method === 'POST') return handlePost(request, env, ctx, id, mode);
    if (request.method !== 'GET' && request.method !== 'HEAD') return notFound();

    return handleGet(request, env, ctx, id, mode);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(gcExpired(env));
  },
};
