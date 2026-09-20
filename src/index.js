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
 *   - GET  /:note.page           -> stored note as a Markdown page
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
 *
 * Security:
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
import MarkdownIt from 'markdown-it';

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
 * `undefined` means "no choice" (saveNote keeps the note's current expiry, or
 * uses NOTE_TTL_DAYS for a new note); `null` means "never expires".
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
 * Friendly plain-text receipt for a command-line write (curl/wget): confirms
 * the save, prints the save time, and lists the read URLs.
 */
function cliReceipt(url, id, verb, updatedAt, expiresAt) {
  return textOk([
    `${verb}.`,
    `Note:    ${id}`,
    `Saved:   ${formatUtc(updatedAt)}`,
    `Expires: ${formatUtc(expiresAt)}`,
    `Plain:   ${url.origin}/${id}.txt`,
    `Base64:  ${url.origin}/${id}.base64`,
    `Page:    ${url.origin}/${id}.page`,
    `Editor:  ${url.origin}/${id}`,
    '',
  ].join('\n'));
}

function cliDeleted(id) {
  return textOk(`Deleted.\nNote:    ${id}\n`);
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
      return textOk(
        [
          locked ? 'Password set.' : 'Protection removed.',
          `Note:    ${id}`,
          `Protected: ${locked ? 'yes' : 'no'}`,
          '',
        ].join('\n'),
      );
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
      const row = loaded.row || {};
      const origin = (extra && extra.origin) || '';
      const userAgent = (extra && extra.userAgent) || '';
      const headers = noStore({ 'Content-Type': 'text/html; charset=utf-8' });
      // TelegramBot honours a remembered noindex as "no preview", so omit
      // X-Robots-Tag only for its .page fetches (case-insensitive UA sniff);
      // browsers and search crawlers keep the noindex default. Locked notes
      // never reach here (checkReadPassword 401s first), so previews leak
      // nothing. Cache-Control: no-store is always kept.
      if (/telegrambot/i.test(userAgent)) delete headers['X-Robots-Tag'];
      return new Response(
        renderPageView(row.id, text, { createdAt: row.created_at, updatedAt: row.updated_at }, origin),
        { headers },
      );
    }
    default:
      return new Response(text, { headers: headers(plain) });
  }
}

async function handleGet(request, env, ctx, id, mode) {
  const url = new URL(request.url);
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
// Markdown page view (`.page` suffix; rendered with markdown-it)
// ---------------------------------------------------------------------------

/** Hard cap on Markdown input length so hostile input stays cheap to render. */
const PAGE_MAX_CHARS = 1000000;

/**
 * Decode HTML entities back to characters for URL-scheme checks, so
 * `javascript&#58;...` cannot smuggle a dangerous scheme past the filter.
 */
function decodeEntitiesForCheck(value) {
  return String(value)
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#x([0-9a-f]+);?/gi, (m, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);?/g, (m, dec) => String.fromCharCode(parseInt(dec, 10)));
}

/**
 * True when the (possibly entity-encoded, padded) URL uses a dangerous
 * scheme: javascript:, data:, vbscript:, or file:. Comparison is done after
 * entity decoding and after trimming leading spaces/control characters, so
 * case, spacing, and encoding tricks do not slip through.
 */
function hasDangerousScheme(url) {
  const cleaned = decodeEntitiesForCheck(url).replace(/^[\s\x00-\x20]+/, '').toLowerCase();
  return /^(javascript|data|vbscript|file)\s*:/.test(cleaned);
}

/**
 * True for a raw link target we keep: only http, https, or mailto. Anything
 * else (relative URLs included) degrades to plain text.
 */
function isSafeHrefRaw(href) {
  const clean = String(href).trim();
  if (!clean) return false;
  if (hasDangerousScheme(clean)) return false;
  const decoded = decodeEntitiesForCheck(clean).replace(/^[\s\x00-\x20]+/, '');
  return /^(https?:|mailto:)/i.test(decoded);
}

/**
 * True for a raw image source we keep: http, https, or a relative path. Any
 * other scheme (or a protocol-relative `//host/...`) drops the image.
 */
function isSafeImgSrcRaw(src) {
  const clean = String(src).trim();
  if (!clean) return false;
  if (hasDangerousScheme(clean)) return false;
  const decoded = decodeEntitiesForCheck(clean).replace(/^[\s\x00-\x20]+/, '');
  if (/^\/\//.test(decoded)) return false;
  const scheme = decoded.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (scheme) return /^(https?)$/i.test(scheme[1]);
  return true;
}

/**
 * Shared markdown-it instance for `.page`. `html:false` turns raw HTML
 * (iframe/video/script/img-onerror) into escaped text; `linkify:false` keeps
 * bare URLs unlinked; tables are disabled so they degrade to plain-text
 * paragraphs instead of 404ing.
 */
const pageMd = new MarkdownIt({ html: false, linkify: false, typographer: false, breaks: false });
pageMd.disable('table');
// Identity link normalization: the default encodes URLs via mdurl/punycode
// (see markdown-it#945) and would rewrite hrefs before we see them. Scheme
// safety is enforced by our own render rules below, so keep the raw href.
pageMd.normalizeLink = function (url) { return url; };
// Accept every link at parse time; bad protocols degrade to label text in
// link_open/link_close instead of leaking back as `[t](u)` source text.
pageMd.validateLink = function () { return true; };

/** Map a heading level onto the Telegraph scale (h1 never survives: see below). */
function pageHeadingTag(level) {
  if (level <= 2) return 'h2';
  if (level === 3) return 'h3';
  return 'h4';
}

function pageRemapHeading(tokens, idx, options) {
  tokens[idx].tag = pageHeadingTag(Number(tokens[idx].tag.slice(1)));
  return pageMd.renderer.renderToken(tokens, idx, options);
}

// The first h1 is consumed as the page title (markdownToHtml splices its
// tokens out); any later h1 degrades to h2, h2 stays h2, h3 stays h3,
// h4 and deeper become h4.
pageMd.renderer.rules.heading_open = pageRemapHeading;
pageMd.renderer.rules.heading_close = pageRemapHeading;

// Fenced and indented code: drop the language hint, escape the raw content.
function pageCodeBlock(tokens, idx) {
  return '<pre><code>' + escapeHtml(tokens[idx].content) + '</code></pre>\n';
}
pageMd.renderer.rules.fence = pageCodeBlock;
pageMd.renderer.rules.code_block = pageCodeBlock;

// Links: only http/https/mailto survive. Anything else (javascript:, data:,
// vbscript:, file:, relative URLs) degrades to its label text: both tags are
// suppressed via the env counter while children render normally. Survivors
// keep only href (+rel) — any title attribute is dropped.
pageMd.renderer.rules.link_open = function (tokens, idx, options, env) {
  const href = tokens[idx].attrGet('href') || '';
  if (!isSafeHrefRaw(href)) {
    env.badLinkDepth = (env.badLinkDepth || 0) + 1;
    return '';
  }
  tokens[idx].attrs = [['href', String(href).trim()], ['rel', 'noopener']];
  return pageMd.renderer.renderToken(tokens, idx, options);
};
pageMd.renderer.rules.link_close = function (tokens, idx, options, env) {
  if (env.badLinkDepth > 0) {
    env.badLinkDepth -= 1;
    return '';
  }
  return pageMd.renderer.renderToken(tokens, idx, options);
};

// Images: only src/alt/loading are ever emitted (no title, no event-handler
// attributes). An unsafe src drops the image entirely.
pageMd.renderer.rules.image = function (tokens, idx, options, env) {
  const tok = tokens[idx];
  const src = tok.attrGet('src') || '';
  if (!isSafeImgSrcRaw(src)) return '';
  const alt = escapeHtml(pageMd.renderer.renderInlineAsText(tok.children || [], options, env));
  return '<img src="' + escapeHtml(String(src).trim()) + '" alt="' + alt + '" loading="lazy">';
};

/**
 * A paragraph holding nothing but one image (ignoring blank text and line
 * breaks), or null. Used to wrap lone images in figure/figcaption.
 */
function pageSingleImage(tokens, idx) {
  const inline = tokens[idx + 1];
  if (!inline || inline.type !== 'inline' || !inline.children) return null;
  const kids = inline.children.filter(function (t) {
    return !(
      (t.type === 'text' && /^\s*$/.test(t.content)) ||
      t.type === 'softbreak' ||
      t.type === 'hardbreak'
    );
  });
  if (kids.length === 1 && kids[0].type === 'image') return kids[0];
  return null;
}

pageMd.renderer.rules.paragraph_open = function (tokens, idx, options, env) {
  // Tight-list paragraphs are hidden: render nothing, like the default rule
  // (renderToken does this automatically; this custom rule must do it here).
  // Figures therefore only ever wrap top-level lone images.
  if (tokens[idx].hidden) return '';
  const img = pageSingleImage(tokens, idx);
  if (!img) return '<p>';
  if (!isSafeImgSrcRaw(img.attrGet('src') || '')) {
    env.figureDrop = true;
    return '';
  }
  env.figureAlt = pageMd.renderer.renderInlineAsText(img.children || [], options, env);
  env.figureOpen = true;
  return '<figure>';
};

pageMd.renderer.rules.paragraph_close = function (tokens, idx, options, env) {
  if (tokens[idx].hidden) return '';
  if (env.figureDrop) {
    env.figureDrop = false;
    return '';
  }
  if (env.figureOpen) {
    env.figureOpen = false;
    const cap = env.figureAlt !== undefined && /\S/.test(env.figureAlt)
      ? '<figcaption>' + escapeHtml(env.figureAlt) + '</figcaption>'
      : '';
    env.figureAlt = undefined;
    return cap + '</figure>\n';
  }
  return '</p>\n';
};

/**
 * Find the source line of the page title: the first `# ` heading (exactly
 * one `#`) outside fenced code. Mirrors the old hand-rolled rule so title
 * selection does not drift.
 */
function findPageTitleLine(lines) {
  let fenced = false;
  for (let k = 0; k < lines.length; k++) {
    if (/^\s{0,3}```/.test(lines[k])) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    const tm = lines[k].match(/^\s{0,3}(#{1,6})\s+(.*?)(?:\s+#+)?\s*$/);
    if (tm && tm[1] === '#' && /\S/.test(tm[2])) return k;
  }
  return -1;
}

/** Truncate to n Unicode code points, appending … when cut. */
function truncateCodePoints(s, n) {
  const points = [...String(s)];
  if (points.length <= n) return String(s);
  return points.slice(0, n).join('') + '…';
}

/** Collapse all whitespace runs to single spaces and trim. */
function collapseWhitespace(s) {
  return String(s).replace(/\s+/g, ' ').trim();
}

/**
 * Reduce our own safe article/title HTML back to preview plain text:
 * images contribute their alt text, every other tag contributes its words.
 * Tags can only be our whitelist (plus markdown-it defaults: strong, em,
 * s, code, pre, a, blockquote, ul/ol/li, br, hr, table-free), so stripping
 * them is safe.
 */
function htmlToPlain(html) {
  return String(html)
    .replace(/<img\b[^>]*\balt="([^"]*)"[^>]*>/gi, ' $1 ')
    .replace(/<[^>]*>/g, ' ');
}

/**
 * Render a note body to a Telegraph-style fragment. Returns
 * `{ title, html }`: `title` is safe inline HTML for the page header (''
 * when the note has no `# ` heading), `html` is the article fragment.
 * markdown-it emits only its default tags here (p, h1-h6 remapped to
 * h2-h4, strong, em, s, code, pre, blockquote, ul, ol, li, br, hr, a,
 * img, figure, figcaption); raw HTML from the note stays escaped text.
 */
export function markdownToHtml(source) {
  let text = String(source == null ? '' : source);
  if (text.length > PAGE_MAX_CHARS) text = text.slice(0, PAGE_MAX_CHARS);
  const env = {};
  const tokens = pageMd.parse(text, env);
  // Consume the title's token triple so it never renders in the body.
  const titleLine = findPageTitleLine(text.replace(/\r\n?/g, '\n').split('\n'));
  let titleHtml = '';
  if (titleLine !== -1) {
    for (let k = 0; k + 2 < tokens.length; k++) {
      if (
        tokens[k].type === 'heading_open' &&
        tokens[k + 1].type === 'inline' &&
        tokens[k + 2].type === 'heading_close' &&
        tokens[k + 1].map &&
        tokens[k + 1].map[0] === titleLine
      ) {
        titleHtml = pageMd.renderer.render(tokens[k + 1].children, pageMd.options, {});
        tokens.splice(k, 3);
        break;
      }
    }
  }
  return { title: titleHtml, html: pageMd.renderer.render(tokens, pageMd.options, env) };
}

/**
 * Full read-only note page in a minimal Telegraph-like frame: centred column,
 * header (title + date), article, and a back-to-editor footer, plus
 * server-rendered share-preview meta (Telegram shows it without running JS).
 * Zero JavaScript, zero external fonts/CSS/JS; styling is one small inline
 * block. `meta` takes `{ createdAt, updatedAt }` (a notes row with
 * `created_at` / `updated_at` works too); `origin` (e.g. request.url's
 * origin) builds the absolute og:url and is omitted when unknown. The title
 * falls back to the note id, the description to `Web Notepad — {id}`.
 */
export function renderPageView(id, text, meta, origin) {
  const safeId = String(id == null ? '' : id);
  const parsed = markdownToHtml(text);
  const titleHtml = parsed.title || escapeHtml(safeId);
  // Preview plain text: strip our own safe markup (images give alt text),
  // collapse whitespace, then truncate by code points — never raw Markdown.
  const plainTitle = truncateCodePoints(collapseWhitespace(htmlToPlain(parsed.title)), 80) || safeId;
  const bodyHtml = parsed.html || '<p class="empty">Empty note.</p>';
  const plainDesc = truncateCodePoints(collapseWhitespace(htmlToPlain(parsed.html)), 160) ||
    'Web Notepad — ' + safeId;
  const m = meta || {};
  const createdAt = m.createdAt !== undefined ? m.createdAt : m.created_at;
  const updatedAt = m.updatedAt !== undefined ? m.updatedAt : m.updated_at;
  const stamp = updatedAt != null ? updatedAt : createdAt != null ? createdAt : null;
  const addressHtml = stamp != null
    ? '<address>' + escapeHtml(formatUtc(stamp)) + '</address>'
    : '';
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
    + '<title>' + escapeHtml(plainTitle) + '</title>\n'
    + '<meta name="description" content="' + escapeHtml(plainDesc) + '">\n'
    + '<meta property="og:title" content="' + escapeHtml(plainTitle) + '">\n'
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
    + '.wrap{max-width:732px;margin:0 auto;padding:21px 0 60px}main{display:block}\n'
    + 'h1{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:32px;line-height:1.25;font-weight:700;margin:21px 21px 12px;overflow-wrap:break-word}\n'
    + 'address{font-style:normal;font-size:15px;color:#79828B;margin:0 21px 21px}\n'
    + '.content p{margin:0 21px 12px;overflow-wrap:break-word}\n'
    + '.content h2{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:28px;line-height:1.3;font-weight:700;margin:26px 21px 12px}\n'
    + '.content h3{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:24px;line-height:1.35;font-weight:700;margin:24px 21px 10px}\n'
    + '.content h4{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:21px;line-height:1.4;font-weight:700;margin:22px 21px 10px}\n'
    + '.content a{color:inherit;text-decoration:underline}\n'
    + '.content code{font-family:Menlo,Consolas,monospace;font-size:16px;background:#F5F8FC;padding:2px 4px;border-radius:3px;overflow-wrap:break-word}\n'
    + '.content pre{background:#F5F8FC;padding:14px 21px;margin:0 0 14px;overflow-x:auto}\n'
    + '.content pre code{background:none;padding:0;border-radius:0}\n'
    + '.content blockquote{margin:0 21px 14px;padding:0 0 0 16px;border-left:3px solid #000;font-style:italic}\n'
    + '.content blockquote p{margin:0}\n'
    + '.content ul,.content ol{margin:0 21px 14px;padding:0;list-style:none}\n'
    + '.content ul li{position:relative;padding-left:24px;margin-bottom:8px}\n'
    + '.content ul li:before{content:"•";position:absolute;left:8px}\n'
    + '.content ol{counter-reset:pageol}.content ol li{position:relative;padding-left:30px;margin-bottom:8px;counter-increment:pageol}\n'
    + '.content ol li:before{content:counter(pageol) ".";position:absolute;left:8px}\n'
    + '.content img{max-width:100%;height:auto;display:block}\n'
    + '.content figure{margin:0 0 16px;text-align:center}\n'
    + '.content figure img{margin:0 auto}\n'
    + '.content figcaption{font-size:15px;color:#79828B;margin-top:8px;padding:0 21px}\n'
    + '.content hr{border:none;border-top:1px solid #c9cdd1;width:50%;margin:24px auto}\n'
    + '.content .empty{color:#79828B;font-style:italic}\n'
    + 'footer{margin:32px 21px 0;font-size:15px;color:#79828B;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}\n'
    + 'footer a{color:inherit}\n'
    + '@media(max-width:480px){.wrap{padding:16px 0 40px}h1{font-size:28px;margin:16px 16px 10px}address,.content p,.content h2,.content h3,.content h4,.content blockquote,.content ul,.content ol,footer{margin-left:16px;margin-right:16px}}\n'
    + '</style>\n'
    + '</head>\n'
    + '<body>\n'
    + '<div class="wrap">\n'
    + '<main>\n'
    + '<header>\n'
    + '<h1>' + titleHtml + '</h1>\n'
    + addressHtml + (addressHtml ? '\n' : '')
    + '</header>\n'
    + '<article class="content">\n'
    + bodyHtml + '\n'
    + '</article>\n'
    + '<footer><a href="/' + escapeHtml(safeId) + '">Edit this note</a></footer>\n'
    + '</main>\n'
    + '</div>\n'
    + '</body>\n'
    + '</html>';
}


// ---------------------------------------------------------------------------
// Instance skill doc (/SKILLS.md)
// ---------------------------------------------------------------------------

/** Usage doc served by this instance at GET /SKILLS.md. */
export function skillsDoc(origin) {
  const base = origin || 'BASE';
  return ('# Web Notepad Skills\n'
  + '\n'
  + 'This file explains how to use this Web Notepad instance.\n'
  + 'The base URL below is the host that serves this file.\n'
  + '\n'
  + '## Save a note\n'
  + '\n'
  + 'Browser: open / and type. The page saves on its own.\n'
  + 'Pick any ID: open /my-note and type. An empty save deletes the note.\n'
  + '\n'
  + 'CLI (curl or wget user agent):\n'
  + '\n'
  + 'echo hello | curl --data-binary @- BASE/my-note\n'
  + 'echo hello | curl --data-binary @- BASE/   # new random ID, receipt shows it\n'
  + '\n'
  + 'A save prints a receipt with Note, Saved, Expires, and read URLs.\n'
  + '\n'
  + '## Read a note\n'
  + '\n'
  + 'curl BASE/my-note            # raw text (curl/wget only)\n'
  + 'curl BASE/my-note.txt        # plain text\n'
  + 'curl BASE/my-note.base64     # Base64\n'
  + 'curl BASE/my-note.page       # Markdown page (HTML)\n'
  + '\n'
  + 'Browsers open /my-note and get the editor.\n'
  + '\n'
  + '## Output modes\n'
  + '\n'
  + 'Three spellings, first match wins: suffix, second path part, ?mode=.\n'
  + '\n'
  + '/my-note.txt = plain, /my-note.base64 = base64, /my-note.page = page.\n'
  + '/my-note/plain, /my-note/mtime, /my-note/html, /my-note/css,\n'
  + '/my-note/js, /my-note/json, /my-note/page.\n'
  + '/my-note?mode=page\n'
  + '\n'
  + 'mtime = updated_at as unix seconds. html/css/js/json = body as that type.\n'
  + 'An unknown suffix (for example /index.jsp) returns 400.\n'
  + '\n'
  + '## .page\n'
  + '\n'
  + '/my-note.page renders Markdown to a plain article page (no JS).\n'
  + 'The first "# Title" line becomes the page title.\n'
  + 'The page head has og:title and og:description, so a link\n'
  + 'shared to Telegram shows a text preview.\n'
  + '\n'
  + '## Append\n'
  + '\n'
  + 'echo " world" | curl --data-binary @- BASE/my-note/append\n'
  + '\n'
  + '## Expiry\n'
  + '\n'
  + 'Tokens: 24h, 72h, 1w, never. New notes live 30 days by default.\n'
  + '\n'
  + 'curl -d \'expires=24h\' BASE/my-note/expire\n'
  + 'curl -d \'expires=never\' BASE/my-note/expire\n'
  + '\n'
  + 'A raw-body CLI save keeps the current expiry.\n'
  + '\n'
  + '## Password lock\n'
  + '\n'
  + 'curl -d \'new=secret\' BASE/my-note/password\n'
  + 'curl -H \'X-Note-Password: secret\' BASE/my-note.txt\n'
  + 'curl \'BASE/my-note.txt?pw=secret\'\n'
  + '\n'
  + 'Reads take the header or ?pw=. Writes take only the header.\n'
  + 'A missing or wrong password returns 401.\n'
  + 'Change: curl -d \'current=secret&new=other\' BASE/my-note/password\n'
  + 'Remove: curl -d \'current=secret&new=\' BASE/my-note/password\n'
  + '\n'
  + '## IDs and limits\n'
  + '\n'
  + 'IDs use a-z A-Z 0-9 _ -, any length.\n'
  + 'Every response is no-store and noindex.\n'
  + 'Browser form saves need the page CSRF token (blind POST = 403).\n'
  + 'Raw writes need a curl or wget user agent.\n'
  + '').split('BASE').join(base);
}


// ---------------------------------------------------------------------------
// Worker entrypoint
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
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

    // Instance skill doc: exact match only, no note lookup, no password gate.
    if (segments.length === 1 && segments[0] === 'SKILLS.md') {
      if (request.method !== 'GET' && request.method !== 'HEAD') return notFound();
      return new Response(skillsDoc(url.origin), {
        headers: noStore({ 'Content-Type': 'text/markdown; charset=utf-8' }),
      });
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
