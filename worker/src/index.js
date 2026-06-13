'use strict';

const GEMINI_MODEL   = 'gemini-2.5-flash-lite';
const RATE_LIMIT     = 10;                // max calls per IP per hour
const MAX_BYTES      = 5 * 1024 * 1024;  // 5 MB
const HMAC_WINDOW_MS = 5 * 60 * 1000;    // 5-minute replay window

const ALLOWED_ORIGINS = new Set([
  'https://strattpllaner.github.io',
  'https://strattpllaner.web.app',
  'https://strattpllaner.firebaseapp.com',
]);

// Magic byte signatures
const MAGIC = {
  'image/jpeg': Uint8Array.from([0xFF, 0xD8, 0xFF]),
  'image/png':  Uint8Array.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
};

const _enc = new TextEncoder();

// Patterns that indicate embedded executables or injection payloads
const EXEC_MARKERS = [
  _enc.encode('<?php'),
  _enc.encode('<?='),
  _enc.encode('<script'),
  _enc.encode('javascript:'),
  _enc.encode('vbscript:'),
  Uint8Array.from([0x4D, 0x5A]),               // Windows PE (MZ)
  Uint8Array.from([0x7F, 0x45, 0x4C, 0x46]),   // Linux ELF
  _enc.encode('#!/'),                           // Shell shebang
];

// ── Helpers ────────────────────────────────────────────────────────────────────

function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.has(origin)) return true;
  try {
    const u = new URL(origin);
    if (u.protocol === 'http:' &&
        (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) return true;
  } catch { /* invalid URL */ }
  return false;
}

function securityHeaders() {
  return {
    'X-Content-Type-Options':    'nosniff',
    'X-Frame-Options':           'DENY',
    'X-XSS-Protection':          '1; mode=block',
    'Referrer-Policy':           'no-referrer',
    'Content-Security-Policy':   "default-src 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control':             'no-store, no-cache, must-revalidate, private',
  };
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin':  origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-App-Sig, X-User-Id, Authorization',
    'Access-Control-Max-Age':       '3600',
    'Vary':                         'Origin',
  };
}

function jsonResponse(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...securityHeaders(),
      ...extraHeaders,
    },
  });
}

// ── HMAC app-attestation (constant-time via Web Crypto) ───────────────────────

async function verifyHmac(sigHeader, userId, secret) {
  if (!sigHeader || !userId || !secret) return false;

  const dotIdx = sigHeader.indexOf('.');
  if (dotIdx === -1) return false;
  const ts     = sigHeader.slice(0, dotIdx);
  const sigHex = sigHeader.slice(dotIdx + 1);

  const age = Date.now() - Number(ts);
  if (isNaN(age) || age < 0 || age > HMAC_WINDOW_MS) return false;
  if (sigHex.length === 0 || sigHex.length % 2 !== 0) return false;
  if (!/^[0-9a-f]+$/i.test(sigHex)) return false;

  const cryptoKey = await crypto.subtle.importKey(
    'raw', _enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
  );

  const sigBytes = Uint8Array.from(
    sigHex.match(/.{2}/g).map(b => parseInt(b, 16)),
  );

  // crypto.subtle.verify performs constant-time comparison internally
  return crypto.subtle.verify(
    'HMAC', cryptoKey, sigBytes,
    _enc.encode(`${ts}:${userId}`),
  );
}

// ── Rate limiting via KV (eventually-consistent — acceptable here) ─────────────

async function checkRateLimit(ip, kv) {
  const now = new Date();
  const bucket =
    `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-` +
    `${now.getUTCDate()}-${now.getUTCHours()}`;
  const key = `rl:${ip}:${bucket}`;

  const raw   = await kv.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= RATE_LIMIT) return false;

  // TTL 2 h so stale keys expire automatically
  await kv.put(key, String(count + 1), { expirationTtl: 7200 });
  return true;
}

// ── Image validation ──────────────────────────────────────────────────────────

function indexOf(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function validateImage(part) {
  const { mimeType, data } = part.inlineData ?? {};

  if (!mimeType || !MAGIC[mimeType]) {
    return `Tipo de archivo no permitido: ${mimeType || 'desconocido'}`;
  }
  if (!data || typeof data !== 'string') {
    return 'Datos de imagen ausentes o inválidos';
  }
  if (!/^[A-Za-z0-9+/]+=*$/.test(data)) {
    return 'Codificación base64 inválida';
  }
  if (/\.(jpe?g|png)\.(exe|php|sh|js|py|bat|cmd|scr)/i.test(data.slice(0, 200))) {
    return 'Nombre de archivo sospechoso (doble extensión)';
  }

  const rawSize = Math.floor(data.length * 3 / 4);
  if (rawSize > MAX_BYTES) return 'Imagen demasiado grande (máximo 5 MB)';

  let bytes;
  try {
    bytes = Uint8Array.from(atob(data), c => c.charCodeAt(0));
  } catch {
    return 'No se pudo decodificar la imagen';
  }

  const magic = MAGIC[mimeType];
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) {
      return `El archivo no es un ${mimeType} válido (magic bytes incorrectos)`;
    }
  }

  for (const marker of EXEC_MARKERS) {
    if (indexOf(bytes, marker) !== -1) {
      return 'Contenido sospechoso detectado en la imagen';
    }
  }

  return null; // OK
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') ?? '';
    // Cloudflare sets CF-Connecting-IP to the real client IP
    const ip = request.headers.get('CF-Connecting-IP') ??
               request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
               'unknown';

    // CORS gate — all responses (including errors) respect this
    if (!isAllowedOrigin(origin)) {
      return jsonResponse(403, { error: { message: 'Forbidden' } });
    }
    const cors = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...securityHeaders(), ...cors },
      });
    }
    if (request.method !== 'POST') {
      return jsonResponse(405, { error: { message: 'Method not allowed' } }, cors);
    }

    // ── 1. HMAC app-attestation ──
    const userId = request.headers.get('X-User-Id') ?? '';
    const appSig = request.headers.get('X-App-Sig') ?? '';

    let hmacOk = false;
    try {
      hmacOk = await verifyHmac(appSig, userId, env.HMAC_SECRET);
    } catch { /* fail closed */ }

    if (!hmacOk) {
      return jsonResponse(403, { error: { message: 'Firma de request inválida' } }, cors);
    }

    // ── 2. Rate limiting (fail-open to avoid blocking users on KV outage) ──
    let allowed = true;
    try {
      allowed = await checkRateLimit(ip, env.RATE_LIMIT_KV);
    } catch { /* fail-open */ }

    if (!allowed) {
      return jsonResponse(
        429,
        { error: { message: `Límite de ${RATE_LIMIT} llamadas por hora alcanzado` } },
        cors,
      );
    }

    // ── 3. Parse body ──
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse(400, { error: { message: 'JSON inválido' } }, cors);
    }
    if (!body || !Array.isArray(body.contents)) {
      return jsonResponse(400, { error: { message: 'Cuerpo de request inválido' } }, cors);
    }

    // ── 4. Image validation (magic bytes + malware scan) ──
    for (const content of body.contents) {
      for (const part of content.parts ?? []) {
        if (!part.inlineData) continue;
        const err = validateImage(part);
        if (err) return jsonResponse(400, { error: { message: err } }, cors);
      }
    }

    // ── 5. Proxy to Gemini — key never exposed to the frontend ──
    const geminiUrl =
      `https://generativelanguage.googleapis.com/v1beta/models/` +
      `${GEMINI_MODEL}:generateContent?key=${env.GEMINI_KEY}`;

    try {
      const upstream = await fetch(geminiUrl, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });
      const data = await upstream.json().catch(() => ({}));
      return new Response(JSON.stringify(data), {
        status:  upstream.status,
        headers: {
          'Content-Type': 'application/json',
          ...securityHeaders(),
          ...cors,
        },
      });
    } catch {
      // Never expose internal error details
      return jsonResponse(502, { error: { message: 'Error contactando a la IA' } }, cors);
    }
  },
};
