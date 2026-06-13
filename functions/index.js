'use strict';

const { onRequest }    = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const logger           = require('firebase-functions/logger');
const admin            = require('firebase-admin');
const crypto           = require('crypto');

admin.initializeApp();

// Secrets set via:  firebase functions:secrets:set GEMINI_KEY
//                   firebase functions:secrets:set HMAC_SECRET
const GEMINI_KEY  = defineSecret('GEMINI_KEY');
const HMAC_SECRET = defineSecret('HMAC_SECRET');

const GEMINI_MODEL       = 'gemini-2.5-flash-lite';
const RATE_LIMIT_PER_HOUR = 10;
const MAX_RAW_BYTES       = 5 * 1024 * 1024;           // 5 MB
const ALLOWED_MIME        = new Set(['image/jpeg', 'image/png']);
const HMAC_WINDOW_MS      = 5 * 60 * 1000;             // 5-minute replay window

// ── Magic bytes ──────────────────────────────────────────────────────────────
// JPEG: FF D8 FF  |  PNG: 89 50 4E 47 0D 0A 1A 0A
const MAGIC = {
  'image/jpeg': [0xFF, 0xD8, 0xFF],
  'image/png':  [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
};

// Markers that indicate embedded executables or injection payloads
const EXEC_MARKERS = [
  Buffer.from('<?php'),
  Buffer.from('<?='),
  Buffer.from('<script'),
  Buffer.from('javascript:'),
  Buffer.from('vbscript:'),
  Buffer.from('\x4D\x5A'),   // Windows PE (MZ)
  Buffer.from('\x7FELF'),    // Linux ELF
  Buffer.from('#!/'),        // Shell shebang
];

// ── CORS ─────────────────────────────────────────────────────────────────────
function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (
    origin === 'https://strattpllaner.github.io' ||
    origin === 'https://strattpllaner.web.app'   ||
    origin === 'https://strattpllaner.firebaseapp.com'
  ) return true;
  try {
    const u = new URL(origin);
    if (u.protocol === 'http:' &&
        (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) return true;
  } catch { /* invalid URL */ }
  return false;
}

function setCorsHeaders(res, origin) {
  res.set('Access-Control-Allow-Origin', origin);
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-App-Sig');
  res.set('Access-Control-Max-Age', '3600');
  res.set('Vary', 'Origin');
}

// ── Security headers (helmet-style) ──────────────────────────────────────────
function setSecurityHeaders(res) {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Content-Security-Policy', "default-src 'none'");
  res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function getClientIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.ip ||
    'unknown'
  );
}

async function logSuspicious(uid, ip, reason, extra = {}) {
  try {
    await admin.firestore().collection('securityLogs').add({
      type:   'suspicious_request',
      uid:    uid || 'unauthenticated',
      ip,
      reason,
      ...extra,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (e) {
    logger.warn('Security log write failed', { error: String(e) });
  }
}

// ── Rate limiting (Firestore transaction) ─────────────────────────────────────
async function checkRateLimit(uid) {
  const db  = admin.firestore();
  const ref = db.collection('rateLimit').doc(uid);
  const now = new Date();
  const hour = `${now.getUTCFullYear()}-${now.getUTCMonth()}-${now.getUTCDate()}-${now.getUTCHours()}`;

  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const d    = snap.exists ? snap.data() : {};
    if (d.hour === hour && (d.count || 0) >= RATE_LIMIT_PER_HOUR) return false;
    const newCount = d.hour === hour ? (d.count || 0) + 1 : 1;
    tx.set(ref, { hour, count: newCount }, { merge: true });
    return true;
  });
}

// ── HMAC verification (constant-time) ────────────────────────────────────────
function verifyHmac(timestamp, uid, sigHex, secret) {
  const age = Date.now() - Number(timestamp);
  if (!timestamp || !sigHex || isNaN(age) || age < 0 || age > HMAC_WINDOW_MS) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}:${uid}`)
    .digest('hex');

  if (sigHex.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(sigHex,   'hex'),
    );
  } catch {
    return false;
  }
}

// ── Image validation ──────────────────────────────────────────────────────────
function validateImagePart(part) {
  const { mimeType, data } = part.inlineData || {};

  if (!mimeType || !ALLOWED_MIME.has(mimeType)) {
    return { ok: false, reason: `Tipo de archivo no permitido: ${mimeType || 'desconocido'}` };
  }
  if (!data || typeof data !== 'string') {
    return { ok: false, reason: 'Datos de imagen ausentes o inválidos' };
  }

  // Reject double-extension patterns in any metadata field (extra safety)
  if (/\.(jpg|jpeg|png)\.(exe|php|sh|js|py|bat|cmd|scr)/i.test(data.slice(0, 200))) {
    return { ok: false, reason: 'Nombre de archivo sospechoso (doble extensión)' };
  }

  // Only valid base64 characters
  if (!/^[A-Za-z0-9+/]+=*$/.test(data)) {
    return { ok: false, reason: 'Codificación base64 inválida' };
  }

  // Size check: base64 length → approximate raw bytes
  const rawSize = Math.floor(data.length * 3 / 4);
  if (rawSize > MAX_RAW_BYTES) {
    return { ok: false, reason: `Imagen demasiado grande (>${Math.round(MAX_RAW_BYTES / 1024 / 1024)}MB)` };
  }

  // Magic byte verification (decode first 16 bytes)
  const header   = Buffer.from(data.slice(0, 24), 'base64');
  const expected = MAGIC[mimeType];
  for (let i = 0; i < expected.length; i++) {
    if (header[i] !== expected[i]) {
      return { ok: false, reason: `El archivo no es un ${mimeType} válido (magic bytes incorrectos)` };
    }
  }

  // Scan full decoded buffer for embedded executables / scripts
  const full = Buffer.from(data, 'base64');
  for (const marker of EXEC_MARKERS) {
    if (full.indexOf(marker) !== -1) {
      return { ok: false, reason: 'Contenido sospechoso detectado en la imagen' };
    }
  }

  return { ok: true };
}

// ── Main handler ──────────────────────────────────────────────────────────────
exports.gemini = onRequest(
  {
    secrets:        [GEMINI_KEY, HMAC_SECRET],
    region:         'us-central1',
    cors:           false,     // handled manually below
    maxInstances:   10,
    memory:         '512MiB',  // needed for base64 image decoding
    timeoutSeconds: 60,
  },
  async (req, res) => {
    const ip     = getClientIp(req);
    const origin = req.headers.origin || '';

    // Security headers on every response (including errors)
    setSecurityHeaders(res);

    // ── CORS ──
    if (!isAllowedOrigin(origin)) {
      logger.warn('CORS: origin blocked', { origin, ip });
      res.status(403).json({ error: { message: 'Forbidden' } });
      return;
    }
    setCorsHeaders(res, origin);

    if (req.method === 'OPTIONS') {
      res.status(204).send('');
      return;
    }
    if (req.method !== 'POST') {
      res.status(405).json({ error: { message: 'Method not allowed' } });
      return;
    }

    // ── 1. Firebase Auth verification ──
    const tokenMatch = (req.headers.authorization || '').match(/^Bearer (.+)$/);
    if (!tokenMatch) {
      await logSuspicious(null, ip, 'Missing auth token');
      res.status(401).json({ error: { message: 'Autenticación requerida' } });
      return;
    }
    let uid;
    try {
      uid = (await admin.auth().verifyIdToken(tokenMatch[1])).uid;
    } catch {
      await logSuspicious(null, ip, 'Invalid auth token');
      res.status(401).json({ error: { message: 'Sesión inválida o expirada' } });
      return;
    }

    // ── 2. HMAC app-attestation ──
    const [timestamp, sigHex] = (req.headers['x-app-sig'] || '').split('.');
    if (!verifyHmac(timestamp, uid, sigHex, HMAC_SECRET.value())) {
      await logSuspicious(uid, ip, 'Invalid HMAC', { timestamp });
      res.status(403).json({ error: { message: 'Firma de request inválida' } });
      return;
    }

    // ── 3. Rate limiting ──
    let allowed = true;
    try {
      allowed = await checkRateLimit(uid);
    } catch (e) {
      // Fail open to avoid blocking users during Firestore outages
      logger.error('Rate limit check failed', { uid, error: String(e) });
    }
    if (!allowed) {
      await logSuspicious(uid, ip, 'Rate limit exceeded');
      res.status(429).json({ error: { message: `Límite de ${RATE_LIMIT_PER_HOUR} llamadas por hora alcanzado` } });
      return;
    }

    // ── 4. Body structure ──
    const body = req.body;
    if (!body || !Array.isArray(body.contents)) {
      res.status(400).json({ error: { message: 'Cuerpo de request inválido' } });
      return;
    }

    // ── 5. Image validation (magic bytes + malware scan) ──
    for (const content of body.contents) {
      for (const part of content.parts || []) {
        if (!part.inlineData) continue;
        const check = validateImagePart(part);
        if (!check.ok) {
          await logSuspicious(uid, ip, 'Image validation failed', { reason: check.reason });
          res.status(400).json({ error: { message: check.reason } });
          return;
        }
      }
    }

    // ── 6. Forward to Gemini (key never exposed to frontend) ──
    const url =
      'https://generativelanguage.googleapis.com/v1beta/models/' +
      `${GEMINI_MODEL}:generateContent?key=${GEMINI_KEY.value()}`;
    try {
      const upstream = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });
      const data = await upstream.json().catch(() => ({}));
      res.status(upstream.status).json(data);
    } catch (err) {
      logger.error('Gemini request failed', { uid, error: String(err) });
      // Never expose internal error details
      res.status(502).json({ error: { message: 'Error contactando a la IA' } });
    }
  },
);
