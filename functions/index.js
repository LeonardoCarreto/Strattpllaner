/**
 * Proxy seguro de Gemini para Strattpllaner.
 *
 * La app NO llama a Gemini directamente. Llama a esta función (/api/gemini),
 * que: 1) verifica que el usuario tenga sesión iniciada (Firebase Auth),
 *      2) llama a Gemini con la API Key SECRETA (guardada en Secret Manager),
 *      3) devuelve la respuesta de Gemini tal cual.
 *
 * Así la API Key nunca sale al navegador ni aparece en el código.
 */

const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");

admin.initializeApp();

// La key se guarda con:  firebase functions:secrets:set GEMINI_KEY
const GEMINI_KEY = defineSecret("GEMINI_KEY");

// Modelo que usa la app (el mismo que tenías en el código).
const GEMINI_MODEL = "gemini-2.5-flash-lite";

exports.gemini = onRequest(
  {
    secrets: [GEMINI_KEY],
    region: "us-central1",
    cors: true,
    // Tope de instancias para evitar sustos de facturación si hay abuso.
    maxInstances: 10,
    memory: "256MiB",
    timeoutSeconds: 60,
  },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ error: { message: "Method not allowed" } });
      return;
    }

    // 1) Verificar sesión: solo usuarios con login pueden usar la IA.
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer (.+)$/);
    if (!match) {
      res.status(401).json({ error: { message: "Falta autenticación" } });
      return;
    }

    let uid;
    try {
      const decoded = await admin.auth().verifyIdToken(match[1]);
      uid = decoded.uid;
    } catch (e) {
      res.status(401).json({ error: { message: "Sesión inválida o expirada" } });
      return;
    }

    // 2) Validar el cuerpo (debe ser el payload de Gemini: { contents: [...] }).
    const body = req.body;
    if (!body || typeof body !== "object" || !Array.isArray(body.contents)) {
      res.status(400).json({ error: { message: "Cuerpo inválido" } });
      return;
    }

    // 3) Reenviar a Gemini con la key secreta.
    const url =
      `https://generativelanguage.googleapis.com/v1beta/models/` +
      `${GEMINI_MODEL}:generateContent?key=${GEMINI_KEY.value()}`;

    try {
      const upstream = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await upstream.json().catch(() => ({}));
      // Devolvemos el mismo status y cuerpo que Gemini, para que la app
      // siga manejando los 429 / errores igual que antes.
      res.status(upstream.status).json(data);
    } catch (err) {
      logger.error("Error llamando a Gemini", { uid, err: String(err) });
      res.status(502).json({ error: { message: "Error contactando a la IA" } });
    }
  }
);
