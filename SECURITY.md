# Seguridad del Proxy Gemini — StrattPlanner

Toda la comunicación con la IA pasa por `worker/src/index.js` (Cloudflare Worker). El frontend nunca habla con Gemini directamente ni ve la API Key.

---

## 1. Gestión de secretos

| Secreto | Almacenamiento | Cómo configurar |
|---------|---------------|-----------------|
| `GEMINI_KEY` | Cloudflare Secrets | `wrangler secret put GEMINI_KEY` |
| `HMAC_SECRET` | Cloudflare Secrets | `wrangler secret put HMAC_SECRET` |

- Los secretos se inyectan en tiempo de ejecución vía `env.GEMINI_KEY` / `env.HMAC_SECRET`. **Nunca aparecen en el código, en `wrangler.toml` ni en logs.**
- Para rotar un secret: volver a ejecutar `wrangler secret put <NOMBRE>` con el nuevo valor.

---

## 2. App-Attestation: HMAC por request

El header `X-App-Sig: <timestamp>.<hmacHex>` se añade a cada request desde el frontend.

**Algoritmo:**
```
HMAC-SHA256( "${timestamp}:${uid}", HMAC_SECRET )
```

El `uid` se envía también en el header `X-User-Id`. El Worker verifica la firma usando `crypto.subtle.verify()` (Web Crypto API), que realiza comparación en tiempo constante internamente — sin timing attacks.

**Protecciones:**
- **Replay attacks:** el timestamp debe estar dentro de ±5 minutos del reloj del Worker. Requests antiguos/futuros son rechazados.
- **Fail-closed:** cualquier excepción durante la verificación resulta en `403`.
- Requests sin firma válida → `403 Forbidden`.

**Limitación conocida:** `APP_HMAC_SECRET` está embebido en el bundle de JavaScript (visible para quienes inspeccionan el código). Esto es "app attestation lite" — previene scraping casual y requiere que un atacante extraiga el secret antes de poder hacer llamadas. La protección principal es la combinación CORS + HMAC + rate limiting.

---

## 3. Rate Limiting

- **Límite:** 10 llamadas por IP por hora.
- **Almacenamiento:** Cloudflare KV, clave `rl:{ip}:{año}-{mes}-{día}-{hora}`, TTL 2 horas.
- **Consistencia eventual:** KV no es transaccional — dos requests concurrentes pueden incrementar el contador simultáneamente. Para este caso de uso (fotos de tareas) la tolerancia es aceptable.
- **Fail-open:** si KV falla, la llamada se permite para no bloquear usuarios.
- Exceder el límite → `429 Too Many Requests`.

> La IP real del cliente llega en el header `CF-Connecting-IP`, inyectado automáticamente por Cloudflare.

---

## 4. CORS

Solo se aceptan requests de los siguientes orígenes:

| Origen | Tipo |
|--------|------|
| `https://strattpllaner.github.io` | Producción (GitHub Pages) |
| `https://strattpllaner.web.app` | Firebase Hosting |
| `https://strattpllaner.firebaseapp.com` | Firebase Hosting legacy |
| `http://localhost:*` | Desarrollo local |
| `http://127.0.0.1:*` | Desarrollo local |

- El origen se parsea con `new URL()` para evitar falsos positivos (ej. `http://localhost.evil.com`).
- CORS denegado → `403` inmediato, sin intentar otras validaciones.
- Requests preflight OPTIONS → `204 No Content`.
- Header `Vary: Origin` incluido para que los CDN respeten el CORS.

---

## 5. Validación de imágenes

Todas las imágenes pasan por `validateImage()` antes de llegar a Gemini:

### 5.1 Tipos permitidos
Solo `image/jpeg` e `image/png`. Cualquier otro `mimeType` → `400`.

### 5.2 Tamaño
Máximo **5 MB** en bytes raw (calculado desde la longitud base64). Se rechaza antes de decodificar completamente.

### 5.3 Magic bytes
Los primeros bytes del archivo se comparan contra las firmas conocidas:
- JPEG: `FF D8 FF`
- PNG: `89 50 4E 47 0D 0A 1A 0A`

Si el `mimeType` declarado no coincide con los magic bytes → `400`. Previene que un archivo malicioso se camufle como imagen.

### 5.4 Codificación base64
El payload se verifica con `/^[A-Za-z0-9+/]+=*$/` para garantizar solo caracteres base64 válidos.

### 5.5 Doble extensión
Se rechaza cualquier metadata con patrones como `foto.jpg.exe`, `.jpg.php`, etc.

### 5.6 Scan de contenido malicioso
El buffer decodificado se escanea en busca de marcadores de ejecutables y scripts:

| Marcador | Tipo de amenaza |
|----------|----------------|
| `<?php`, `<?=` | PHP injection |
| `<script` | XSS / script injection |
| `javascript:`, `vbscript:` | URL injection |
| `MZ` (bytes `4D 5A`) | Windows PE executable |
| `\x7FELF` | Linux ELF binary |
| `#!/` | Shell shebang |

---

## 6. Headers de seguridad

Cada response (incluyendo errores) incluye:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store, no-cache, must-revalidate, private
```

---

## 7. Protección de errores

- Los errores internos **nunca** exponen stack traces ni detalles de implementación al cliente.
- Errores de Gemini se devuelven tal cual (status + JSON), sin revelar la URL ni la API Key.
- Fallos internos → `502 Bad Gateway` con mensaje genérico.

---

## 8. Setup inicial (primera vez)

```bash
# Prerequisito: Node.js instalado
cd worker
npm install

# 1. Crear el namespace KV para rate limiting
wrangler kv namespace create RATE_LIMIT_KV
wrangler kv namespace create RATE_LIMIT_KV --preview
# → Copia los IDs que devuelven y pégalos en wrangler.toml

# 2. Configurar secrets (se piden de forma interactiva)
wrangler secret put GEMINI_KEY
# → pegar la API Key de Gemini cuando lo pida

wrangler secret put HMAC_SECRET
# → pegar el valor: str4tt_2024_7f3e9a1b_c4d5e6f8
#   (debe coincidir exactamente con APP_HMAC_SECRET en index.html)

# 3. Desplegar
wrangler deploy
# → El comando imprime la URL del Worker, algo como:
#   https://strattpllaner-gemini-proxy.TU_SUBDOMAIN.workers.dev

# 4. Actualizar index.html
# Reemplaza TU_SUBDOMAIN en GEMINI_PROXY_URL con el subdominio de tu cuenta Cloudflare.

# 5. (Desarrollo local)
wrangler dev
# → Inicia el Worker en http://localhost:8787
```

---

## 9. Modelo de amenazas y mitigaciones

| Amenaza | Mitigación |
|---------|-----------|
| Robo de API Key de Gemini | Cloudflare Secrets — nunca sale al cliente |
| Llamadas desde otras apps/dominios | CORS restrictivo + HMAC de app-attestation |
| Abuso / spam de IA | Rate limit 10/hora por IP via KV |
| XSS en otro dominio | CORS restrictivo |
| Upload de ejecutables camuflados como imágenes | Magic bytes + scan de marcadores |
| Imágenes gigantes (DoS) | Límite de 5 MB validado antes de decodificar |
| Replay de requests | Ventana HMAC de 5 minutos |
| Timing attacks en HMAC | `crypto.subtle.verify()` (comparación en tiempo constante) |
| Exposición de errores internos | Mensajes genéricos, sin stack traces |

---

## 10. Diferencias respecto a la arquitectura anterior (Firebase Functions)

| Aspecto | Firebase Functions (anterior) | Cloudflare Workers (actual) |
|---------|-------------------------------|----------------------------|
| Plataforma | Google Cloud / Firebase | Cloudflare Edge Network |
| Autenticación de usuario | Firebase ID Token (server-side) | No verificada en servidor |
| Rate limiting | Firestore por UID | KV por IP |
| Logging de eventos sospechosos | Firestore `securityLogs` | No persiste (solo logs de Cloudflare) |
| Plan gratuito | Requiere tarjeta | Sin tarjeta requerida |
| Latencia | ~200-500ms (cold start) | ~5-50ms (edge, sin cold start) |
| Secrets | Firebase Secret Manager | Cloudflare Secrets |
