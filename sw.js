// ⚠️ PARA FORZAR ACTUALIZACIÓN: cambia CACHE_VERSION en cada deploy.
// Incrementa la versión: 'v1.0.1' → 'v1.0.2' → 'v1.0.3' ...
// Cambiar la versión invalida el caché viejo y todos los usuarios reciben
// la versión nueva la próxima vez que abran la app.
const CACHE_VERSION = 'v1.2.7';
const CACHE_NAME = 'strattpllaner-' + CACHE_VERSION;

// Archivos base para que la app funcione offline
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-192x192.png',
  '/icons/icon-512x512.png',
  // Fuente principal de la app
  'https://fonts.googleapis.com/css2?family=Baloo+Bhaijaan+2:wght@400;500;600;700;800&display=swap'
];

// Dominios que NUNCA se cachean (Firebase, Auth, APIs, anuncios): siempre red.
const NETWORK_ONLY = [
  'firebaseio.com',
  'firestore.googleapis.com',
  'identitytoolkit.googleapis.com',
  'securetoken.googleapis.com',
  'accounts.google.com',
  'googleapis.com',
  'googlesyndication.com',
  'doubleclick.net'
];

// ── Instalación: cachea los archivos base y activa de inmediato ──────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS).catch(err => {
        console.warn('[SW] Error cacheando assets:', err);
      }))
      .then(() => self.skipWaiting())
  );
});

// ── Activación: borra cachés viejos y toma control inmediato ─────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Fetch ────────────────────────────────────────────────────────────────
// HTML / raíz → NETWORK FIRST (siempre la versión más reciente; caché solo offline)
// Assets estáticos → CACHE FIRST (más rápido)
self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Firebase, Auth, APIs externas y anuncios: dejar que el navegador maneje la red.
  if (NETWORK_ONLY.some(domain => url.hostname.includes(domain))) return;

  const isHTML =
    req.mode === 'navigate' ||
    url.pathname === '/' ||
    url.pathname.endsWith('/') ||
    url.pathname.endsWith('.html');

  if (isHTML) {
    // NETWORK FIRST: intenta la red; si responde, actualiza el caché.
    // Si no hay conexión, sirve la copia cacheada.
    event.respondWith(
      fetch(req)
        .then(response => {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(req, clone));
          return response;
        })
        .catch(() => caches.match(req).then(cached => cached || caches.match('/index.html')))
    );
    return;
  }

  // CACHE FIRST: sirve del caché si existe; si no, va a la red y lo guarda.
  event.respondWith(
    caches.match(req).then(cached => {
      if (cached) return cached;
      return fetch(req).then(response => {
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(req, clone));
        }
        return response;
      });
    })
  );
});
