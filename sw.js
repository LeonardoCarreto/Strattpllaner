const CACHE_NAME = 'strattpllaner-v29';

// Archivos a cachear para uso offline
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-192x192.png',
  '/icons/icon-512x512.png',
  // Fuentes de Google
  'https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800;900&family=Special+Elite&display=swap'
];

// ── Instalación: cachea los archivos base ──────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(STATIC_ASSETS).catch(err => {
        console.warn('[SW] Error cacheando assets:', err);
      });
    })
  );
  self.skipWaiting();
});

// ── Activación: borra cachés viejos ───────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// ── Fetch: Network First para Firebase/Google, Cache First para el resto ──
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Siempre ir a la red para Firebase, Google Auth y APIs externas
  const networkOnly = [
    'firebaseio.com',
    'firestore.googleapis.com',
    'identitytoolkit.googleapis.com',
    'securetoken.googleapis.com',
    'accounts.google.com',
    'googleapis.com'
  ];

  if (networkOnly.some(domain => url.hostname.includes(domain))) {
    return; // deja que el navegador maneje la petición normalmente
  }

  // Para todo lo demás: Network First, con fallback a caché
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Si la respuesta es válida, la guardamos en caché
        if (response && response.status === 200 && event.request.method === 'GET') {
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseClone);
          });
        }
        return response;
      })
      .catch(() => {
        // Sin red: intentar desde caché
        return caches.match(event.request).then(cached => {
          if (cached) return cached;
          // Si es navegación (HTML), devolver index.html
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html');
          }
        });
      })
  );
});
