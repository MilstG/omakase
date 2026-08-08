/* Service worker mínimo: shell estático con cache, API siempre por red. */
const CACHE='kanjo-v1';
const SHELL=['/shim.js','/manifest.json','/icon-192.png','/icon-512.png'];
self.addEventListener('install', e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)).catch(()=>{}));
  self.skipWaiting();
});
self.addEventListener('activate', e=>{
  e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e=>{
  const u=new URL(e.request.url);
  if(u.pathname.startsWith('/api/')) return;                 /* la API nunca se cachea */
  if(e.request.method!=='GET') return;
  if(u.pathname==='/'){                                       /* index: red primero, cache de respaldo */
    e.respondWith(fetch(e.request).then(r=>{ const cp=r.clone(); caches.open(CACHE).then(c=>c.put(e.request,cp)); return r; }).catch(()=>caches.match(e.request)));
    return;
  }
  e.respondWith(caches.match(e.request).then(hit=>hit||fetch(e.request).then(r=>{ const cp=r.clone(); caches.open(CACHE).then(c=>c.put(e.request,cp)); return r; })));
});
