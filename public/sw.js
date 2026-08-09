/* Service worker: shell con cache, API siempre por red.
   '/' y '/shim.js' van red-primero: si no, un deploy que cambie el shim
   nunca llega a las PWAs instaladas (cache-first + nombre fijo). */
const CACHE='kanjo-v2';
const SHELL=['/manifest.json','/icon-192.png','/icon-512.png'];
const NET_FIRST=new Set(['/','/index.html','/shim.js','/login.html']);
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
  if(NET_FIRST.has(u.pathname)){                              /* red primero, cache de respaldo */
    e.respondWith(fetch(e.request).then(r=>{ const cp=r.clone(); caches.open(CACHE).then(c=>c.put(e.request,cp)); return r; }).catch(()=>caches.match(e.request)));
    return;
  }
  e.respondWith(caches.match(e.request).then(hit=>hit||fetch(e.request).then(r=>{ const cp=r.clone(); caches.open(CACHE).then(c=>c.put(e.request,cp)); return r; })));
});
