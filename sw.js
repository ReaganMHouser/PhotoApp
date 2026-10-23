const C="pj-shell-v8",SHELL=["./","index.html","styles.css","config.js","supabase.js","manifest.webmanifest","icon-192.png","icon-512.png","apple-touch-icon.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(SHELL)));self.skipWaiting()});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener("fetch",e=>{const u=new URL(e.request.url);if(e.request.method!=="GET"||u.origin!==location.origin)return;
 // only same-origin app files are cached (never Supabase API/storage or signed URLs); network-first for shell so updates (e.g. config.js) appear; fall back to cache offline
 if(u.search&&!u.pathname.endsWith(".js"))return;
 e.respondWith(fetch(e.request).then(r=>{if(r.ok&&r.type==="basic"){const c=r.clone();caches.open(C).then(x=>x.put(e.request,c))}return r}).catch(()=>caches.match(e.request).then(r=>r||caches.match("index.html"))))});
