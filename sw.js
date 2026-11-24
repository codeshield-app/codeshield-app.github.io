/* CodeShield — service worker: lets the app open and scan offline (e.g. on a weak exhibition network).
   App files are cached; GitHub requests always go to the network. */
const VERSION = "codeshield-v0.5.1";
const APP = [
  "./", "index.html", "css/style.css", "icon.svg", "manifest.webmanifest", "og-image.jpg",
  "js/app.js", "js/engine.js", "js/rules.js", "js/tests.js", "js/patch.js", "js/taint.js",
  "js/db.js", "js/github.js", "js/report.js", "js/samples.js", "js/benchmark.js", "js/export.js", "js/progress.js", "js/academy.js", "js/attacks.js"
];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(APP)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET") return;
  if (url.hostname.endsWith("github.com") || url.hostname.endsWith("githubusercontent.com")) return;   // always live
  // fonts: cache after first use
  if (url.hostname.includes("fonts.g")){
    e.respondWith(caches.open(VERSION).then(c => c.match(e.request).then(hit => hit || fetch(e.request).then(r => { c.put(e.request, r.clone()); return r; }))));
    return;
  }
  if (url.origin !== location.origin) return;
  // app files: network first (so updates arrive), cache as fallback when offline
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok){ const copy = r.clone(); caches.open(VERSION).then(c => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request).then(hit => hit || caches.match("index.html"))));
});
