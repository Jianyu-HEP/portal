'use strict';
(() => {
  const form = document.querySelector('#unlockForm');
  const message = document.querySelector('#message');
  const button = form.querySelector('button');
  const decoder = new TextDecoder();
  const packCache = new Map(), imageCache = new Map();
  const decode64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const request = async path => {
    const response = await fetch(new URL(path, location.href), {cache:'no-store'});
    if (!response.ok) throw Error('download');
    return response.arrayBuffer();
  };
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!crypto.subtle) { message.textContent = 'Please open the HTTPS link in a recent browser.'; return; }
    button.disabled = true; message.textContent = 'Unlocking...';
    let meta, encrypted, key;
    try {
      meta = await (await fetch('./vault.json', {cache:'no-store'})).json();
      encrypted = new Uint8Array(await request(meta.bundle));
      const password = document.querySelector('#password').value;
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
      key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:decode64(meta.salt), iterations:meta.iterations, hash:'SHA-256'}, material, {name:'AES-GCM', length:256}, false, ['decrypt']);
    } catch (_) {
      message.textContent = 'Connection failed. Please try again.'; button.disabled = false; return;
    }
    let bundle;
    try {
      const clear = await crypto.subtle.decrypt({name:'AES-GCM',iv:encrypted.slice(0,12),additionalData:new TextEncoder().encode('portal-bundle-v1')},key,encrypted.slice(12));
      bundle = JSON.parse(decoder.decode(clear));
    } catch (_) {
      message.textContent = 'Incorrect access code. Please try again.'; button.disabled = false; document.querySelector('#password').select(); return;
    }
    document.querySelector('#password').value = '';
    async function imageURL(path) {
      if (imageCache.has(path)) return imageCache.get(path);
      const promise = (async () => {
        const asset = bundle.assets[path];
        if (!asset) throw Error('unknown asset');
        if (!packCache.has(asset.file)) packCache.set(asset.file, request(asset.file).catch(error => {packCache.delete(asset.file);throw error;}));
        const pack = new Uint8Array(await packCache.get(asset.file));
        const cipher = pack.slice(asset.offset, asset.offset+asset.length);
        const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:cipher.slice(0,12),additionalData:new TextEncoder().encode(path)},key,cipher.slice(12));
        return URL.createObjectURL(new Blob([plain], {type:asset.mime}));
      })();
      imageCache.set(path, promise);
      promise.catch(() => imageCache.delete(path));
      return promise;
    }
    const loading = new WeakSet();
    async function loadImage(img) {
      if (loading.has(img)) return;
      loading.add(img);
      try {img.src = await imageURL(img.dataset.privateSrc);img.removeAttribute('data-private-src');}
      catch (_) {loading.delete(img);img.alt += ' (Loading failed. Click to retry.)';img.onclick=()=>loadImage(img);}
    }
    const observer = new IntersectionObserver(entries => {
      entries.filter(e => e.isIntersecting).forEach(e => {observer.unobserve(e.target);loadImage(e.target);});
    }, {rootMargin:'250px'});
    const scan = root => {
      if (root.nodeType !== 1) return;
      if (root.matches('img[data-private-src]')) observer.observe(root);
      root.querySelectorAll('img[data-private-src]').forEach(img => observer.observe(img));
    };
    const style = document.createElement('style'); style.textContent=bundle.css;document.head.append(style);
    document.querySelector('#lockStyle').remove();
    document.body.className = '';document.body.innerHTML=bundle.html;
    document.title = bundle.title;
    window.PORTAL_DATA = bundle.data;
    new MutationObserver(records => records.forEach(record => record.addedNodes.forEach(scan))).observe(document.body, {childList:true,subtree:true});
    document.body.addEventListener('click', async event => {
      const logout=event.target.closest('#staticLogout');
      if (logout) {event.preventDefault();location.reload();return;}
      const link=event.target.closest('a[data-private-href]');
      if (!link) return;
      event.preventDefault();
      const preview = window.open('about:blank','_blank');
      if (preview) preview.opener=null;
      try {const url=await imageURL(link.dataset.privateHref);if(preview)preview.location.replace(url);else{link.href=url;link.removeAttribute('data-private-href');link.textContent='Ready. Click to open.';}}
      catch (_) {if(preview)preview.close();link.textContent='Loading failed. Click to retry.';}
    });
    scan(document.body);
    // Key stays in memory only; refresh/exit requires the password again.
    window.addEventListener('pagehide', () => {observer.disconnect();key=null;packCache.clear();imageCache.forEach(p=>p.then(URL.revokeObjectURL).catch(()=>{}));imageCache.clear();});
    window.addEventListener('pageshow', event => {if(event.persisted)location.reload();});
    try {new Function(bundle.app)();}
    catch (_) {message.textContent='Unable to open content. Please refresh.';console.error('Content initialization failed');}
  });
})();
