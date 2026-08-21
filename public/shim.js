/* shim.js — implementa window.storage contra la API del servidor.
   Login con overlay, versiones por clave, manejo de conflictos 409, y la
   sesión del servidor (usuario + rol + matriz de permisos) publicada en
   window.KANJO_SESSION para que el tablero pinte lo que corresponde. */
(function(){
  const VERS = {};
  let authed = false, authP = null;

  /* ---- toast mínimo ---- */
  function toast(msg){
    let t=document.getElementById('kjToast');
    if(!t){ t=document.createElement('div'); t.id='kjToast';
      t.style.cssText='position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#26221c;color:#f4efe6;font:12px Inter,sans-serif;padding:9px 16px;border-radius:3px;z-index:99999;box-shadow:0 4px 14px rgba(0,0,0,.25);transition:opacity .3s';
      document.body.appendChild(t); }
    t.textContent=msg; t.style.opacity='1';
    clearTimeout(t._h); t._h=setTimeout(()=>{ t.style.opacity='0'; }, 2600);
  }

  /* ---- overlay de login ---- */
  function loginOverlay(){
    return new Promise(resolve=>{
      const ov=document.createElement('div');
      ov.id='kjLogin';
      ov.style.cssText='position:fixed;inset:0;background:#f4efe6;z-index:99998;display:flex;align-items:center;justify-content:center;font-family:Inter,sans-serif';
      ov.innerHTML=
        '<div style="width:320px;max-width:90vw;background:#fdfaf3;border:1px solid #d8d2c4;border-radius:3px;padding:28px 26px;box-shadow:0 6px 24px rgba(60,50,30,.10)">'
        +'<div style="font-family:\'Zilla Slab\',Georgia,serif;font-size:22px;font-weight:600;color:#26221c">Kanjō <span style="color:#A87338">勘定</span></div>'
        +'<div style="font-size:11.5px;color:#8a8377;margin:4px 0 18px">La sesión venció · volvé a entrar</div>'
        +'<input id="kjUs" type="text" placeholder="Usuario" autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false" style="width:100%;box-sizing:border-box;padding:9px 11px;margin-bottom:8px;border:1px solid #d8d2c4;border-radius:3px;font:13px \'JetBrains Mono\',monospace;background:#fff;outline:none">'
        +'<input id="kjPw" type="password" placeholder="Contraseña" autocomplete="current-password" style="width:100%;box-sizing:border-box;padding:9px 11px;border:1px solid #d8d2c4;border-radius:3px;font:13px \'JetBrains Mono\',monospace;background:#fff;outline:none">'
        +'<div id="kjErr" style="font-size:11px;color:#A8392B;min-height:16px;margin-top:6px"></div>'
        +'<button id="kjGo" style="width:100%;margin-top:8px;padding:10px;border:none;border-radius:3px;background:#26221c;color:#f4efe6;font:600 12.5px Inter,sans-serif;letter-spacing:.04em;cursor:pointer">Entrar</button>'
        +'</div>';
      document.body.appendChild(ov);
      const us=ov.querySelector('#kjUs'), pw=ov.querySelector('#kjPw'), err=ov.querySelector('#kjErr'), go=ov.querySelector('#kjGo');
      async function attempt(){
        err.textContent=''; go.disabled=true; go.textContent='…';
        try{
          const r=await fetch('/api/login',{ method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({ username: us.value.trim(), password: pw.value }) });
          if(r.ok){
            const j=await r.json();
            setSession(j.session);
            /* contraseña de un solo uso: hay que cambiarla antes de seguir */
            if(j.session && j.session.mustChange){ location.replace('/login.html'); return; }
            ov.remove(); resolve(); return;
          }
          err.textContent = r.status===429 ? 'Demasiados intentos: esperá unos minutos.' : 'Usuario o contraseña incorrectos.';
        }catch(e){ err.textContent='No se pudo conectar con el servidor.'; }
        go.disabled=false; go.textContent='Entrar'; pw.select();
      }
      go.addEventListener('click', attempt);
      [us,pw].forEach(el=>el.addEventListener('keydown', e=>{ if(e.key==='Enter') attempt(); }));
      setTimeout(()=>us.focus(), 50);
    });
  }

  /* Una sola puerta de entrada para la sesión: el tablero lee KANJO_SESSION.
     KANJO_SERVER_ROLE queda como alias del id del rol (compatibilidad). */
  function setSession(s){
    if(!s) return;
    window.KANJO_SESSION = s;
    window.KANJO_SERVER_ROLE = s.role;
  }
  async function me(){
    try{
      const r=await fetch('/api/me');
      if(r.ok){ const j=await r.json(); setSession(j.session); window.KANJO_MODULES=j.modules||[]; return true; }
    }catch(e){}
    return false;
  }
  function ensureAuth(){
    if(authed) return Promise.resolve();
    if(!authP) authP=(async()=>{
      if(!(await me())) await loginOverlay();
      authed=true;
      if(window.applyRoles){ try{ window.applyRoles(); }catch(e){} }
    })();
    return authP;
  }

  async function req(method, key, body){
    await ensureAuth();
    const r=await fetch('/api/storage/'+encodeURIComponent(key), {
      method, headers: body?{'Content-Type':'application/json'}:undefined,
      body: body?JSON.stringify(body):undefined });
    if(r.status===401){ authed=false; authP=null; await ensureAuth(); return req(method,key,body); }
    return r;
  }

  window.storage = {
    async get(key){
      const r=await req('GET', key);
      if(r.status===404) return null;
      if(!r.ok) throw new Error('storage.get '+r.status);
      const j=await r.json(); VERS[key]=j.version;
      return { key, value:j.value };
    },
    async set(key, value){
      let v=VERS[key];
      if(v===undefined){                       /* primera escritura: aprender versión actual */
        const g=await req('GET', key);
        if(g.ok){ const j=await g.json(); VERS[key]=j.version; v=j.version; }
        else v=null;
      }
      let r=await req('PUT', key, { value, version: v==null?null:v });
      if(r.status===403){ toast('Tu rol no puede modificar «'+key.replace('kanjo:','')+'»'); throw new Error('forbidden'); }
      if(r.status===409){
        const ok=window.confirm('Otro dispositivo modificó "'+key.replace('kanjo:','')+'" mientras trabajabas.\n\nAceptar = pisar con TU versión.\nCancelar = recargar y traer lo último.');
        if(ok) r=await req('PUT', key, { value, force:true });
        else { location.reload(); throw new Error('conflict-reload'); }
      }
      if(!r.ok) throw new Error('storage.set '+r.status);
      const j=await r.json(); VERS[key]=j.version;
      return { key, value };
    },
    async delete(key){
      const r=await req('DELETE', key);
      if(r.status===403){ toast('Tu rol no puede borrar «'+key.replace('kanjo:','')+'»'); throw new Error('forbidden'); }
      if(!r.ok && r.status!==404) throw new Error('storage.delete '+r.status);
      delete VERS[key];
      return { key, deleted:true };
    },
    async list(prefix){
      await ensureAuth();
      const r=await fetch('/api/storage?prefix='+encodeURIComponent(prefix||''));
      if(!r.ok) throw new Error('storage.list '+r.status);
      return { keys:(await r.json()).keys };
    }
  };

  window.addEventListener('load', ()=>{
    ensureAuth();
    if('serviceWorker' in navigator){ try{ navigator.serviceWorker.register('/sw.js'); }catch(e){} }
  });
})();
