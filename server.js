/* Kanjō 勘定 — servidor Express
   - Sirve el tablero (public/) con shim de storage
   - API /api/storage con versiones y control de concurrencia
   - Sesiones firmadas (HMAC) con dos roles: admin y staff
   - Staff no puede escribir claves sensibles (enforcement real, del lado del servidor) */
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const db = require('./lib/db');

const ADMIN_PW = process.env.APP_PASSWORD_ADMIN || process.env.APP_PASSWORD || '';
const STAFF_PW = process.env.APP_PASSWORD_STAFF || '';
/* El secreto NUNCA se deriva de las contraseñas (permitiría forjar cookies o
   brute-forcearlas offline). Sin SESSION_SECRET se genera uno aleatorio por
   proceso: las sesiones caen en cada restart — definilo en Railway. */
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if(!process.env.SESSION_SECRET)
  console.warn('[auth] ⚠ SESSION_SECRET no definido — se generó uno efímero (las sesiones caen en cada deploy/restart).');
const SESS_TTL_MS = 1000*60*60*24*14;   /* 14 días */
const COOKIE = 'kanjo_sess';
/* Modo dev: sin contraseña y sin Postgres, cualquier password entra como admin.
   Con DATABASE_URL (producción) el server se niega a arrancar sin contraseña. */
const DEV_OPEN = !ADMIN_PW && !process.env.DATABASE_URL;

/* Claves que el staff puede LEER (la app las necesita para renderizar)
   pero NO escribir: modelo financiero, escenarios, caja, permisos y sync. */
const ADMIN_ONLY_WRITE = ['kanjo:baseline','kanjo:scenarios','kanjo:caja','kanjo:auth','kanjo:cierres','kanjo:kata','kanjo:wa','kanjo:dou','kanjo:shun',
  'kanjo:hito','kanjo:hitopay','kanjo:kondate'];   /* plantel+grilla, tarifas, cartas QR: escribe admin. Fichaje (hitopunch) y servicio (seki) los escribe el staff */
/* Claves que el staff tampoco puede LEER (saldos de caja, P&L congelado):
   ocultar el tab no alcanza si la API igual entrega el dato. */
const ADMIN_ONLY_READ = ['kanjo:caja','kanjo:cierres','kanjo:hitopay'];   /* hitopay: sueldos y tarifas por hora */

if(!ADMIN_PW && process.env.DATABASE_URL){
  console.error('[auth] ✖ APP_PASSWORD_ADMIN es obligatoria en producción (hay DATABASE_URL). Definila en Railway.');
  process.exit(1);
}
if(DEV_OPEN) console.warn('[auth] ⚠ MODO DEV ABIERTO: sin APP_PASSWORD_ADMIN ni DATABASE_URL, cualquier contraseña entra como admin.');

const app = express();
app.set('trust proxy', 1);            /* Railway: 1 proxy adelante → req.ip es la IP real del cliente */
app.disable('x-powered-by');
app.use(express.json({ limit:'8mb' }));

/* ---------- headers de seguridad ---------- */
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','same-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
    "font-src https://fonts.gstatic.com; img-src 'self' data:; "+
    "connect-src 'self'; "+
    "frame-ancestors 'none'; base-uri 'self'");
  next();
});

/* ---------- sesión ---------- */
const b64u = b => Buffer.from(b).toString('base64url');
const hmac = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function tsEq(a,b){ const A=Buffer.from(String(a)), B=Buffer.from(String(b)); return A.length===B.length && crypto.timingSafeEqual(A,B); }
function signSession(role){
  const body = b64u(JSON.stringify({ role, exp: Date.now()+SESS_TTL_MS }));
  return body+'.'+hmac(body);
}
function readSession(req){
  const raw = (req.headers.cookie||'').split(/;\s*/).find(c=>c.startsWith(COOKIE+'='));
  if(!raw) return null;
  const tok = raw.slice(COOKIE.length+1);
  const i = tok.lastIndexOf('.');
  if(i<0) return null;
  const body = tok.slice(0,i), mac = tok.slice(i+1);
  if(!tsEq(hmac(body), mac)) return null;
  try{
    const p = JSON.parse(Buffer.from(body,'base64url').toString());
    if(!p.exp || p.exp < Date.now()) return null;
    return p.role==='admin'||p.role==='staff' ? p : null;
  }catch(e){ return null; }
}
function setCookie(res, req, value, maxAge){
  const secure = (req.headers['x-forwarded-proto']||'').includes('https');
  res.setHeader('Set-Cookie',
    `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure?'; Secure':''}`);
}

/* ---------- rate limit de login ---------- */
const attempts = new Map();
function limited(ip){
  const now=Date.now();
  /* poda: sin esto el Map crece sin límite */
  if(attempts.size>5000) for(const [k,v] of attempts){ if(now>=v.resetAt) attempts.delete(k); }
  const a=attempts.get(ip);
  if(a && now<a.resetAt && a.n>=10) return true;
  if(!a || now>=a.resetAt) attempts.set(ip,{n:0,resetAt:now+10*60*1000});
  return false;
}
function bump(ip){ const a=attempts.get(ip); if(a) a.n++; }

/* ---------- auth API ---------- */
app.post('/api/login', (req,res)=>{
  /* req.ip con trust proxy: la parte spoofeable de X-Forwarded-For no cuenta */
  const ip = req.ip || req.socket.remoteAddress || '?';
  if(limited(ip)) return res.status(429).json({ error:'too_many_attempts' });
  const pw = String((req.body&&req.body.password)||'');
  let role = null;
  if(ADMIN_PW && tsEq(pw, ADMIN_PW)) role='admin';
  else if(STAFF_PW && tsEq(pw, STAFF_PW)) role='staff';
  else if(DEV_OPEN) role='admin';
  if(!role){ bump(ip); return res.status(401).json({ error:'bad_password' }); }
  setCookie(res, req, signSession(role), SESS_TTL_MS/1000);
  db.audit(role,'login',null,null,null);
  res.json({ ok:true, role });
});
app.post('/api/logout', (req,res)=>{ setCookie(res, req, 'x', 0); res.json({ ok:true }); });
app.get('/api/me', (req,res)=>{
  const s = readSession(req);
  if(!s) return res.status(401).json({ error:'unauthenticated' });
  res.json({ role: s.role });
});

/* ---------- storage API ---------- */
function requireAuth(req,res,next){
  const s = readSession(req);
  if(!s) return res.status(401).json({ error:'unauthenticated' });
  req.role = s.role; next();
}
const validKey = k => /^kanjo:[a-z0-9_-]{1,64}$/i.test(k);

app.get('/api/storage', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  res.json({ keys: await db.list(req.query.prefix||'') });
});
app.get('/api/storage/:key', requireAuth, async (req,res)=>{
  const k=req.params.key;
  if(!validKey(k)) return res.status(400).json({ error:'bad_key' });
  if(req.role!=='admin' && ADMIN_ONLY_READ.includes(k))
    return res.status(403).json({ error:'admin_only', key:k });
  const r = await db.get(k);
  if(!r) return res.status(404).json({ error:'not_found' });
  res.json(r);
});
app.put('/api/storage/:key', requireAuth, async (req,res)=>{
  const k=req.params.key;
  if(!validKey(k)) return res.status(400).json({ error:'bad_key' });
  if(req.role!=='admin' && ADMIN_ONLY_WRITE.includes(k))
    return res.status(403).json({ error:'admin_only', key:k });
  const { value, version, force } = req.body||{};
  if(typeof value!=='string') return res.status(400).json({ error:'value_must_be_string' });
  if(value.length > 4*1024*1024) return res.status(413).json({ error:'too_large' });
  const r = await db.set(k, value, version==null?null:+version, !!force);
  if(!r.ok && r.conflict) return res.status(409).json({ error:'version_conflict', current:r.current });
  db.audit(req.role, force?'write_force':'write', k, r.version>1? r.version-1:null, r.version);
  res.json({ ok:true, version:r.version });
});
app.delete('/api/storage/:key', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  const k=req.params.key;
  if(!validKey(k)) return res.status(400).json({ error:'bad_key' });
  await db.del(k);
  db.audit(req.role,'delete',k,null,null);
  res.json({ ok:true });
});

/* ---------- IA: puntuar maridaje (proxy — la key nunca sale del servidor) ---------- */
const aiLimit=new Map();
app.post('/api/ai/pair', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  const KEY=process.env.OPENAI_API_KEY||'';
  if(!KEY) return res.status(501).json({ error:'no_api_key' });
  const ip=req.ip||req.socket.remoteAddress||'?';
  const now=Date.now();
  if(aiLimit.size>2000) for(const [k,v] of aiLimit){ if(now>=v.resetAt) aiLimit.delete(k); }
  const a=aiLimit.get(ip);
  if(a && now<a.resetAt && a.n>=30) return res.status(429).json({ error:'rate_limited' });
  if(!a || now>=a.resetAt) aiLimit.set(ip,{n:0,resetAt:now+10*60*1000});
  aiLimit.get(ip).n++;
  const { bebida, pasos, paso, bebidas } = req.body||{};
  const modeB = bebida && Array.isArray(pasos) && pasos.length && pasos.length<=40;      /* una bebida vs el menú */
  const modeP = paso && Array.isArray(bebidas) && bebidas.length && bebidas.length<=40;  /* un paso vs la carta */
  if(!modeB && !modeP) return res.status(400).json({ error:'bad_request' });
  const ings=x=>Array.isArray(x&&x.i)&&x.i.length? ' | ingredientes: '+x.i.slice(0,10).map(s=>String(s).slice(0,40)).join(', ') : '';
  const sys='Sos un sommelier especializado en cocina japonesa omakase en Buenos Aires. Respondé SOLO un objeto JSON válido, sin markdown: {"scores":{"<id>":0-3,...para todos los ids...},"notas":{"<id>":"nota breve",...solo para scores>=2...}}. Escala: 0 no va, 1 funciona, 2 muy bien, 3 maridaje de firma (máximo 2 o 3 treses). Los ingredientes del escandallo son la señal más importante: puntuá según lo que el plato ES hoy, no según su nombre. Notas en castellano rioplatense, máximo 12 palabras.';
  let usr;
  if(modeB){
    const menu=pasos.map(p=>`${String(p.id).slice(0,24)}: ${String(p.n).slice(0,60)} — ${String(p.d||'').slice(0,90)}${ings(p)}${p.prem?' (premium)':''}`).join('\n');
    usr='Menú (id: paso — descripción):\n'+menu+'\n\nBebida a puntuar contra cada paso:\n'+String(bebida.n).slice(0,80)+' — '+String(bebida.d||'').slice(0,200)+'\nCategoría: '+String(bebida.cat||'')+(bebida.tier?' '+bebida.tier:'');
  } else {
    const carta=bebidas.map(b=>`${String(b.id).slice(0,24)}: ${String(b.n).slice(0,60)} — ${String(b.d||'').slice(0,90)} [${String(b.cat||'')}${b.tier?' '+b.tier:''}]`).join('\n');
    usr='Carta de bebidas (id: bebida — descripción [categoría]):\n'+carta+'\n\nPlato del omakase, a puntuar contra cada bebida:\n'+String(paso.n).slice(0,80)+' — '+String(paso.d||'').slice(0,200)+ings(paso)+(paso.prem?' (paso premium)':'')
      +'\n\nAdemás clasificá el plato en UN arquetipo de sabor y agregá al JSON la clave "arch" con el id. Opciones — salino: huevas y salinos · uni: erizo y cremosos yodados · carne: res/wagyu · marisco: mariscos dulces (crustáceos, moluscos) · graso: pescado graso o azul (salmón, atún, bonito, caballa, hiramasa) · blanco: pescado blanco delicado · arroz: shari, tamago, miso, temaki · dulce: postre.';
  }
  const AI_BASE=(process.env.OPENAI_BASE_URL||'https://api.openai.com').replace(/\/+$/,'');
  const MODEL=process.env.OPENAI_MODEL||'gpt-5.5';
  const isReasoner=/^(gpt-5|o\d)/i.test(MODEL);   /* gpt-5.x y o-series: effort, sin temperature */
  const payload={ model: MODEL,
    response_format:{type:'json_object'},
    messages:[{role:'system',content:sys},{role:'user',content:usr}] };
  if(isReasoner) payload.reasoning_effort=process.env.OPENAI_REASONING_EFFORT||'medium';
  else payload.temperature=0.4;
  const callAI=body=>fetch(AI_BASE+'/v1/chat/completions',{
    method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+KEY },
    body:JSON.stringify(body) });
  try{
    let r=await callAI(payload);
    if(r.status===400){
      /* modelos nuevos (razonadores, gpt-5.x) pueden rechazar temperature u otros
         parámetros de sampling: reintentar una vez con el payload mínimo */
      const t=await r.text().catch(()=>'');
      console.warn('[ai] 400, reintento sin sampling params:', t.slice(0,160));
      const min={ model:payload.model, response_format:payload.response_format, messages:payload.messages };
      r=await callAI(min);
    }
    if(!r.ok){ const t=await r.text().catch(()=>''); console.warn('[ai]', r.status, t.slice(0,200)); return res.status(502).json({ error:'upstream_'+r.status }); }
    const j=await r.json();
    const raw=(j.choices&&j.choices[0]&&j.choices[0].message&&j.choices[0].message.content)||'';
    const obj=JSON.parse(String(raw).replace(/```json|```/g,'').trim());
    if(!obj.scores) return res.status(502).json({ error:'no_scores' });
    db.audit(req.role,'ai_pair',null,null,null);
    const out={ scores:obj.scores, notas:obj.notas||{} };
    if(modeP && typeof obj.arch==='string') out.arch=String(obj.arch).slice(0,20);
    res.json(out);
  }catch(e){ console.warn('[ai]', e.message); res.status(502).json({ error:'upstream_error' }); }
});

/* ---------- IA: Wa 輪 — alta de producto en la carta de maridaje ----------
   Puntúa un producto nuevo contra el lado opuesto completo, redacta perfil y
   notas elaboradas, y para bebidas propone una alternativa conseguible en
   Argentina. Mismo régimen que /api/ai/pair: solo admin, auditado, límite
   compartido de 30 llamadas cada 10 minutos por IP. */
app.post('/api/ai/wa', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  const KEY=process.env.OPENAI_API_KEY||'';
  if(!KEY) return res.status(501).json({ error:'no_api_key' });
  const ip=req.ip||req.socket.remoteAddress||'?';
  const now=Date.now();
  if(aiLimit.size>2000) for(const [k,v] of aiLimit){ if(now>=v.resetAt) aiLimit.delete(k); }
  const a=aiLimit.get(ip);
  if(a && now<a.resetAt && a.n>=30) return res.status(429).json({ error:'rate_limited' });
  if(!a || now>=a.resetAt) aiLimit.set(ip,{n:0,resetAt:now+10*60*1000});
  aiLimit.get(ip).n++;
  const { nuevo, contra } = req.body||{};
  if(!nuevo || !nuevo.n || !Array.isArray(contra) || !contra.length || contra.length>80)
    return res.status(400).json({ error:'bad_request' });
  const esBebida = nuevo.tipo==='bebida';
  const lista=contra.map(c=>`${String(c.id).slice(0,24)}: ${String(c.n).slice(0,60)}${c.fam?' ['+String(c.fam).slice(0,24)+']':''}${c.cat?' ['+String(c.cat).slice(0,24)+(c.tier?' '+String(c.tier).slice(0,10):'')+']':''}`).join('\n');
  const sys='Sos un sommelier y cocinero especializado en omakase japonés en Buenos Aires. Respondé SOLO un objeto JSON válido, sin markdown: '
    +'{"scores":{"<id>":0-3,...para todos los ids...},"notas":{"<id>":"por qué funciona, 1-2 oraciones con el mecanismo gastronómico o químico",...solo para scores>=2...},"perfil":"perfil del producto nuevo, 2-3 oraciones con sustancia (técnica, origen, cómo marida)"'
    +(esBebida?',"alt":{"n":"alternativa equivalente que se consiga en Argentina (etiqueta o estilo local/importación estable)","w":"por qué es un reemplazo digno, 1-2 oraciones"}':'')
    +'}. Escala: 0 no va, 1 funciona, 2 muy bien, 3 maridaje de firma (máximo 2 o 3 treses). Castellano rioplatense. Nada de tanino alto con pescado graso (metálico); la bebida del postre nunca menos dulce que el plato.';
  const usr='Producto NUEVO en la carta ('+String(nuevo.tipo||'producto').slice(0,12)+'):\n'
    +String(nuevo.n).slice(0,80)+' — '+String(nuevo.d||'sin descripción').slice(0,240)
    +(nuevo.cat?'\nCategoría: '+String(nuevo.cat).slice(0,24):'')
    +(nuevo.tier?'\nNivel: '+String(nuevo.tier).slice(0,10):'')
    +(nuevo.fam?'\nFamilia: '+String(nuevo.fam).slice(0,24):'')
    +'\n\nPuntualo contra cada uno de estos (id: nombre [familia/categoría]):\n'+lista;
  const AI_BASE=(process.env.OPENAI_BASE_URL||'https://api.openai.com').replace(/\/+$/,'');
  const MODEL=process.env.OPENAI_MODEL||'gpt-5.5';
  const isReasoner=/^(gpt-5|o\d)/i.test(MODEL);
  const payload={ model:MODEL, response_format:{type:'json_object'},
    messages:[{role:'system',content:sys},{role:'user',content:usr}] };
  if(isReasoner) payload.reasoning_effort=process.env.OPENAI_REASONING_EFFORT||'medium';
  else payload.temperature=0.4;
  const callAI=body=>fetch(AI_BASE+'/v1/chat/completions',{
    method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+KEY },
    body:JSON.stringify(body) });
  try{
    let r=await callAI(payload);
    if(r.status===400){
      const t=await r.text().catch(()=>'');
      console.warn('[ai:wa] 400, reintento sin sampling params:', t.slice(0,160));
      r=await callAI({ model:payload.model, response_format:payload.response_format, messages:payload.messages });
    }
    if(!r.ok){ const t=await r.text().catch(()=>''); console.warn('[ai:wa]', r.status, t.slice(0,200)); return res.status(502).json({ error:'upstream_'+r.status }); }
    const j=await r.json();
    const raw=(j.choices&&j.choices[0]&&j.choices[0].message&&j.choices[0].message.content)||'';
    const obj=JSON.parse(String(raw).replace(/```json|```/g,'').trim());
    if(!obj.scores) return res.status(502).json({ error:'no_scores' });
    db.audit(req.role,'ai_wa',null,null,null);
    const out={ scores:obj.scores, notas:obj.notas||{}, perfil:typeof obj.perfil==='string'?obj.perfil.slice(0,600):'' };
    if(esBebida && obj.alt && obj.alt.n) out.alt={ n:String(obj.alt.n).slice(0,120), w:String(obj.alt.w||'').slice(0,400) };
    res.json(out);
  }catch(e){ console.warn('[ai:wa]', e.message); res.status(502).json({ error:'upstream_error' }); }
});

/* ---------- IA: Wa 輪 — referencia de precios con búsqueda web ----------
   Busca online (Argentina) el precio retail de hasta 8 bebidas por llamada y
   devuelve una REFERENCIA en ARS y USD neto estimado. Es techo retail, no costo
   de factura: el cliente lo muestra como sugerencia editable, nunca lo guarda solo.
   Admin-only, auditado, comparte el límite de 30/10min. */
app.post('/api/ai/wa/precios', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  const KEY=process.env.OPENAI_API_KEY||'';
  if(!KEY) return res.status(501).json({ error:'no_api_key' });
  const ip=req.ip||req.socket.remoteAddress||'?';
  const now=Date.now();
  const a=aiLimit.get(ip);
  if(a && now<a.resetAt && a.n>=30) return res.status(429).json({ error:'rate_limited' });
  if(!a || now>=a.resetAt) aiLimit.set(ip,{n:0,resetAt:now+10*60*1000});
  aiLimit.get(ip).n++;
  const { bebidas } = req.body||{};
  if(!Array.isArray(bebidas)||!bebidas.length||bebidas.length>8) return res.status(400).json({ error:'bad_request' });
  const lista=bebidas.map(b=>`${String(b.id).slice(0,24)}: ${String(b.n).slice(0,80)} [${String(b.cat||'').slice(0,12)}${b.tier?' '+String(b.tier).slice(0,10):''}]`).join('\n');
  const instr='Sos un sommelier en Buenos Aires. Buscá en la web el precio ONLINE ACTUAL en Argentina (vinotecas, tiendas, supermercados online) de cada bebida listada, o de su equivalente más cercano disponible localmente. Buscá también la cotización del dólar MEP de hoy. Respondé SOLO un objeto JSON, sin markdown: {"precios":{"<id>":{"ars":precio retail en pesos con IVA o null,"usd":precio convertido a USD y dividido por 1.21 (neto de IVA), redondeado a 2 decimales, o null,"fuente":"tienda/sitio y aclaración breve","match":"exacto|equivalente|no encontrado"}}}. Si un producto no se consigue en Argentina, buscá el equivalente que sugiere el estilo y aclaralo en fuente. Nunca inventes precios: si no encontrás nada creíble, null.';
  const AI_BASE=(process.env.OPENAI_BASE_URL||'https://api.openai.com').replace(/\/+$/,'');
  const MODEL=process.env.OPENAI_MODEL||'gpt-5.5';
  try{
    /* Responses API con web_search; si el upstream no lo soporta, fallback a chat sin búsqueda */
    let raw='', conBusqueda=true;
    let r=await fetch(AI_BASE+'/v1/responses',{
      method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+KEY },
      body:JSON.stringify({ model:MODEL, tools:[{type:'web_search'}], input:[
        { role:'system', content:instr },
        { role:'user', content:'Bebidas:\n'+lista }
      ]})});
    if(r.ok){
      const j=await r.json();
      raw=j.output_text||'';
      if(!raw && Array.isArray(j.output))
        raw=j.output.flatMap(o=>Array.isArray(o.content)?o.content:[]).map(c=>c.text||'').join('');
    } else {
      conBusqueda=false;
      const t=await r.text().catch(()=>'' );
      console.warn('[ai:wa:precios] responses '+r.status+' — fallback sin búsqueda:', t.slice(0,140));
      const r2=await fetch(AI_BASE+'/v1/chat/completions',{
        method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+KEY },
        body:JSON.stringify({ model:MODEL, response_format:{type:'json_object'},
          messages:[{role:'system',content:instr+' (No tenés búsqueda web disponible: estimá desde tu conocimiento del mercado argentino y marcá cada fuente como "estimación del modelo, sin búsqueda".)'},
                    {role:'user',content:'Bebidas:\n'+lista}] })});
      if(!r2.ok){ const t2=await r2.text().catch(()=>''); console.warn('[ai:wa:precios]', r2.status, t2.slice(0,160)); return res.status(502).json({ error:'upstream_'+r2.status }); }
      const j2=await r2.json();
      raw=(j2.choices&&j2.choices[0]&&j2.choices[0].message&&j2.choices[0].message.content)||'';
    }
    const m=String(raw).replace(/```json|```/g,'').match(/\{[\s\S]*\}/);
    if(!m) return res.status(502).json({ error:'no_json' });
    const obj=JSON.parse(m[0]);
    if(!obj.precios) return res.status(502).json({ error:'no_precios' });
    const out={};
    for(const [k,v] of Object.entries(obj.precios)){
      if(!v||typeof v!=='object') continue;
      out[String(k).slice(0,24)]={
        ars: typeof v.ars==='number'&&v.ars>0?Math.round(v.ars):null,
        usd: typeof v.usd==='number'&&v.usd>0?Math.round(v.usd*100)/100:null,
        fuente: String(v.fuente||'').slice(0,160),
        match: ['exacto','equivalente','no encontrado'].includes(v.match)?v.match:'equivalente'
      };
    }
    db.audit(req.role,'ai_wa_precios',null,null,null);
    res.json({ precios:out, busqueda:conBusqueda });
  }catch(e){ console.warn('[ai:wa:precios]', e.message); res.status(502).json({ error:'upstream_error' }); }
});

app.get('/api/audit', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  res.json({ entries: await db.auditList(req.query.limit) });
});


/* ---------- IA: Shun 旬 — estacionalidad de producto con búsqueda web ----------
   Recibe hasta 6 ingredientes y devuelve, por cada uno, los 12 meses con estado
   (2 pico · 1 aceptable · 0 fuera · -1 veda legal), nota corta y confianza.
   Busca online zafras y vedas argentinas vigentes. La respuesta entra al cliente
   como sugerencia ✦ pendiente: la IA propone, el itamae decide.
   Admin-only, auditado, comparte el límite de 30/10min. */
app.post('/api/ai/shun', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  const KEY=process.env.OPENAI_API_KEY||'';
  if(!KEY) return res.status(501).json({ error:'no_api_key' });
  const ip=req.ip||req.socket.remoteAddress||'?';
  const now=Date.now();
  if(aiLimit.size>2000) for(const [k,v] of aiLimit){ if(now>=v.resetAt) aiLimit.delete(k); }
  const a=aiLimit.get(ip);
  if(a && now<a.resetAt && a.n>=30) return res.status(429).json({ error:'rate_limited' });
  if(!a || now>=a.resetAt) aiLimit.set(ip,{n:0,resetAt:now+10*60*1000});
  aiLimit.get(ip).n++;
  const { items } = req.body||{};
  if(!Array.isArray(items) || !items.length || items.length>6) return res.status(400).json({ error:'bad_request' });
  const lista=items.map(i=>`${String(i.id).slice(0,24)}: ${String(i.n).slice(0,60)} [${String(i.cat||'').slice(0,20)}]`).join('\n');
  const instr='Sos un experto en producto de mar y huerta de Argentina asesorando a un omakase en Buenos Aires. '
    +'Para cada ingrediente listado, buscá en la web la estacionalidad REAL en Argentina: zafras, desembarques, vedas vigentes por resolución (CFP, provincias), cosechas. '
    +'Respondé SOLO un objeto JSON, sin markdown: {"temporadas":{"<id>":{"m":[12 enteros, enero a diciembre: 2 pico de calidad, 1 aceptable, 0 fuera de temporada, -1 veda legal],'
    +'"nota":"una línea: zafra/veda/fuente de la estacionalidad","confianza":"alta|media|baja"}}}. '
    +'Reglas: si hay veda legal usá -1 en esos meses y nombrá la norma en la nota. Nunca inventes: si no encontrás datos creíbles para un ingrediente, usá confianza "baja", meses conservadores (0/1) y decilo en la nota. Producto de cultivo/importado estable: todo 1 con nota. Castellano rioplatense.';
  const AI_BASE=(process.env.OPENAI_BASE_URL||'https://api.openai.com').replace(/\/+$/,'');
  const MODEL=process.env.OPENAI_MODEL||'gpt-5.5';
  try{
    /* Responses API con web_search; fallback a chat sin búsqueda (igual que /api/ai/wa/precios) */
    let raw='', conBusqueda=true;
    let r=await fetch(AI_BASE+'/v1/responses',{
      method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+KEY },
      body:JSON.stringify({ model:MODEL, tools:[{type:'web_search'}], input:[
        { role:'system', content:instr },
        { role:'user', content:'Ingredientes:\n'+lista }
      ]})});
    if(r.ok){
      const j=await r.json();
      raw=j.output_text||'';
      if(!raw && Array.isArray(j.output))
        raw=j.output.flatMap(o=>Array.isArray(o.content)?o.content:[]).map(c=>c.text||'').join('');
    } else {
      conBusqueda=false;
      const t=await r.text().catch(()=>'');
      console.warn('[ai:shun] responses '+r.status+' — fallback sin búsqueda:', t.slice(0,140));
      const r2=await fetch(AI_BASE+'/v1/chat/completions',{
        method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+KEY },
        body:JSON.stringify({ model:MODEL, response_format:{type:'json_object'},
          messages:[{role:'system',content:instr+' (No tenés búsqueda web: usá tu conocimiento del mercado argentino, bajá la confianza un nivel y aclaralo en cada nota.)'},
                    {role:'user',content:'Ingredientes:\n'+lista}] })});
      if(!r2.ok){ const t2=await r2.text().catch(()=>''); console.warn('[ai:shun]', r2.status, t2.slice(0,160)); return res.status(502).json({ error:'upstream_'+r2.status, detail:String(t2).slice(0,220) }); }
      const j2=await r2.json();
      raw=(j2.choices&&j2.choices[0]&&j2.choices[0].message&&j2.choices[0].message.content)||'';
    }
    const m=String(raw).replace(/```json|```/g,'').match(/\{[\s\S]*\}/);
    if(!m) return res.status(502).json({ error:'no_json' });
    const obj=JSON.parse(m[0]);
    if(!obj.temporadas) return res.status(502).json({ error:'no_temporadas' });
    const out={};
    for(const [k,v] of Object.entries(obj.temporadas)){
      if(!v||typeof v!=='object'||!Array.isArray(v.m)||v.m.length!==12) continue;
      out[String(k).slice(0,24)]={
        m: v.m.map(x=>[2,1,0,-1].includes(+x)?+x:0),
        nota: String(v.nota||'').slice(0,240),
        confianza: ['alta','media','baja'].includes(v.confianza)?v.confianza:'baja'
      };
    }
    if(!Object.keys(out).length) return res.status(502).json({ error:'empty' });
    db.audit(req.role,'ai_shun',null,null,null);
    res.json({ temporadas: out, busqueda: conBusqueda });
  }catch(e){ console.warn('[ai:shun]', e.message); res.status(502).json({ error:'upstream_error' }); }
});


/* ---------- Hito 人: hora del servidor para el fichaje ----------
   El fichaje no confía en el reloj del celular: el cliente pide la hora acá
   y guarda ese valor. Si este endpoint falla, el cliente marca el punch como
   "hora local" para que el admin lo revise. */
app.get('/api/time', requireAuth, (req,res)=>{ res.setHeader('Cache-Control','no-store'); res.json({ now:new Date().toISOString() }); });

/* ---------- Kondate 献立: carta pública por token ----------
   GET /c/:token          página de solo lectura (sin sesión) con el snapshot publicado
   GET /c/:token/qr.png   QR del link (para imprimir / pegar en la barra)
   GET /c/:token/qr       hoja imprimible con el QR y el título (Guardar como PDF desde el navegador)
   El token es aleatorio por carta; nunca expone ids internos ni datos de Genka
   más allá de lo que el admin aprobó. Cartas archivadas muestran solo el título. */
let QR=null; try{ QR=require('qrcode'); }catch(e){ console.warn('[kondate] paquete qrcode no instalado: /c/:token/qr.png devolverá 501'); }
const kdEsc = s => String(s==null?'':s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const kdTokenOk = t => /^[a-z0-9]{10,40}$/i.test(t);
async function kdFindByToken(token){
  const r=await db.get('kanjo:kondate'); if(!r||!r.value) return null;
  let d; try{ d=JSON.parse(r.value); }catch(e){ return null; }
  const cartas=Array.isArray(d&&d.cartas)?d.cartas:[];
  return cartas.find(c=>c&&c.token===token)||null;
}
function kdBaseUrl(req){ return (process.env.PUBLIC_URL||((req.headers['x-forwarded-proto']||req.protocol)+'://'+req.get('host'))).replace(/\/+$/,''); }
const KD_CSS=`:root{--paper:#ECE5D6;--panel:#F4EEE1;--ink:#211C16;--soft:#6A6052;--rule:#CBC1AB;--brass:#A87338;--verm:#A8392B;--indigo:#1E3A4C}
*{box-sizing:border-box}html,body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 Inter,system-ui,sans-serif;-webkit-text-size-adjust:100%}
main{max-width:560px;margin:0 auto;padding:34px 22px 60px}h1{font-family:'Zilla Slab',Georgia,serif;font-size:28px;line-height:1.1;margin:0;font-weight:700}
.sub{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--soft);margin:8px 0 18px}.intro{color:var(--soft);font-size:14px;margin:0 0 18px}
.ps{padding:12px 0;border-top:1px solid var(--rule)}.ps b{font-family:'Zilla Slab',Georgia,serif;font-size:17px;display:block;font-weight:600}
.ps .n{font-family:'JetBrains Mono',ui-monospace,monospace;color:var(--brass);font-size:12px;margin-right:6px}.ps .o{font-size:12.5px;color:var(--soft)}
.ps .m{font-size:12.5px;color:var(--indigo)}.ps .a{font-size:11px;color:var(--verm);margin-top:3px;letter-spacing:.02em}
.ps .en{font-size:13px;color:var(--soft);font-style:italic}.ft{margin-top:26px;font-size:11.5px;color:var(--soft);border-top:1px solid var(--rule);padding-top:12px}
.arch{padding:40px 0;text-align:center;color:var(--soft)}`;
app.get('/c/:token', async (req,res)=>{
  res.setHeader('Cache-Control','no-store');
  const t=req.params.token; if(!kdTokenOk(t)) return res.status(404).type('text/plain').send('No encontrado');
  let c=null; try{ c=await kdFindByToken(t); }catch(e){ return res.status(500).type('text/plain').send('Error'); }
  if(!c) return res.status(404).type('text/plain').send('Carta no encontrada');
  const snap=(c.state==='publicada'||c.state==='archivada') && c.pub ? c.pub : null;
  const head='<!doctype html><html lang="es-AR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>'+kdEsc((snap&&snap.title)||c.title||'Carta')+'</title>'
    +'<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Zilla+Slab:wght@600;700&family=Inter:wght@400;500&family=JetBrains+Mono&display=swap" rel="stylesheet"><style>'+KD_CSS+'</style></head><body><main>';
  if(!snap) return res.status(200).type('html').send(head+'<h1>'+kdEsc(c.title||'Carta')+'</h1><div class="arch">Esta carta todavía no fue publicada.</div></main></body></html>');
  if(c.state==='archivada') return res.type('html').send(head+'<h1>'+kdEsc(snap.title)+'</h1><div class="sub">'+kdEsc(snap.sub||'')+'</div><div class="arch">Este servicio ya terminó. Gracias por venir.</div></main></body></html>');
  const sh=snap.show||{}; const lang=snap.lang||'es';
  const pasos=(snap.pasos||[]).filter(p=>!p.hidden);
  const body=pasos.map((p,i)=>'<div class="ps"><b><span class="n">'+String(i+1).padStart(2,'0')+'</span>'+kdEsc(p.n)+'</b>'
    +(lang!=='en'&&p.d?'<div>'+kdEsc(p.d)+'</div>':'')
    +(lang!=='es'&&p.den?'<div class="en">'+kdEsc(p.den)+'</div>':(lang==='en'&&p.d?'<div>'+kdEsc(p.d)+'</div>':''))
    +(sh.origen&&p.o?'<div class="o">'+kdEsc(p.o)+'</div>':'')
    +(sh.mar&&p.m?'<div class="m">'+kdEsc(p.m)+'</div>':'')
    +(sh.alg&&Array.isArray(p.alg)&&p.alg.length?'<div class="a">'+kdEsc(p.alg.join(' · '))+'</div>':'')
    +'</div>').join('');
  const precio=sh.precio&&snap.precio?'<div class="ps"><b>'+(lang==='en'?'Full menu':'Menú completo')+'</b><div>'+kdEsc(snap.precio)+'</div></div>':'';
  const foot=lang==='en'?'Please tell us about any allergy or restriction before we begin.':'Avisanos cualquier alergia o restricción antes de empezar.';
  res.type('html').send(head+'<h1>'+kdEsc(snap.title)+'</h1><div class="sub">'+kdEsc(snap.sub||'')+'</div>'+(snap.intro?'<p class="intro">'+kdEsc(snap.intro)+'</p>':'')+body+precio+'<div class="ft">'+foot+' · v'+(snap.v||1)+'</div></main></body></html>');
});
app.get('/c/:token/qr.png', async (req,res)=>{
  const t=req.params.token; if(!kdTokenOk(t)) return res.status(404).end();
  if(!QR) return res.status(501).type('text/plain').send('Falta el paquete qrcode (npm i qrcode)');
  try{
    const c=await kdFindByToken(t); if(!c) return res.status(404).end();
    const buf=await QR.toBuffer(kdBaseUrl(req)+'/c/'+t,{ type:'png', width:+req.query.w>0?Math.min(+req.query.w,2000):600, margin:2, errorCorrectionLevel:'M', color:{ dark:'#211C16', light:'#FFFFFF' } });
    res.setHeader('Content-Disposition','inline; filename="carta-'+t.slice(0,6)+'.png"'); res.type('png').send(buf);
  }catch(e){ console.warn('[kondate:qr]', e.message); res.status(500).end(); }
});
app.get('/c/:token/qr', async (req,res)=>{
  const t=req.params.token; if(!kdTokenOk(t)) return res.status(404).end();
  try{
    const c=await kdFindByToken(t); if(!c) return res.status(404).end();
    const url=kdBaseUrl(req)+'/c/'+t;
    res.type('html').send('<!doctype html><html lang="es-AR"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>QR · '+kdEsc(c.title)+'</title><link href="https://fonts.googleapis.com/css2?family=Zilla+Slab:wght@700&family=Inter&display=swap" rel="stylesheet"><style>'+KD_CSS
      +'main{max-width:420px;text-align:center;padding-top:60px}img{width:300px;height:300px;border:1px solid var(--rule);background:#fff;padding:12px}.u{font-family:ui-monospace,monospace;font-size:12px;color:var(--soft);margin-top:10px;word-break:break-all}@media print{.np{display:none}}</style></head><body><main>'
      +'<h1>'+kdEsc(c.title)+'</h1><div class="sub">Escaneá para ver la carta</div><img src="/c/'+t+'/qr.png?w=900" alt="QR"><div class="u">'+kdEsc(url)+'</div>'
      +'<p class="np" style="margin-top:22px;font-size:12px;color:var(--soft)">Imprimí esta hoja o usá «Guardar como PDF» en el diálogo de impresión.</p><button class="np" onclick="print()" style="padding:9px 16px;border:1px solid var(--indigo);background:var(--indigo);color:#fff;border-radius:2px;cursor:pointer">Imprimir</button></main></body></html>');
  }catch(e){ res.status(500).end(); }
});

/* ---------- IA: Kondate 献立 — redactar la carta para el comensal ----------
   Recibe los pasos (nombre + descripción técnica de Genka + ingredientes +
   maridaje de Wa si lo hay) y devuelve por paso: descripción breve en
   castellano rioplatense, versión en inglés y una línea de maridaje. NO
   propone alérgenos (se marcan a mano). Todo vuelve ✦ sin aprobar.
   Mismo régimen que el resto: admin, auditado, límite compartido 30/10min. */
app.post('/api/ai/kondate', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  const KEY=process.env.OPENAI_API_KEY||'';
  if(!KEY) return res.status(501).json({ error:'no_api_key' });
  const ip=req.ip||req.socket.remoteAddress||'?';
  const now=Date.now();
  if(aiLimit.size>2000) for(const [k,v] of aiLimit){ if(now>=v.resetAt) aiLimit.delete(k); }
  const a=aiLimit.get(ip);
  if(a && now<a.resetAt && a.n>=30) return res.status(429).json({ error:'rate_limited' });
  if(!a || now>=a.resetAt) aiLimit.set(ip,{n:0,resetAt:now+10*60*1000});
  aiLimit.get(ip).n++;
  const { pasos, tono } = req.body||{};
  if(!Array.isArray(pasos) || !pasos.length || pasos.length>24) return res.status(400).json({ error:'bad_request' });
  const lista=pasos.map(p=>`${String(p.id).slice(0,24)}: ${String(p.n).slice(0,60)} — ${String(p.d||'').slice(0,120)}`
    +(Array.isArray(p.i)&&p.i.length?' | ingredientes: '+p.i.slice(0,10).map(s=>String(s).slice(0,40)).join(', '):'')
    +(p.o?' | origen: '+String(p.o).slice(0,60):'')+(p.m?' | maridaje: '+String(p.m).slice(0,80):'')).join('\n');
  const sys='Redactás la carta que lee el comensal en un omakase de 13 lugares en Buenos Aires. Respondé SOLO un objeto JSON válido, sin markdown: {"pasos":{"<id>":{"d":"descripción para el comensal, castellano rioplatense, 6 a 14 palabras, sin tecnicismos de cocina ni cantidades","den":"la misma idea en inglés, 6 a 14 palabras","m":"línea de maridaje si hay bebida: qué busca el vínculo, máximo 10 palabras; vacío si no hay"}}}. '
    +'Tono: '+(['sobrio','cálido','poético'].includes(tono)?tono:'sobrio')+'. Nunca inventes ingredientes ni orígenes que no estén en los datos. No menciones alérgenos. No uses signos de exclamación.';
  const AI_BASE=(process.env.OPENAI_BASE_URL||'https://api.openai.com').replace(/\/+$/,'');
  const MODEL=process.env.OPENAI_MODEL||'gpt-5.5';
  const isReasoner=/^(gpt-5|o\d)/i.test(MODEL);
  const payload={ model:MODEL, response_format:{type:'json_object'}, messages:[{role:'system',content:sys},{role:'user',content:'Pasos (id: nombre — descripción técnica):\n'+lista}] };
  if(isReasoner) payload.reasoning_effort=process.env.OPENAI_REASONING_EFFORT||'medium'; else payload.temperature=0.5;
  const callAI=body=>fetch(AI_BASE+'/v1/chat/completions',{ method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+KEY }, body:JSON.stringify(body) });
  try{
    let r=await callAI(payload);
    if(r.status===400){ const t=await r.text().catch(()=>''); console.warn('[ai:kondate] 400, reintento mínimo:', t.slice(0,160)); r=await callAI({ model:payload.model, response_format:payload.response_format, messages:payload.messages }); }
    if(!r.ok){ const t=await r.text().catch(()=>''); console.warn('[ai:kondate]', r.status, t.slice(0,200)); return res.status(502).json({ error:'upstream_'+r.status }); }
    const j=await r.json();
    const raw=(j.choices&&j.choices[0]&&j.choices[0].message&&j.choices[0].message.content)||'';
    const obj=JSON.parse(String(raw).replace(/```json|```/g,'').trim());
    if(!obj.pasos||typeof obj.pasos!=='object') return res.status(502).json({ error:'no_pasos' });
    const out={};
    for(const [k,v] of Object.entries(obj.pasos)){ if(!v||typeof v!=='object') continue; out[String(k).slice(0,24)]={ d:String(v.d||'').slice(0,160), den:String(v.den||'').slice(0,160), m:String(v.m||'').slice(0,120) }; }
    if(!Object.keys(out).length) return res.status(502).json({ error:'empty' });
    db.audit(req.role,'ai_kondate',null,null,null);
    res.json({ pasos:out });
  }catch(e){ console.warn('[ai:kondate]', e.message); res.status(502).json({ error:'upstream_error' }); }
});

/* ---------- salud + estáticos ---------- */
app.get('/healthz', (req,res)=>res.json({ ok:true, db: db.backend() }));
/* El tablero embebe el modelo del negocio: solo se sirve con sesión válida.
   Sin sesión se entrega la página de login (el shim sigue como red de
   seguridad para sesiones que expiran en medio del uso). */
app.get(['/','/index.html'], (req,res)=>{
  res.setHeader('Cache-Control','no-store');
  if(readSession(req)) return res.sendFile(path.join(__dirname,'public','index.html'));
  res.sendFile(path.join(__dirname,'public','login.html'));
});
app.use(express.static(path.join(__dirname,'public'), { index:false }));

const PORT = process.env.PORT || 3000;
db.init().then(()=>{
  app.listen(PORT, ()=>console.log('[kanjo] escuchando en :'+PORT+' · db='+db.backend()));
}).catch(e=>{ console.error('[db] error de inicio:', e); process.exit(1); });
