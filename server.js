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
const SECRET = process.env.SESSION_SECRET
  || crypto.createHash('sha256').update('kanjo·'+ADMIN_PW+'·'+STAFF_PW).digest('hex');
const SESS_TTL_MS = 1000*60*60*24*14;   /* 14 días */
const COOKIE = 'kanjo_sess';

/* Claves que el staff puede LEER (la app las necesita para renderizar)
   pero NO escribir: modelo financiero, escenarios, caja, permisos y sync. */
const ADMIN_ONLY_WRITE = ['kanjo:baseline','kanjo:scenarios','kanjo:caja','kanjo:auth','kanjo:sheeturl','kanjo:cierres'];

if(!ADMIN_PW) console.warn('[auth] ⚠ Definí APP_PASSWORD_ADMIN — sin contraseña nadie puede entrar.');

const app = express();
app.use(express.json({ limit:'8mb' }));

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
  const now=Date.now(); const a=attempts.get(ip);
  if(a && now<a.resetAt && a.n>=10) return true;
  if(!a || now>=a.resetAt) attempts.set(ip,{n:0,resetAt:now+10*60*1000});
  return false;
}
function bump(ip){ const a=attempts.get(ip); if(a) a.n++; }

/* ---------- auth API ---------- */
app.post('/api/login', (req,res)=>{
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?';
  if(limited(ip)) return res.status(429).json({ error:'too_many_attempts' });
  const pw = String((req.body&&req.body.password)||'');
  let role = null;
  if(ADMIN_PW && tsEq(pw, ADMIN_PW)) role='admin';
  else if(STAFF_PW && tsEq(pw, STAFF_PW)) role='staff';
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
  const ip=req.headers['x-forwarded-for']||req.socket.remoteAddress||'?';
  const now=Date.now(); const a=aiLimit.get(ip);
  if(a && now<a.resetAt && a.n>=30) return res.status(429).json({ error:'rate_limited' });
  if(!a || now>=a.resetAt) aiLimit.set(ip,{n:0,resetAt:now+10*60*1000});
  aiLimit.get(ip).n++;
  const { bebida, pasos, paso, bebidas } = req.body||{};
  const modeB = bebida && Array.isArray(pasos) && pasos.length && pasos.length<=40;      /* una bebida vs el menú */
  const modeP = paso && Array.isArray(bebidas) && bebidas.length && bebidas.length<=40;  /* un paso vs la carta */
  if(!modeB && !modeP) return res.status(400).json({ error:'bad_request' });
  const sys='Sos un sommelier especializado en cocina japonesa omakase en Buenos Aires. Respondé SOLO un objeto JSON válido, sin markdown: {"scores":{"<id>":0-3,...para todos los ids...},"notas":{"<id>":"nota breve",...solo para scores>=2...}}. Escala: 0 no va, 1 funciona, 2 muy bien, 3 maridaje de firma (máximo 2 o 3 treses). Notas en castellano rioplatense, máximo 12 palabras.';
  let usr;
  if(modeB){
    const menu=pasos.map(p=>`${String(p.id).slice(0,24)}: ${String(p.n).slice(0,60)} — ${String(p.d||'').slice(0,90)}${p.prem?' (premium)':''}`).join('\n');
    usr='Menú (id: paso — descripción):\n'+menu+'\n\nBebida a puntuar contra cada paso:\n'+String(bebida.n).slice(0,80)+' — '+String(bebida.d||'').slice(0,200)+'\nCategoría: '+String(bebida.cat||'')+(bebida.tier?' '+bebida.tier:'');
  } else {
    const carta=bebidas.map(b=>`${String(b.id).slice(0,24)}: ${String(b.n).slice(0,60)} — ${String(b.d||'').slice(0,90)} [${String(b.cat||'')}${b.tier?' '+b.tier:''}]`).join('\n');
    usr='Carta de bebidas (id: bebida — descripción [categoría]):\n'+carta+'\n\nPlato nuevo del omakase, a puntuar contra cada bebida:\n'+String(paso.n).slice(0,80)+' — '+String(paso.d||'').slice(0,200)+(paso.prem?' (paso premium)':'');
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
    res.json({ scores:obj.scores, notas:obj.notas||{} });
  }catch(e){ console.warn('[ai]', e.message); res.status(502).json({ error:'upstream_error' }); }
});

app.get('/api/audit', requireAuth, async (req,res)=>{
  if(req.role!=='admin') return res.status(403).json({ error:'admin_only' });
  res.json({ entries: await db.auditList(req.query.limit) });
});

/* ---------- salud + estáticos ---------- */
app.get('/healthz', (req,res)=>res.json({ ok:true, db: db.backend() }));
app.use(express.static(path.join(__dirname,'public'), { index:'index.html' }));

const PORT = process.env.PORT || 3000;
db.init().then(()=>{
  app.listen(PORT, ()=>console.log('[kanjo] escuchando en :'+PORT+' · db='+db.backend()));
}).catch(e=>{ console.error('[db] error de inicio:', e); process.exit(1); });
