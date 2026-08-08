/* db.js — capa clave-valor con versiones.
   Con DATABASE_URL (plugin Postgres de Railway) usa Postgres;
   sin ella cae a un archivo JSON local (solo desarrollo). */
const fs = require('fs');
const path = require('path');

const PG_URL = process.env.DATABASE_URL || '';
let pool = null;

async function init(){
  if(PG_URL){
    const { Pool } = require('pg');
    pool = new Pool({ connectionString: PG_URL, ssl: /localhost|127\.0\.0\.1/.test(PG_URL) ? undefined : { rejectUnauthorized:false } });
    await pool.query(`CREATE TABLE IF NOT EXISTS kv (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS audit (
      id SERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      role TEXT, action TEXT NOT NULL, key TEXT,
      from_version INTEGER, to_version INTEGER
    )`);
    console.log('[db] Postgres listo');
  } else {
    console.log('[db] sin DATABASE_URL — archivo local data.json (solo desarrollo)');
  }
}

const FILE = path.join(__dirname, '..', 'data.json');
function fRead(){ try{ return JSON.parse(fs.readFileSync(FILE,'utf8')); }catch(e){ return {}; } }
function fWrite(d){ fs.writeFileSync(FILE, JSON.stringify(d,null,1)); }

async function get(key){
  if(pool){
    const r = await pool.query('SELECT value, version FROM kv WHERE key=$1',[key]);
    return r.rows[0] ? { key, value:r.rows[0].value, version:r.rows[0].version } : null;
  }
  const d=fRead();
  return d[key] ? { key, value:d[key].value, version:d[key].version } : null;
}

/* Concurrencia optimista:
   version===null → crear o, si existe, conflicto
   version===n    → pisa solo si la versión actual es n
   force===true   → pisa siempre (tras confirmación del usuario) */
async function set(key, value, version, force){
  if(pool){
    if(force){
      const r = await pool.query(
        `INSERT INTO kv(key,value,version) VALUES($1,$2,1)
         ON CONFLICT (key) DO UPDATE SET value=$2, version=kv.version+1, updated_at=now()
         RETURNING version`,[key,value]);
      return { ok:true, version:r.rows[0].version };
    }
    if(version==null){
      const r = await pool.query(
        `INSERT INTO kv(key,value,version) VALUES($1,$2,1)
         ON CONFLICT (key) DO NOTHING RETURNING version`,[key,value]);
      if(r.rows[0]) return { ok:true, version:r.rows[0].version };
      return { ok:false, conflict:true, current: await get(key) };
    }
    const r = await pool.query(
      'UPDATE kv SET value=$2, version=version+1, updated_at=now() WHERE key=$1 AND version=$3 RETURNING version',
      [key,value,version]);
    if(r.rows[0]) return { ok:true, version:r.rows[0].version };
    return { ok:false, conflict:true, current: await get(key) };
  }
  const d=fRead(), cur=d[key];
  if(force){ const v=cur?cur.version+1:1; d[key]={value,version:v}; fWrite(d); return {ok:true,version:v}; }
  if(version==null){
    if(cur) return { ok:false, conflict:true, current:{key,value:cur.value,version:cur.version} };
    d[key]={value,version:1}; fWrite(d); return {ok:true,version:1};
  }
  if(cur && cur.version===version){ d[key]={value,version:version+1}; fWrite(d); return {ok:true,version:version+1}; }
  return { ok:false, conflict:true, current: cur?{key,value:cur.value,version:cur.version}:null };
}

async function del(key){
  if(pool){ await pool.query('DELETE FROM kv WHERE key=$1',[key]); return {ok:true}; }
  const d=fRead(); delete d[key]; fWrite(d); return {ok:true};
}

async function list(prefix){
  if(pool){
    const r = prefix
      ? await pool.query("SELECT key FROM kv WHERE key LIKE $1 || '%' ORDER BY key",[prefix])
      : await pool.query('SELECT key FROM kv ORDER BY key');
    return r.rows.map(x=>x.key);
  }
  const d=fRead();
  return Object.keys(d).filter(k=>!prefix||k.startsWith(prefix)).sort();
}

/* ---- audit log ---- */
async function audit(role, action, key, fromV, toV){
  try{
    if(pool){
      await pool.query('INSERT INTO audit(role,action,key,from_version,to_version) VALUES($1,$2,$3,$4,$5)',
        [role||null, action, key||null, fromV==null?null:fromV, toV==null?null:toV]);
    } else {
      const d=fRead();
      d.__audit = d.__audit || { value:'[]', version:0 };
      const arr=JSON.parse(d.__audit.value);
      arr.push({ ts:new Date().toISOString(), role, action, key, from_version:fromV??null, to_version:toV??null });
      while(arr.length>500) arr.shift();
      d.__audit.value=JSON.stringify(arr); fWrite(d);
    }
  }catch(e){ console.warn('[audit]', e.message); }
}
async function auditList(limit){
  limit=Math.min(Math.max(+limit||50,1),200);
  if(pool){
    const r=await pool.query('SELECT ts,role,action,key,from_version,to_version FROM audit ORDER BY id DESC LIMIT $1',[limit]);
    return r.rows;
  }
  const d=fRead();
  const arr=d.__audit? JSON.parse(d.__audit.value):[];
  return arr.slice(-limit).reverse();
}

function backend(){ return pool ? 'postgres' : 'file'; }
module.exports = { init, get, set, del, list, backend, audit, auditList };
