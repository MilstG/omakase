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
    /* el audit viejo solo guardaba el rol; ahora también quién */
    await pool.query(`ALTER TABLE audit ADD COLUMN IF NOT EXISTS username TEXT`);
    await pool.query(`CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      hint TEXT,
      perms TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT false,
      builtin BOOLEAN NOT NULL DEFAULT false,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      role_id TEXT NOT NULL,
      person_id TEXT,
      pw TEXT NOT NULL,
      must_change BOOLEAN NOT NULL DEFAULT false,
      active BOOLEAN NOT NULL DEFAULT true,
      sv INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_login TIMESTAMPTZ
    )`);
    console.log('[db] Postgres listo');
  } else {
    console.log('[db] sin DATABASE_URL — archivo local data.json (solo desarrollo)');
  }
}

const FILE = path.join(__dirname, '..', 'data.json');
function fRead(){ try{ return JSON.parse(fs.readFileSync(FILE,'utf8')); }catch(e){ return {}; } }
function fWrite(d){
  const tmp=FILE+'.tmp';
  fs.writeFileSync(tmp, JSON.stringify(d,null,1));
  fs.renameSync(tmp, FILE);                      /* atómico: nunca queda un data.json a medias */
}

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
  /* __audit, __users y __roles son internos: nunca salen como claves kanjo:* */
  return Object.keys(d).filter(k=>!k.startsWith('__')).filter(k=>!prefix||k.startsWith(prefix)).sort();
}

/* ---- audit log ---- */
let auditN=0;
async function audit(role, action, key, fromV, toV, username){
  try{
    if(pool){
      await pool.query('INSERT INTO audit(role,action,key,from_version,to_version,username) VALUES($1,$2,$3,$4,$5,$6)',
        [role||null, action, key||null, fromV==null?null:fromV, toV==null?null:toV, username||null]);
      if(++auditN % 200 === 0)                    /* poda barata: cada 200 inserts, conservar las últimas 4000 */
        await pool.query('DELETE FROM audit WHERE id < (SELECT COALESCE(MAX(id),0) FROM audit) - 4000');
    } else {
      const d=fRead();
      d.__audit = d.__audit || { value:'[]', version:0 };
      const arr=JSON.parse(d.__audit.value);
      arr.push({ ts:new Date().toISOString(), role, username:username||null, action, key, from_version:fromV??null, to_version:toV??null });
      while(arr.length>500) arr.shift();
      d.__audit.value=JSON.stringify(arr); fWrite(d);
    }
  }catch(e){ console.warn('[audit]', e.message); }
}
async function auditList(limit){
  limit=Math.min(Math.max(+limit||50,1),200);
  if(pool){
    const r=await pool.query('SELECT ts,role,username,action,key,from_version,to_version FROM audit ORDER BY id DESC LIMIT $1',[limit]);
    return r.rows;
  }
  const d=fRead();
  const arr=d.__audit? JSON.parse(d.__audit.value):[];
  return arr.slice(-limit).reverse();
}

/* =====================================================================
   RBAC · usuarios y roles
   En Postgres son dos tablas; sin DATABASE_URL viven en data.json bajo
   __users / __roles, que list() ya no expone como claves kanjo:*.
   Los perms viajan como TEXT/JSON: una matriz módulo → none|read|write.
   ===================================================================== */
function fColl(name){ const d=fRead(); const a=d['__'+name]; return Array.isArray(a)?a:[]; }
function fCollWrite(name, arr){ const d=fRead(); d['__'+name]=arr; fWrite(d); }

const roleOut = r => ({ id:r.id, name:r.name, hint:r.hint||'',
  perms: typeof r.perms==='string'? JSON.parse(r.perms) : (r.perms||{}),
  isAdmin: !!(r.is_admin ?? r.isAdmin), builtin: !!r.builtin });

async function rolesList(){
  if(pool){ const r=await pool.query('SELECT * FROM roles ORDER BY builtin DESC, name'); return r.rows.map(roleOut); }
  return fColl('roles').map(roleOut);
}
async function roleUpsert(r){
  const perms = JSON.stringify(r.perms||{});
  if(pool){
    await pool.query(
      `INSERT INTO roles(id,name,hint,perms,is_admin,builtin) VALUES($1,$2,$3,$4,$5,$6)
       ON CONFLICT (id) DO UPDATE SET name=$2, hint=$3, perms=$4, is_admin=$5, updated_at=now()`,
      [r.id, r.name, r.hint||'', perms, !!r.isAdmin, !!r.builtin]);
    return;
  }
  const arr=fColl('roles'); const i=arr.findIndex(x=>x.id===r.id);
  const row={ id:r.id, name:r.name, hint:r.hint||'', perms, is_admin:!!r.isAdmin, builtin:!!r.builtin };
  if(i<0) arr.push(row); else arr[i]=Object.assign({}, arr[i], { name:row.name, hint:row.hint, perms:row.perms, is_admin:row.is_admin });
  fCollWrite('roles', arr);
}
async function roleDelete(id){
  if(pool){ await pool.query('DELETE FROM roles WHERE id=$1 AND builtin=false',[id]); return; }
  fCollWrite('roles', fColl('roles').filter(r=>r.id!==id || r.builtin));
}

const userOut = u => u && ({ id:u.id, username:u.username, name:u.name,
  roleId:u.role_id ?? u.roleId, personId:u.person_id ?? u.personId ?? null,
  pw:u.pw, mustChange:!!(u.must_change ?? u.mustChange), active:!!u.active,
  sv:+(u.sv||1), createdAt:u.created_at ?? u.createdAt ?? null,
  lastLogin:u.last_login ?? u.lastLogin ?? null });

async function usersList(){
  if(pool){ const r=await pool.query('SELECT * FROM users ORDER BY active DESC, name'); return r.rows.map(userOut); }
  return fColl('users').map(userOut);
}
async function userByUsername(username){
  const u=String(username||'').toLowerCase();
  if(pool){ const r=await pool.query('SELECT * FROM users WHERE username=$1',[u]); return userOut(r.rows[0]); }
  return userOut(fColl('users').find(x=>x.username===u));
}
async function userGet(id){
  if(pool){ const r=await pool.query('SELECT * FROM users WHERE id=$1',[id]); return userOut(r.rows[0]); }
  return userOut(fColl('users').find(x=>x.id===id));
}
/* Crea o pisa. Devuelve {ok} o {ok:false, error:'username_taken'}. */
async function userUpsert(u){
  const username=String(u.username||'').toLowerCase();
  if(pool){
    try{
      await pool.query(
        `INSERT INTO users(id,username,name,role_id,person_id,pw,must_change,active,sv)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO UPDATE SET username=$2, name=$3, role_id=$4, person_id=$5,
           pw=$6, must_change=$7, active=$8, sv=$9`,
        [u.id, username, u.name, u.roleId, u.personId||null, u.pw, !!u.mustChange, u.active!==false, +(u.sv||1)]);
      return { ok:true };
    }catch(e){
      if(e && e.code==='23505') return { ok:false, error:'username_taken' };
      throw e;
    }
  }
  const arr=fColl('users');
  if(arr.some(x=>x.username===username && x.id!==u.id)) return { ok:false, error:'username_taken' };
  const row={ id:u.id, username, name:u.name, role_id:u.roleId, person_id:u.personId||null,
    pw:u.pw, must_change:!!u.mustChange, active:u.active!==false, sv:+(u.sv||1),
    created_at:u.createdAt||new Date().toISOString(), last_login:u.lastLogin||null };
  const i=arr.findIndex(x=>x.id===u.id);
  if(i<0) arr.push(row); else arr[i]=row;
  fCollWrite('users', arr);
  return { ok:true };
}
async function userDelete(id){
  if(pool){ await pool.query('DELETE FROM users WHERE id=$1',[id]); return; }
  fCollWrite('users', fColl('users').filter(x=>x.id!==id));
}
async function userTouchLogin(id){
  if(pool){ await pool.query('UPDATE users SET last_login=now() WHERE id=$1',[id]); return; }
  const arr=fColl('users'); const u=arr.find(x=>x.id===id);
  if(u){ u.last_login=new Date().toISOString(); fCollWrite('users', arr); }
}

function backend(){ return pool ? 'postgres' : 'file'; }
module.exports = { init, get, set, del, list, backend, audit, auditList,
  rolesList, roleUpsert, roleDelete,
  usersList, userGet, userByUsername, userUpsert, userDelete, userTouchLogin };
