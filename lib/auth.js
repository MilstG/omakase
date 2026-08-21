/* auth.js — usuarios, contraseñas y resolución de permisos.
   Contraseñas con scrypt (viene en el core de Node: sin dependencias nuevas).
   Los usuarios y roles se cachean en memoria unos segundos para no pegarle a
   Postgres en cada request; cualquier alta o cambio invalida el caché al
   instante, así que un cambio de rol aplica sin volver a loguear. */
const crypto = require('crypto');
const db = require('./db');
const rbac = require('./rbac');

/* ---------- contraseñas ---------- */
const SCRYPT = { N: 16384, r: 8, p: 1, len: 64 };
const b64 = b => Buffer.from(b).toString('base64');

function hashPassword(pw){
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(pw), salt, SCRYPT.len, { N:SCRYPT.N, r:SCRYPT.r, p:SCRYPT.p, maxmem: 64*1024*1024 });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, b64(salt), b64(dk)].join('$');
}
function verifyPassword(pw, stored){
  try{
    const [algo, N, r, p, salt, hash] = String(stored||'').split('$');
    if(algo !== 'scrypt') return false;
    const s = Buffer.from(salt, 'base64'), want = Buffer.from(hash, 'base64');
    const dk = crypto.scryptSync(String(pw), s, want.length, { N:+N, r:+r, p:+p, maxmem: 64*1024*1024 });
    return dk.length === want.length && crypto.timingSafeEqual(dk, want);
  }catch(e){ return false; }
}
/* Contraseña inicial legible y dictable por teléfono, sin caracteres ambiguos. */
const PW_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
function randomPassword(n = 10){
  const out = [];
  for(const b of crypto.randomBytes(n)) out.push(PW_ALPHABET[b % PW_ALPHABET.length]);
  return out.join('');
}
const rid = () => crypto.randomBytes(9).toString('base64url');

/* ---------- caché de usuarios y roles ---------- */
const TTL_MS = 10_000;
let cache = { at: 0, users: new Map(), roles: new Map(), adminCount: 0 };
let loading = null;

function invalidate(){ cache.at = 0; }

async function refresh(){
  const [users, roles] = await Promise.all([db.usersList(), db.rolesList()]);
  const uMap = new Map(), rMap = new Map();
  roles.forEach(r => rMap.set(r.id, r));
  users.forEach(u => uMap.set(u.id, u));
  const adminCount = users.filter(u => u.active && (rMap.get(u.roleId) || {}).isAdmin).length;
  cache = { at: Date.now(), users: uMap, roles: rMap, adminCount };
  return cache;
}
async function state(){
  if(Date.now() - cache.at < TTL_MS) return cache;
  if(!loading) loading = refresh().finally(()=>{ loading = null; });
  return loading;
}

/* ---------- sesión resuelta ----------
   Lo que ve el resto del servidor: rol y matriz de permisos ya aplanados. */
function resolve(user, role){
  if(!user || !role) return null;
  return {
    uid: user.id, username: user.username, name: user.name,
    personId: user.personId || null,
    role: role.id, roleName: role.name,
    perms: role.isAdmin ? Object.fromEntries(rbac.MODULE_IDS.map(m=>[m,'write'])) : (role.perms||{}),
    isAdmin: !!role.isAdmin,
    mustChange: !!user.mustChange,
    sv: user.sv,
  };
}
/* Devuelve la sesión resuelta si el usuario sigue activo y la cookie no quedó
   vieja (sv sube al cambiar contraseña o dar de baja: mata sesiones abiertas). */
async function sessionFor(uid, sv){
  const st = await state();
  const u = st.users.get(uid);
  if(!u || !u.active) return null;
  if(sv != null && +sv !== +u.sv) return null;
  return resolve(u, st.roles.get(u.roleId));
}
async function findByUsername(username){
  const st = await state();
  for(const u of st.users.values()) if(u.username === String(username||'').toLowerCase()) return u;
  return null;
}
async function roleOf(u){ return (await state()).roles.get(u.roleId); }
async function adminCount(){ return (await state()).adminCount; }
async function allUsers(){ return [...(await state()).users.values()]; }
async function allRoles(){ return [...(await state()).roles.values()]; }

/* ---------- arranque ----------
   Siembra los roles que falten y, si no hay ni un usuario, crea el primer
   admin. Si hay APP_PASSWORD_ADMIN usa esa contraseña (nadie queda afuera al
   deployar); si no, inventa una y la imprime en el log una sola vez. */
async function bootstrap(){
  const existingRoles = await db.rolesList();
  const have = new Map(existingRoles.map(r => [r.id, r]));
  for(const r of rbac.DEFAULT_ROLES) if(!have.has(r.id)) await db.roleUpsert(r);
  /* Red de seguridad: el rol admin tiene que seguir siendo admin. Si una
     migración vieja o un toqueteo a mano lo dejó sin la bandera, se repara
     acá — un tablero sin nadie que pueda administrarlo no se arregla solo. */
  const adminRole = have.get('admin');
  if(adminRole && !adminRole.isAdmin){
    const def = rbac.DEFAULT_ROLES.find(r => r.id === 'admin');
    await db.roleUpsert(Object.assign({}, def, { name: adminRole.name || def.name }));
    console.warn('[auth] el rol admin estaba sin la bandera de administrador — reparado.');
  }

  const users = await db.usersList();
  const seeded = [];
  if(!users.length){
    const envPw = process.env.APP_PASSWORD_ADMIN || process.env.APP_PASSWORD || '';
    const pw = envPw || randomPassword();
    await db.userUpsert({ id: rid(), username:'admin', name:'Admin', roleId:'admin',
      pw: hashPassword(pw), mustChange: !envPw, active:true, sv:1 });
    seeded.push({ username:'admin', role:'admin', pw: envPw ? null : pw });

    const staffPw = process.env.APP_PASSWORD_STAFF || '';
    if(staffPw){
      await db.userUpsert({ id: rid(), username:'staff', name:'Equipo (heredado)', roleId:'encargado',
        pw: hashPassword(staffPw), mustChange:false, active:true, sv:1 });
      seeded.push({ username:'staff', role:'encargado', pw:null });
    }
  }
  invalidate();
  if(seeded.length){
    console.log('[auth] usuarios iniciales creados:');
    for(const s of seeded)
      console.log('  · ' + s.username + ' (' + s.role + ')' +
        (s.pw ? ' — contraseña de un solo uso: ' + s.pw + '  ← anotala, no se muestra otra vez'
              : ' — usa la contraseña que ya tenías en las variables de entorno'));
  }
  return seeded;
}

module.exports = { hashPassword, verifyPassword, randomPassword, rid,
  invalidate, sessionFor, findByUsername, roleOf, adminCount, allUsers, allRoles,
  resolve, bootstrap };
