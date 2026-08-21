/* rbac.js — la política de permisos de Kanjō, en un solo archivo.
   Acá se define QUÉ módulos existen, a qué módulo pertenece cada clave
   kanjo:* y con qué nivel se la puede tocar. El servidor es la única
   autoridad: el tablero usa esta misma tabla solo para pintar la UI.

   Tres niveles por módulo:
     none   no lo ve
     read   lo ve, no lo toca
     write  lo ve y lo edita

   Regla de oro para las claves: LEER casi todo es necesario para que la app
   renderice (el Resumen calcula sobre baseline, services, compras…), así que
   la mayoría de las claves tienen lectura 'core' = cualquier sesión válida.
   Lo que de verdad es sensible — caja, cierres, sueldos — tiene su propio
   candado de lectura. ESCRIBIR, en cambio, siempre pide el módulo dueño. */

const LEVELS = { none: 0, read: 1, write: 2 };
const lvl = v => LEVELS[v] == null ? 0 : LEVELS[v];

/* ---------- módulos ----------
   Los primeros 20 son los tabs del tablero; los últimos tres son
   pseudo-módulos que no tienen tab propio pero sí sensibilidad propia. */
const MODULES = [
  { id:'resumen',  label:'Resumen 週報' },
  { id:'costos',   label:'Esquema de costos 勘定' },
  { id:'turnos',   label:'Analista de turnos 番付' },
  { id:'heika',    label:'Precios dinámicos 平価' },
  { id:'yoso',     label:'Pronóstico 予想' },
  { id:'genka',    label:'Costeo de menú 原価' },
  { id:'aisho',    label:'Maridaje 相性' },
  { id:'compras',  label:'Compras 仕入' },
  { id:'oroshi',   label:'Proveedores 卸' },
  { id:'caja',     label:'Caja 現金' },
  { id:'reservas', label:'Reservas 予約' },
  { id:'crm',      label:'Clientes 顧客' },
  { id:'kata',     label:'Manual 型' },
  { id:'wa',       label:'Rueda 輪' },
  { id:'dou',      label:'Procedimientos 道' },
  { id:'shun',     label:'Estacionalidad 旬' },
  { id:'zaiko',    label:'Inventario 在庫' },
  { id:'hito',     label:'Equipo 人' },
  { id:'kondate',  label:'Carta QR 献立' },
  { id:'seki',     label:'Servicio 席' },
  /* pseudo-módulos: sin tab, con candado */
  { id:'cierres',  label:'Cierre de mes 締', pseudo:true, hint:'P&L congelado de meses cerrados' },
  { id:'hitopay',  label:'Sueldos y tarifas 給', pseudo:true, hint:'lo que cobra cada persona' },
  { id:'admin',    label:'Usuarios y backup 管', pseudo:true, hint:'usuarios, roles, audit log, backup total' },
];
const MODULE_IDS = MODULES.map(m => m.id);
const TABS = MODULES.filter(m => !m.pseudo).map(m => m.id);

/* ---------- claves ----------
   read:  'core' = cualquier sesión autenticada · [mods] = alguno con lectura
   write: [mods] = alguno con escritura
   Una clave desconocida cae en el default: se lee, la escribe solo admin. */
const CORE = 'core';
const KEY_POLICY = {
  'kanjo:baseline':  { read:CORE,        write:['costos'] },
  'kanjo:scenarios': { read:CORE,        write:['yoso'] },
  /* el servicio lo carga tanto el analista como el salón (carga rápida / Seki) */
  'kanjo:services':  { read:CORE,        write:['turnos','seki'] },
  'kanjo:fchealth':  { read:CORE,        write:['genka','costos'] },
  'kanjo:genka':     { read:CORE,        write:['genka'] },
  'kanjo:compras':   { read:CORE,        write:['compras'] },
  'kanjo:mermas':    { read:CORE,        write:['compras'] },
  'kanjo:fxlog':     { read:CORE,        write:['compras','costos'] },
  'kanjo:caja':      { read:['caja'],    write:['caja'] },
  'kanjo:cierres':   { read:['cierres'], write:['cierres'] },
  'kanjo:reservas':  { read:CORE,        write:['reservas'] },
  'kanjo:stock':     { read:CORE,        write:['zaiko','compras'] },
  /* datos personales de clientes (teléfono, notas, cumpleaños): candado propio,
     no se hereda de reservas ni del servicio. Quien cierra el servicio y anota
     visitas necesita 'crm' en escritura, no alcanza con 'seki'. */
  'kanjo:crm':       { read:['crm'],     write:['crm'] },
  'kanjo:aisho':     { read:CORE,        write:['aisho'] },
  'kanjo:kata':      { read:CORE,        write:['kata'] },
  'kanjo:kataruns':  { read:CORE,        write:['kata'] },
  'kanjo:dou':       { read:CORE,        write:['dou'] },
  'kanjo:shun':      { read:CORE,        write:['shun'] },
  'kanjo:zaiko':     { read:CORE,        write:['zaiko'] },
  'kanjo:oroshi':    { read:CORE,        write:['oroshi'] },
  'kanjo:wa':        { read:CORE,        write:['wa'] },
  'kanjo:hito':      { read:CORE,        write:['hito'] },
  'kanjo:hitopay':   { read:['hitopay'], write:['hitopay'] },
  /* cada uno ficha lo suyo: alcanza con estar en el turno */
  'kanjo:hitopunch': { read:CORE,        write:['hito','seki'] },
  'kanjo:kondate':   { read:CORE,        write:['kondate'] },
  'kanjo:seki':      { read:CORE,        write:['seki'] },
  /* legado del control por PIN del navegador; ya no se usa, queda cerrado */
  'kanjo:auth':      { read:CORE,        write:['admin'] },
};
const KEY_DEFAULT = { read:CORE, write:['admin'] };
const keyPolicy = k => KEY_POLICY[k] || KEY_DEFAULT;

/* ---------- roles por defecto ----------
   admin no lleva matriz: es dueño de todo por definición y no se edita.
   El resto arranca con esto y se ajusta desde Resumen → Administración. */
function emptyPerms(){ const p={}; MODULE_IDS.forEach(m=>p[m]='none'); return p; }
function perms(over){ return Object.assign(emptyPerms(), over); }

const DEFAULT_ROLES = [
  { id:'admin', name:'Admin', isAdmin:true, builtin:true,
    hint:'Dueño del tablero: todo, incluida la gestión de usuarios.',
    perms: perms(Object.fromEntries(MODULE_IDS.map(m=>[m,'write']))) },

  { id:'encargado', name:'Encargado', builtin:true,
    hint:'Corre el día a día. No ve caja, cierres ni sueldos.',
    perms: perms({ resumen:'write', costos:'read', turnos:'write', heika:'read', yoso:'read',
      genka:'write', aisho:'write', compras:'write', oroshi:'write', reservas:'write',
      crm:'write', kata:'write', wa:'write', dou:'write', shun:'write', zaiko:'write',
      hito:'read', kondate:'write', seki:'write' }) },

  { id:'cocina', name:'Cocina · itamae', builtin:true,
    hint:'Producto y escandallo: costeo, compras, inventario, estacionalidad.',
    perms: perms({ resumen:'read', turnos:'read', genka:'write', aisho:'read',
      compras:'write', oroshi:'write', reservas:'read', kata:'write', wa:'read',
      dou:'write', shun:'write', zaiko:'write', hito:'read', kondate:'read', seki:'read' }) },

  { id:'sala', name:'Sala · sommelier', builtin:true,
    hint:'Reservas, clientes y el servicio de la noche.',
    perms: perms({ resumen:'read', turnos:'read', aisho:'write', reservas:'write',
      crm:'write', kata:'write', wa:'read', dou:'read', shun:'read', zaiko:'read',
      hito:'read', kondate:'read', seki:'write' }) },

  { id:'contador', name:'Contador · solo lectura', builtin:true,
    hint:'Lee lo financiero, no escribe nada.',
    perms: perms({ resumen:'read', costos:'read', turnos:'read', heika:'read', yoso:'read',
      genka:'read', compras:'read', oroshi:'read', caja:'read', reservas:'read',
      zaiko:'read', hito:'read', cierres:'read', hitopay:'read' }) },
];

/* ---------- chequeos ----------
   El objeto `sess` que reciben es { role, perms, isAdmin } ya resuelto. */
function can(sess, mod, need){
  if(!sess) return false;
  if(sess.isAdmin) return true;
  return lvl((sess.perms||{})[mod]) >= lvl(need);
}
function canAny(sess, mods, need){
  if(!sess) return false;
  if(sess.isAdmin) return true;
  return (mods||[]).some(m => can(sess, m, need));
}
function canReadKey(sess, key){
  const p = keyPolicy(key);
  if(p.read === CORE) return !!sess;
  return canAny(sess, p.read, 'read');
}
function canWriteKey(sess, key){
  return canAny(sess, keyPolicy(key).write, 'write');
}
/* Módulos que la sesión puede al menos ver — para pintar los tabs. */
function visibleTabs(sess){
  if(!sess) return [];
  if(sess.isAdmin) return TABS.slice();
  return TABS.filter(t => lvl((sess.perms||{})[t]) >= 1);
}
/* Normaliza una matriz que llega del cliente: nada de módulos inventados
   ni de niveles fuera de la escala. */
function sanitizePerms(raw){
  const out = emptyPerms();
  if(raw && typeof raw === 'object')
    for(const m of MODULE_IDS)
      if(['none','read','write'].includes(raw[m])) out[m] = raw[m];
  return out;
}

module.exports = {
  LEVELS, lvl, MODULES, MODULE_IDS, TABS, CORE,
  KEY_POLICY, KEY_DEFAULT, keyPolicy, DEFAULT_ROLES,
  emptyPerms, sanitizePerms,
  can, canAny, canReadKey, canWriteKey, visibleTabs,
};
