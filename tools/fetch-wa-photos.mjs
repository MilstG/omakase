#!/usr/bin/env node
/* Wa 輪 — repositorio de fotos (v3)
   Busca una foto de licencia libre por producto y la guarda en
   public/img/wa/<id>.jpg (~640px). Créditos en public/img/wa/credits.json.

   Fuente primaria: Openverse (api.openverse.org — el buscador CC de WordPress,
   sin API key y sin bloqueo a IPs de datacenter, que es lo que mató las
   corridas contra Wikimedia desde los runners de GitHub).
   Fallback: la API de Wikimedia Commons.

   Uso:
     node tools/fetch-wa-photos.mjs           # baja solo las que faltan
     node tools/fetch-wa-photos.mjs --force   # re-baja todo
     node tools/fetch-wa-photos.mjs uni yuzu  # solo esos ids */

import { mkdir, writeFile, readFile, access } from 'node:fs/promises';
import path from 'node:path';

const OUT = path.join(process.cwd(), 'public', 'img', 'wa');
const OPENVERSE = 'https://api.openverse.org/v1/images/';
const COMMONS = 'https://commons.wikimedia.org/w/api.php';
const FORCE = process.argv.includes('--force');
const ONLY = process.argv.slice(2).filter(a => !a.startsWith('--'));

/* id → términos de búsqueda en Commons (inglés rinde mejor ahí) */
const Q = {
  /* pescados y preparaciones */
  salmon:'salmon sashimi', chutoro:'chutoro tuna sushi', otoro:'otoro tuna sushi', akami:'maguro akami sushi',
  hamachi:'hamachi sashimi', saba:'shime saba sushi', iwashi:'iwashi sushi', kohada:'kohada sushi',
  sanma:'sanma grilled fish', hirame:'hirame sushi', tai:'madai sea bream', suzuki:'japanese sea bass suzuki fish',
  kinmedai:'kinmedai splendid alfonsino', chernia:'grouper fish dish', lenguado:'sole flatfish dish', mero:'grouper fish',
  ebi:'ebi shrimp nigiri', langostino:'red shrimp carpaccio', centolla:'king crab dish', hotate:'hotate scallop sushi',
  ostra:'fresh oysters plate', tako:'tako octopus sushi', ika:'ika squid sushi', anago:'anago sushi',
  unagi:'unagi kabayaki', uni:'uni sea urchin sushi', ikura:'ikura gunkan', tobiko:'tobiko gunkan',
  nigiri:'nigiri sushi rice', tamago:'tamagoyaki', misosoup:'miso soup bowl', chawan:'chawanmushi',
  tempura:'shrimp tempura', aburi:'aburi salmon sushi', wagyu:'wagyu beef marbling', karaage:'chicken karaage',
  mochi:'matcha mochi', helado:'black sesame ice cream',
  /* cava común */
  s1:'gekkeikan sake bottle', s2:'hakutsuru sake', s3:'nigori sake', s4:'atsukan hot sake tokkuri',
  s5:'kimoto sake brewery', s6:'umeshu plum wine',
  v1:'sparkling wine glass bottle', v2:'riesling wine bottle', v3:'pinot noir glass bottle',
  v4:'albarino white wine', v5:'semillon wine', v6:'chardonnay unoaked wine',
  c1:'japanese rice lager beer', c2:'witbier glass', c3:'kolsch beer glass', c4:'amber ale glass',
  c5:'session ipa beer', c6:'dry stout pint',
  t1:'sencha green tea', t2:'genmaicha', t3:'hojicha tea', t4:'mugicha barley tea',
  t5:'kukicha twig tea', t6:'sobacha buckwheat tea',
  /* cava premium */
  S1:'dassai sake', S2:'kubota sake niigata', S3:'dewazakura sake', S4:'kokuryu sake',
  S5:'koshu aged sake', S6:'yuzushu yuzu liqueur',
  V1:'blanc de blancs champagne', V2:'chablis wine bottle', V3:'mosel riesling kabinett',
  V4:'burgundy pinot noir bottle', V5:'sancerre wine', V6:'late harvest dessert wine',
  C1:'hitachino nest white ale', C2:'yuzu sour beer', C3:'gueuze lambic bottle',
  C4:'belgian tripel beer', C5:'saison beer bottle', C6:'baltic porter beer',
  T1:'gyokuro tea leaves', T2:'matcha bowl whisk', T3:'shincha green tea', T4:'aged oolong tea',
  T5:'kukicha hojicha roasted twig tea', T6:'matcha iri genmaicha',
  /* despensa */
  yuzu:'yuzu fruit', sudachi:'sudachi citrus', shiso:'shiso perilla leaf', myoga:'myoga ginger bud',
  gari:'gari pickled ginger', umeboshi:'umeboshi', wasabi:'fresh wasabi grated', karashi:'karashi mustard',
  sansho:'sansho pepper', shichimi:'shichimi togarashi', momiji:'momiji oroshi grated daikon',
  shoyu:'soy sauce dish', miso:'miso paste', ponzu:'ponzu sauce', mirin:'mirin bottle',
  dashi:'dashi broth katsuobushi', katsuo:'katsuobushi flakes', kombu:'kombu kelp dried',
  daikon:'daikon radish', negi:'negi welsh onion', kyuri:'japanese cucumber kyuri', nasu:'japanese eggplant nasu',
  renkon:'renkon lotus root sliced', takenoko:'takenoko bamboo shoot', shiitake:'shiitake mushrooms',
  goma:'roasted sesame seeds', nori:'nori sheets', tofu:'silken tofu'
};

const UA = { 'User-Agent': 'kanjo-wa-photo-fetch/3.0 (uso interno de un restaurante; una corrida)' };
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* fetch con timeout + reintentos cortos (429/5xx/red) */
async function fetchRetry(url, opts={}, tries=3){
  let wait=2000;
  for(let i=0;i<tries;i++){
    try{
      const r = await fetch(url, Object.assign({ signal: AbortSignal.timeout(20000) }, opts));
      if(r.status===429 || r.status>=500){
        if(i===tries-1) throw new Error('http '+r.status);
        console.warn('  … '+r.status+', reintento en '+(wait/1000)+'s');
        await sleep(wait); wait*=3; continue;
      }
      return r;
    }catch(e){
      if(i===tries-1) throw e;
      console.warn('  … '+(e.message||e.name)+', reintento en '+(wait/1000)+'s');
      await sleep(wait); wait*=3;
    }
  }
}

/* ---- fuente 1: Openverse ---- */
async function searchOpenverse(q){
  const u = new URL(OPENVERSE);
  u.search = new URLSearchParams({ q, page_size:'8', mature:'false', license_type:'all-cc' });
  const r = await fetchRetry(u, { headers: UA });
  if(!r.ok) throw new Error('openverse '+r.status);
  const j = await r.json();
  for(const it of (j.results||[])){
    if(!it || !it.id) continue;
    return {
      /* el endpoint /thumb/ de Openverse sirve ~600px desde su propio proxy:
         una sola fuente de descarga, sin depender del host original */
      thumb: OPENVERSE + it.id + '/thumb/',
      page: it.foreign_landing_url || it.url || '',
      license: (it.license ? it.license.toUpperCase() : '') + (it.license_version ? ' ' + it.license_version : ''),
      artist: String(it.creator || '').slice(0,120),
      title: String(it.title || '').slice(0,120),
      src: 'openverse:' + (it.source || it.provider || '')
    };
  }
  return null;
}

/* ---- fuente 2 (fallback): Wikimedia Commons ---- */
async function searchCommons(q){
  const u = new URL(COMMONS);
  u.search = new URLSearchParams({
    action:'query', format:'json', generator:'search', maxlag:'5',
    gsrsearch:`filetype:bitmap ${q}`, gsrnamespace:'6', gsrlimit:'5',
    prop:'imageinfo', iiprop:'url|extmetadata', iiurlwidth:'640'
  });
  const r = await fetchRetry(u, { headers: UA }, 2);
  if(!r.ok) throw new Error('commons '+r.status);
  const j = await r.json();
  const pages = Object.values(j?.query?.pages || {}).sort((a,b)=>(a.index||9)-(b.index||9));
  for(const p of pages){
    const ii = p.imageinfo && p.imageinfo[0];
    if(!ii || !ii.thumburl) continue;
    if(/\.(svg|gif|tiff?)$/i.test(ii.url||'')) continue;
    const md = ii.extmetadata || {};
    return {
      thumb: ii.thumburl, page: ii.descriptionurl || '',
      license: (md.LicenseShortName && md.LicenseShortName.value) || '',
      artist: ((md.Artist && md.Artist.value) || '').replace(/<[^>]+>/g,'').trim().slice(0,120),
      title: p.title || '', src: 'commons'
    };
  }
  return null;
}

/* query completo → recortado → primera palabra; Openverse primero, Commons después */
async function searchThumb(q){
  const words=q.split(' ');
  const variants=[q];
  if(words.length>2) variants.push(words.slice(0,2).join(' '));
  if(words.length>1) variants.push(words[0]);
  for(const v of variants){
    try{ const hit=await searchOpenverse(v); if(hit) return hit; }catch(e){ console.warn('  openverse:', e.message); }
    await sleep(300);
  }
  for(const v of variants){
    try{ const hit=await searchCommons(v); if(hit) return hit; }catch(e){ console.warn('  commons:', e.message); break; }
    await sleep(300);
  }
  return null;
}

async function main(){
  await mkdir(OUT, { recursive:true });
  let credits = {};
  try{ credits = JSON.parse(await readFile(path.join(OUT,'credits.json'),'utf8')); }catch(e){}
  const ids = ONLY.length ? ONLY : Object.keys(Q);
  let ok=0, skip=0; const fail=[];
  for(const id of ids){
    const q = Q[id];
    if(!q){ console.warn('· sin keywords para', id, '— agregalo al mapa Q'); continue; }
    const dest = path.join(OUT, id + '.jpg');
    if(!FORCE){ try{ await access(dest); skip++; continue; }catch(e){} }
    try{
      const hit = await searchThumb(q);
      if(!hit){ fail.push(id); console.warn('✗', id, '(sin resultados para:', q+')'); continue; }
      const img = await fetchRetry(hit.thumb, { headers: UA });
      if(!img.ok) throw new Error('descarga '+img.status);
      const buf = Buffer.from(await img.arrayBuffer());
      if(buf.length < 2048) throw new Error('descarga vacía');
      await writeFile(dest, buf);
      credits[id] = { file: hit.title, page: hit.page, license: hit.license, artist: hit.artist, source: hit.src, q };
      ok++;
      console.log('✓', id, '←', hit.title||hit.page, hit.license ? '['+hit.license+']' : '', '('+hit.src+')');
      await writeFile(path.join(OUT,'credits.json'), JSON.stringify(credits,null,1));  /* progreso incremental */
    }catch(e){ fail.push(id); console.warn('✗', id, e.message); }
    await sleep(3200);   /* Openverse anónimo: quedarse bien abajo del límite por minuto */
  }
  await writeFile(path.join(OUT,'credits.json'), JSON.stringify(credits,null,1));
  console.log(`\nListo: ${ok} bajadas · ${skip} ya estaban · ${fail.length} fallaron${fail.length?' → '+fail.join(', '):''}`);
  if(fail.length) console.log('El script es incremental: corriéndolo de nuevo baja SOLO las que faltan.');
  console.log('Revisá a ojo las fotos, reemplazá las que no te gusten con un .jpg propio del mismo nombre, y commiteá public/img/wa/.');
}
main().catch(e=>{ console.error(e); process.exit(1); });
