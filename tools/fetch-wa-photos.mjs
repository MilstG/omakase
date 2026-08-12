#!/usr/bin/env node
/* Wa 輪 — repositorio de fotos
   Baja una foto de licencia libre de Wikimedia Commons por cada producto de la
   carta y la guarda en public/img/wa/<id>.jpg (640px de ancho). Los créditos y
   la página de origen de cada imagen quedan en public/img/wa/credits.json.

   Uso (una sola vez, o cuando agregues productos):
     node tools/fetch-wa-photos.mjs           # baja solo las que faltan
     node tools/fetch-wa-photos.mjs --force   # re-baja todo
     node tools/fetch-wa-photos.mjs uni yuzu  # solo esos ids

   Después: git add public/img/wa && commit. La CSP del server solo permite
   imágenes propias ('self'), así que el repositorio local es el único camino. */

import { mkdir, writeFile, readFile, access } from 'node:fs/promises';
import path from 'node:path';

const OUT = path.join(process.cwd(), 'public', 'img', 'wa');
const API = 'https://commons.wikimedia.org/w/api.php';
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

const UA = { 'User-Agent': 'kanjo-wa-photo-fetch/1.0 (uso interno de un restaurante; una corrida)' };
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* fetch con reintentos: Commons devuelve 429/503 seguido desde IPs de datacenter */
async function fetchRetry(url, opts, tries=4){
  let wait=2000;
  for(let i=0;i<tries;i++){
    try{
      const r = await fetch(url, opts);
      if(r.status===429 || r.status===503 || r.status>=500){
        if(i===tries-1) throw new Error('commons '+r.status);
        console.warn('  … '+r.status+', reintento en '+(wait/1000)+'s');
        await sleep(wait); wait*=3; continue;
      }
      return r;
    }catch(e){
      if(i===tries-1) throw e;
      console.warn('  … '+e.message+', reintento en '+(wait/1000)+'s');
      await sleep(wait); wait*=3;
    }
  }
}

async function searchOnce(q){
  const u = new URL(API);
  u.search = new URLSearchParams({
    action:'query', format:'json', generator:'search', maxlag:'5',
    gsrsearch:`filetype:bitmap ${q}`, gsrnamespace:'6', gsrlimit:'5',
    prop:'imageinfo', iiprop:'url|extmetadata', iiurlwidth:'640'
  });
  const r = await fetchRetry(u, { headers: UA });
  if(!r.ok) throw new Error('commons '+r.status);
  const j = await r.json();
  if(j.error && j.error.code==='maxlag'){ await sleep(5000); return searchOnce(q); }
  const pages = Object.values(j?.query?.pages || {}).sort((a,b)=>(a.index||9)-(b.index||9));
  for(const p of pages){
    const ii = p.imageinfo && p.imageinfo[0];
    if(!ii || !ii.thumburl) continue;
    if(/\.(svg|gif|tiff?)$/i.test(ii.url||'')) continue;
    const md = ii.extmetadata || {};
    return {
      thumb: ii.thumburl,
      page: ii.descriptionurl || '',
      license: (md.LicenseShortName && md.LicenseShortName.value) || '',
      artist: ((md.Artist && md.Artist.value) || '').replace(/<[^>]+>/g,'').trim().slice(0,120),
      title: p.title || ''
    };
  }
  return null;
}

/* si la búsqueda completa no da nada, probar versiones más cortas del query */
async function searchThumb(q){
  const variants=[q];
  const words=q.split(' ');
  if(words.length>2) variants.push(words.slice(0,2).join(' '));
  if(words.length>1) variants.push(words[0]);
  for(const v of variants){
    const hit = await searchOnce(v);
    if(hit) return hit;
    await sleep(400);
  }
  return null;
}

async function main(){
  await mkdir(OUT, { recursive:true });
  let credits = {};
  try{ credits = JSON.parse(await readFile(path.join(OUT,'credits.json'),'utf8')); }catch(e){}
  const ids = ONLY.length ? ONLY : Object.keys(Q);
  let ok=0, skip=0, fail=[];
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
      await writeFile(dest, Buffer.from(await img.arrayBuffer()));
      credits[id] = { file: hit.title, page: hit.page, license: hit.license, artist: hit.artist, q };
      ok++;
      console.log('✓', id, '←', hit.title, hit.license ? '['+hit.license+']' : '');
    }catch(e){ fail.push(id); console.warn('✗', id, e.message); }
    await sleep(1100);  /* modales con la API de Commons — los runners de GitHub comparten IP y Commons los limita fuerte */
  }
  await writeFile(path.join(OUT,'credits.json'), JSON.stringify(credits,null,1));
  console.log(`\nListo: ${ok} bajadas · ${skip} ya estaban · ${fail.length} fallaron${fail.length?' → '+fail.join(', '):''}`);
  if(fail.length) console.log('El script es incremental: corriéndolo de nuevo baja SOLO las que faltan.');
  console.log('Revisá a ojo las fotos (Commons a veces devuelve algo raro), reemplazá las que no te gusten');
  console.log('con cualquier .jpg propio del mismo nombre, y commiteá public/img/wa/.');
}
main().catch(e=>{ console.error(e); process.exit(1); });
