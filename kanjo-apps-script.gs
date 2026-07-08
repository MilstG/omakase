/**
 * Kanjō — backend de Google Sheets para la app de analytics del omakase.
 *
 * QUÉ HACE
 *   Guarda un servicio por fila y responde a la app: listar, agregar,
 *   editar, borrar y reemplazar todo. La app es tu única pantalla;
 *   esta sheet es el depósito que también ve tu contador.
 *
 * CÓMO INSTALARLO (una sola vez, ~10 min)
 *   1. Creá una Google Sheet nueva y vacía.
 *   2. Menú: Extensiones → Apps Script.
 *   3. Borrá lo que haya y pegá TODO este archivo. Guardá (ícono de disquete).
 *   4. Implementar → Nueva implementación → tipo "Aplicación web".
 *        - Ejecutar como: Yo
 *        - Quién tiene acceso: Cualquier persona
 *      Implementar. Autorizá los permisos cuando te los pida.
 *   5. Copiá la "URL de la aplicación web" (termina en /exec).
 *   6. Pegala en la app, en la tarjeta "Sincronización · Google Sheets",
 *      y tocá "Conectar / Probar".
 *
 * NOTA: si más adelante editás este script, volvé a "Implementar →
 * Administrar implementaciones → editar (lápiz) → Nueva versión" para
 * que los cambios tomen efecto en la misma URL.
 */

var SHEET_NAME = 'Servicios';
var HEADERS = ['id','date','turno','covers','omakase','premium','bebidas','extras',
               'payCard','payQR','payCash','cashDiscPct','cashUndeclared','updatedAt'];

function getSheet_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sh = ss.getSheetByName(SHEET_NAME);
  if (!sh) sh = ss.insertSheet(SHEET_NAME);
  if (sh.getLastRow() === 0) sh.appendRow(HEADERS);
  return sh;
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function rowToObj_(headers, row) {
  var o = {};
  for (var i = 0; i < headers.length; i++) {
    var v = row[i];
    if (headers[i] === 'date' && v instanceof Date) {
      v = Utilities.formatDate(v, Session.getScriptTimeZone(), 'yyyy-MM-dd');
    }
    o[headers[i]] = v;
  }
  return o;
}

function readAll_(sh) {
  var values = sh.getDataRange().getValues();
  if (values.length < 2) return [];
  var headers = values[0];
  var out = [];
  for (var r = 1; r < values.length; r++) {
    if (values[r][0] === '' && values[r][1] === '') continue; // saltear filas vacías
    out.push(rowToObj_(headers, values[r]));
  }
  return out;
}

function recToRow_(rec) {
  return HEADERS.map(function (h) {
    if (h === 'updatedAt') return new Date();
    if (h === 'cashUndeclared') return rec[h] ? true : false;
    return (rec[h] !== undefined && rec[h] !== null) ? rec[h] : '';
  });
}

function findRow_(sh, id) {
  var last = sh.getLastRow();
  if (last < 2) return -1;
  var ids = sh.getRange(1, 1, last, 1).getValues();
  for (var r = 1; r < ids.length; r++) {
    if (String(ids[r][0]) === String(id)) return r + 1; // fila 1-based
  }
  return -1;
}

// Lectura directa (abrir la URL en el navegador también lista los datos)
function doGet(e) {
  try { return json_({ ok: true, services: readAll_(getSheet_()) }); }
  catch (err) { return json_({ ok: false, error: String(err) }); }
}

// Todas las operaciones de la app llegan acá
function doPost(e) {
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(20000); // evita choques si entran dos cambios juntos
    var sh = getSheet_();
    var body = (e && e.postData && e.postData.contents) ? JSON.parse(e.postData.contents) : {};
    var action = body.action || 'list';

    if (action === 'list') {
      return json_({ ok: true, services: readAll_(sh) });
    }
    if (action === 'add') {
      sh.appendRow(recToRow_(body.record));
      return json_({ ok: true });
    }
    if (action === 'update') {
      var row = findRow_(sh, body.record.id);
      if (row < 0) sh.appendRow(recToRow_(body.record));
      else sh.getRange(row, 1, 1, HEADERS.length).setValues([recToRow_(body.record)]);
      return json_({ ok: true });
    }
    if (action === 'delete') {
      var r = findRow_(sh, body.id);
      if (r > 0) sh.deleteRow(r);
      return json_({ ok: true });
    }
    if (action === 'replaceAll') {
      if (sh.getLastRow() > 1) {
        sh.getRange(2, 1, sh.getLastRow() - 1, HEADERS.length).clearContent();
      }
      var recs = body.services || [];
      if (recs.length) {
        sh.getRange(2, 1, recs.length, HEADERS.length).setValues(recs.map(recToRow_));
      }
      return json_({ ok: true, count: recs.length });
    }
    return json_({ ok: false, error: 'accion desconocida: ' + action });
  } catch (err) {
    return json_({ ok: false, error: String(err) });
  } finally {
    try { lock.releaseLock(); } catch (e2) {}
  }
}
