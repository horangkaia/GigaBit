// functions/index.js
const crypto = require("crypto");
const { onRequest } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");

initializeApp();

// ---------- CONFIG (set as env vars on deploy; DO NOT hardcode in repo) ----------
const SIGN_SECRET = process.env.SIGN_SECRET || "REPLACE_ME_SIGN_SECRET";
const OWNER_PASS  = process.env.OWNER_PASS  || "REPLACE_ME_OWNER_PASS";
// ---------------------------------------------------------------------------------

function base64urlEncode(str) {
  return Buffer.from(str, "utf8").toString("base64").replace(/=/g,"").replace(/\+/g,'-').replace(/\//g,'_');
}
function base64urlDecode(b64) {
  // pad if necessary
  b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return Buffer.from(b64, 'base64').toString('utf8');
}
function signPayload(payloadB64) {
  return crypto.createHmac('sha256', SIGN_SECRET).update(payloadB64).digest('hex');
}

async function findRecordByKey(db, fullKey) {
  const snap = await db.ref('keys').orderByChild('key').equalTo(fullKey).limitToFirst(1).get();
  if (!snap.exists()) return null;
  const obj = snap.val();
  const id = Object.keys(obj)[0];
  return { id, rec: obj[id] };
}

// -------------------- generateKey (admin-only) --------------------
exports.generateKey = onRequest(async (req, res) => {
  try {
    const { pw, type, days, hwid } = req.query;
    if (!pw || pw !== OWNER_PASS) return res.status(401).json({ error: 'Unauthorized' });

    if (!['single','global'].includes(type)) return res.status(400).json({ error: 'Invalid type' });
    const dur = Number(days);
    if (![30,180,365].includes(dur)) return res.status(400).json({ error: 'Invalid days' });

    const issued = Date.now();
    const payloadObj = { type, days: dur, hwid: hwid || '*', issued };
    const payloadB64 = base64urlEncode(JSON.stringify(payloadObj));
    const sig = signPayload(payloadB64);
    const fullKey = `${payloadB64}.${sig}`;

    // compute expires
    const expires = issued + dur * 24*60*60*1000;

    const db = getDatabase();
    const ref = await db.ref('keys').push({
      key: fullKey,
      payload: payloadObj,
      type,
      hwid: hwid || '*',
      days: dur,
      issued,
      expires,
      paid: false,
      used: false,
      revoked: false,
      createdAt: Date.now()
    });

    return res.json({ key: fullKey, payload: payloadObj, id: ref.key });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'INTERNAL' });
  }
});

// -------------------- verifyKey (called by Tampermonkey) --------------------
exports.verifyKey = onRequest(async (req, res) => {
  try {
    const { key, hwid } = req.query;
    if (!key) return res.json({ valid:false, reason:'NO_KEY' });

    const parts = key.split('.');
    if (parts.length !== 2) return res.json({ valid:false, reason:'BAD_FORMAT' });
    const [payloadB64, sig] = parts;

    // verify signature server-side using SIGN_SECRET
    const expected = signPayload(payloadB64);
    if (sig !== expected) return res.json({ valid:false, reason:'BAD_SIGNATURE' });

    const payloadStr = base64urlDecode(payloadB64);
    let payload;
    try { payload = JSON.parse(payloadStr); } catch(e){ return res.json({ valid:false, reason:'BAD_PAYLOAD' }); }

    const db = getDatabase();
    const found = await findRecordByKey(db, key);
    if (!found) return res.json({ valid:false, reason:'NOT_FOUND' });

    const rec = found.rec;

    if (rec.revoked) return res.json({ valid:false, reason:'REVOKED' });
    if (!rec.paid) return res.json({ valid:false, reason:'UNPAID' });

    const now = Date.now();
    const expires = rec.expires || (payload.issued + payload.days*24*60*60*1000);
    if (now > expires) return res.json({ valid:false, reason:'EXPIRED' });

    if (payload.type === 'single' && payload.hwid && payload.hwid !== '*' && hwid && payload.hwid !== hwid)
      return res.json({ valid:false, reason:'HWID_MISMATCH' });

    const daysLeft = Math.ceil((expires - now) / (24*60*60*1000));
    return res.json({ valid:true, daysLeft, payload, recordId: found.id, record: rec });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ valid:false, reason:'INTERNAL' });
  }
});

// -------------------- listKeys (admin-only) --------------------
exports.listKeys = onRequest(async (req, res) => {
  try {
    const { pw } = req.query;
    if (!pw || pw !== OWNER_PASS) return res.status(401).json({ error: 'Unauthorized' });
    const db = getDatabase();
    const snap = await db.ref('keys').orderByChild('createdAt').limitToLast(500).get();
    const data = snap.exists() ? snap.val() : {};
    return res.json({ ok:true, keys: data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error:'INTERNAL' });
  }
});

// -------------------- markPaid / markUsed / revokeKey (admin-only) --------------------
async function adminUpdate(req, res, updateObj) {
  try {
    const { pw, id } = req.query;
    if (!pw || pw !== OWNER_PASS) return res.status(401).json({ error: 'Unauthorized' });
    if (!id) return res.status(400).json({ error:'NO_ID' });
    const db = getDatabase();
    await db.ref(`keys/${id}`).update(updateObj);
    const rec = (await db.ref(`keys/${id}`).get()).val() || null;
    return res.json({ ok:true, id, rec });
  } catch (e) { console.error(e); return res.status(500).json({ error:'INTERNAL' }); }
}

exports.markPaid = onRequest((req,res)=> adminUpdate(req,res,{ paid:true, paidAt: Date.now() }));
exports.markUsed = onRequest((req,res)=> adminUpdate(req,res,{ used:true, usedAt: Date.now() }));
exports.revokeKey = onRequest((req,res)=> adminUpdate(req,res,{ revoked:true, revokedAt: Date.now() }));
