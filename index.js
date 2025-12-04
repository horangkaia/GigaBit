// functions/index.js
const crypto = require("crypto");
const { onRequest } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");

initializeApp();

// ========= CONFIG =========
const SIGN_SECRET = process.env.SIGN_SECRET || "DEV_SECRET_CHANGE";
const OWNER_PASS  = process.env.OWNER_PASS  || "DEV_OWNER_PASS";
// ==========================

// --- util base64url ---
function base64urlEncode(str) {
  return Buffer.from(str, "utf8")
    .toString("base64")
    .replace(/=/g,"")
    .replace(/\+/g,'-')
    .replace(/\//g,'_');
}
function base64urlDecode(b64) {
  b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return Buffer.from(b64, 'base64').toString('utf8');
}

function signPayload(payloadB64) {
  return crypto.createHmac("sha256", SIGN_SECRET)
               .update(payloadB64)
               .digest("hex");
}

async function findRecordByKey(db, fullKey) {
  const snap = await db.ref("keys").orderByChild("key").equalTo(fullKey).limitToFirst(1).get();
  if (!snap.exists()) return null;
  const obj = snap.val();
  const id = Object.keys(obj)[0];
  return { id, rec: obj[id] };
}

// ============ CORS helper ============
function allowCORS(res) {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET,POST");
  res.set("Access-Control-Allow-Headers", "Content-Type");
}
// ====================================


// -------------------- generateKey --------------------
exports.generateKey = onRequest(async (req, res) => {
  allowCORS(res);

  try {
    const { pw, type, days, hwid } = req.query;
    if (!pw || pw !== OWNER_PASS)
      return res.status(401).json({ error: "Unauthorized" });

    if (!["single", "global"].includes(type))
      return res.status(400).json({ error: "Invalid type" });

    const dur = Number(days);
    if (![30,180,365].includes(dur))
      return res.status(400).json({ error: "Invalid days" });

    const issued = Date.now();
    const payloadObj = { type, days: dur, hwid: hwid || "*", issued };
    const payloadB64 = base64urlEncode(JSON.stringify(payloadObj));
    const sig = signPayload(payloadB64);
    const fullKey = `${payloadB64}.${sig}`;
    const expires = issued + dur * 86400000;

    const db = getDatabase();
    const ref = await db.ref("keys").push({
      key: fullKey,
      payload: payloadObj,
      type,
      hwid: hwid || "*",
      days: dur,
      issued,
      expires,
      paid: false,
      used: false,
      revoked: false,
      createdAt: Date.now()
    });

    return res.json({
      ok: true,
      id: ref.key,
      key: fullKey,
      payload: payloadObj
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "INTERNAL" });
  }
});


// -------------------- verifyKey --------------------
exports.verifyKey = onRequest(async (req, res) => {
  allowCORS(res);

  try {
    const { key, hwid } = req.query;
    if (!key) return res.json({ valid:false, reason:"NO_KEY" });

    const parts = key.split(".");
    if (parts.length !== 2)
      return res.json({ valid:false, reason:"BAD_FORMAT" });

    const [payloadB64, sig] = parts;

    const expected = signPayload(payloadB64);
    if (sig !== expected)
      return res.json({ valid:false, reason:"BAD_SIGNATURE" });

    let payload;
    try { payload = JSON.parse(base64urlDecode(payloadB64)); }
    catch { return res.json({ valid:false, reason:"BAD_PAYLOAD" }); }

    const db = getDatabase();
    const found = await findRecordByKey(db, key);
    if (!found)
      return res.json({ valid:false, reason:"NOT_FOUND" });

    const rec = found.rec;

    if (rec.revoked) return res.json({ valid:false, reason:"REVOKED" });
    if (!rec.paid)  return res.json({ valid:false, reason:"UNPAID" });

    const now = Date.now();
    const expires = rec.expires;
    if (now > expires)
      return res.json({ valid:false, reason:"EXPIRED" });

    if (
      payload.type === "single" &&
      payload.hwid !== "*" &&
      hwid &&
      payload.hwid !== hwid
    ) {
      return res.json({ valid:false, reason:"HWID_MISMATCH" });
    }

    return res.json({
      valid: true,
      daysLeft: Math.ceil((expires - now) / 86400000),
      payload,
      id: found.id,
      record: rec
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ valid:false, reason:"INTERNAL" });
  }
});


// -------------------- listKeys (admin) --------------------
exports.listKeys = onRequest(async (req, res) => {
  allowCORS(res);

  try {
    const { pw } = req.query;
    if (!pw || pw !== OWNER_PASS)
      return res.status(401).json({ error:"Unauthorized" });

    const snap = await getDatabase()
      .ref("keys")
      .orderByChild("createdAt")
      .limitToLast(500)
      .get();

    return res.json({
      ok: true,
      keys: snap.exists() ? snap.val() : {}
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error:"INTERNAL" });
  }
});


// -------------------- markPaid / markUsed / revokeKey --------------------
async function adminUpdate(req, res, updateObj) {
  allowCORS(res);

  try {
    const { pw, id } = req.query;
    if (!pw || pw !== OWNER_PASS)
      return res.status(401).json({ error:"Unauthorized" });

    const db = getDatabase();
    await db.ref(`keys/${id}`).update(updateObj);
    const rec = (await db.ref(`keys/${id}`).get()).val();

    return res.json({ ok:true, id, rec });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error:"INTERNAL" });
  }
}

exports.markPaid  = onRequest((req,res)=> adminUpdate(req,res,{ paid:true,  paidAt:Date.now() }));
exports.markUsed  = onRequest((req,res)=> adminUpdate(req,res,{ used:true,  usedAt:Date.now() }));
exports.revokeKey = onRequest((req,res)=> adminUpdate(req,res,{ revoked:true,revokedAt:Date.now() }));
