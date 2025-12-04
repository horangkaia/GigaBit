const functions = require("firebase-functions");
const admin = require("firebase-admin");
const cors = require("cors")({ origin: true });

admin.initializeApp();
const db = admin.database();

const OWNER_PW = "kalikiben"; // GANTI WAJIB

function checkPw(req, res) {
  if (!req.query.pw || req.query.pw !== OWNER_PW) {
    res.json({ ok: false, error: "Wrong admin password" });
    return false;
  }
  return true;
}

// ===================================================
// 1. GENERATE KEY
// ===================================================
exports.generateKey = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {

    if (!checkPw(req, res)) return;

    const type = req.query.type || "single";
    const days = Number(req.query.days || 30);
    const hwid = req.query.hwid || "*";

    const id = Date.now().toString();
    const key = "KEY-" + Math.random().toString(36).substring(2).toUpperCase();

    const issued = Date.now();
    const expires = issued + days * 86400000;

    const payload = {
      id,
      key,
      type,
      days,
      hwid,
      paid: false,
      used: false,
      revoked: false,
      issued,
      expires
    };

    await db.ref(`keys/${id}`).set(payload);

    res.json({ ok: true, key, data: payload });
  });
});

// ===================================================
// 2. LIST KEYS
// ===================================================
exports.listKeys = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {

    if (!checkPw(req, res)) return;

    const snap = await db.ref("keys").once("value");
    const val = snap.val() || {};

    res.json({ ok: true, keys: val });
  });
});

// ===================================================
// 3. MARK PAID
// ===================================================
exports.markPaid = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {

    if (!checkPw(req, res)) return;

    const id = req.query.id;
    if (!id) return res.json({ ok: false, error: "Missing id" });

    await db.ref(`keys/${id}/paid`).set(true);
    res.json({ ok: true, id });
  });
});

// ===================================================
// 4. MARK USED
// ===================================================
exports.markUsed = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {

    if (!checkPw(req, res)) return;

    const id = req.query.id;
    if (!id) return res.json({ ok: false, error: "Missing id" });

    await db.ref(`keys/${id}/used`).set(true);
    res.json({ ok: true, id });
  });
});

// ===================================================
// 5. REVOKE KEY
// ===================================================
exports.revokeKey = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {

    if (!checkPw(req, res)) return;

    const id = req.query.id;
    if (!id) return res.json({ ok: false, error: "Missing id" });

    await db.ref(`keys/${id}/revoked`).set(true);
    res.json({ ok: true, id });
  });
});

// ===================================================
// 6. VERIFY KEY (untuk TAMperMonkey / client app)
// ===================================================
exports.verifyKey = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {

    const key = req.query.key;
    const hwid = req.query.hwid;

    if (!key || !hwid) return res.json({ ok: false, error: "Missing key/hwid" });

    // cari berdasarkan key
    const snap = await db.ref("keys").orderByChild("key").equalTo(key).once("value");
    if (!snap.exists()) return res.json({ ok:false, error:"Key not found" });

    const data = Object.values(snap.val())[0];

    if (data.revoked) return res.json({ ok:false, error:"Key revoked" });
    if (!data.paid) return res.json({ ok:false, error:"Key unpaid" });
    if (Date.now() > data.expires) return res.json({ ok:false, error:"Key expired" });

    // HWID check
    if (data.hwid !== "*" && data.hwid !== hwid) {
      return res.json({ ok:false, error:"HWID mismatch" });
    }

    res.json({ ok:true, valid:true, data });
  });
});
