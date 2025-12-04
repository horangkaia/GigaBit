const crypto = require("crypto");
const { onRequest } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");

initializeApp();

// ================================
//  SECRET — Tidak akan pernah ke client
// ================================
const SIGN_SECRET = "KALIKIBEN-BRUTAL-SECRET"; 
const OWNER_PASS = "Kalikiben1@"; // untuk admin generator di Firebase

// ================================
// Helper: Encode Base64URL
// ================================
function base64url(str) {
  return Buffer.from(str).toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// ================================
//  Buat HMAC Signature
// ================================
function sign(payloadB64) {
  return crypto.createHmac("sha256", SIGN_SECRET)
    .update(payloadB64)
    .digest("hex");
}

// ================================
//  API #1 — SERVER-SIDE KEY GENERATOR
// ================================
exports.generateKey = onRequest(async (req, res) => {
  const db = getDatabase();
  const { pw, type, days, hwid } = req.query;

  if (pw !== OWNER_PASS) return res.json({ error: "Unauthorized" });
  if (!["single", "global"].includes(type)) return res.json({ error: "Invalid type" });

  const duration = Number(days);
  if (![30, 180, 365].includes(duration))
    return res.json({ error: "Invalid duration" });

  const payloadObj = {
    type,
    days: duration,
    hwid: hwid || "*",
    issued: Date.now()
  };

  const payloadB64 = base64url(JSON.stringify(payloadObj));
  const signature = sign(payloadB64);
  const fullKey = `${payloadB64}.${signature}`;

  // Save to DB
  await db.ref("keys").push({
    payload: payloadObj,
    key: fullKey,
    status: "unpaid", // default
    created: Date.now()
  });

  res.json({ key: fullKey, payload: payloadObj });
});

// ================================
//  API #2 — VERIFY LICENSE FOR TAMPERMONKEY
// ================================
exports.verifyKey = onRequest(async (req, res) => {
  const db = getDatabase();
  const { key, hwid } = req.query;

  if (!key) return res.json({ valid: false, reason: "NO_KEY" });

  const parts = key.split(".");
  if (parts.length !== 2) return res.json({ valid: false, reason: "FORMAT" });

  const [payloadB64, sig] = parts;

  // Validate crypto signature
  const expectedSig = sign(payloadB64);
  if (sig !== expectedSig)
    return res.json({ valid: false, reason: "SIGNATURE_BAD" });

  const payloadStr = Buffer.from(payloadB64, "base64").toString("utf8");
  const payload = JSON.parse(payloadStr);

  // Check DB
  const snap = await db.ref("keys").orderByChild("key").equalTo(key).get();
  if (!snap.exists()) return res.json({ valid: false, reason: "NOT_FOUND" });

  const data = Object.values(snap.val())[0];

  if (data.status === "revoked")
    return res.json({ valid: false, reason: "REVOKED" });

  if (data.status === "unpaid")
    return res.json({ valid: false, reason: "UNPAID" });

  // Check expiry
  const now = Date.now();
  const expire = payload.issued + payload.days * 24 * 60 * 60 * 1000;
  if (now > expire)
    return res.json({ valid: false, reason: "EXPIRED" });

  // Check HWID
  if (payload.type === "single" && payload.hwid !== "*" && payload.hwid !== hwid)
    return res.json({ valid: false, reason: "HWID_MISMATCH" });

  // Everything OK
  res.json({
    valid: true,
    daysLeft: Math.ceil((expire - now) / 86400000),
    payload
  });
});
