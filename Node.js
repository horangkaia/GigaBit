const crypto = require("crypto");
const { onCall } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");

initializeApp();

// =============== CONFIG ===============
const SIGN_SECRET = "kalikiben"; // ganti!
const OWNER_PASSWORD = "Kalikiben1@"; // ganti!

// =============== HELPERS ===============
function hmacHex(secret, msg) {
  return crypto
    .createHmac("sha256", secret)
    .update(msg)
    .digest("hex");
}

function b64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

// =============== MAIN FUNCTION ===============
// Callable function: "generateKey"
exports.generateKey = onCall(async (req) => {
  const { password, type, days, hwid } = req.data;

  if (password !== OWNER_PASSWORD) {
    throw new Error("Unauthorized");
  }

  if (!["single", "global"].includes(type)) {
    throw new Error("Invalid type");
  }

  const duration = Number(days);
  if (![30, 180, 365].includes(duration)) {
    throw new Error("Invalid days");
  }

  const issued = Date.now();

  const payloadObj = { type, days: duration, hwid, issued };
  const payloadB64 = b64(JSON.stringify(payloadObj));
  const signature = hmacHex(SIGN_SECRET, payloadB64);

  const finalKey = `${payloadB64}.${signature}`;

  // save to DB
  const db = getDatabase();
  await db.ref("keys").push({
    payload: payloadObj,
    key: finalKey,
    status: "unpaid",
    created: Date.now(),
  });

  return {
    key: finalKey,
    payload: payloadObj,
  };
});
