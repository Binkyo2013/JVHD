/*
 * src/crypto-bridge.js
 * Thay thế 3 hàm native của AndroidBridge trên Windows:
 *   - c0(name) : SHA-256(name + salt) hex 64 ký tự
 *   - d0()     : khóa công khai thiết bị (ECDSA P-256)
 *   - e0(data) : chữ ký ECDSA trên data bằng khóa riêng thiết bị
 *
 * Mọi tham số lấy từ config (xem jvhd.config.js).
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

/** c0(name) -> hex
 *  Công thức khớp native (libbtcore.so / n0), đã xác minh = tool đăng ký:
 *    name = String(name).trim().toLowerCase()
 *    input = concat == 'prefix' ? salt+name : name+salt   (salt là VĂN BẢN)
 *    c0   = SHA-256(input) hex
 */
function c0(name, cfg) {
  const a = cfg.auth || cfg;
  const normalized = String(name == null ? "" : name).trim().toLowerCase();
  const salt = String(a.salt || "");
  const text = a.concat === "prefix" ? salt + normalized : normalized + salt;
  return sha256Hex(Buffer.from(text, "utf8"));
}

/* ------------------------------------------------------------------ *
 * Khóa riêng thiết bị
 * ------------------------------------------------------------------ */

function ensureDeviceKey(opts) {
  // opts = { filePath, alg }
  if (fs.existsSync(opts.filePath)) {
    try {
      const pem = fs.readFileSync(opts.filePath, "utf8");
      const key = crypto.createPrivateKey(pem);
      return { key, filePath: opts.filePath };
    } catch (e) { /* rơi xuống tạo mới */ }
  }
  const { privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  fs.mkdirSync(path.dirname(opts.filePath), { recursive: true });
  fs.writeFileSync(opts.filePath, privateKey, { encoding: "utf8", mode: 0o600 });
  return { key: crypto.createPrivateKey(privateKey), filePath: opts.filePath };
}

function rawUncompressedFromSpki(spkiDer) {
  // SPKI DER: last 65 bytes = 0x04 || X || Y (P-256)
  return spkiDer.slice(spkiDer.length - 65);
}

/** d0() -> public key string theo pubKeyFormat trong config */
function d0(key, cfg) {
  const fmt = String((cfg.auth || cfg).pubKeyFormat || "spki-b64");
  const pub = crypto.createPublicKey(key); // nhận private KeyObject -> public KeyObject
  const spki = pub.export({ type: "spki", format: "der" });
  if (fmt === "raw-uncompressed-b64") {
    return rawUncompressedFromSpki(spki).toString("base64");
  }
  // mặc định: spki-b64 (base64 của SPKI DER, không header PEM)
  return spki.toString("base64");
}

/** e0(data) -> chữ ký string theo sigFormat.
 *  Khớp BtK.sg() bản gốc: nếu challengeEncoding="base64" thì data là chuỗi
 *  base64 -> phải BASE64-DECODE trước rồi mới SHA-256 + ký. */
function e0(key, data, cfg) {
  const a = cfg.auth || cfg;
  const enc = String(a.challengeEncoding || "utf8").toLowerCase();
  const text = String(data == null ? "" : data);
  let payload;
  if (enc === "base64") payload = Buffer.from(text, "base64");
  else if (enc === "hex") payload = Buffer.from(text, "hex");
  else payload = Buffer.from(text, "utf8");
  const digest = a.signDigest || "sha256";

  const fmt = String(a.sigFormat || "der-b64");
  const asRaw = fmt.indexOf("raw") === 0;
  let sig;
  if (asRaw) {
    // r||s gộp 64 byte (IEEE P-1363)
    sig = crypto.sign(digest, payload, { key, dsaEncoding: "ieee-p1363" });
  } else {
    // ASN.1 DER (mặc định)
    sig = crypto.sign(digest, payload, key);
  }
  if (fmt.indexOf("-hex") !== -1) return sig.toString("hex");
  return sig.toString("base64");
}

function derToRaw(der) {
  // ECDSA DER -> (r||s) 32 byte mỗi cái
  let r = der[4];
  let offset = 5;
  if (r & 0x80) { r = der[5]; offset = 6; }
  const rStart = offset;
  const rLen = r;
  offset += rLen;
  let s = der[offset + 1];
  offset += 2;
  if (s & 0x80) offset += 1;
  const sStart = offset;
  const sLen = 32;
  const rBytes = pad32(der.slice(rStart, rStart + rLen));
  const sBytes = pad32(der.slice(sStart, sStart + sLen));
  return Buffer.concat([rBytes, sBytes]);
}

function pad32(buf) {
  if (buf.length === 32) return buf;
  const out = Buffer.alloc(32);
  if (buf.length < 32) { buf.copy(out, 32 - buf.length); }
  else { buf.copy(out, 0, buf.length - 32); }
  return out;
}

module.exports = {
  sha256Hex, c0, ensureDeviceKey, d0, e0,
  rawUncompressedFromSpki,
  // helper kiểm thử
  derToRaw,
  signSyncRaw: e0
};
