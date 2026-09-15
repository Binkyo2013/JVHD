/*
 * tools/verify_swift_sig.js
 * ---------------------------------------------------------------------------
 * Kiểm chứng chữ ký do `tools/native_crypto_main.swift` (tức DeviceKey.swift
 * thật trong IPA) tạo ra, bằng CHÍNH `crypto` của Node — cùng thư viện mà bản
 * Windows/Android dùng trong `src/crypto-bridge.js`.
 *
 * Nếu chữ ký Swift verify được bằng Node với khoá công khai dạng
 * raw-uncompressed (0x04||X||Y) thì định dạng d0()/e0() của iOS khớp Android.
 *
 * Cách chạy:  node tools/verify_swift_sig.js '<json của swift>'
 */
"use strict";
const crypto = require("crypto");

const raw = process.argv[2];
if (!raw) { console.error("thiếu JSON đầu vào"); process.exit(2); }
const r = JSON.parse(raw);

let pass = 0, fail = 0;
function ok(cond, name, extra) {
  if (cond) { pass++; console.log("  PASS  " + name); }
  else { fail++; console.log("  FAIL  " + name + (extra ? "  (" + extra + ")" : "")); }
}

console.log("\n[iOS native] đối chiếu d0()/e0() của Swift với crypto Node (chuẩn Android)");

const pubB64 = String(r.d0 || "");
const pubRaw = Buffer.from(pubB64, "base64");
ok(pubRaw.length === 65, "d0() là 65 byte (0x04||X||Y) — khớp pubKeyFormat raw-uncompressed-b64",
   "thực tế " + pubRaw.length + " byte");
ok(pubRaw.length === 65 && pubRaw[0] === 0x04, "byte đầu của d0() là 0x04 (điểm không nén)");

// Dựng lại khoá công khai SPKI từ raw để Node verify được.
const SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
const spki = Buffer.concat([SPKI_PREFIX, pubRaw]);
let pubKey = null;
try { pubKey = crypto.createPublicKey({ key: spki, format: "der", type: "spki" }); } catch (e) { pubKey = null; }
ok(pubKey !== null, "Node đọc được khoá công khai từ d0() (SPKI P-256)");

const challenge = Buffer.from(String(r.challenge || ""), "base64");
const sig = Buffer.from(String(r.sig || ""), "base64");
ok(sig.length > 0, "e0() trả chữ ký khác rỗng");
ok(r.sig_isDER === true, "chữ ký ở dạng DER (khớp sigFormat der-b64)");

let verified = false;
if (pubKey && sig.length) {
  try { verified = crypto.verify("sha256", challenge, pubKey, sig); } catch (e) { verified = false; }
}
ok(verified, "Node VERIFY được chữ ký Swift trên challenge đã base64-decode" +
   "  <-- đúng công thức e0() của Android", "swiftVerify=" + r.swiftVerify);

const KNOWN = "37b5d924f34f64ed7e88033b8c31db39b314ddca0ec624ea94d5b8056467ca5b";
ok(r.c0_Admin2 === KNOWN, "Crypto.swift c0('Admin2') khớp HASH trong jsonbin", "thực tế " + r.c0_Admin2);

console.log("\n  Bảng 'dễ tính' khi giải mã challenge (Swift vs Node Buffer.from base64):");
const len = r.leniency || {};
Object.keys(len).forEach((k) => {
  const v = len[k] || {};
  const diverge = (v.nodeDecodedBytes > 0 && v.swiftDecodedBytes <= 0);
  console.log("   - " + k.padEnd(28) +
    " node=" + String(v.nodeDecodedBytes).padStart(3) + "B" +
    "  swift=" + String(v.swiftDecodedBytes).padStart(3) + "B" +
    "  swiftSigEmpty=" + (v.swiftSigEmpty ? "CÓ" : "không") +
    (diverge ? "   <<< KHÁC BIỆT: iOS hỏng, Android vẫn chạy" : ""));
  if (diverge) fail++;
});

console.log("\n  PASS: " + pass + "   FAIL: " + fail + "\n");
process.exit(fail > 0 ? 1 : 0);
