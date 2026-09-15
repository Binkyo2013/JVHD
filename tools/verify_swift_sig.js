/*
 * tools/verify_swift_sig.js
 * ---------------------------------------------------------------------------
 * Kiểm chứng chữ ký do `tools/native_crypto_main.swift` (tức DeviceKey.swift +
 * Crypto.swift thật trong IPA) tạo ra, bằng CHÍNH `crypto` của Node — cùng thư
 * viện mà bản Windows/Android dùng trong `src/crypto-bridge.js`.
 *
 * Ba điều phải đúng để iOS đăng nhập được như Android:
 *   1. d0() = base64(0x04||X||Y), Node đọc được thành khoá P-256.
 *   2. e0() = chữ ký ECDSA/SHA-256 dạng DER mà Node verify được.
 *   3. e0() KHÔNG BAO GIỜ rỗng — kể cả với payload rỗng/lạ — vì
 *      `app.js` diễn giải chuỗi rỗng là "Thiết bị không hỗ trợ xác thực".
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
ok(sig.length > 0, "e0(challenge) trả chữ ký khác rỗng");
ok(r.sig_isDER === true, "chữ ký ở dạng DER (khớp sigFormat der-b64)");

let verified = false;
if (pubKey && sig.length) {
  try { verified = crypto.verify("sha256", challenge, pubKey, sig); } catch (e) { verified = false; }
}
ok(verified, "Node VERIFY được chữ ký Swift trên challenge đã base64-decode" +
   "  <-- đúng công thức e0() của Android", "swiftVerify=" + r.swiftVerify);

const KNOWN = "37b5d924f34f64ed7e88033b8c31db39b314ddca0ec624ea94d5b8056467ca5b";
ok(r.c0_Admin2 === KNOWN, "Crypto.swift c0('Admin2') khớp HASH trong jsonbin", "thực tế " + r.c0_Admin2);

/* ------------------------------------------------------------------ *
 * ĐIỂM MẤU CHỐT: e0() với payload RỖNG.
 * Node: Buffer.from('','base64') = Buffer rỗng -> crypto.sign vẫn ra chữ ký.
 * iOS trước đây: Data(base64Encoded:"") = nil -> e0() = "" -> app.js báo
 * "Thiết bị không hỗ trợ xác thực, không thể tiếp tục" và CHẶN đăng nhập.
 * ------------------------------------------------------------------ */
const emptySig = Buffer.from(String(r.sigForEmptyInput || ""), "base64");
ok(emptySig.length > 0, "e0('') trả chữ ký KHÁC RỖNG (parity với Node — trước đây rỗng)");
ok(r.sigForEmptyInput_isDER === true, "e0('') cũng ở dạng DER");
let emptyVerified = false;
if (pubKey && emptySig.length) {
  try { emptyVerified = crypto.verify("sha256", Buffer.alloc(0), pubKey, emptySig); } catch (e) { emptyVerified = false; }
}
ok(emptyVerified, "Node VERIFY được e0('') trên message rỗng — đúng bằng hành vi Android");

/* ------------------------------------------------------------------ *
 * Bộ giải mã base64 của Swift phải cho ra ĐÚNG TỪNG BYTE như Node.
 * ------------------------------------------------------------------ */
console.log("\n  Đối chiếu decodeBase64NodeCompatible (Swift) với Buffer.from(x,'base64') (Node):");
const table = r.nodeCompatHex || {};
let mismatch = 0;
Object.keys(table).forEach((sample) => {
  const swiftHex = String(table[sample] || "");
  const nodeHex = Buffer.from(sample, "base64").toString("hex");
  const same = swiftHex === nodeHex;
  if (!same) mismatch++;
  console.log("   " + (same ? "✓" : "✗") + " " + JSON.stringify(sample).padEnd(28) +
    " swift=" + (swiftHex.length / 2) + "B node=" + (nodeHex.length / 2) + "B" +
    (same ? "" : "\n       swift: " + swiftHex + "\n       node : " + nodeHex));
});
ok(mismatch === 0, "mọi mẫu base64 cho ra byte GIỐNG HỆT Node", mismatch + " mẫu lệch");

const signNotEmpty = r.signNotEmpty || {};
const emptySigns = Object.keys(signNotEmpty).filter((k) => !signNotEmpty[k]);
ok(emptySigns.length === 0, "e0() có chữ ký với MỌI dạng payload (không mẫu nào rỗng)",
   emptySigns.map((s) => JSON.stringify(s)).join(", "));

console.log("\n  Khoá thiết bị đang ở tầng nào (DeviceKey.diagnostics):");
console.log("   " + JSON.stringify(r.deviceKeyDiagnostics || {}));
ok(!!(r.deviceKeyDiagnostics && r.deviceKeyDiagnostics.hasKey), "DeviceKey tạo được khoá (d0()/e0() không thể rỗng)");

console.log("\n  PASS: " + pass + "   FAIL: " + fail + "\n");
process.exit(fail > 0 ? 1 : 0);
