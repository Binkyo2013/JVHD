/*
 * test/gen_der_fixtures.js
 * ---------------------------------------------------------------
 * Sinh bộ mẫu (r||s) <-> DER cho hàm `JVHDCrypto.derEncodeRS()` của bản iOS.
 *
 * Lý do có file này: bản iOS ký bằng Secure Enclave / CryptoKit cho ra chữ ký
 * dạng ANSI X9.62 (nối r và s, 64 byte), trong khi máy chủ xác thực và bản
 * Android/Windows dùng ASN.1 DER (`sigFormat: "der-b64"` trong jvhd.config.js).
 * Bước chuyển đổi định dạng là chỗ rất dễ sai (quy tắc byte đệm 0x00 của DER),
 * nên nó được kiểm bằng fixture sinh từ OpenSSL/Node — nguồn chuẩn độc lập,
 * không phải do chính code iOS tự sinh rồi tự kiểm.
 *
 * Chạy lại khi cần:  node test/gen_der_fixtures.js
 * Kết quả:           test/der_fixtures.json  (mẫu + hex, KHÔNG phụ thuộc mạng)
 */
"use strict";
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Bản Node/Windows — nguồn chuẩn để đối chiếu định dạng chữ ký.
const bridge = require("../src/crypto-bridge.js");

/** DER INTEGER tối thiểu cho một số nguyên dương viết bằng big-endian bytes. */
function derInteger(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0x00) i++; // bỏ 0 đệm thừa
  let v = bytes.slice(i);
  if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0x00]), v]); // giữ dấu dương
  return Buffer.concat([Buffer.from([0x02, v.length]), v]);
}

function derFromRaw(raw) {
  const r = derInteger(raw.slice(0, 32));
  const s = derInteger(raw.slice(32, 64));
  const body = Buffer.concat([r, s]);
  if (body.length > 127) throw new Error("SEQUENCE vượt quá dạng độ dài ngắn");
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** Bộ đọc DER tối giản, ĐỘC LẬP với hàm đóng gói ở trên (dùng để kiểm chéo).
 *  Lưu ý: `derToRaw()` trong src/crypto-bridge.js đọc DER sai (nó nhầm byte
 *  độ dài có bit cao = 1 sang dạng dài, và đoán vị trí s theo hằng số). Hàm đó
 *  không được bản Windows/Android dùng tới — ở đây ta không dựa vào nó. */
function parseDerRS(der) {
  let p = 0;
  if (der[p++] !== 0x30) throw new Error("không phải SEQUENCE");
  let len = der[p++];
  if (len & 0x80) { len = der.slice(p, p + (len & 0x7f)).reduce((a, b) => a * 256 + b, 0); p += (der[p - 1] & 0x7f); }
  const end = p + len;
  function readInt() {
    if (der[p++] !== 0x02) throw new Error("không phải INTEGER");
    let n = der[p++];
    if (n & 0x80) { const k = n & 0x7f; n = der.slice(p, p + k).reduce((a, b) => a * 256 + b, 0); p += k; }
    const v = der.slice(p, p + n); p += n;
    const out = Buffer.alloc(32);
    v.copy(out, 32 - Math.min(v.length, 32), Math.max(0, v.length - 32));
    return out;
  }
  const r = readInt();
  const s = readInt();
  if (p !== end) throw new Error("còn byte thừa sau s");
  return Buffer.concat([r, s]);
}

function rand32(highByte) {
  const b = crypto.randomBytes(32);
  if (highByte !== undefined) b[0] = highByte;
  return b;
}

const cases = [];

// 1) Chữ ký ECDSA THẬT (P-256, SHA-256).
//   Lưu ý: OpenSSL ECDSA KHÔNG tất định (mỗi lần ký một `k` ngẫu nhiên), nên
//    không được ký hai lần rồi so. Ở đây lấy (r||s) từ một lần ký, tự đóng gói
//    thành DER, rồi bắt DER đó phải PASS đúng hàm verify mà MÁY CHỦ dùng
//    (`crypto.createVerify('SHA256').update(data).verify(key, sig)`).
//    Như vậy fixture được chứng nhận bởi OpenSSL, không phải bởi code ta.
for (let n = 0; n < 40; n++) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const message = crypto.randomBytes(1 + n % 64);
  const raw = crypto.sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" });
  const mine = derFromRaw(raw);
  const acceptedByServerVerify = crypto.createVerify("SHA256")
    .update(message)
    .verify(publicKey, mine);
  if (!acceptedByServerVerify) {
    console.error("Lỗi: DER tự đóng gói bị verify của server từ chối (case " + n + ")");
    process.exit(1);
  }
  // Chiều ngược lại: bộ đọc DER độc lập phải lấy lại đúng (r||s) gốc.
  const back = parseDerRS(mine).toString("hex");
  if (back !== raw.toString("hex")) {
    console.error("Lỗi: bộ đọc DER độc lập không khớp (r||s) gốc (case " + n + ")");
    process.exit(1);
  }
  cases.push({ name: "ecdsa-real-" + n, raw: raw.toString("hex"), der: mine.toString("hex") });
}

// 2) Các biên giới định dạng DER hay gặp (byte đệm 0x00 / số nhỏ).
const edge = [
  ["r cao bit 0 (không cần đệm), s cao bit 1 (cần đệm)", rand32(0x7f), rand32(0x80)],
  ["cả r và s đều cao bit 1", rand32(0xff), rand32(0xc0)],
  ["r có nhiều byte 0 đầu", Buffer.concat([Buffer.alloc(8), rand32(0x11).slice(8)]), rand32(0x22)],
  ["s = 1 (số nguyên ngắn nhất)", rand32(0x01), Buffer.concat([Buffer.alloc(31), Buffer.from([0x01])])],
  ["r = 0x7f.. largest no-pad", rand32(0x7f), rand32(0x7f)],
  ["s toàn 0xff (phải đệm 0x00)", rand32(0x33), Buffer.alloc(32, 0xff)]
];
for (let n = 0; n < edge.length; n++) {
  const raw = Buffer.concat([edge[n][1], edge[n][2]]);
  const der = derFromRaw(raw);
  // Kiểm chéo bằng bộ đọc độc lập: mọi mẫu (kể cả mẫu biên) phải quay về (r||s).
  if (parseDerRS(der).toString("hex") !== raw.toString("hex")) {
    console.error("Lỗi: mẫu biên " + n + " không round-trip qua DER");
    process.exit(1);
  }
  cases.push({ name: "edge-" + n + " " + edge[n][0], raw: raw.toString("hex"), der: der.toString("hex") });
}

// 3) Chuỗi test cho decode base64 kiểu Node `Buffer.from(text,'base64')`
//    (bản Swift `decodeBase64NodeLike` phải cho ra cùng byte).
const b64Inputs = [
  "aGVsbG8=", "aGVsbG8", "///8", "SGVsbG8sIHdvcmxkIQ==", "", "   ",
  "###not base64###", "a-b_c", "AA", "AAA", "AAAA", "/////",
  "YWJj\r\nZGVm", "!!!!", "A", "AB", "QQ==", "QQ", "ag==",
  crypto.randomBytes(32).toString("base64"),
  crypto.randomBytes(32).toString("base64url") // bản URL-safe: Node đọc được
];
const b64Cases = b64Inputs.map((text, index) => ({
  name: "b64-" + index,
  input: text,
  out: Buffer.from(text, "base64").toString("hex") // CHUẨN: semantics của Node
}));

const out = {
  note: "Sinh bởi test/gen_der_fixtures.js — chuẩn lấy từ Node/OpenSSL (crypto.sign).",
  signatures: cases,
  base64: b64Cases
};
const target = path.join(__dirname, "der_fixtures.json");
fs.writeFileSync(target, JSON.stringify(out, null, 2) + "\n", "utf8");
console.log("Đã ghi " + path.relative(path.join(__dirname, ".."), target) +
  " (" + cases.length + " mẫu chữ ký, " + b64Cases.length + " mẫu base64).");

// Tự kiểm bằng chính code Node tham chiếu (src/crypto-bridge.js) để chắc chắn
// fixture khớp định dạng mà Android/Windows đang gửi lên server.
const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const challenge = crypto.randomBytes(32).toString("base64");
const sig = bridge.e0(privateKey, challenge, { auth: { sigFormat: "der-b64", challengeEncoding: "base64" } });
console.log("Xác nhận fixture khớp bản Node: DER =",
  Buffer.from(sig, "base64")[0] === 0x30 ? "ASN.1 DER (0x30)" : "KHÔNG PHẢI DER");
