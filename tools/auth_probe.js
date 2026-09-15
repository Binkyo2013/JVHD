/*
 * tools/auth_probe.js — CHẨN ĐOÁN (đọc) hợp đồng của máy chủ xác thực.
 *
 * Mục đích: in ra CHÍNH XÁC những gì https://jvhd-auth.onrender.com trả về cho
 * POST /auth/start (và /auth/verify) để đối chiếu với logic Android/iOS.
 *
 * AN TOÀN: KHÔNG BAO GIỜ gọi /auth/bind -> không thể tạo/ghi đè/mất bất kỳ
 * ràng buộc thiết bị nào đang lưu trên JSONBin. /auth/verify chỉ được gọi với
 * chữ ký của một khoá TẠM sinh ra trong tiến trình này (khoá đó không được
 * đăng ký), nên máy chủ chỉ có thể trả "denied", không đổi trạng thái bind.
 *
 * Cách chạy:  node tools/auth_probe.js <hash-hop-le> [hash-khong-ton-tai]
 */
"use strict";

const crypto = require("crypto");

const AUTH = "https://jvhd-auth.onrender.com";
/// Hash chắc chắn KHÔNG nằm trong danh sách hợp lệ -> dùng cho các lời gọi
/// thăm dò có nguy cơ chạm trạng thái (không thể đụng binding thật).
const UNKNOWN_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

function post(path, payload) {
  return new Promise((resolve) => {
    const body = JSON.stringify(payload);
    const req = require("https").request(
      AUTH + path,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body)
        },
        timeout: 120000
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c) => { text += c; });
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text }));
      }
    );
    req.on("error", (e) => resolve({ status: 0, headers: {}, text: "ERROR " + e.message }));
    req.on("timeout", () => { req.destroy(); resolve({ status: 0, headers: {}, text: "TIMEOUT" }); });
    req.end(body);
  });
}

// Mô tả định dạng của một chuỗi: base64 / base64url / hex / khác.
function describe(value) {
  if (typeof value !== "string") return "(không phải chuỗi: " + typeof value + ")";
  const out = { length: value.length };
  out.base64Strict = /^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length % 4 === 0;
  out.base64Loose = /^[A-Za-z0-9+/]+={0,2}$/.test(value);
  out.base64Url = /^[A-Za-z0-9_-]+={0,2}$/.test(value);
  out.hex = /^[0-9a-fA-F]+$/.test(value);
  out.printableAscii = /^[\x20-\x7e]+$/.test(value);
  const asB64 = Buffer.from(value, "base64");
  out.decodedBase64Bytes = asB64.length;
  // Buffer.from(x,'base64') của Node rất "dễ tính": nó bỏ qua ký tự lạ.
  out.roundTripsBase64 = asB64.toString("base64") === value;
  return out;
}

async function main() {
  const hashes = process.argv.slice(2);
  if (!hashes.length) { console.log("cần ít nhất 1 hash"); process.exit(2); }

  for (const h of hashes) {
    console.log("\n================ /auth/start  h=" + h + " ================");
    const res = await post("/auth/start", { h });
    console.log("HTTP " + res.status);
    console.log("content-type: " + (res.headers["content-type"] || "(không có)"));
    console.log("body(raw): " + res.text.slice(0, 2000));
    let parsed = null;
    try { parsed = JSON.parse(res.text); } catch (e) { parsed = null; }
    if (parsed && typeof parsed === "object") {
      console.log("keys: " + JSON.stringify(Object.keys(parsed)));
      console.log("status: " + JSON.stringify(parsed.status));
      for (const key of Object.keys(parsed)) {
        if (typeof parsed[key] === "string" && parsed[key].length > 8) {
          console.log("  trường '" + key + "' -> " + JSON.stringify(describe(parsed[key])));
        }
      }

      // Chỉ thử /auth/verify với hash KHÔNG tồn tại (không thể đang ràng buộc
      // với thiết bị nào) để đọc shape phản hồi mà tuyệt đối không đụng tới
      // dữ liệu bind đang có trên JSONBin.
      const ch = parsed.challenge || parsed.nonce || null;
      if (ch && h === UNKNOWN_HASH) {
        const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
        const sig = crypto.sign("sha256", Buffer.from(ch, "base64"), privateKey).toString("base64");
        console.log("\n---- /auth/verify (hash không tồn tại + khoá TẠM; mong đợi 'denied'/'unknown') ----");
        const v = await post("/auth/verify", { h, sig });
        console.log("HTTP " + v.status + "  body: " + v.text.slice(0, 1000));
      }
    }
  }

  console.log("\n================ /health ================");
  const health = await new Promise((resolve) => {
    require("https").get(AUTH + "/health", (res) => {
      let t = ""; res.on("data", (c) => { t += c; }); res.on("end", () => resolve(t));
    }).on("error", (e) => resolve("ERROR " + e.message));
  });
  console.log(health.slice(0, 1000));
}

main();
