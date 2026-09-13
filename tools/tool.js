#!/usr/bin/env node
/*
 * tools/tool.js — Tiện ích dòng lệnh cho JVHD Desktop.
 * Cách dùng (trong thư mục dự án):
 *   node tools/tool.js hash <username>     -> in SHA-256(name+salt) hex 64 ký tự
 *   node tools/tool.js saltcheck           -> kiểm tra SALT/định dạng đang cấu hình
 *   node tools/tool.js selfcheck           -> tự kiểm tra khóa/sign/verify (không cần mạng)
 *
 * LƯU Ý: hash phụ thuộc SALT trong jvhd.config.js -> phải khớp mã gốc/server của bạn.
 */
"use strict";
const path = require("path");
const config = require(path.join(__dirname, "..", "jvhd.config.js"));
const bridge = require(path.join(__dirname, "..", "src", "crypto-bridge.js"));

function main() {
  const cmd = process.argv[2];
  const arg = process.argv[3];

  if (cmd === "hash") {
    if (!arg) { console.error("Thiếu username. Dùng: node tools/tool.js hash <username>"); process.exit(1); }
    const name = String(arg).trim().toLowerCase();
    console.log("SALT    :", JSON.stringify((config.auth || config).salt));
    console.log("concat  :", (config.auth || config).concat);
    console.log("username:", name);
    console.log("HASH    :", bridge.c0(name, config));
    return;
  }

  if (cmd === "saltcheck") {
    const a = config.auth || config;
    console.log("auth.server       :", a.server);
    console.log("auth.salt         :", JSON.stringify(a.salt));
    if (!a.salt || /THAY_BANG|<\/|>/i.test(String(a.salt))) {
      console.warn("\n[!] SALT đang là giá trị giữ chỗ. Hãy đặt SALT thật trước khi dùng.\n");
    } else {
      console.log("SALT đã được đặt (không phải placeholder).\n");
    }
    return;
  }

  if (cmd === "selfcheck") {
    const os = require("os");
    const fs = require("fs");
    const crypto = require("crypto");
    const a = config.auth || config;
    const tmp = path.join(os.tmpdir(), "jvhd_selfcheck_" + Date.now() + ".json");
    const { key } = bridge.ensureDeviceKey({ filePath: tmp });
    const pub = bridge.d0(key, config);
    // server nhận d0() dạng raw 65 byte (0x04||X||Y) base64 (khớp BtK.pk()).
    // Trong kiểm thử tự nội bộ, ta dựng lại khóa công khai để verify chữ ký.
    const enc = String(a.challengeEncoding || "utf8").toLowerCase();
    const challengeB64 = Buffer.from("selfcheck-challenge").toString("base64");
    const data = challengeB64; // nội dung truyền vào e0 (giống server gửi)
    const sig = bridge.e0(key, data, config);
    const pubBuf = Buffer.from(pub, "base64");
    const pkey = crypto.createPublicKey({
      key: { kty: "EC", crv: "P-256",
             x: pubBuf.slice(1, 33).toString("base64"),
             y: pubBuf.slice(33, 65).toString("base64") },
      format: "jwk"
    });
    const v = crypto.createVerify("sha256");
    v.update(enc === "base64" ? Buffer.from(challengeB64, "base64")
            : enc === "hex" ? Buffer.from(challengeB64, "hex")
            : Buffer.from(challengeB64, "utf8"));
    v.end();
    const good = v.verify(pkey, Buffer.from(sig, "base64"), "der");
    fs.rmSync(tmp, { force: true });
    console.log("pubKeyFormat:", (config.auth || config).pubKeyFormat);
    console.log("sigFormat   :", (config.auth || config).sigFormat);
    console.log("d0() mẫu    :", pub.slice(0, 40) + "...");
    console.log("sign/verify :", good ? "OK (tự kiểm tra đúng)" : "SAI — kiểm tra cấu hình");
    process.exit(good ? 0 : 1);
    return;
  }

  console.log(
    "Cách dùng:\n" +
    "  node tools/tool.js hash <username>\n" +
    "  node tools/tool.js saltcheck\n" +
    "  node tools/tool.js selfcheck"
  );
}

main();
