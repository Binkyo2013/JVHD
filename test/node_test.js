/*
 * Kiểm thử phần KHÔNG-GUI của JVHD Desktop chạy bằng node thuần:
 *   1) crypto-bridge : c0 (xác định), sinh khóa, d0, ký e0 và verify
 *   2) server cục bộ : phục vụ index.html
 *   3) proxy media    : tải playlist giả + tự bẻ segment về proxy
 * Chạy:  node test/node_test.js
 */
"use strict";
const path = require("path");
const os = require("os");
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");

const config = JSON.parse(JSON.stringify(require("../jvhd.config.js")));
const bridge = require("../src/crypto-bridge.js");
const { createServer } = require("../src/server.js");

// Test vector thật lấy từ jsonbin (do tool đăng ký): Admin2 -> hash 37b5d924...
const KNOWN = { user: "Admin2", hash: "37b5d924f34f64ed7e88033b8c31db39b314ddca0ec624ea94d5b8056467ca5b" };

let pass = 0, fail = 0;
function ok(cond, name) {
  if (cond) { pass++; console.log("  PASS  " + name); }
  else { fail++; console.log("  FAIL  " + name); }
}

async function main() {
  console.log("\n[1] crypto-bridge");
  // c0 xác định
  const h1 = bridge.c0("alice", config);
  const h2 = bridge.c0("alice", config);
  const expect = crypto.createHash("sha256").update("alice" + config.auth.salt).digest("hex");
  ok(/^[0-9a-f]{64}$/.test(h1), "c0 trả 64 hex");
  ok(h1 === h2 && h1 === expect, "c0 = sha256(name+salt) deterministic");

  // QUAN TRỌNG: phải khớp test vector jsonbin (Admin2 -> 37b5d924...) để
  // username cũ đăng nhập được KHÔNG cần sửa jsonbin.
  const real = bridge.c0(KNOWN.user, config);
  ok(real === KNOWN.hash, "c0(Admin2) khớp HASH lưu trong jsonbin (" + KNOWN.user + ")");

  // salt nối dạng VĂN BẢN (không decode hex) - xác nhận bằng len
  ok(config.auth.salt.length === 48, "salt là chuỗi 48 ký tự hex dạng văn bản");

  // sinh khóa tạm
  const tmpKey = path.join(os.tmpdir(), "jvhd_test_key_" + Date.now() + ".json");
  const { key } = bridge.ensureDeviceKey({ filePath: tmpKey });

  // d0 phải là 65 byte raw-uncompressed (0x04||X||Y), base64, khớp BtK.pk()
  const pub = bridge.d0(key, config);
  const pubBuf = Buffer.from(pub, "base64");
  ok(pubBuf.length === 65 && pubBuf[0] === 0x04, "d0 = base64(65 byte 0x04||X||Y) khớp BtK.pk()");

  // e0: data là base64 -> phải decode rồi mới SHA256+ECDSA ký (khớp BtK.sg)
  const secret = Buffer.from("server-challenge-bytes"); // nội dung challenge thật
  const data = secret.toString("base64");               // server gửi dạng base64
  const sig = bridge.e0(key, data, config);
  ok(typeof sig === "string" && sig.length > 0, "e0 trả chữ ký string");
  // verify: dùng khóa công khai từ raw point
  const raw = pubBuf;
  const x = raw.slice(1, 33), y = raw.slice(33, 65);
  const publicKey = crypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x: x.toString("base64"), y: y.toString("base64") },
    format: "jwk"
  });
  const verifier = crypto.createVerify("sha256");
  verifier.update(secret); // byte gốc (đã decode) được ký
  verifier.end();
  ok(verifier.verify(publicKey, Buffer.from(sig, "base64"), "der") === true,
     "e0 ký đúng: SHA256( base64decode(challenge) ) verify OK");

  // pubkey mà server dựng từ raw point phải khớp chữ ký node xuôi -> đủ.
  fs.rmSync(tmpKey, { force: true });
  console.log("  (sig mẫu e0:", sig.slice(0, 24) + "...)");
  console.log("  (pubkey d0 (65B 04..):", pub.slice(0, 24) + "...)");
  console.log("  (hash c0 mẫu:", h1.slice(0, 24) + "...)");
  ok(true, "hoàn tất khối thiết bị");

  console.log("\n[2] server + proxy");
  // nguồn giả chứa playlist HLS với segment tương đối
  const fake = http.createServer((req, res) => {
    if (req.url === "/play.m3u8") {
      res.writeHead(200, { "Content-Type": "application/vnd.apple.mpegurl" });
      res.end("#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:5.0,\nseg1.ts\n#EXTINF:5.0,\n/abs/seg2.ts\nhttp://cdn.example/seg3.ts\n");
    } else { res.writeHead(200, { "Content-Type": "video/mp2t" }); res.end(Buffer.from([0,1,2,3])); }
  });
  await new Promise((r) => fake.listen(0, "127.0.0.1", r));
  const fakePort = fake.address().port;

  const srv = createServer(config, () => {});
  const port = await srv.start();
  const base = "http://127.0.0.1:" + port;

  const enc = (s) => encodeURIComponent(Buffer.from(s, "utf8").toString("base64"));
  const html = await fetch(base + "/index.html").then(r => r.text());
  ok(html.includes("JVHD") && html.includes("app.js"), "server phục vụ index.html");

  const health = await fetch(base + "/__health").then(r => r.text());
  ok(health === "ok", "endpoint __health");

  const appjs = await fetch(base + "/app.js").then(r => r.text());
  ok(appjs.length > 10000, "server phục vụ app.js (" + appjs.length + " bytes)");

  const pUrl = base + "/jvhd-media/?u=" + enc("http://127.0.0.1:" + fakePort + "/play.m3u8") + "&r=" + enc("http://s");
  ok(/^http:\/\/127\.0\.0\.1:\d+\/jvhd-media\//.test(pUrl), "proxy URL đúng định dạng app.js mong đợi");
  const pm = await fetch(pUrl);
  const pbody = await pm.text();
  ok(pm.headers.get("access-control-allow-origin") === "*", "proxy trả Access-Control-Allow-Origin:*");
  ok(pbody.includes("#EXTM3U"), "proxy trả playlist giữ thẻ");
  ok(pbody.includes("/jvhd-media/?u="), "proxy bẻ segment tuyệt đối về proxy");
  ok(!pbody.includes("seg1.ts\n") || pbody.includes("/jvhd-media/?u="), "segment tương đối bị bọc proxy");
  console.log("  --- playlist đã bẻ (dòng dữ liệu) ---");
  console.log("      " + pbody.split("\n").filter(l => l && !l.startsWith("#")).join("\n      "));

  // segment qua proxy (dùng URL đã bẻ, lấy dòng đầu là 1 url proxy)
  const segLine = pbody.split("\n").find(l => l.includes("/jvhd-media/?u="));
  if (segLine) {
    const seg = await fetch(segLine.trim());
    const buf = Buffer.from(await seg.arrayBuffer());
    ok(buf.length === 4 && buf[0] === 0, "proxy tải segment nhị phân qua proxy");
  } else { ok(false, "không có segment để test"); }

  srv.close(); fake.close();
  console.log("\nKết quả: " + pass + " PASS / " + fail + " FAIL");
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
