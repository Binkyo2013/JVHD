/*
 * Kiểm thử ĐƯỜNG XÁC THỰC CỦA BẢN iOS chạy bằng node thuần.
 *
 * Điểm mấu chốt: file này NẠP THẬT `www/ios-bridge.js` (sau khi thay các
 * placeholder __JVHD_*__ y hệt LocalServer.swift:substituteRuntimePlaceholders)
 * rồi chạy đúng chuỗi lệnh XHR mà `www/app.js:jvhdUserAuthRequest()` phát ra.
 * Không có logic xác thực nào được viết lại ở đây — mọi thứ được kiểm tra đều
 * là mã thật đang đóng gói vào IPA.
 *
 * Môi trường WKWebView + local server Swift được mô phỏng bằng:
 *   - stub XMLHttpRequest (đồng bộ & bất đồng bộ, như WebKit)
 *   - handleLocal(): sao chép bảng định tuyến của LocalServer.swift:route()
 *     và hành vi của MediaProxy.swift:handle() (ép GET, bỏ body, UA iPhone)
 *   - fakeUpstreamAuth(): máy chủ xác thực onrender, ghi lại request nhận được
 *
 * Chạy:  node test/ios_auth_test.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const vm = require("vm");

const config = require("../jvhd.config.js");
// Bản Node/Windows — dùng làm CHUẨN đối chiếu (không viết lại công thức ở đây).
const nodeBridge = require("../src/crypto-bridge.js");

let pass = 0, fail = 0;
const failures = [];
function ok(cond, name) {
  if (cond) { pass++; console.log("  PASS  " + name); }
  else { fail++; failures.push(name); console.log("  FAIL  " + name); }
}
function eq(actual, expected, name) {
  ok(actual === expected, name + "  (thực tế: " + JSON.stringify(actual) + " · mong đợi: " + JSON.stringify(expected) + ")");
}

/* ====================================================================== *
 * 1. Máy chủ xác thực GIẢ (https://jvhd-auth.onrender.com)
 *    Ghi lại đúng những gì nó nhận được để soi method/body/header.
 * ====================================================================== */
const AUTH_ORIGIN = "https://jvhd-auth.onrender.com";
const upstreamLog = [];

function fakeUpstreamAuth(req) {
  // req = { method, url, headers, body }
  const u = new URL(req.url);
  upstreamLog.push({
    method: req.method,
    path: u.pathname,
    contentType: req.headers["content-type"] || "",
    body: req.body
  });

  if (u.pathname === "/health") {
    return { status: 200, body: "ok", contentType: "text/plain" };
  }

  let payload = null;
  try { payload = JSON.parse(req.body || ""); } catch (e) { payload = null; }

  // Máy chủ thật đòi POST + JSON {h:...}; thiếu là từ chối.
  if (req.method !== "POST" || !payload || typeof payload.h !== "string") {
    return { status: 400, body: JSON.stringify({ status: "error", message: "bad request" }), contentType: "application/json" };
  }

  if (u.pathname === "/auth/start") {
    return {
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ status: "challenge", challenge: Buffer.from("server-challenge-bytes").toString("base64") })
    };
  }
  if (u.pathname === "/auth/verify") {
    const okSig = typeof payload.sig === "string" && payload.sig.length > 0;
    return {
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ status: okSig ? "ok" : "denied" })
    };
  }
  if (u.pathname === "/auth/bind") {
    return { status: 200, contentType: "application/json", body: JSON.stringify({ status: "ok" }) };
  }
  return { status: 404, body: "{}", contentType: "application/json" };
}

/* ====================================================================== *
 * 2. Local server GIẢ — sao chép LocalServer.swift:route() + MediaProxy
 * ====================================================================== */
const BASE = "http://127.0.0.1:38755";
const PUBKEY = Buffer.from([0x04].concat(new Array(64).fill(0x41))).toString("base64");

// Các request mà proxy nội dung gửi LÊN upstream (để soi xem body có còn không).
const proxiedUpstreamLog = [];

function handleLocal(req) {
  const u = new URL(req.url, BASE);
  const pathname = u.pathname;

  if (pathname === "/__health") return { status: 200, body: "ok", contentType: "text/plain" };

  if (pathname === "/__native/c0") {
    // stand-in cho JVHDCrypto.c0() của Swift — dùng chính bản Node làm chuẩn.
    const name = String(u.searchParams.get("n") || "");
    return { status: 200, body: nodeBridge.c0(name, config), contentType: "text/plain" };
  }
  if (pathname === "/__native/d0") return { status: 200, body: PUBKEY, contentType: "text/plain" };
  if (pathname === "/__native/e0") {
    // Chữ ký giả dạng base64 (bản thật ký ECDSA trong Secure Enclave).
    const raw = Buffer.from("challenge-placeholder").toString("base64");
    return { status: 200, body: Buffer.from("sig:" + raw).toString("base64"), contentType: "text/plain" };
  }
  if (pathname === "/__native/api") {
    // stand-in cho LocalServer.swift:relayAPI() — GIỮ NGUYÊN method + body +
    // Content-Type, đúng như bản Swift gửi lên máy chủ thật.
    const pad = (s) => s + "=".repeat((4 - (s.length % 4)) % 4);
    const target = u.searchParams.get("u") || "";
    const decoded = Buffer.from(pad(target.replace(/-/g, "+").replace(/_/g, "/")), "base64").toString("utf8");
    if (!/^https?:\/\//.test(decoded)) return { status: 400, body: "bad target", contentType: "text/plain" };
    const upstream = fakeUpstreamAuth({ method: req.method, url: decoded, headers: req.headers, body: req.body });
    return { status: upstream.status, body: upstream.body, contentType: upstream.contentType };
  }
  if (pathname === "/jvhd-media" || pathname === "/jvhd-media/") {
    const encodedTarget = u.searchParams.get("u") || "";
    const pad = (s) => s + "=".repeat((4 - (s.length % 4)) % 4);
    const decoded = Buffer.from(pad(encodedTarget.replace(/-/g, "+").replace(/_/g, "/")), "base64").toString("utf8");
    if (!/^http/.test(decoded)) return { status: 400, body: "bad target", contentType: "text/plain" };

    // >>> MediaProxy.swift:95  urlRequest.httpMethod = "GET"
    // >>> và KHÔNG BAO GIỜ đọc request.body
    const forwarded = { method: "GET", url: decoded, headers: req.headers, body: "" };
    proxiedUpstreamLog.push({ method: forwarded.method, url: decoded, body: forwarded.body, originalMethod: req.method, originalBody: req.body });

    if (/^https:\/\/jvhd-auth\.onrender\.com/.test(decoded)) {
      const upstream = fakeUpstreamAuth(forwarded);
      return { status: upstream.status, body: upstream.body, contentType: upstream.contentType };
    }
    return { status: 200, body: "#EXTM3U\n#EXT-X-VERSION:3\n", contentType: "application/vnd.apple.mpegurl" };
  }
  return { status: 404, body: "Not found", contentType: "text/plain" };
}

/* ====================================================================== *
 * 3. Stub XMLHttpRequest giống WebKit (đồng bộ + bất đồng bộ)
 * ====================================================================== */
function makeXHR() {
  function dispatch(req) {
    if (req.url.indexOf(BASE) === 0 || req.url.indexOf("/") === 0) {
      return handleLocal({ method: req.method, url: req.url, headers: req.headers, body: req.body });
    }
    return fakeUpstreamAuth(req);
  }
  class FakeXHR {
    constructor() {
      this.readyState = 0; this.status = 0; this.responseText = "";
      this._headers = {}; this._method = "GET"; this._url = ""; this._async = true;
      this.onreadystatechange = null; this.onerror = null; this.timeout = 0;
      this._responseURL = "";
      // ios-bridge.js sẽ defineProperty đè lên (configurable) — giống WebKit.
      Object.defineProperty(this, "responseURL", {
        configurable: true,
        get: () => this._responseURL
      });
    }
    open(method, url, async) {
      this._method = String(method).toUpperCase();
      this._url = url;
      this._async = async !== false;
      this._headers = {};
      this.readyState = 1;
    }
    setRequestHeader(k, v) { this._headers[String(k).toLowerCase()] = v; }
    abort() { this.readyState = 4; this.status = 0; }
    send(body) {
      let res;
      try {
        res = dispatch({ method: this._method, url: this._url, headers: this._headers, body: body == null ? "" : String(body) });
      } catch (e) {
        this.status = 0; this.readyState = 4;
        if (this.onerror) this.onerror(e);
        return;
      }
      this.status = res.status;
      this.responseText = res.body;
      this._responseURL = this._url;
      this.readyState = 4;
      if (this.onreadystatechange) this.onreadystatechange();
    }
  }
  return FakeXHR;
}

/* ====================================================================== *
 * 4. Nạp THẬT www/ios-bridge.js trong môi trường WKWebView mô phỏng
 * ====================================================================== */
function loadRealBridge() {
  let source = fs.readFileSync(path.join(__dirname, "..", "www", "ios-bridge.js"), "utf8");
  // đúng thứ tự LocalServer.swift:substituteRuntimePlaceholders()
  source = source.replace(/__JVHD_BASE_URL__/g, BASE)
                 .replace(/__JVHD_PUBKEY__/g, PUBKEY)
                 .replace(/__JVHD_SALT__/g, config.auth.salt)
                 .replace(/__JVHD_CONCAT__/g, config.auth.concat);

  const listeners = [];
  const noop = () => {};
  const sandbox = {
    console: { log: noop, warn: noop, error: noop },
    setTimeout: (fn) => { try { fn(); } catch (e) {} return 0; },
    clearTimeout: noop, setInterval: noop, clearInterval: noop,
    TextEncoder: TextEncoder, TextDecoder: TextDecoder,
    URL: URL, Buffer: undefined,
    XMLHttpRequest: makeXHR(),
    document: {
      readyState: "loading",
      title: "JVHD",
      addEventListener: (t, fn) => listeners.push([t, fn]),
      querySelector: () => null,
      querySelectorAll: () => [],
      createElement: () => ({ setAttribute: noop, style: { setProperty: noop } }),
      documentElement: { style: { setProperty: noop }, classList: { add: noop } },
      body: { classList: { add: noop } }
    },
    location: { href: BASE + "/index.html", origin: BASE }
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.window.addEventListener = noop;
  sandbox.window.innerHeight = 390;
  sandbox.window.innerWidth = 844;
  sandbox.btoa = (s) => Buffer.from(s, "binary").toString("base64");
  sandbox.atob = (s) => Buffer.from(s, "base64").toString("binary");

  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "www/ios-bridge.js" });
  return sandbox;
}

/* ====================================================================== *
 * 5. Chạy đúng chuỗi lệnh của app.js:jvhdUserAuthRequest()
 *    (chép nguyên văn, chỉ thay XMLHttpRequest bằng của môi trường)
 * ====================================================================== */
function jvhdUserAuthRequest(XHR, JVHD_AUTH_API, p, payload, success, failure) {
  const xhr = new XHR();
  let finished = false;
  function done(fn, arg) { if (finished) return; finished = true; fn(arg); }
  xhr.onreadystatechange = function () {
    if (xhr.readyState !== 4) return;
    if (xhr.status < 200 || xhr.status >= 300) { done(failure, new Error("HTTP " + xhr.status)); return; }
    let data = null;
    try { data = JSON.parse(xhr.responseText); } catch (e) { done(failure, e); return; }
    done(success, data);
  };
  xhr.onerror = function () { done(failure, new Error("network")); };
  try {
    xhr.open("POST", JVHD_AUTH_API + p, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(JSON.stringify(payload));
  } catch (e) { done(failure, e); }
}

/* ====================================================================== */
function main() {
  console.log("\n[1] Nạp www/ios-bridge.js thật vào môi trường WKWebView mô phỏng");
  const bridge = loadRealBridge();
  ok(bridge.window.__JVHD_IOS__ === true, "ios-bridge.js đã chạy (window.__JVHD_IOS__ = true)");
  ok(bridge.window.AndroidBridge && typeof bridge.window.AndroidBridge.c0 === "function",
     "window.AndroidBridge được cài (c0/d0/e0)");

  console.log("\n[2] Mật mã iOS phải khớp bản Node/Android (test vector jsonbin)");
  const KNOWN = { user: "Admin2", hash: "37b5d924f34f64ed7e88033b8c31db39b314ddca0ec624ea94d5b8056467ca5b" };
  const iosHash = bridge.window.AndroidBridge.c0(KNOWN.user);
  eq(iosHash, KNOWN.hash, "c0(Admin2) của ios-bridge.js khớp HASH lưu trong jsonbin");
  eq(iosHash, nodeBridge.c0(KNOWN.user, config), "c0 khớp src/crypto-bridge.js (bản Node/Windows)");
  eq(bridge.window.AndroidBridge.c0("  AlIcE  "), nodeBridge.c0("  AlIcE  ", config),
     "c0 chuẩn hoá trim+lowercase giống nhau");
  eq(bridge.window.AndroidBridge.d0(), PUBKEY, "d0() trả khoá công khai do Swift chèn");
  ok(String(bridge.window.AndroidBridge.e0("aGVsbG8=")).length > 0, "e0() trả chữ ký khác rỗng");

  console.log("\n[3] Luồng xác thực: app.js gọi POST /auth/start");
  upstreamLog.length = 0;
  proxiedUpstreamLog.length = 0;
  const XHR = bridge.window.XMLHttpRequest;
  let result = null, error = null;
  jvhdUserAuthRequest(XHR, AUTH_ORIGIN, "/auth/start", { h: iosHash },
    (r) => { result = r; }, (e) => { error = e; });

  const hit = upstreamLog[upstreamLog.length - 1] || null;
  ok(hit !== null, "máy chủ xác thực NHẬN ĐƯỢC request");
  if (hit) {
    eq(hit.method, "POST", "máy chủ nhận POST (không bị proxy ép thành GET)");
    let parsed = null;
    try { parsed = JSON.parse(hit.body); } catch (e) { parsed = null; }
    ok(parsed !== null, "body JSON tới được máy chủ (proxy không nuốt mất body)");
    eq(parsed && parsed.h, iosHash, "trường 'h' (hash username) nguyên vẹn");
  }
  ok(error === null, "app.js KHÔNG rơi vào jvhdUserAuthNetworkError (lỗi: " + (error && error.message) + ")");
  eq(result && result.status, "challenge", "server trả {status:'challenge'} -> app.js ký tiếp được");
  if (hit) {
    ok(/application\/json/i.test(hit.contentType), "Content-Type: application/json tới được máy chủ");
  }

  console.log("\n[3b] Bước 2 của luồng: ký challenge (e0) rồi POST /auth/verify");
  upstreamLog.length = 0;
  let verifyResult = null, verifyError = null;
  const signature = bridge.window.AndroidBridge.e0(result && result.challenge);
  ok(String(signature).length > 0, "e0(challenge) trả chữ ký để gửi lên server");
  jvhdUserAuthRequest(XHR, AUTH_ORIGIN, "/auth/verify", { h: iosHash, sig: signature },
    (r) => { verifyResult = r; }, (e) => { verifyError = e; });
  const verifyHit = upstreamLog[upstreamLog.length - 1] || null;
  eq(verifyHit && verifyHit.method, "POST", "/auth/verify cũng tới server bằng POST");
  ok(verifyError === null, "/auth/verify không lỗi mạng (lỗi: " + (verifyError && verifyError.message) + ")");
  eq(verifyResult && verifyResult.status, "ok", "server xác nhận chữ ký -> ĐĂNG NHẬP THÀNH CÔNG");

  console.log("\n[3c] Nhánh bind (tài khoản chưa gắn thiết bị)");
  upstreamLog.length = 0;
  let bindResult = null, bindError = null;
  jvhdUserAuthRequest(XHR, AUTH_ORIGIN, "/auth/bind",
    { h: iosHash, k: PUBKEY, nonce: "bm9uY2U=", sig: signature },
    (r) => { bindResult = r; }, (e) => { bindError = e; });
  ok(bindError === null, "/auth/bind không lỗi mạng (lỗi: " + (bindError && bindError.message) + ")");
  eq(bindResult && bindResult.status, "ok", "/auth/bind trả ok");

  console.log("\n[4] Regression: proxy nội dung vẫn hoạt động cho GET chéo nguồn");
  proxiedUpstreamLog.length = 0;
  const mediaXhr = new XHR();
  mediaXhr.open("GET", "https://cdn.example.com/live/master.m3u8", true);
  mediaXhr.send(null);
  ok(proxiedUpstreamLog.length === 1 && proxiedUpstreamLog[0].method === "GET",
     "GET chéo nguồn vẫn đi qua /jvhd-media/ như cũ");
  ok(/^#EXTM3U/.test(mediaXhr.responseText), "proxy trả playlist về cho hls.js");
  eq(bridge.window.AndroidBridge.proxyMedia("https://x.test/a.mp4", ""),
     BASE + "/jvhd-media/?u=" + encodeURIComponent(Buffer.from("https://x.test/a.mp4").toString("base64"))
       + "&r=" + encodeURIComponent(Buffer.from("https://x.test/a.mp4").toString("base64")),
     "proxyMedia() vẫn bọc URL đúng định dạng");

  console.log("\n[5] Regression: request cùng nguồn không bị bẻ");
  proxiedUpstreamLog.length = 0;
  const localXhr = new XHR();
  localXhr.open("GET", BASE + "/__health", true);
  localXhr.send(null);
  eq(localXhr.responseText, "ok", "GET /__health cùng nguồn trả 'ok'");
  eq(proxiedUpstreamLog.length, 0, "request cùng nguồn KHÔNG đi qua proxy");

  console.log("\n==============================================");
  console.log("  PASS: " + pass + "   FAIL: " + fail);
  if (fail > 0) {
    console.log("\n  Các kiểm thử THẤT BẠI:");
    failures.forEach((f) => console.log("   - " + f));
    console.log("\n  Nếu request tới máy chủ là GET với body rỗng thì đúng là");
    console.log("  iOS đang bẻ POST /auth/* qua proxy nội dung (MediaProxy ép GET).");
  }
  console.log("==============================================\n");
  process.exit(fail > 0 ? 1 : 0);
}

main();
