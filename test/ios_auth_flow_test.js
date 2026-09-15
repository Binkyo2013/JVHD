/*
 * test/ios_auth_flow_test.js
 * ============================================================================
 * Kiểm TOÀN BỘ luồng xác thực của bản iOS — bao gồm nhánh "thiết bị mới"
 * (bind) — bằng mã THẬT:
 *
 *   · www/ios-bridge.js      : nạp thật (sau khi thay placeholder như Swift)
 *   · quy tắc máy chủ        : CHÉP NGUYÊN VĂN từ hkrmta-code/jvhd-auth
 *                              commit d61e85787 (2026-08-30) — CRYPTO_HASH_RE,
 *                              pubFromRaw(), verifySig(), newNonce(), takeNonce(),
 *                              handleStart/Bind/Verify. Server chỉ để ĐỐI CHIẾU,
 *                              không bị sửa bởi test này.
 *   · tầng native iOS        : mô phỏng ĐÚNG hai chế độ của DeviceKey.swift —
 *                              "legacy" (trước bản sửa: SecKeyCreateSignature trả
 *                              ANSI X9.62, signChallenge fail khi chuỗi rỗng) và
 *                              "fixed" (derEncodeRS + decodeBase64NodeCompatible).
 *   · bước đi của app.js     : trình tự submitJvhdUserGate() chép nguyên văn,
 *                              kèm kiểm tra NGUYÊN VĂN để phát hiện lệch (xem
 *                              guardAppFlowUnchanged()).
 *
 * Mục tiêu chứng minh:
 *   1) Thiết bị iOS MỚI đăng nhập được (bind -> ok) với cùng logic Android.
 *   2) Bản cũ thất bại ĐÚNG vì định dạng chữ ký X9.62 != DER.
 *   3) Bản cũ thất bại ĐÚNG vì e0("") -> "" -> "Thiết bị không hỗ trợ xác thực".
 *   4) Không có bất kỳ ghi nào xuống JSONBin (chỉ đọc cấu hình như trước).
 *   5) Ràng buộc Android/Windows không đổi (câu lỗi không đổi khi không phải iOS).
 *
 * Chạy:  node test/ios_auth_flow_test.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const vm = require("vm");

const config = require("../jvhd.config.js");
const nodeBridge = require("../src/crypto-bridge.js"); // bản Node/Windows = chuẩn Android

let pass = 0, fail = 0;
const failures = [];
function ok(cond, name) {
  if (cond) { pass++; console.log("  PASS  " + name); }
  else { fail++; failures.push(name); console.log("  FAIL  " + name); }
}
function eq(actual, expected, name) {
  ok(actual === expected, name + "  (thực tế: " + JSON.stringify(actual) + " · mong đợi: " + JSON.stringify(expected) + ")");
}

const AUTH_ORIGIN = "https://jvhd-auth.onrender.com";
const BASE = "http://127.0.0.1:38755";
const JSONBIN_ORIGIN = "https://api.jsonbin.io";

/* ====================================================================== *
 * A. Chuẩn DER — hàm đã được test/gen_der_fixtures.js chứng nhận bằng
 *    crypto.createVerify của chính OpenSSL/server.
 * ====================================================================== */
function derInteger(bytes) {
  let v = bytes.slice();
  while (v.length > 1 && v[0] === 0x00) v = v.slice(1);
  if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0x00]), v]);
  return Buffer.concat([Buffer.from([0x02, v.length]), v]);
}
function derEncodeRS(raw) { // mô phỏng JVHDCrypto.derEncodeRS()
  if (raw.length < 8 || raw.length % 2 !== 0) return null;
  const half = raw.length / 2;
  const body = Buffer.concat([derInteger(raw.slice(0, half)), derInteger(raw.slice(half))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
function rawFromDer(der) { // chiều ngược lại (mô phỏng JVHDCrypto.derDecodeRS)
  const rLen = der[3];
  const r = der.slice(4, 4 + rLen);
  const p = 4 + rLen;
  const sLen = der[p + 1];
  const s = der.slice(p + 2, p + 2 + sLen);
  const pad = (b) => {
    let v = b;
    while (v.length > 1 && v[0] === 0x00) v = v.slice(1); // bỏ 0 đệm dấu
    return Buffer.concat([Buffer.alloc(32 - v.length), v]);
  };
  return Buffer.concat([pad(r), pad(s)]);
}

/* ====================================================================== *
 * B. Thiết bị giả lập: một khoá P-256 duy nhất cho cả phiên (như Secure
 *    Enclave: tạo一次, dùng mãi).
 * ====================================================================== */
const device = (() => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey,
    // pubKeyFormat "raw-uncompressed-b64" = 0x04||X||Y (65 byte)
    pub: spki.slice(spki.length - 65).toString("base64")
  };
})();

/** e0() theo DeviceKey.swift — mode "fixed": SecKey X9.62 -> derEncodeRS -> DER.
 *  mode "legacy": trả nguyên X9.62 (r||s) như bản trước khi có derEncodeRS. */
function iosSignRaw(messageBytes, mode, keyPair) {
  const pair = keyPair || device;
  const raw = crypto.sign("sha256", messageBytes, { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
  if (mode === "legacy") return raw;
  return derEncodeRS(raw);
}
/** Android/Windows: crypto.sign('sha256', payload, key) -> DER. */
function androidSign(messageBytes) {
  return Buffer.from(nodeBridge.e0(device.privateKey, Buffer.from(messageBytes).toString("base64"),
    { auth: Object.assign({}, config.auth, { challengeEncoding: "base64" }) }), "base64");
}

/* ====================================================================== *
 * C. Máy chủ xác thực GIẢ — quy tắc chép nguyên văn từ jvhd-auth d61e85787
 * ====================================================================== */
const CRYPTO_HASH_RE = /^[0-9a-f]{64}$/;
const SPKI_P256 = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
const CHALLENGE_TTL_MS = 120000;

function pubFromRaw(kB64) {
  try {
    const raw = Buffer.from(String(kB64), "base64");
    if (raw.length !== 65 || raw[0] !== 4) return null;
    return crypto.createPublicKey({ key: Buffer.concat([SPKI_P256, raw]), format: "der", type: "spki" });
  } catch (e) { return null; }
}
function verifySig(keyObj, dataBuf, sigB64) {
  try {
    return crypto.createVerify("SHA256").update(dataBuf).verify(keyObj, Buffer.from(String(sigB64), "base64"));
  } catch (e) { return false; }
}

const allowlist = new Set();
const KNOWN = { user: "Admin2", hash: nodeBridge.c0("Admin2", config) };
allowlist.add(KNOWN.hash);

const server = {
  bindings: {},          // { [hash]: { k: '<b64 65B>', at: ms } } — cùng cấu trúc JSONBin
  pending: {},
  writes: 0,
  newNonce(h, kind) {
    const value = crypto.randomBytes(32).toString("base64");
    this.pending[h] = { v: value, kind, exp: Date.now() + CHALLENGE_TTL_MS };
    return value;
  },
  takeNonce(h, kind, value) {
    const item = this.pending[h];
    delete this.pending[h];
    if (!item || item.kind !== kind || item.v !== value || Date.now() > item.exp) return null;
    return item.v;
  },
  start(body) {
    const h = body.h;
    if (typeof h !== "string" || !CRYPTO_HASH_RE.test(h)) return { status: 400, json: { status: "bad" } };
    if (!allowlist.has(h)) return { status: 200, json: { status: "unknown" } };
    if (this.bindings[h]) return { status: 200, json: { status: "challenge", challenge: this.newNonce(h, "verify") } };
    return { status: 200, json: { status: "bind", nonce: this.newNonce(h, "bind") } };
  },
  bind(body) {
    const { h, k } = body;
    if (typeof h !== "string" || !CRYPTO_HASH_RE.test(h) || typeof k !== "string") return { status: 400, json: { status: "bad" } };
    const nonce = this.takeNonce(h, "bind", body.nonce);
    if (!nonce) return { status: 200, json: { status: "bad" } };
    const keyObj = pubFromRaw(k);
    if (!keyObj) return { status: 200, json: { status: "bad" } };
    if (!verifySig(keyObj, Buffer.from(nonce, "base64"), body.sig)) return { status: 200, json: { status: "bad" } };
    if (this.bindings[h]) return { status: 200, json: { status: "denied" } };
    this.bindings[h] = { k, at: Date.now() };
    this.writes++;
    return { status: 200, json: { status: "ok" } };
  },
  verify(body) {
    const h = body.h;
    if (typeof h !== "string" || !CRYPTO_HASH_RE.test(h)) return { status: 400, json: { status: "bad" } };
    const item = this.pending[h];
    const challenge = this.takeNonce(h, "verify", item ? item.v : undefined);
    const bound = this.bindings[h];
    if (!challenge || !bound) return { status: 200, json: { status: "denied" } };
    const keyObj = pubFromRaw(bound.k);
    if (!keyObj || !verifySig(keyObj, Buffer.from(challenge, "base64"), body.sig)) return { status: 200, json: { status: "denied" } };
    return { status: 200, json: { status: "ok" } };
  }
};

/* ====================================================================== *
 * D. Máy chủ cục bộ GIẢ — mô phỏng LocalServer.swift theo từng chế độ
 * ====================================================================== */
const sentToAuth = [];     // mọi request tới máy chủ xác thực (method + path + body)
const sentElsewhere = [];  // để chứng minh iOS không đụng JSONBin

/** decodeBase64NodeCompatible() — luật đã kiểm 4020 mẫu khớp Buffer.from(x,'base64'). */
function decodeBase64NodeCompatible(text) {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const table = new Int16Array(256).fill(-1);
  for (let i = 0; i < 64; i++) table[ALPHABET.charCodeAt(i)] = i;
  table["-".charCodeAt(0)] = 62; table["_".charCodeAt(0)] = 63;
  const bytes = Buffer.from(String(text), "utf8");
  const out = [];
  let bits = 0, collected = 0;
  for (const byte of bytes) {
    if (byte === 0x3d) break;
    const value = table[byte];
    if (value < 0) continue;
    bits = (bits << 6) | value; collected += 6;
    if (collected === 24) { out.push((bits >> 16) & 255, (bits >> 8) & 255, bits & 255); bits = 0; collected = 0; }
  }
  if (collected === 12) out.push((bits >> 4) & 255);
  else if (collected === 18) { out.push((bits >> 10) & 255, (bits >> 2) & 255); }
  return Buffer.from(out);
}
/** decodeBase64Loose() bản cũ: nil khi rỗng / có ký tự ngoài bảng. */
function decodeBase64LooseLegacy(text) {
  let cleaned = String(text).trim().replace(/-/g, "+").replace(/_/g, "/");
  const remainder = cleaned.length % 4;
  if (remainder) cleaned += "=".repeat(4 - remainder);
  if (!/^[A-Za-z0-9+/=]*$/.test(cleaned)) return null;
  const data = Buffer.from(cleaned, "base64");
  if (data.length === 0) return null;
  return data;
}

function makeLocalHandler(options) {
  const mode = options.signMode;           // "fixed" | "legacy"
  const keyAvailable = options.keyAvailable !== false;
  return function handleLocal(req) {
    const u = new URL(req.url, BASE);
    const p = u.pathname;
    if (p === "/__health") return { status: 200, body: "ok" };
    if (p === "/__native/c0") {
      return { status: 200, body: nodeBridge.c0(String(u.searchParams.get("n") || ""), config) };
    }
    if (p === "/__native/d0") {
      // Giống hỡi LocalServer.swift:keyFailureBody() — 500 + "ERR: <tóm tắt>"
      if (!keyAvailable) {
        return { status: 500, body: "ERR: backend=none · keychain=OSStatus -34018 · d0=SecKeyCreateRandomKey lỗi: errSecMissingEntitlement#-34018" };
      }
      return { status: 200, body: (options.keyPair || device).pub };
    }
    if (p === "/__native/e0") {
      if (!keyAvailable) return { status: 500, body: "ERR: backend=none · e0=không có khoá thiết bị" };
      const payload = String(req.body || "");
      // OLD: decodeBase64Loose -> guard let else return "" -> 500 -> bridge trả ""
      // NEW: decodeBase64NodeCompatible -> luôn ký (kể cả dữ liệu rỗng), như Node
      const message = mode === "legacy" ? decodeBase64LooseLegacy(payload) : decodeBase64NodeCompatible(payload);
      if (!message) return { status: 500, body: "" };
      const signature = iosSignRaw(message, mode, options.keyPair);
      if (!signature) return { status: 500, body: "ERR: chuyển X9.62 -> DER thất bại" };
      return { status: 200, body: signature.toString("base64") };
    }
    if (p === "/__native/api") {
      const target = decodeBase64LooseLegacy(u.searchParams.get("u")) || Buffer.from(String(u.searchParams.get("u") || ""), "base64");
      const urlText = target.toString("utf8");
      const upstream = new URL(urlText);
      const record = { method: req.method, path: upstream.pathname, contentType: req.headers["content-type"] || "", body: req.body };
      if (upstream.origin === AUTH_ORIGIN) sentToAuth.push(record);
      else sentElsewhere.push(record);
      if (upstream.pathname === "/health") return { status: 200, body: "ok" };
      let payload = null;
      try { payload = JSON.parse(req.body || ""); } catch (e) { payload = null; }
      if (req.method !== "POST" || !payload || typeof payload.h !== "string") {
        return { status: 400, body: JSON.stringify({ status: "bad" }) };
      }
      const result = upstream.pathname === "/auth/start" ? server.start(payload)
        : upstream.pathname === "/auth/bind" ? server.bind(payload)
        : upstream.pathname === "/auth/verify" ? server.verify(payload)
        : { status: 404, json: { error: "not found" } };
      return { status: result.status, body: JSON.stringify(result.json) };
    }
    return { status: 404, body: "Not found" };
  };
}

/* ====================================================================== *
 * E. Nạp www/ios-bridge.js THẬT với native server mô phỏng ở trên
 * ====================================================================== */
function loadBridge(options) {
  const handleLocal = makeLocalHandler(options);
  let source = fs.readFileSync(path.join(__dirname, "..", "www", "ios-bridge.js"), "utf8");
  source = source.replace(/__JVHD_BASE_URL__/g, BASE)
                 .replace(/__JVHD_PUBKEY__/g, options.injectPubkey === false ? "" : (options.keyPair || device).pub)
                 .replace(/__JVHD_SALT__/g, config.auth.salt)
                 .replace(/__JVHD_CONCAT__/g, config.auth.concat);

  class FakeXHR {
    constructor() {
      this.readyState = 0; this.status = 0; this.responseText = "";
      this._headers = {}; this._method = "GET"; this._url = "";
      this._responseURL = "";
      Object.defineProperty(this, "responseURL", { configurable: true, get: () => this._responseURL });
    }
    open(method, url) { this._method = String(method).toUpperCase(); this._url = url; this._headers = {}; this.readyState = 1; }
    setRequestHeader(k, v) { this._headers[String(k).toLowerCase()] = v; }
    abort() { this.readyState = 4; this.status = 0; }
    send(body) {
      const raw = String(body == null ? "" : body);
      const self = this;
      const respond = (res) => {
        self.status = res.status; self.responseText = res.body;
        self._responseURL = self._url; self.readyState = 4;
        if (self.onreadystatechange) self.onreadystatechange();
      };
      if (self._url.indexOf(BASE) === 0) { respond(handleLocal({ method: self._method, url: self._url, headers: self._headers, body: raw })); return; }
      // Cross-origin (máy chủ xác thực): app.js luôn bị ios-bridge bẻ sang /__native/api.
      const u = new URL(self._url);
      if (u.origin === AUTH_ORIGIN) {
        const result = self._method === "GET" && u.pathname === "/health"
          ? { status: 200, body: "ok" }
          : (() => {
              let payload = null;
              try { payload = JSON.parse(raw); } catch (e) { payload = null; }
              const rec = { method: self._method, path: u.pathname, contentType: self._headers["content-type"] || "", body: raw };
              sentToAuth.push(rec);
              if (!payload || typeof payload.h !== "string") return { status: 400, body: JSON.stringify({ status: "bad" }) };
              const r = u.pathname === "/auth/start" ? server.start(payload)
                : u.pathname === "/auth/bind" ? server.bind(payload)
                : u.pathname === "/auth/verify" ? server.verify(payload)
                : { status: 404, json: { error: "not found" } };
              return { status: r.status, body: JSON.stringify(r.json) };
            })();
        respond(result); return;
      }
      sentElsewhere.push({ method: self._method, url: self._url });
      respond({ status: 403, body: "blocked in test" });
    }
  }

  const noop = () => {};
  const sandbox = {
    console: { log: noop, warn: noop, error: noop },
    setTimeout: (fn) => { try { fn(); } catch (e) {} return 0; },
    clearTimeout: noop, setInterval: noop, clearInterval: noop,
    TextEncoder, TextDecoder, URL, XMLHttpRequest: FakeXHR,
    document: {
      readyState: "loading", title: "JVHD",
      addEventListener: noop, querySelector: () => null, querySelectorAll: () => [],
      createElement: () => ({ setAttribute: noop, style: { setProperty: noop } }),
      documentElement: { style: { setProperty: noop }, classList: { add: noop } },
      body: { classList: { add: noop } }
    },
    location: { href: BASE + "/index.html", origin: BASE }
  };
  sandbox.window = sandbox; sandbox.self = sandbox; sandbox.globalThis = sandbox;
  sandbox.window.addEventListener = noop;
  sandbox.window.innerHeight = 390; sandbox.window.innerWidth = 844;
  sandbox.btoa = (s) => Buffer.from(s, "binary").toString("base64");
  sandbox.atob = (s) => Buffer.from(s, "base64").toString("binary");
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "www/ios-bridge.js" });
  return sandbox;
}

/* ====================================================================== *
 * F. Hai hàm của app.js chép nguyên văn (jvhdUserNativeHash + submit)
 * ====================================================================== */
function jvhdUserNativeHash(bridge, name) {
  try {
    if (!bridge || typeof bridge.c0 !== "function") return null;
    var digest = bridge.c0(String(name));
    if (typeof digest !== "string") return null;
    return /^[0-9a-f]{64}$/.test(digest) ? digest : null;
  } catch (e) { return null; }
}
function jvhdUserAuthRequest(XHR, apiBase, p, payload, success, failure) {
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
    xhr.open("POST", apiBase + p, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(JSON.stringify(payload));
  } catch (e) { done(failure, e); }
}

/** submitJvhdUserGate() — chỉ phần quyết định, giữ nguyên nhánh rẽ của app.js. */
function runGate(sandbox) {
  const XHR = sandbox.XMLHttpRequest;
  const bridge = sandbox.window.AndroidBridge;
  const result = { outcome: null, detail: "" };
  const digest = jvhdUserNativeHash(bridge, "  ADMIN2  ");
  if (!digest) { result.outcome = "hard"; result.detail = "thiếu c0()"; return result; }
  if (!bridge || typeof bridge.d0 !== "function" || typeof bridge.e0 !== "function") {
    result.outcome = "hard"; result.detail = "thiếu AndroidBridge"; return result;
  }
  jvhdUserAuthRequest(XHR, AUTH_ORIGIN, "/auth/start", { h: digest }, (r) => {
    if (r && r.status === "bind") {
      const devicePub = bridge.d0();
      const bindSig = devicePub ? bridge.e0(r.nonce) : "";
      if (!devicePub || !bindSig) { result.outcome = "hard"; result.detail = "d0()/e0() rỗng"; return; }
      jvhdUserAuthRequest(XHR, AUTH_ORIGIN, "/auth/bind", { h: digest, k: devicePub, nonce: r.nonce, sig: bindSig }, (b) => {
        if (b && b.status === "ok") { result.outcome = "ok"; result.digest = digest; return; }
        if (b && b.status === "denied") { result.outcome = "fail"; result.detail = "Tài khoản đã được gắn với thiết bị khác"; return; }
        result.outcome = "soft"; result.detail = "Phiên xác thực hết hạn, vui lòng thử lại";
      }, () => { result.outcome = "net"; result.detail = "Không kết nối được máy chủ xác thực, thử lại"; });
    } else if (r && r.status === "challenge") {
      const sig = bridge.e0(r.challenge);
      if (!sig) { result.outcome = "hard"; result.detail = "e0() rỗng"; return; }
      jvhdUserAuthRequest(XHR, AUTH_ORIGIN, "/auth/verify", { h: digest, sig: sig }, (v) => {
        if (v && v.status === "ok") { result.outcome = "ok"; result.digest = digest; return; }
        if (v && v.status === "denied") { result.outcome = "fail"; result.detail = "Thiết bị không khớp thiết bị đã đăng ký"; return; }
        result.outcome = "soft"; result.detail = "Phiên xác thực hết hạn, vui lòng thử lại";
      }, () => { result.outcome = "net"; result.detail = "Không kết nối được máy chủ xác thực, thử lại"; });
    } else {
      result.outcome = "fail"; result.detail = "Tên người dùng không đúng";
    }
  }, () => { result.outcome = "net"; result.detail = "Không kết nối được máy chủ xác thực, thử lại"; });
  return result;
}

/** app.js có đổi bước đi không? Nếu đổi thì bài kiểm này phải báo ngay. */
function guardAppFlowUnchanged() {
  const app = fs.readFileSync(path.join(__dirname, "..", "www", "app.js"), "utf8");
  const must = [
    'var devicePub = bridge.d0();',
    'var bindSig = devicePub ? bridge.e0(r.nonce) : "";',
    'if (!devicePub || !bindSig) { jvhdUserAuthHardError(); return; }',
    '"/auth/bind", { h: digest, k: devicePub, nonce: r.nonce, sig: bindSig }',
    'var sig = bridge.e0(r.challenge);',
    'if (!jvhdUserIOSDiag) return "";' // không có -> xem bước dưới
  ];
  const missing = must.filter((snippet) => snippet !== 'if (!jvhdUserIOSDiag) return "";' && app.indexOf(snippet) === -1);
  ok(missing.length === 0, "trình tự bind/verify trong app.js khớp bản chép ở test" + (missing.length ? " — thiếu: " + missing.join(" | ") : ""));
  // Bản sửa iOS-only: helper chẩn đoán PHẢI chặn sớm khi không phải iOS,
  // nhờ đó Android/Windows giữ nguyên 100% câu chữ.
  const diagGuard = /function jvhdUserIOSDiag\(\)\s*\{[\s\S]{0,200}?if \(!window\.__JVHD_IOS__\) return "";/;
  ok(diagGuard.test(app), "chẩn đoán iOS bị khoá sau cờ __JVHD_IOS__ (Android không đổi câu lỗi)");
  const hardSites = (app.match(/Thiết bị không hỗ trợ xác thực, không thể tiếp tục"\s*\+\s*jvhdUserIOSDiag\(\)/g) || []).length;
  ok(hardSites === 3, "cả 3 chỗ báo lỗi thiết bị đều nối chẩn đoán (thực tế: " + hardSites + ")");
}

/* ====================================================================== *
 * Các kịch bản
 * ====================================================================== */
function reset() {
  server.bindings = {};
  server.pending = {};
  server.writes = 0;
  sentToAuth.length = 0;
  sentElsewhere.length = 0;
}

console.log("\n[0] Tự kiểm bộ đóng gói DER dùng trong file này");
{
  const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname, "der_fixtures.json"), "utf8"));
  let bad = 0;
  for (const item of fixtures.signatures) {
    const encoded = derEncodeRS(Buffer.from(item.raw, "hex"));
    if (!encoded || encoded.toString("hex") !== item.der) bad++;
    if (rawFromDer(Buffer.from(item.der, "hex")).toString("hex") !== item.raw) bad++;
  }
  ok(bad === 0, "derEncodeRS mô phỏng khớp " + fixtures.signatures.length + " mẫu DER chuẩn OpenSSL");
  let badB64 = 0;
  for (const item of fixtures.base64) {
    if (decodeBase64NodeCompatible(item.input).toString("hex") !== item.out) badB64++;
  }
  ok(badB64 === 0, "decodeBase64NodeCompatible mô phỏng khớp Buffer.from(x,'base64') trên " + fixtures.base64.length + " mẫu");
}

console.log("\n[1] iOS bản CŨ (chưa sửa) trên THIẾT BỊ MỚI — định dạng chữ ký bị server bác");
reset();
{
  const sandbox = loadBridge({ signMode: "legacy" });
  // Bản cũ trả chữ ký ANSI X9.62 (r||s, 64 byte, KHÔNG phải DER) dù config hứa
  // sigFormat = "der-b64".
  const sigBytes = Buffer.from(String(sandbox.window.AndroidBridge.e0(crypto.randomBytes(32).toString("base64"))), "base64");
  eq(sigBytes.length, 64, "legacy: e0() trả đúng 64 byte r||s (X9.62)");
  ok(sigBytes[0] !== 0x30, "legacy: không phải ASN.1 DER (byte đầu khác 0x30)");
  const out = runGate(sandbox);
  eq(out.outcome, "soft", "legacy: bind bị server trả 'bad' -> app báo 'Phiên xác thực hết hạn…'");
  ok(sentToAuth.some((r) => r.path === "/auth/bind"), "legacy: /auth/bind CÓ được gửi nhưng bị bác");
  ok(server.writes === 0, "legacy: KHÔNG ghi binding nào (JSONBin không nhận dữ liệu rác)");
}

console.log("\n[1b] iOS bản CŨ khi Keychain không dùng được -> ĐÚNG câu lỗi người dùng báo");
{
  reset();
  const sandbox = loadBridge({ signMode: "legacy", keyAvailable: false, injectPubkey: false });
  const out = runGate(sandbox);
  eq(out.outcome, "hard", "legacy: d0()/e0() rỗng -> 'Thiết bị không hỗ trợ xác thực, không thể tiếp tục'");
  ok(out.outcome === "hard", "đây là con đường sinh ra câu lỗi trong báo cáo (không phải lỗi mạng, không phải sai tên)");
}

console.log("\n[2] Chữ ký X9.62 bị server từ chối — bằng chứng định dạng");
{
  const message = crypto.randomBytes(32);
  const raw = crypto.sign("sha256", message, { key: device.privateKey, dsaEncoding: "ieee-p1363" });
  const keyObj = pubFromRaw(device.pub);
  eq(verifySig(keyObj, message, raw.toString("base64")), false, "server verifySig(X9.62 raw) = false (bản iOS cũ luôn bị từ chối)");
  eq(verifySig(keyObj, message, derEncodeRS(raw).toString("base64")), true, "server verifySig(DER) = true (bản iOS đã sửa khớp Android)");
  eq(verifySig(keyObj, message, androidSign(message).toString("base64")), true, "Android/Windows ký DER -> server chấp nhận (chuẩn đối chiếu)");
}

console.log("\n[3] iOS bản ĐÃ SỬA trên thiết bị mới: bind thành công như Android");
reset();
{
  const sandbox = loadBridge({ signMode: "fixed" });
  const out = runGate(sandbox);
  eq(out.outcome, "ok", "thiết bị iOS mới đăng nhập thành công (start -> bind -> ok)");
  const bind = sentToAuth.filter((r) => r.path === "/auth/bind")[0];
  ok(!!bind, "có POST /auth/bind");
  eq(bind && bind.method, "POST", "/auth/bind gửi bằng POST");
  eq(bind && bind.contentType, "application/json", "/auth/bind giữ Content-Type application/json");
  const payload = JSON.parse(bind.body);
  ok(Object.keys(payload).sort().join(",") === "h,k,nonce,sig", "body bind đúng 4 trường h/k/nonce/sig, không thêm cơ chế riêng");
  eq(payload.h, KNOWN.hash, "h = SHA-256(username+salt) khớp vector jsonbin (Admin2)");
  eq(payload.k, device.pub, "k = base64(0x04||X||Y) 65 byte — định dạng server yêu cầu");
  const binding = server.bindings[KNOWN.hash];
  ok(!!binding && binding.k === device.pub, "server lưu binding {k, at} ĐÚNG cấu trúc JSONBin hiện tại");
  ok(Object.keys(binding).sort().join(",") === "at,k", "không thêm trường lạ vào bản ghi binding");
  eq(server.writes, 1, "đúng 1 lần ghi binding (1 username = 1 thiết bị)");
}

console.log("\n[4] iOS đã bind: mở lại lần sau xác thực im lặng (challenge -> verify)");
{
  const sandbox = loadBridge({ signMode: "fixed" });
  const out = runGate(sandbox); // hash không còn ở pending của app -> vẫn dùng c0
  eq(out.outcome, "ok", "lần hai vẫn đăng nhập được (challenge/verify)");
  const verify = sentToAuth.filter((r) => r.path === "/auth/verify").pop();
  ok(!!verify, "có POST /auth/verify");
  eq(verify && verify.method, "POST", "/auth/verify gửi bằng POST");
  eq(server.writes, 1, "lần hai KHÔNG ghi binding mới (không làm bẩn JSONBin)");
}

console.log("\n[5] Thiết bị thứ hai dùng cùng tài khoản vẫn bị từ chối — như Android");
{
  const saved = JSON.parse(JSON.stringify(server.bindings));
  const other = (() => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const spki = publicKey.export({ type: "spki", format: "der" });
    return { privateKey, pub: spki.slice(spki.length - 65).toString("base64") };
  })();
  const previous = device.pub;
  // Thiết bị khác: khoá riêng KHÁC, tự ký bằng khoá của nó -> bind hợp lệ về mặt
  // chữ ký, nhưng server phải từ chối vì hash đã có binding (1 user = 1 device).
  const sandbox = loadBridge({ signMode: "fixed", keyPair: { privateKey: other.privateKey, pub: other.pub } });
  const out = runGate(sandbox);
  eq(out.outcome, "fail", "thiết bị thứ hai nhận 'Tài khoản đã được gắn với thiết bị khác'");
  eq(server.bindings[KNOWN.hash].k, previous, "binding cũ KHÔNG bị ghi đè");
}

console.log("\n[6] Challenge rỗng / không phải base64 — bản cũ sinh ra câu lỗi, bản mới vẫn ký");
{
  const legacy = loadBridge({ signMode: "legacy" });
  eq(legacy.window.AndroidBridge.e0(""), "", "legacy: e0('') = '' -> app báo 'thiết bị không hỗ trợ'");
  const fixed = loadBridge({ signMode: "fixed" });
  const sig = fixed.window.AndroidBridge.e0("");
  ok(String(sig).length > 0, "đã sửa: e0('') vẫn trả chữ ký (giống Node crypto.sign trên buffer rỗng)");
  const weird = fixed.window.AndroidBridge.e0("###khong phai base64###");
  ok(String(weird).length > 0, "đã sửa: e0(chuỗi lạ) không chết, ký trên byte Node cũng sẽ ký");
  eq(verifySig(pubFromRaw(device.pub), decodeBase64NodeCompatible(""), String(sig)), true,
     "chữ ký của e0('') verify đúng trên dữ liệu mà Node sẽ ký (Buffer.from('','base64'))");
}

console.log("\n[7] Không lấy được khoá: câu lỗi phải nói rõ bước hỏng (không còn mơ hồ)");
{
  const sandbox = loadBridge({ signMode: "fixed", keyAvailable: false, injectPubkey: false });
  const bridge = sandbox.window.AndroidBridge;
  eq(bridge.d0(), "", "d0() rỗng khi Keychain bị chặn");
  const status = sandbox.window.JVHDiOS.authStatus();
  ok(/lý-do=.*errSecMissingEntitlement/.test(status), "lý do tầng khoá được đưa lên câu lỗi (không còn mơ hồ): " + status);
  const out = runGate(sandbox);
  eq(out.outcome, "hard", "vẫn fail-closed (không cho qua khi không có khoá) — đúng như Android");
}

console.log("\n[8] iOS không đụng vào cơ chế JSONBin");
{
  reset();
  const sandbox = loadBridge({ signMode: "fixed" });
  runGate(sandbox);
  const jsonbin = sentToAuth.concat(sentElsewhere).filter((r) => String(r.url || "").indexOf(JSONBIN_ORIGIN) === 0);
  ok(jsonbin.length === 0, "không có request nào tới api.jsonbin.io từ cầu nối iOS");
  const hosts = [...new Set(sentToAuth.map((r) => r.path))].sort().join(" ");
  eq(hosts, "/auth/bind /auth/start", "iOS chỉ gọi /auth/start + /auth/bind (GET /health khi warm-up do app.js gửi trực tiếp)");
  const writes = sentToAuth.filter((r) => r.method !== "GET" && r.method !== "HEAD").map((r) => r.path);
  ok(writes.every((p) => ["/auth/start", "/auth/bind", "/auth/verify"].indexOf(p) !== -1),
     "mọi request ghi đều nằm trong 3 endpoint xác thực cũ, không có endpoint mới");
}

guardAppFlowUnchanged();

console.log("\n==============================================");
console.log("  PASS: " + pass + "   FAIL: " + fail);
if (fail) { console.log("  Lỗi: " + failures.join("\n       ")); process.exitCode = 1; }
console.log("==============================================");
