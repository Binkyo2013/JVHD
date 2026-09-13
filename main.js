/*
 * main.js — Tiến trình chính Electron của JVHD Desktop.
 *  - Khởi động server cục bộ (static + proxy media)
 *  - Quản lý khóa thiết bị & phục vụ c0/d0/e0 qua IPC
 *  - Mở cửa sổ app chạy trang www/index.html
 */
"use strict";

const { app, BrowserWindow, ipcMain, session, screen, net } = require("electron");
const path = require("path");
const fs = require("fs");

const config = require("./jvhd.config.js");
const bridge = require("./src/crypto-bridge.js");
const { createServer } = require("./src/server.js");

// Cho phép video/âm thanh tự phát (HLS của JVHD autoplay).
app.commandLine.appendSwitch("autoplay-policy", "no-user-gesture-required");

let win = null;
let localPort = 0;
let deviceKey = null;
let currentZoom = 1;

// [Windows LIVE] Cửa sổ Electron ẩn dùng để "điều hướng thật" trang live
// (stripchat/chaturbate) giống trình duyệt: chạy JS, tự bấm lớp xác nhận
// "18+/age-gate/consent" nếu có, để WAF cấp cookie & SPA render ra danh sách
// thẻ, rồi trả về DOM đã render. Không cần sửa logic app.js.
let livePageWindow = null;
let livePageBusy = false;

function log(...a) { console.log("[JVHD]", ...a); }

function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

// Load 1 URL trong cửa sổ ẩn và chờ trang "định cư" (load + tĩnh lại).
async function navigateAndSettle(url, settleMs) {
  if (!livePageWindow || livePageWindow.isDestroyed()) {
    livePageWindow = new BrowserWindow({
      show: false,
      backgroundColor: "#000",
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: false,
        backgroundThrottling: false,
        webSecurity: true
      }
    });
    // Không mở cửa sổ ngoài / thoát hẳn app khi chỗ trang quảng cáo.
    livePageWindow.webContents.setWindowOpenHandler(({ url }) => {
      try { livePageWindow.loadURL(url).catch(() => {}); } catch (e) {}
      return { action: "deny" };
    });
  }
  const wc = livePageWindow.webContents;
  try {
    const p = wc.loadURL(url);
    await new Promise((resolve) => {
      let done = false;
      const fin = () => { if (!done) { done = true; resolve(); } };
      const t = setTimeout(fin, 25000);
      wc.once("did-finish-load", fin);
      wc.once("did-fail-load", (_e, code, desc) => { if (code === -3) fin(); });
      p.catch(() => {});
    });
  } catch (e) { /* continue */ }
  await delay(settleMs || 2500);
}

// Tự bấm nút lớp xác nhận độ tuổi / đồng ý (nếu trang có). Trả true nếu thấy
// nút nào đó đã được bấm. Heuristic dùng nhiều selector + nội dung.
async function autoPassGate() {
  if (!livePageWindow || livePageWindow.isDestroyed()) return false;
  const wc = livePageWindow.webContents;
  try {
    const clicked = await wc.executeJavaScript(`(function(){
      function fire(el){ try{ el.click(); }catch(e){ try{ el.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true})); }catch(e2){} } }
      var RE=/18|age|adult|enter|agree|accept|consent|continue|cont(?:inue)?|tôi|đủ|yes|confirm|allow|ok/i;
      function isRealLink(el){
        var tag=(el.tagName||'').toLowerCase();
        if(tag!=='a') return false;
        var h=(el.getAttribute&&el.getAttribute('href'))||'';
        return /^(\\/|https?:|\\?)/i.test(h.trim()); // link điều hướng thật -> bỏ qua
      }
      var all=document.querySelectorAll('button,a,[role=button],[data-testid],[data-qa]');
      var cand=[];
      for(var i=0;i<all.length;i++){ var el=all[i]; if(!el||!el.offsetParent) continue;
        if(isRealLink(el)) continue;
        var t=((el.innerText||el.textContent||el.getAttribute('aria-label')||el.getAttribute('data-qa')||el.getAttribute('data-testid')||'')+'');
        if(RE.test(t)) cand.push(el); }
      // Ưu tiên nút có text ngắn & là button (gần giống nút consent)
      cand.sort(function(a,b){
        var ta=(a.innerText||a.textContent||'').trim().length;
        var tb=(b.innerText||b.textContent||'').trim().length;
        var aa=a.tagName==='BUTTON'?0:1, bb=b.tagName==='BUTTON'?0:1;
        return (aa-bb)||(ta-tb);
      });
      if(cand.length){ fire(cand[0]); return cand.length; }
      return 0;
    })()`);
    return !!clicked;
  } catch (e) { return false; }
}

// Sinh đối tượng giống Response cho openMedia() của server.
function textResponseLike(status, text, contentType) {
  const enc = new TextEncoder();
  const bytes = enc.encode(text);
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    }
  });
  return {
    status: status,
    headers: new Headers({ "content-type": contentType || "text/html; charset=utf-8" }),
    body: stream,
    arrayBuffer: async () => bytes.buffer
  };
}

// [Windows LIVE] fetch "trình-duyệt-thật" cho host bị WAF (stripchat/chaturbate).
// Được server.js gọi khi cần tải trang HTML live. Tuần tự hoá để tránh nhiều
// window cùng lúc.
async function rawViaNetFast(u) {
  try {
    const origin = new URL(u).origin;
    const ses = session.defaultSession;
    const cookies = await ses.cookies.get({ url: origin });
    const cookieHeader = cookies.map((c) => c.name + "=" + c.value).join("; ");
    const headers = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml",
      "Accept-Language": "vi,en;q=0.8",
      "Cache-Control": "no-cache"
    };
    if (cookieHeader) headers.Cookie = cookieHeader;
    const res = await net.fetch(u, { redirect: "follow", headers });
    if (!res.ok) return "";
    return await res.text();
  } catch (e) { return ""; }
}

// Cache SSR list theo URL (TTL ~45s) để lần mở LIVE lặp lại không phải đi lại
// flow chậm -> tránh renderer timeout.
const liveSsCache = new Map(); // url -> {at, html}
function liveCacheGet(target) {
  const c = liveSsCache.get(target);
  if (c && Date.now() - c.at < 45000) return c.html;
  if (c) liveSsCache.delete(target);
  return "";
}
function liveCachePut(target, html) {
  if (html && html.length > 2000) liveSsCache.set(target, { at: Date.now(), html });
}

function liveMetrics(t) {
  t = String(t);
  return {
    cState: (t.match(/__PRELOADED_STATE__/g) || []).length,
    cUser: (t.match(/"username"\s*:/g) || []).length,
    cPlay: (t.match(/"hlsPlaylist"/g) || []).length,
    cStream: (t.match(/"streamName"/g) || []).length,
    len: t.length
  };
}
function liveHasModel(m) { return m.cState > 0 && (m.cPlay > 0 || m.cStream > 0 || m.cUser > 0); }

async function inPageFetch(url) {
  // fetch trong window đã mở sẵn trang cùng registrable-domain -> nhanh & có
  // đầy đủ browser session/cookie (net.fetch từ main có thể bị 406 vì khác vân
  // tay TLS/HTTP2 so với window thật).
  try {
    if (!livePageWindow || livePageWindow.isDestroyed()) return "";
    const u1 = new URL(url);
    const cur = await livePageWindow.webContents.executeJavaScript("location.href").catch(() => "");
    const u2 = cur ? new URL(cur) : null;
    if (!u2) return "";
    const d = (h) => h.split(".").slice(-2).join(".");
    if (d(u1.hostname) !== d(u2.hostname)) return "";
    const raw = await livePageWindow.webContents.executeJavaScript(
      "fetch(" + JSON.stringify(url) + ",{credentials:'include',redirect:'follow',headers:{'Accept':'text/html'}}).then(function(r){if(!r.ok)return Promise.reject(String(r.status));return r.text();})"
    );
    return String(raw || "");
  } catch (e) { return ""; }
}

async function browserFetchLive(url, tries) {
  try {
    const target = url;
    const cached = liveCacheGet(target);
    if (cached) { log("[live-browser] CACHE_HIT len=", cached.length); return textResponseLike(200, cached, "text/html; charset=utf-8"); }
    const cbUrl = target + (target.indexOf("?") === -1 ? "?" : "&") + "_jvhd=" + Date.now();

    // ĐƯỜNG NHANH 1: fetch trong-page qua window đã có sẵn (cùng domain).
    let fastBody = "";
    for (const cand of [target, cbUrl]) {
      const t = await inPageFetch(cand);
      if (String(t).length > String(fastBody).length) fastBody = String(t);
    }
    const mFast = liveMetrics(fastBody);
    if (liveHasModel(mFast)) {
      log("[live-browser] FAST_INPAGE len=", fastBody.length, "RAW[state=" + mFast.cState + ",user=" + mFast.cUser + ",play=" + mFast.cPlay + ",stream=" + mFast.cStream + "]");
      liveCachePut(target, fastBody);
      return textResponseLike(200, fastBody, "text/html; charset=utf-8");
    }

    // ĐƯỜNG NHANH 2: net.fetch + consent cookie (nếu CDN/WAF chấp nhận).
    let netBody = "";
    for (const cand of [cbUrl, target]) {
      const t = await rawViaNetFast(cand);
      if (String(t).length > String(netBody).length) netBody = String(t);
    }
    const mNet = liveMetrics(netBody);
    if (liveHasModel(mNet)) {
      log("[live-browser] FAST_NET len=", netBody.length, "RAW[state=" + mNet.cState + ",user=" + mNet.cUser + ",play=" + mNet.cPlay + ",stream=" + mNet.cStream + "]");
      liveCachePut(target, netBody);
      return textResponseLike(200, netBody, "text/html; charset=utf-8");
    }

    // ĐƯỜNG CHẬM: cần window điều hướng + bấm age-gate (chỉ lần đầu sau khởi động).
    const waitStart = Date.now();
    while (livePageBusy && Date.now() - waitStart < 30000) await delay(100);
    livePageBusy = true;
    try {
      // Trước khi mở window, thử lại nhanh 1 lần (request khác có thể vừa set cookie).
      let body2 = await inPageFetch(target);
      const m2 = liveMetrics(body2);
      if (liveHasModel(m2)) { liveCachePut(target, body2); log("[live-browser] FAST2 len=", body2.length); return textResponseLike(200, body2, "text/html; charset=utf-8"); }

      await navigateAndSettle(target, 1200);
      let gateClicked = false;
      if (await autoPassGate()) { gateClicked = true; await delay(1200); }
      await navigateAndSettle(target, 1200);
      if (await autoPassGate()) { gateClicked = true; await delay(1000); }
      if (!livePageWindow || livePageWindow.isDestroyed()) return textResponseLike(502, "live-browser-closed", "text/html");
      // Sau gate: RAW qua in-page fetch (window đang ở đúng target).
      let rawBody = "";
      for (const cand of [cbUrl, target]) {
        const t = await inPageFetch(cand);
        if (String(t).length > String(rawBody).length) rawBody = String(t);
      }
      const mRaw = liveMetrics(rawBody);
      const domHtml = await livePageWindow.webContents.executeJavaScript("document.documentElement.outerHTML").catch(() => "");
      const mDom = liveMetrics(domHtml);
      const rawScore = mRaw.cState * 10000 + (mRaw.cPlay + mRaw.cStream) * 100 + mRaw.cUser;
      const domScore = mDom.cState * 10000 + (mDom.cPlay + mDom.cStream) * 100 + mDom.cUser;
      const useRaw = liveHasModel(mRaw) ? true : (mRaw.len > 0 && rawScore > domScore);
      const bestHtml = useRaw ? rawBody : domHtml;
      log("[live-browser] url=", String(target).slice(0, 70),
        "RAW[state=" + mRaw.cState + ",user=" + mRaw.cUser + ",play=" + mRaw.cPlay + ",stream=" + mRaw.cStream + ",len=" + mRaw.len + "]",
        "DOM[state=" + mDom.cState + ",user=" + mDom.cUser + ",play=" + mDom.cPlay + ",stream=" + mDom.cStream + ",len=" + mDom.len + "]",
        "gate-clicked=", gateClicked, "chose=", useRaw ? "RAW" : "DOM");
      liveCachePut(target, bestHtml);
      return textResponseLike(200, bestHtml, "text/html; charset=utf-8");
    } finally {
      livePageBusy = false;
    }
  } catch (e) {
    return textResponseLike(502, "live-browser-fetch-error", "text/html");
  }
}

// [Windows LIVE] Warm-up cookie nền lúc khởi động: mở nhanh trang live trong
// cửa sổ ẩn để WAF cấp session/age cookie vào session mặc định (dùng chung với
// cửa sổ app + renderer), giúp các lần sau (kể cả fetch trực tiếp của renderer)
// không bị 406. Chạy nền, lỗi thì bỏ qua.
const LIVE_WARM_URLS = [
  "https://vi.stripchat.com/girls",
  "https://stripchat.com/girls"
];
function warmUpLiveCookies() {
  (async () => {
    for (const u of LIVE_WARM_URLS) {
      try {
        await browserFetchLive(u);
        log("[live-warm] ok " + u);
        break; // 1 host đủ set cookie cho cả tên miền
      } catch (e) { /* thử tiếp */ }
    }
  })();
}

function zoomBy(delta) {
  if (!win) return;
  currentZoom = Math.max(0.5, Math.min(3, currentZoom + delta));
  win.webContents.setZoomFactor(currentZoom);
}

/* ------------------------------------------------------------------ *
 * Khóa thiết bị (lưu 1 lần trong userData)
 * ------------------------------------------------------------------ */
function loadDeviceKey() {
  const filePath = path.join(app.getPath("userData"), "device_key.json");
  try {
    const rec = bridge.ensureDeviceKey({
      filePath, alg: "ec",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" }
    });
    return rec.key;
  } catch (e) {
    log("Không tạo được khóa thiết bị:", e.message);
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * IPC: c0 / d0 / e0 / exit
 * ------------------------------------------------------------------ */
function registerIpc() {
  ipcMain.on("jvhd:hash", (event, name) => {
    try { event.returnValue = bridge.c0(String(name), config); }
    catch (e) { event.returnValue = ""; }
  });
  ipcMain.on("jvhd:pubkey", (event) => {
    try { event.returnValue = deviceKey ? bridge.d0(deviceKey, config) : ""; }
    catch (e) { event.returnValue = ""; }
  });
  ipcMain.on("jvhd:sign", (event, data) => {
    try { event.returnValue = deviceKey ? bridge.e0(deviceKey, String(data), config) : ""; }
    catch (e) { event.returnValue = ""; }
  });
  ipcMain.on("jvhd:base", (event) => { event.returnValue = "http://127.0.0.1:" + localPort; });
  ipcMain.on("jvhd:exit", () => { app.quit(); });
}

/* ------------------------------------------------------------------ *
 * Bơm header CORS cho những nguồn phát trực tiếp (stripchat direct...)
 * ------------------------------------------------------------------ */
function setupCorsInjector() {
  const ses = session.defaultSession;
  ses.webRequest.onHeadersReceived((details, callback) => {
    const url = details.url || "";
    const isLocal = /^http:\/\/127\.0\.0\.1(:\d+)?\//.test(url) || /^http:\/\/localhost/.test(url);
    const h = details.responseHeaders || {};
    const hasKey = (obj, name) => { for (const k in obj) { if (String(k).toLowerCase() === name.toLowerCase()) return true; } return false; };
    if (!isLocal) {
      // Chỉ THÊM header CORS khi nguồn CHƯA gửi sẵn (tránh trùng '*, *' gây lỗi)
      if (!hasKey(h, "Access-Control-Allow-Origin")) h["Access-Control-Allow-Origin"] = ["*"];
      if (!hasKey(h, "Access-Control-Allow-Methods")) h["Access-Control-Allow-Methods"] = ["GET, HEAD, OPTIONS"];
      if (!hasKey(h, "Access-Control-Allow-Headers")) h["Access-Control-Allow-Headers"] = ["*"];
    }
    callback({ responseHeaders: h });
  });
  ses.webRequest.onBeforeSendHeaders((details, callback) => {
    callback({ requestHeaders: details.requestHeaders });
  });
}

/* ------------------------------------------------------------------ *
 * Cửa sổ (nội dung thiết kế 1920x1080, tự co khớp màn hình)
 * ------------------------------------------------------------------ */
function createWindow() {
  const wa = screen.getPrimaryDisplay().workArea;
  const fit = config.window.fitToScreen !== false;
  let scale = 1;
  if (fit) {
    scale = Math.min(wa.width / 1920, wa.height / 1080);
    scale = Math.max(0.5, Math.min(1, scale));
  }
  win = new BrowserWindow({
    width: Math.round(1920 * scale),
    height: Math.round(1080 * scale),
    show: false,
    autoHideMenuBar: true,
    backgroundColor: "#07070a",
    title: "JVHD",
    icon: path.join(__dirname, "www", "JVHD.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      // [Windows ENV PARITY] Bật truy cập cross-origin giống WebView Android gốc
      // (vốn chạy không bắt buộc CORS). app.js đọc thẳng mã nguồn trang remote
      // qua requestJvhdText() để resolve LIVESTREAM (stripchat/chaturbate); nếu
      // bật webSecurity, Chromium chặn đọc chéo nguồn -> rơi xuống proxy/dự phòng
      // và LIVE báo "không tìm thấy luồng". Tắt webSecurity khôi phục đúng hành
      // vi gốc. An toàn vì mọi điều hướng đã khoá về localhost.
      webSecurity: false,
      zoomFactor: scale
    }
  });

  // Không cho mở cửa sổ mới / điều hướng ra ngoài.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url) { require("electron").shell.openExternal(url); }
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (e, url) => {
    const allowed = "http://127.0.0.1:" + localPort + "/";
    if (url !== allowed && url.indexOf("127.0.0.1:" + localPort) === -1) e.preventDefault();
  });

  win.once("ready-to-show", () => win.show());
  if (process.env.JVHD_DEBUG) {
    win.webContents.on("console-message", (event, level, message) => {
      const msg = typeof message === "string" ? message : (event && event.message) || String(message || "");
      const lvl = (event && event.level) || level;
      console.log("[renderer:" + lvl + "]", msg);
    });
    win.webContents.on("did-fail-load", (e, code, desc) => log("load fail code=" + code + " " + desc));
  }
  win.loadURL("http://127.0.0.1:" + localPort + "/");
  currentZoom = scale;
  win.webContents.setZoomFactor(scale);

  if (process.env.JVHD_DEBUG) {
    setTimeout(() => {
      win.webContents.executeJavaScript(`(function(){
        var probe = {
          standalone: !!window.__BINTV_JVHD_STANDALONE__,
          androidBridge: typeof window.AndroidBridge,
          hls: typeof window.Hls,
          tizen: typeof window.tizen,
          pinGate: !!document.getElementById('bintv-jvhd-pin-gate'),
          title: document.title
        };
        try {
          if (window.AndroidBridge) {
            probe.c0 = window.AndroidBridge.c0('alice');
            probe.hasPub = !!window.AndroidBridge.d0();
            probe.sigLen = window.AndroidBridge.e0('challenge').length;
          }
        } catch (probeError) { probe.probeError = String(probeError); }
        return JSON.stringify(probe);
      })()`).then((r) => log("DEBUG-DOM " + r)).catch((e) => log("DEBUG-ERR " + e));
    }, 4000);
  }

  win.webContents.on("before-input-event", (event, input) => {
    if (input.type !== "keyDown") return;
    // F11 toàn màn hình
    if (config.window.allowFullscreen && input.key === "F11") {
      win.setFullScreen(!win.isFullScreen());
      event.preventDefault();
      return;
    }
    // Ctrl + / - / 0 : phóng to, thu nhỏ, về 100%
    if (input.control && !input.alt && !input.meta) {
      const k = String(input.key);
      if (k === "+" || k === "=") { zoomBy(0.1); event.preventDefault(); }
      else if (k === "-") { zoomBy(-0.1); event.preventDefault(); }
      else if (k === "0") { currentZoom = 1; win.webContents.setZoomFactor(1); event.preventDefault(); }
    }
  });
}

/* ------------------------------------------------------------------ *
 * Khởi động
 * ------------------------------------------------------------------ */
async function bootstrap() {
  try {
    // [Windows LIVE] Gắn fetch "trình-duyệt-thật" cho host live bị WAF. Server
    // sẽ ưu tiên dùng nó để tải trang HTML live (stripchat/chaturbate).
    config.livePageFetcher = browserFetchLive;
    const srv = createServer(config, log);
    localPort = await srv.start();
    log("Server cục bộ sẵn sàng tại http://127.0.0.1:" + localPort + "/");
  } catch (e) {
    log("Không khởi động được server:", e);
    app.quit();
    return;
  }
  deviceKey = loadDeviceKey();
  if (!deviceKey) { log("Không có khóa thiết bị — kiểm tra quyền ghi userData."); }
  registerIpc();
  setupCorsInjector();
  createWindow();
  // [Windows LIVE] Warm-up cookie nền cho stripchat để khi mở LIVE không bị 406.
  setTimeout(warmUpLiveCookies, 4000);
}

app.whenReady().then(() => {
  bootstrap();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on("window-all-closed", () => { app.quit(); });
