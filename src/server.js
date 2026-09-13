/*
 * src/server.js
 * 1) Phục vụ tĩnh thư mục /www (index.html, app.js, style.css, ...)
 * 2) Endpoint proxy media  GET /jvhd-media?u=<b64 url>&r=<b64 referer>
 *    - Giả trình duyệt (UA) để tránh WAF chặn.
 *    - Tự bẻ danh sách phát HLS (.m3u8) để mọi segment đi qua proxy
 *      => hls.js trong Electron không bao giờ gặp lỗi CORS.
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const cryptoBridge = require("./crypto-bridge");

// [Windows ENV] Khi server chạy trong tiến trình MAIN của Electron, ta dùng
// stack mạng Chromium (electron.net.fetch) cho các host bị WAF chống-bot
// (stripchat/chaturbate/doppiocdn). Node fetch (undici, HTTP/1.1) bị WAF trả
// 406 vì không cùng "dấu vân tay" TLS/HTTP2 của trình duyệt thật; Chromium
// stack dùng đúng như WebView Android gốc -> trả 200. Khi chạy ngoài Electron
// (test bằng node thuần) netFetch = null và rơi về global fetch.
let netFetch = null;
let inElectron = false;
try {
  const el = require("electron");
  if (el && el.net && typeof el.net.fetch === "function") {
    netFetch = el.net.fetch.bind(el.net);
    inElectron = true;
  }
} catch (e) { netFetch = null; inElectron = false; }

const WWW_DIR = path.join(__dirname, "..", "www");

// Host nguồn live bị WAF -> bắt buộc đi qua Chromium stack khi có thể.
const WAF_LIVE_RE = /(^|\.)(stripchat\.com|stripchats\.io|chaturbate\.com)$/i;
function chooseFetcher(url) {
  if (netFetch) {
    try { if (WAF_LIVE_RE.test(new URL(url).hostname)) return netFetch; } catch (e) {}
  }
  return fetch;
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2"
};

function base64Url(raw) {
  return Buffer.from(String(raw), "utf8").toString("base64");
}
function deb64(str) {
  try { return Buffer.from(String(str), "base64").toString("utf8"); }
  catch (e) { return ""; }
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "*"
  };
}

function createServer(config, logger) {
  const log = logger || ((...a) => console.log("[jvhd]", ...a));
  const proxyCfg = config.proxy || {};
  const livePageFetcher = (typeof config.livePageFetcher === "function") ? config.livePageFetcher : null;
  log("[env] outbound-engine=", inElectron && netFetch ? "chromium-net.fetch" : "node-fetch", livePageFetcher ? "+browser-fetch-live" : "");
  const UA = proxyCfg.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
  // Cookie jar theo host (để CDN như phncdn/tiktokcdn nhận cookie set từ master
  // rồi dùng lại cho variant/segment).
  const cookieJar = new Map(); // host(origin) -> "a=1; b=2"

  function myOrigin(req) {
    const host = req.headers.host || ("127.0.0.1:" + config.localPort);
    return "http://" + host;
  }

  function cookieForHost(host) {
    return cookieJar.get(host) || "";
  }
  function storeCookies(host, setCookieHeaders) {
    if (!host || !setCookieHeaders || !setCookieHeaders.length) return;
    const existing = (cookieJar.get(host) || "").split("; ").filter(Boolean);
    const map = {};
    existing.forEach((c) => { const i = c.indexOf("="); if (i > 0) map[c.slice(0, i)] = c; });
    setCookieHeaders.forEach((line) => {
      const semi = line.indexOf(";");
      const pair = (semi > 0 ? line.slice(0, semi) : line).trim();
      const i = pair.indexOf("=");
      if (i <= 0) return;
      map[pair.slice(0, i).trim()] = pair.trim();
    });
    const merged = Object.keys(map).map((k) => map[k]).join("; ");
    if (merged) cookieJar.set(host, merged);
  }

  /* ---------- helper: HTTP(S) fetch theo redirect thủ công ---------- */
  // Mở media, theo redirect. Trả { resp } với body là web-stream để caller
  // quyết định: buff (playlist cần rewrite) hoặc stream thẳng (media mp4 lớn
  // không cần nạp hết vào RAM).
  async function openMedia(target, headers, maxRedirects) {
    let cur = target;
    const hostForCookies = new URL(target).host;
    const stored = cookieForHost(hostForCookies);
    if (stored && !headers.Cookie) headers.Cookie = stored;
    let last = null;
    // [Windows LIVE] Nếu là host live bị WAF và URL là TRANG (không phải media
    // .m3u8/.ts/.mp4) thì ưu tiên "trình-duyệt-thật" (cửa sổ Electron ẩn điều
    // hướng + chạy JS + bấm age-gate) để lấy DOM đã render — như trình duyệt.
    const looksLikeMedia = /\.(m3u8|ts|mp4|m4v|webm|mov|m4a|mp3|aac|flv|jpg|jpeg|png|webp|gif)(\?|$)/i.test(String(cur).split("?")[0]);
    let fetcher = null;
    if (livePageFetcher && !looksLikeMedia && /^https?:/i.test(cur)) {
      try { if (WAF_LIVE_RE.test(new URL(cur).hostname)) fetcher = livePageFetcher; } catch (e) {}
    }
    if (!fetcher) fetcher = chooseFetcher(cur);
    if (fetcher === livePageFetcher) log("[proxy-live] browser-fetch ->", cur.slice(0, 140));
    for (let i = 0; i <= maxRedirects; i++) {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), proxyCfg.timeoutMs || 25000);
      let res;
      try {
        res = await fetcher(cur, { redirect: "manual", signal: controller.signal, headers });
      } catch (e) { clearTimeout(t); throw e; } finally { clearTimeout(t); }
      try {
        const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
        if (sc && sc.length) storeCookies(hostForCookies, sc);
      } catch (e) { /* ignore */ }
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        cur = new URL(res.headers.get("location"), cur).toString();
        last = cur;
        try { if (res.body && res.body.cancel) await res.body.cancel(); } catch (e) {}
        continue;
      }
      return { resp: res, finalUrl: cur, status: res.status, headers: res.headers };
    }
    throw new Error("Quá nhiều redirect: " + last);
  }

  async function streamBody(reader, res) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.write(Buffer.from(value))) {
        await new Promise((resolve) => res.once("drain", resolve));
      }
    }
    try { await reader.cancel(); } catch (e) {}
    res.end();
  }

  function looksLikePlaylist(head, upstreamType) {
    if (upstreamType && /mpegurl/i.test(upstreamType)) return true;
    const h = (head || "").toString("utf8").slice(0, 512).trimStart();
    return h.indexOf("#EXTM3U") === 0 || /\.m3u8(\?|$)/i.test(h.slice(0, 200));
  }

  /* Bẻ playlist: mọi URI con (variant/segment/key) đều bọc về proxy, đồng
     thời GIỮ NGUYÊN referer gốc để CDN anti-hotlink khỏi chặn sub-request. */
  function rewritePlaylist(text, playlistFinalUrl, origin, refererToCarry) {
    const base = new URL(playlistFinalUrl);
    const carry = refererToCarry || playlistFinalUrl;
    return text.split(/\r?\n/).map((line) => {
      const trimmed = line.trim();
      if (trimmed === "" || trimmed.charAt(0) === "#") {
        // #EXT-X-KEY / MAP / MEDIA có URI="..." -> bọc luôn
        if (/URI\s*=\s*"/i.test(line)) {
          return line.replace(/URI\s*=\s*"([^"]+)"/gi, (all, u) => {
            const abs = new URL(u, base).toString();
            return 'URI="' + encodeURI(b64Url(abs, origin, carry)) + '"';
          });
        }
        return line;
      }
      let abs;
      try { abs = new URL(trimmed, base).toString(); } catch (e) { return line; }
      return b64Url(abs, origin, carry);
    }).join("\n");
  }

  function b64Url(absUrl, origin, refererToCarry) {
    const r = refererToCarry || absUrl;
    return origin + "/jvhd-media/?u=" + encodeURIComponent(base64Url(absUrl)) +
      "&r=" + encodeURIComponent(base64Url(r));
  }

  /* ---------- proxy media ---------- */
  async function handleProxy(req, res) {
    const q = new URL(req.url, myOrigin(req));
    const target = deb64(q.searchParams.get("u") || "");
    const referer = deb64(q.searchParams.get("r") || "") || target;
    if (!/^https?:\/\//i.test(target)) { res.writeHead(400); res.end("bad target"); return; }

    // KHÔNG gửi Origin giả: khi trình duyệt tải media con (video/segment) nó
    // chỉ gửi Referer chứ không gửi Origin; gửi Origin giả làm WAF một số CDN
    // (ByteDance/ipstatp/tiktokcdn, phncdn) trả 403.
    const headers = {
      "User-Agent": UA,
      "Accept": "*/*",
      "Accept-Language": "vi,en;q=0.8",
      "Cache-Control": "no-cache"
    };
    if (/^https?:/i.test(referer)) headers.Referer = referer;
    // Hỗ trợ seek/tua mp4: chuyển tiếp Range của trình duyệt lên upstream.
    if (req.headers.range) headers.Range = req.headers.range;

    try {
      const up = await openMedia(target, headers, proxyCfg.maxRedirects || 6);
      const resp = up.resp;
      const ctype = up.headers.get("content-type") || "";
      const origin = myOrigin(req);
      const finalUrl = up.finalUrl || target;

      // Quyết định có phải playlist cần rewrite hay không: dựa vào content-type
      // mpegurl, HOẶC đọc chunk đầu để sniff #EXTM3U (CDN hay trả text/plain).
      let isPlaylist = proxyCfg.rewriteHls && /mpegurl/i.test(ctype);
      let firstChunk = null;
      let reader = null;
      if (proxyCfg.rewriteHls && !isPlaylist && !req.headers.range && resp.body && resp.body.getReader) {
        reader = resp.body.getReader();
        const r0 = await reader.read();
        if (r0 && r0.value && r0.value.length) {
          firstChunk = r0.value;
          isPlaylist = looksLikePlaylist(firstChunk, ctype);
        }
      }
      if (process.env.JVHD_VERBOSE) log("[proxy] ", up.status, ctype, isPlaylist ? "playlist" : "media", target.slice(0, 140));

      if (isPlaylist) {
        // Gom toàn bộ body rồi rewrite (playlist thường nhỏ).
        let body;
        if (reader) {
          const chunks = firstChunk ? [firstChunk] : [];
          for (;;) {
            const r = await reader.read();
            if (r.done) break;
            chunks.push(r.value);
          }
          try { await reader.cancel(); } catch (e) {}
          body = Buffer.concat(chunks.map((c) => Buffer.from(c)));
        } else {
          body = Buffer.from(await resp.arrayBuffer());
        }
        const text = body.toString("utf8");
        const rewritten = rewritePlaylist(text, finalUrl, origin, referer);
        const out = Buffer.from(rewritten, "utf8");
        res.writeHead(up.status || 200, Object.assign(corsHeaders(), {
          "Content-Type": ctype || "application/vnd.apple.mpegurl",
          "Cache-Control": "no-store",
          "Content-Length": out.length
        }));
        res.end(out);
        return;
      }

      // Media thường (mp4/ts/...): stream thẳng, không nạp cả file.
      const headersOut = Object.assign(corsHeaders(), {
        "Content-Type": ctype || "application/octet-stream",
        "Cache-Control": "no-store"
      });
      // truyền qua header Range/Content-Length để trình duyệt seek/đọc moov
      const cr = up.headers.get("content-range");
      const ar = up.headers.get("accept-ranges");
      const cl = up.headers.get("content-length");
      const cd = up.headers.get("content-disposition");
      if (cr) headersOut["Content-Range"] = cr;
      if (ar) headersOut["Accept-Ranges"] = ar;
      if (cd) headersOut["Content-Disposition"] = cd;
      if (cl) headersOut["Content-Length"] = cl;
      if (reader) {
        res.writeHead(up.status || 200, headersOut);
        if (firstChunk) res.write(Buffer.from(firstChunk));
        try { await streamBody(reader, res); } catch (e) { try { res.destroy(); } catch (e2) {} }
      } else if (resp.body && resp.body.getReader) {
        res.writeHead(up.status || 200, headersOut);
        try { await streamBody(resp.body.getReader(), res); } catch (e) { try { res.destroy(); } catch (e2) {} }
      } else {
        const b = Buffer.from(await resp.arrayBuffer());
        if (!cl) headersOut["Content-Length"] = b.length;
        res.writeHead(up.status || 200, headersOut);
        res.end(b);
      }
    } catch (err) {
      log("proxy error", target.slice(0, 140), err.message);
      if (!res.headersSent) {
        res.writeHead(502, Object.assign(corsHeaders(), { "Content-Type": "text/plain; charset=utf-8" }));
      }
      res.end("Proxy error: " + (err && err.message));
    }
  }

  /* ---------- static ---------- */
  function handleStatic(req, res, pathname) {
    let rel = decodeURIComponent(pathname);
    if (rel === "/" || rel === "") rel = "/index.html";
    // chống đi ra ngoài www
    const file = path.normalize(path.join(WWW_DIR, rel));
    if (!file.startsWith(WWW_DIR)) { res.writeHead(403); res.end("Forbidden"); return; }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); res.end("Not found"); return; }
      const ext = path.extname(file).toLowerCase();
      res.writeHead(200, Object.assign(corsHeaders(), {
        "Content-Type": MIME[ext] || "application/octet-stream",
        "Cache-Control": "no-cache"
      }));
      res.end(data);
    });
  }

  const server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const pathname = u.pathname;
    if (req.method === "OPTIONS") { res.writeHead(204, corsHeaders()); res.end(); return; }
    if (pathname === "/jvhd-media" || pathname === "/jvhd-media/") { handleProxy(req, res); return; }
    if (pathname === "/__health") { res.writeHead(200, corsHeaders()); res.end("ok"); return; }
    if (req.method === "GET" || req.method === "HEAD") { handleStatic(req, res, pathname); return; }
    res.writeHead(405); res.end();
  });

  server.start = () => new Promise((resolve) => {
    server.on("error", (e) => { throw e; });
    server.listen(0, config.bindHost || "127.0.0.1", () => {
      const port = server.address().port;
      resolve(port);
    });
  });

  return server;
}

module.exports = { createServer, WWW_DIR, MIME };
