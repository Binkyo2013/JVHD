/*
 * preload.js
 * Tiêm window.AndroidBridge vào trang app.js — giống hệt addJavascriptInterface
 * của WebView Android gốc. Bảo toàn toàn bộ hợp đồng app.js đang dùng:
 *   proxyMedia(url, referer) -> chuỗi URL proxy (đồng bộ)
 *   c0(name)  -> SHA-256 hex 64 ký tự (đồng bộ)
 *   d0()      -> khóa công khai thiết bị  (đồng bộ)
 *   e0(data)  -> chữ ký ECDSA              (đồng bộ)
 *   exitApp() -> đóng cửa sổ app
 */
"use strict";
const { contextBridge, ipcRenderer } = require("electron");

function b64u(s) {
  return Buffer.from(String(s), "utf8").toString("base64");
}

// proxyMedia chỉ cần bẻ URL -> endpoint proxy cùng nguồn (không cần IPC).
function buildProxyUrl(url, referer) {
  let origin = "";
  try {
    const loc = window.location;
    if (loc && /^https?:/.test(loc.origin)) origin = loc.origin;
  } catch (e) { origin = ""; }
  if (!origin) origin = ipcRenderer.sendSync("jvhd:base");
  const u = encodeURIComponent(b64u(url));
  const r = encodeURIComponent(b64u(referer || url));
  return origin + "/jvhd-media/?u=" + u + "&r=" + r;
}

contextBridge.exposeInMainWorld("AndroidBridge", {
  proxyMedia: (url, referer) => buildProxyUrl(url, referer),
  c0: (name) => ipcRenderer.sendSync("jvhd:hash", String(name == null ? "" : name)),
  d0: () => ipcRenderer.sendSync("jvhd:pubkey"),
  e0: (data) => ipcRenderer.sendSync("jvhd:sign", String(data == null ? "" : data)),
  exitApp: () => { ipcRenderer.send("jvhd:exit"); return "1"; }
});
