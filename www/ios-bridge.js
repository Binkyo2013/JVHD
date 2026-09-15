/*
 * ios-bridge.js — LỚP TƯƠNG THÍCH iOS (chỉ chạy trong WKWebView của app iOS)
 * ============================================================================
 * Bản Windows dùng Electron + Node.js để cung cấp cho app.js:
 *   1. window.AndroidBridge (c0/d0/e0/proxyMedia/exitApp)  <- native
 *   2. Cửa sổ ẩn tải trang live (vượt WAF)
 *   3. Bơm header CORS để đọc chéo nguồn bằng XHR
 * Trên iOS KHÔNG có Node.js và KHÔNG có cách tắt CORS của WKWebView, nên file
 * này thay thế bằng:
 *   1. AndroidBridge giả lập: c0 tính bằng SHA-256 thuần JS, d0 lấy khoá công
 *      khai native (đã chèn sẵn), e0 gọi local server bằng XHR ĐỒNG BỘ.
 *   2. Mọi XHR chéo nguồn tự động đi qua máy chủ cục bộ -> không còn lỗi CORS:
 *        · GET/HEAD  -> /jvhd-media   (proxy nội dung, bẻ lại playlist HLS)
 *        · POST/...  -> /__native/api (chuyển tiếp ĐÚNG method + body + Content-Type)
 *      Tách hai kênh là bắt buộc: /jvhd-media chỉ biết GET và không đọc body,
 *      nếu lời gọi xác thực POST /auth/* rơi vào đó thì máy chủ nhận GET rỗng
 *      và đăng nhập luôn báo "không kết nối được máy chủ xác thực".
 *   3. Khi hls.js không chạy được (iOS < 17.1 không có ManagedMediaSource),
 *      tự động chuyển luồng HLS sang AVPlayer native.
 *
 * File này được local server chèn vào index.html KHI CHẠY TRÊN iOS. Bản
 * Windows/Electron dựng file bằng server Node nên không hề đụng tới file này.
 */
(function () {
    "use strict";

    // Các hằng số do Swift chèn vào khi phục vụ file (xem LocalServer.swift).
    var BASE = "__JVHD_BASE_URL__";
    var PUBKEY = "__JVHD_PUBKEY__";
    var SALT = "__JVHD_SALT__";
    var CONCAT = "__JVHD_CONCAT__";

    window.__JVHD_IOS__ = true;
    window.__JVHD_NATIVE__ = true;

    /* ------------------------------------------------------------------ *
     * 0. Tiện ích
     * ------------------------------------------------------------------ */
    var lastError = "";
    // Lý do kỹ thuật gần nhất mà tầng native báo về (chuỗi sau "ERR:").
    var lastReason = "";
    // Bản khoá công khai lấy từ native — xem d0() để biết vì sao cần cache.
    var cachedPub = "";
    function log() {
        try { console.log.apply(console, ["[JVHD-iOS]"].concat([].slice.call(arguments))); } catch (e) {}
    }
    function absoluteUrl(url) {
        try { return new URL(url, window.location.href).href; } catch (e) { return String(url || ""); }
    }
    function isHttp(url) { return /^https?:\/\//i.test(String(url || "")); }
    function sameOrigin(url) {
        try {
            var target = new URL(url, window.location.href);
            return target.origin === window.location.origin;
        } catch (e) { return true; }
    }
    function b64(text) {
        // Base64 chuẩn (giống Buffer.from(x,'utf8').toString('base64') của Node)
        // để Swift đọc lại bằng Data(base64Encoded:).
        if (typeof window.btoa === "function") {
            return window.btoa(unescape(encodeURIComponent(String(text))));
        }
        return "";
    }

    /* ------------------------------------------------------------------ *
     * 1. SHA-256 thuần JS (khớp 100% crypto.createHash('sha256') của Node)
     *    Dùng cho c0() để không phải chờ round-trip sang native.
     * ------------------------------------------------------------------ */
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
    function utf8Bytes(text) {
        if (typeof TextEncoder !== "undefined") { return new TextEncoder().encode(String(text)); }
        var out = [], str = String(text);
        for (var i = 0; i < str.length; i++) {
            var code = str.charCodeAt(i);
            if (code < 0x80) out.push(code);
            else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
            else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
                var next = str.charCodeAt(i + 1);
                var cp = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
                out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
                i++;
            } else out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
        return new Uint8Array(out);
    }
    function sha256Hex(text) {
        var bytes = utf8Bytes(text);
        var length = bytes.length;
        var blocks = Math.ceil((length + 9) / 64);
        var total = blocks * 64;
        var padded = new Uint8Array(total);
        padded.set(bytes);
        padded[length] = 0x80;
        var bitLength = length * 8;
        var hi = Math.floor(bitLength / 4294967296);
        var lo = bitLength >>> 0;
        padded[total - 8] = (hi >>> 24) & 0xff;
        padded[total - 7] = (hi >>> 16) & 0xff;
        padded[total - 6] = (hi >>> 8) & 0xff;
        padded[total - 5] = hi & 0xff;
        padded[total - 4] = (lo >>> 24) & 0xff;
        padded[total - 3] = (lo >>> 16) & 0xff;
        padded[total - 2] = (lo >>> 8) & 0xff;
        padded[total - 1] = lo & 0xff;

        var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        var w = new Array(64);
        for (var offset = 0; offset < total; offset += 64) {
            for (var j = 0; j < 16; j++) {
                var base = offset + j * 4;
                w[j] = ((padded[base] << 24) | (padded[base + 1] << 16) | (padded[base + 2] << 8) | padded[base + 3]) >>> 0;
            }
            for (var j2 = 16; j2 < 64; j2++) {
                var x = w[j2 - 15], y = w[j2 - 2];
                var s0 = (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
                var s1 = (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) >>> 0;
                w[j2] = (w[j2 - 16] + s0 + w[j2 - 7] + s1) >>> 0;
            }
            var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
            for (var k = 0; k < 64; k++) {
                var S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
                var ch = ((e & f) ^ ((~e) & g)) >>> 0;
                var t1 = (h + S1 + ch + K[k] + w[k]) >>> 0;
                var S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
                var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
                var t2 = (S0 + maj) >>> 0;
                h = g; g = f; f = e; e = (d + t1) >>> 0;
                d = c; c = b; b = a; a = (t1 + t2) >>> 0;
            }
            H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
            H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
        }
        var hex = "";
        for (var i2 = 0; i2 < H.length; i2++) {
            var value = H[i2].toString(16);
            while (value.length < 8) value = "0" + value;
            hex += value;
        }
        return hex;
    }

    /* ------------------------------------------------------------------ *
     * 2. Gọi native (XHR đồng bộ tới local server) — dùng cho e0()
     *    WKScriptMessageHandler chỉ bất đồng bộ, trong khi app.js cần chữ ký
     *    TRẢ VỀ NGAY, nên ta dùng XHR đồng bộ tới 127.0.0.1 (rất nhanh).
     * ------------------------------------------------------------------ */
    function nativeCall(path, payload) {
        var url = (BASE || window.location.origin) + path;
        try {
            var xhr = new XMLHttpRequest();
            xhr.open("POST", url, false); // đồng bộ
            xhr.setRequestHeader("Content-Type", "text/plain;charset=utf-8");
            xhr.send(payload == null ? "" : payload);
            var text = xhr.responseText || "";
            if (xhr.status >= 200 && xhr.status < 400) return text;
            // Khi thiếu khoá, Swift trả 503 kèm "ERR: <lý do>". Giữ lại lý do để
            // báo đúng bước hỏng (trước đây mọi lỗi đều chỉ còn "thiết bị không
            // hỗ trợ xác thực", không ai biết hỏng ở khâu nào).
            if (text.indexOf("ERR:") === 0) lastReason = text.slice(4).replace(/^\s+/, "");
            else lastReason = "HTTP " + xhr.status;
            lastError = "nativeCall " + path + " -> " + lastReason;
        } catch (e) {
            lastReason = "exception " + e;
            lastError = "nativeCall " + path + " -> " + e;
        }
        log(lastError);
        return "";
    }

    /* ------------------------------------------------------------------ *
     * 3. Cầu nối sang AVPlayer native
     * ------------------------------------------------------------------ */
    function postNative(message) {
        try {
            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.jvhdNative) {
                window.webkit.messageHandlers.jvhdNative.postMessage(message);
                return true;
            }
        } catch (e) { log("postNative lỗi", e); }
        return false;
    }

    var JVHDiOS = {
        version: "1.0",
        sha256Hex: sha256Hex,
        openNativePlayer: function (url, title, referer) {
            var target = absoluteUrl(url);
            if (!isHttp(target)) { log("openNativePlayer: URL không hợp lệ"); return false; }
            try {
                document.querySelectorAll && [].forEach.call(document.querySelectorAll("video"), function (video) {
                    try { video.pause(); } catch (e) {}
                });
            } catch (e) {}
            window.__jvhdNativePlayerActive = true;
            return postNative({ action: "play", url: target, title: title || "", referer: referer || "" });
        },
        closeNativePlayer: function () {
            window.__jvhdNativePlayerActive = false;
            postNative({ action: "close" });
        },
        exitApp: function () { postNative({ action: "exit" }); },
        toast: function (text) { postNative({ action: "toast", text: String(text || "") }); },
        /// Trạng thái cầu nối xác thực, dùng cho thông báo lỗi trên iOS.
        /// Không phát sinh request mạng: chỉ đọc những gì đã biết.
        authStatus: function () {
            var parts = [];
            parts.push("c0=" + (typeof sha256Hex === "function" ? "ok" : "khong"));
            parts.push("pubkey=" + (cachedPub ? "native" : (PUBKEY && PUBKEY.indexOf("__") !== 0 ? "chèn-sẵn" : "trống")));
            parts.push("base=" + (BASE ? "ok" : "trống"));
            if (lastReason) parts.push("lý-do=" + lastReason);
            return parts.join(" · ");
        },
        /// Lý do kỹ thuật gần nhất (rỗng nếu chưa có lỗi).
        lastReason: function () { return lastReason; }
    };
    window.JVHDiOS = JVHDiOS;

    /* ------------------------------------------------------------------ *
     * 4. window.AndroidBridge — hợp đồng y hệt bản Android/Windows
     * ------------------------------------------------------------------ */
    function buildProxyUrl(url, referer) {
        var origin = BASE || (window.location && window.location.origin) || "";
        if (!origin) return String(url || "");
        var target = String(url == null ? "" : url);
        var ref = String(referer == null || referer === "" ? target : referer);
        return origin + "/jvhd-media/?u=" + encodeURIComponent(b64(target)) + "&r=" + encodeURIComponent(b64(ref));
    }

    // Kênh API (POST/PUT/PATCH/DELETE): KHÁC proxy nội dung ở chỗ máy chủ cục bộ
    // chuyển tiếp ĐÚNG method + body + Content-Type. /jvhd-media chỉ biết GET và
    // không đọc body, nên tuyệt đối không được dùng cho lời gọi xác thực.
    function buildApiUrl(url) {
        var origin = BASE || (window.location && window.location.origin) || "";
        if (!origin) return String(url || "");
        return origin + "/__native/api?u=" + encodeURIComponent(b64(String(url == null ? "" : url)));
    }

    if (typeof window.AndroidBridge === "undefined") {
        window.AndroidBridge = {
            // Bọc URL nguồn qua proxy cục bộ (đồng bộ, không cần gọi native).
            proxyMedia: function (url, referer) { return buildProxyUrl(url, referer); },
            // SHA-256(name + salt) — tính tại chỗ, có dự phòng qua native.
            c0: function (name) {
                try {
                    var normalized = String(name == null ? "" : name).trim().toLowerCase();
                    var text = CONCAT === "prefix" ? (SALT + normalized) : (normalized + SALT);
                    var digest = sha256Hex(text);
                    if (/^[0-9a-f]{64}$/.test(digest)) return digest;
                } catch (e) {}
                return nativeCall("/__native/c0?n=" + encodeURIComponent(String(name == null ? "" : name)), "");
            },
            // Khoá công khai thiết bị.
            // LUÔN hỏi native trước: khoá dùng để KÝ nằm trong Secure Enclave /
            // Keychain / tệp khoá, còn `__JVHD_PUBKEY__` chèn lúc phục vụ trang
            // chỉ là bản sao. Nếu khoá được tạo SAU lúc chèn (lần mở đầu tiên)
            // hoặc được tạo lại sau khi cài đè app, bản sao đó lệch -> server bind
            // với khoá không khớp chữ ký -> lần sau vào app báo "thiết bị không
            // khớp". Vì vậy chỉ dùng PUBKEY làm dự phòng khi native không trả lời.
            d0: function () {
                var value = nativeCall("/__native/d0", "");
                if (/^[A-Za-z0-9+/=]{40,}$/.test(String(value))) {
                    cachedPub = value;
                    return value;
                }
                if (cachedPub) return cachedPub;
                if (PUBKEY && PUBKEY.indexOf("__") !== 0) return PUBKEY;
                return "";
            },
            // Chữ ký ECDSA — bắt buộc qua native (khoá không rời thiết bị).
            // Thử lại một lần: lần gọi đầu có thể kích hoạt việc tạo khoá, và Secure
            // Enclave đôi khi bận ngay sau khi mở app.
            e0: function (data) {
                var text = String(data == null ? "" : data);
                var signature = nativeCall("/__native/e0", text);
                if (signature) return signature;
                return nativeCall("/__native/e0", text);
            },
            // iOS không cho phép app tự thoát -> đưa app về nền (hành vi chuẩn iOS).
            exitApp: function () { JVHDiOS.exitApp(); return "1"; },
            // Các hàm phụ của tizen_shim (không dùng trên iOS).
            getInstalledApps: function () { return "[]"; },
            launchApp: function () { return "0"; },
            getMyAppId: function () { return "com.bintv.jvhd.ios"; },
            clearCookies: function () { return "1"; }
        };
    }

    /* ------------------------------------------------------------------ *
     * 5. Chống lỗi CORS: mọi XHR chéo nguồn tự đi qua proxy cục bộ.
     *    Tương đương bộ bơm header CORS của Electron, nhưng hợp lệ trên iOS.
     * ------------------------------------------------------------------ */
    (function installXhrProxying() {
        if (typeof window.XMLHttpRequest === "undefined") return;
        var RealXHR = window.XMLHttpRequest;
        var responseURLDescriptor = null;
        try {
            responseURLDescriptor = Object.getOwnPropertyDescriptor(RealXHR.prototype, "responseURL");
        } catch (e) { responseURLDescriptor = null; }

        // Request chéo nguồn có cần đi nhờ máy chủ cục bộ không?
        // (WKWebView không cho tắt CORS, khác WebView Android và Electron.)
        function needsRelay(url) {
            var target = absoluteUrl(url);
            if (!isHttp(target)) return false;
            if (target.indexOf("/jvhd-media/") !== -1) return false; // đã là proxy nội dung
            if (target.indexOf("/__native/") !== -1) return false;   // đã là kênh native/API
            return !sameOrigin(target);
        }
        // Chỉ lời đọc nội dung mới đi qua proxy HLS.
        function isMediaVerb(verb) { return verb === "GET" || verb === "HEAD"; }

        function PatchedXHR() {
            var xhr = new RealXHR();
            var originalUrl = null;
            var proxiedUrl = null;
            var originalOpen = xhr.open;
            xhr.open = function (method, url) {
                var args = [].slice.call(arguments);
                var verb = String(method == null ? "GET" : method).toUpperCase();
                originalUrl = absoluteUrl(url);
                proxiedUrl = null;
                if (needsRelay(originalUrl)) {
                    if (isMediaVerb(verb)) {
                        // Giữ nguyên hành vi cũ 100% cho nội dung/HLS.
                        proxiedUrl = buildProxyUrl(originalUrl, "");
                        args[1] = proxiedUrl;
                    } else {
                        // POST/PUT/... : giữ method, để nguyên body + Content-Type
                        // do app.js set — máy chủ cục bộ sẽ chuyển tiếp y hệt.
                        // (Trước đây nhánh này rơi vào /jvhd-media nên bị ép GET và
                        //  mất body JSON -> đăng nhập iOS luôn báo lỗi mạng.)
                        proxiedUrl = buildApiUrl(originalUrl);
                        args[0] = verb;
                        args[1] = proxiedUrl;
                    }
                }
                return originalOpen.apply(xhr, args);
            };
            // app.js đọc response.url để suy ra origin của nguồn -> khi đi qua
            // proxy phải trả lại URL GỐC (giống jvhdFetchTextSmart bản Windows).
            try {
                Object.defineProperty(xhr, "responseURL", {
                    configurable: true,
                    get: function () {
                        if (proxiedUrl) return originalUrl;
                        try {
                            if (responseURLDescriptor && responseURLDescriptor.get) {
                                return responseURLDescriptor.get.call(xhr);
                            }
                        } catch (e) {}
                        return originalUrl;
                    }
                });
            } catch (e) {}
            return xhr;
        }
        PatchedXHR.prototype = RealXHR.prototype;
        PatchedXHR.UNSENT = RealXHR.UNSENT;
        PatchedXHR.OPENED = RealXHR.OPENED;
        PatchedXHR.HEADERS_RECEIVED = RealXHR.HEADERS_RECEIVED;
        PatchedXHR.LOADING = RealXHR.LOADING;
        PatchedXHR.DONE = RealXHR.DONE;
        window.XMLHttpRequest = PatchedXHR;
    })();

    /* ------------------------------------------------------------------ *
     * 6. Co giao diện 1920x1080 vừa màn hình iPhone (như fitToScreen trên
     *    Windows). Swift gọi __jvhdApplyFit() khi xoay màn hình / pinch.
     * ------------------------------------------------------------------ */
    var DESIGN_W = 1920, DESIGN_H = 1080;
    function applyFit(scale, layoutWidth) {
        try {
            var meta = document.querySelector('meta[name="viewport"]');
            if (!meta) {
                meta = document.createElement("meta");
                meta.setAttribute("name", "viewport");
                (document.head || document.documentElement).appendChild(meta);
            }
            var content = "width=" + Math.round(layoutWidth) +
                ", initial-scale=" + scale +
                ", minimum-scale=" + scale +
                ", maximum-scale=" + scale +
                ", user-scalable=no, viewport-fit=cover";
            meta.setAttribute("content", content);
            document.documentElement.style.setProperty("--jvhd-fit-scale", String(scale));
        } catch (e) { log("applyFit lỗi", e); }
    }
    window.__jvhdApplyFit = applyFit;

    function fitFor(screenPointsW, screenPointsH, zoom) {
        var s = Math.min(screenPointsW / DESIGN_W, screenPointsH / DESIGN_H) * (zoom || 1);
        s = Math.max(0.15, Math.min(3, s));
        // Layout viewport đúng bằng kích thước màn hình chia tỉ lệ -> vừa khít,
        // không tràn viền, không bị notch che (CSS dùng env(safe-area-inset-*)).
        var layoutWidth = screenPointsW / s;
        return { scale: s, layoutWidth: layoutWidth };
    }
    window.__jvhdFitFor = fitFor;

    /* ------------------------------------------------------------------ *
     * 7. HLS: nếu hls.js không chạy được trên máy này (iOS < 17.1), thay
     *    lớp Hls bằng cầu nối sang AVPlayer native.
     * ------------------------------------------------------------------ */
    function installHlsShim() {
        if (!window.Hls) return;
        var nativeFallback = !(window.Hls.isSupported && window.Hls.isSupported());
        if (!nativeFallback) { log("hls.js khả dụng, dùng trình phát web"); return; }
        log("hls.js không khả dụng -> dùng AVPlayer native cho luồng HLS");

        var RealHls = window.Hls;
        function NativeHls(config) {
            this.config = config || {};
            this.levels = [];
            this.currentLevel = -1;
            this._handlers = {};
            this._url = null;
            this._media = null;
            this._destroyed = false;
        }
        NativeHls.isSupported = function () { return false; };
        NativeHls.Events = RealHls.Events;
        NativeHls.ErrorTypes = RealHls.ErrorTypes;
        NativeHls.ErrorDetails = RealHls.ErrorDetails;
        NativeHls.DefaultConfig = RealHls.DefaultConfig || {};
        NativeHls.prototype.on = function (event, callback) {
            if (!event || typeof callback !== "function") return this;
            (this._handlers[event] = this._handlers[event] || []).push(callback);
            return this;
        };
        NativeHls.prototype.off = function (event, callback) {
            try {
                if (!this._handlers[event]) return this;
                if (!callback) { delete this._handlers[event]; return this; }
                this._handlers[event] = this._handlers[event].filter(function (item) { return item !== callback; });
            } catch (e) {}
            return this;
        };
        NativeHls.prototype.loadSource = function (url) { this._url = url; return this; };
        NativeHls.prototype.attachMedia = function (video) {
            var self = this;
            this._media = video;
            try { if (video) { video.pause(); video.removeAttribute("src"); video.load(); } } catch (e) {}
            if (this._url) {
                var referer = "";
                try { referer = window.location.href; } catch (e) {}
                JVHDiOS.openNativePlayer(this._url, document.title || "JVHD", referer);
            }
            return this;
        };
        NativeHls.prototype.detachMedia = function () { return this; };
        NativeHls.prototype.destroy = function () {
            if (this._destroyed) return;
            this._destroyed = true;
            JVHDiOS.closeNativePlayer();
        };
        NativeHls.prototype.startLoad = function () {};
        NativeHls.prototype.stopLoad = function () {};
        NativeHls.prototype.recoverMediaError = function () { return true; };
        NativeHls.prototype.swapAudioCodec = function () {};
        NativeHls.prototype._emit = function (event, data) {
            var list = this._handlers[event] || [];
            for (var i = 0; i < list.length; i++) {
                try { list[i](event, data); } catch (e) {}
            }
        };
        window.Hls = NativeHls;
    }

    // Theo dõi <video> lỗi (.m3u8 mà trình duyệt không tự phát được) -> native.
    function installVideoWatchdog() {
        document.addEventListener("error", function (event) {
            try {
                var el = event.target;
                if (!el || el.tagName !== "VIDEO") return;
                var src = el.currentSrc || el.src || "";
                if (!/\.m3u8(\?|$)/i.test(src)) return;
                if (window.__jvhdNativePlayerActive) return;
                el.__jvhdVideoErrors = (el.__jvhdVideoErrors || 0) + 1;
                if (el.__jvhdVideoErrors >= 2) {
                    el.__jvhdVideoErrors = 0;
                    log("video lỗi 2 lần -> chuyển AVPlayer native");
                    JVHDiOS.openNativePlayer(src, document.title || "JVHD", window.location.href);
                }
            } catch (e) {}
        }, true);
    }

    /* ------------------------------------------------------------------ *
     * 8. Gợi ý xoay ngang (giao diện được thiết kế theo tỉ lệ 16:9)
     * ------------------------------------------------------------------ */
    function installOrientationHint() {
        var hinted = false;
        function check() {
            try {
                if (window.innerHeight > window.innerWidth) {
                    if (!hinted) {
                        hinted = true;
                        JVHDiOS.toast("Xoay ngang để xem tốt hơn");
                        setTimeout(function () { hinted = false; }, 20000);
                    }
                }
            } catch (e) {}
        }
        window.addEventListener("resize", check, false);
        window.addEventListener("orientationchange", function () { setTimeout(check, 400); }, false);
        setTimeout(check, 1200);
    }

    /* ------------------------------------------------------------------ *
     * 9. Khởi động
     * ------------------------------------------------------------------ */
    function boot() {
        installHlsShim();
        installVideoWatchdog();
        installOrientationHint();
        try {
            document.documentElement.classList.add("jvhd-ios");
            document.body && document.body.classList.add("jvhd-ios");
        } catch (e) {}
        log("ios-bridge sẵn sàng · base=" + BASE + " · pubkey=" + (PUBKEY ? PUBKEY.slice(0, 12) + "…" : "(trống)"));
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot, false);
    } else {
        boot();
    }
})();
