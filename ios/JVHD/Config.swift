/*
 * Config.swift
 * JVHD for iOS
 *
 * Bản sao Swift của `jvhd.config.js` (bản Electron/Windows).
 * Mọi giá trị ở đây PHẢI khớp với máy chủ xác thực của bạn, nếu không
 * đăng nhập sẽ bị từ chối giống hệt như trên Windows.
 */

import Foundation

enum JVHDConfig {

    // MARK: - Máy chủ cục bộ (local HTTP server chạy trong app)

    /// Chỉ lắng nghe trên loopback: không bao giờ mở ra mạng LAN.
    static let bindHost = "127.0.0.1"
    /// Cổng ưu tiên; nếu bận thì hệ điều hành tự cấp cổng khác (giống bản Windows).
    static let preferredPort: UInt16 = 38755

    // MARK: - Xác thực (khớp jvhd-auth server + JSONBin)

    static let authServer = "https://jvhd-auth.onrender.com"

    /// SALT nối dạng VĂN BẢN (không decode hex) — khớp 100% libbtcore.so.
    static let salt = "4f4e804da5c307dd7d88d2b58e1a44c6b312c1430ff4d29d"
    /// "suffix" = sha256(name + salt) · "prefix" = sha256(salt + name)
    static let concat = "suffix"
    /// d0(): base64( 0x04 || X(32) || Y(32) ) — khớp BtK.pk()
    static let pubKeyFormat = "raw-uncompressed-b64"
    /// e0(): ECDSA P-256, DER, base64 — khớp BtK.sg()
    static let sigFormat = "der-b64"
    static let signDigest = "sha256"
    /// challenge từ server là base64 -> phải decode trước khi SHA-256 + ký.
    static let challengeEncoding = "base64"

    // MARK: - Proxy nội dung

    /// User-Agent iPhone Safari thật (tránh WAF chặn UA "TV/Android").
    static let proxyUserAgent =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    static let proxyTimeout: TimeInterval = 25
    static let maxRedirects = 6
    /// Bẻ lại playlist HLS để mọi segment đi qua proxy (hết lỗi CORS).
    static let rewriteHLS = true

    // MARK: - Giao diện

    /// Kích thước thiết kế của giao diện web (bản TV 1920x1080).
    static let designWidth: CGFloat = 1920
    static let designHeight: CGFloat = 1080
    /// Tự co cho vừa màn hình iPhone (giống `window.fitToScreen` bản Windows).
    static let fitToScreen = true
    /// Giới hạn pinch-zoom.
    static let minFitScale: CGFloat = 0.15
    static let maxFitScale: CGFloat = 3.0

    // MARK: - Cầu nối JS <-> Native

    static let scriptMessageNative = "jvhdNative"
    static let scriptMessageLog = "jvhdLog"
}
