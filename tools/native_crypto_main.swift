/*
 * tools/native_crypto_main.swift
 * ---------------------------------------------------------------------------
 * BỘ KIỂM TRA NATIVE (chạy trên macOS/Xcode của GitHub Actions).
 *
 * Nạp THẬT `ios/JVHD/Config.swift`, `ios/JVHD/Crypto.swift` và
 * `ios/JVHD/DeviceKey.swift` — đúng ba tệp được đóng gói vào IPA — rồi chạy
 * lại chính xác những gì `LocalServer.swift` làm cho `/__native/d0` và
 * `/__native/e0`:
 *
 *   d0()      = DeviceKey.shared.publicKeyBase64()
 *   e0(base64)= DeviceKey.shared.signBase64(JVHDCrypto.decodeBase64Loose(x))
 *
 * Kết quả in ra dạng JSON một dòng (prefix `SWIFT_RESULT `) để bước Node
 * `tools/verify_swift_sig.js` kiểm chứng chữ ký bằng `crypto` của Node —
 * tức là kiểm chứng bằng CHÍNH công cụ mà bản Android/Windows dùng.
 */

import Foundation
import Security

struct NativeCryptoProbe {

    /// Bản sao đúng nguyên văn `LocalServer.swift:signChallenge(_:)`.
    static func signChallenge(_ payload: String) -> String {
        var data: Data?
        if JVHDConfig.challengeEncoding == "base64" {
            data = JVHDCrypto.decodeBase64Loose(payload)
        } else if JVHDConfig.challengeEncoding == "hex" {
            data = Data(hexString: payload)
        } else {
            data = Data(payload.utf8)
        }
        guard let message = data else { return "" }
        return DeviceKey.shared.signBase64(message: message)
    }

    static func run() -> Int {
        var report: [String: Any] = [:]
        report["concat"] = JVHDConfig.concat
        report["salt"] = JVHDConfig.salt
        report["challengeEncoding"] = JVHDConfig.challengeEncoding
        report["pubKeyFormat"] = JVHDConfig.pubKeyFormat
        report["sigFormat"] = JVHDConfig.sigFormat

        // --- d0(): khoá công khai -------------------------------------------
        let pub = DeviceKey.shared.publicKeyBase64()
        report["d0"] = pub
        if let raw = Data(base64Encoded: pub) {
            report["d0_bytes"] = raw.count
            report["d0_firstByte"] = raw.isEmpty ? -1 : Int(raw[0])
        } else {
            report["d0_bytes"] = 0
        }
        // c0() phải khớp test vector jsonbin (Admin2).
        report["c0_Admin2"] = JVHDCrypto.c0("Admin2")

        // --- e0(): ký challenge ---------------------------------------------
        let challengeBytes = Data((0..<32).map { UInt8($0) })
        let challengeB64 = challengeBytes.base64EncodedString()
        report["challenge"] = challengeB64
        let sig = signChallenge(challengeB64)
        report["sig"] = sig
        if let sigRaw = Data(base64Encoded: sig) {
            report["sig_bytes"] = sigRaw.count
            // DER ECDSA luôn bắt đầu bằng SEQUENCE (0x30).
            report["sig_isDER"] = !sigRaw.isEmpty && sigRaw[0] == 0x30
        } else {
            report["sig_bytes"] = 0
        }

        // Tự kiểm chứng ngay trong Swift (khoá công khai + chữ ký vừa tạo).
        if let key = DeviceKey.shared.privateKey(),
           let pubKey = SecKeyCopyPublicKey(key),
           let sigData = Data(base64Encoded: sig) {
            var error: Unmanaged<CFError>?
            report["swiftVerify"] = SecKeyVerifySignature(
                pubKey, .ecdsaSignatureMessageX962SHA256, challengeBytes as CFData, sigData as CFData, &error)
        } else {
            report["swiftVerify"] = false
        }

        // --- Các định dạng challenge khác mà server CÓ THỂ gửi --------------
        // Node dùng Buffer.from(x,'base64') rất dễ tính; Swift trả rỗng nếu
        // không decode được -> e0 rỗng -> app.js báo "Thiết bị không hỗ trợ
        // xác thực". Bảng này phơi bày đúng khác biệt đó.
        var leniency: [String: Any] = [:]
        let samples: [(String, String)] = [
            ("base64 chuẩn", "aGVsbG8td29ybGQ="),
            ("base64 thiếu đệm '='", "aGVsbG8td29ybGQ"),
            ("base64url", "aGVsbG8td29ybGQ_"),
            ("hex 64 ký tự", String(repeating: "ab", count: 32)),
            ("chuỗi ngẫu nhiên thường", "n8Kd2-sX91_qW"),
            ("chuỗi rỗng", "")
        ]
        for (label, sample) in samples {
            let decoded = JVHDCrypto.decodeBase64Loose(sample)
            let signed = signChallenge(sample)
            leniency[label] = [
                "sample": sample,
                "swiftDecodedBytes": decoded?.count ?? -1,
                "swiftSigEmpty": signed.isEmpty,
                "nodeDecodedBytes": nodeBase64Len(sample)
            ]
        }
        report["leniency"] = leniency

        let json = (try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])) ?? Data()
        print("SWIFT_RESULT " + (String(data: json, encoding: .utf8) ?? "{}"))
        return 0
    }

    /// Đếm số byte mà `Buffer.from(x,'base64')` của Node sẽ tạo ra.
    /// Node bỏ qua mọi ký tự ngoài bảng base64 và không đòi đệm '='.
    static func nodeBase64Len(_ text: String) -> Int {
        let table = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        let chars = text.filter { table.contains($0) }
        // Node giải mã theo từng nhóm 4 ký tự; nhóm cuối 1 ký tự bị bỏ.
        let groups = chars.count / 4
        let rest = chars.count % 4
        var bytes = groups * 3
        if rest == 2 { bytes += 1 }
        else if rest == 3 { bytes += 2 }
        return bytes
    }
}

@main
enum Main {
    static func main() {
        exit(Int32(NativeCryptoProbe.run()))
    }
}

// `Data(hexString:)` nằm trong LocalServer.swift (không nạp ở đây) — nạp lại
// nguyên văn để `signChallenge` biên dịch được và hành vi y hệt.
extension Data {
    init?(hexString: String) {
        let text = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        let length = text.count
        guard length % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length / 2)
        var index = text.startIndex
        for _ in 0..<(length / 2) {
            let next = text.index(index, offsetBy: 2)
            guard let value = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(value)
            index = next
        }
        self = Data(bytes)
    }
}
