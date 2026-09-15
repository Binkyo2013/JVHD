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
 *   e0(base64)= DeviceKey.shared.signBase64(JVHDCrypto.decodeBase64NodeCompatible(x))
 *
 * Kết quả in ra dạng JSON một dòng (prefix `SWIFT_RESULT `) để bước Node
 * `tools/verify_swift_sig.js` kiểm chứng chữ ký bằng `crypto` của Node —
 * tức là kiểm chứng bằng CHÍNH công cụ mà bản Android/Windows dùng.
 */

import CryptoKit
import Foundation
import Security

struct NativeCryptoProbe {

    /// Bản sao đúng nguyên văn `LocalServer.swift:signChallenge(_:)`.
    static func signChallenge(_ payload: String) -> String {
        var data: Data
        if JVHDConfig.challengeEncoding == "base64" {
            data = JVHDCrypto.decodeBase64NodeCompatible(payload)
        } else if JVHDConfig.challengeEncoding == "hex" {
            data = Data(hexString: payload) ?? Data()
        } else {
            data = Data(payload.utf8)
        }
        return DeviceKey.shared.signBase64(message: data)
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

        // Khoá đang nằm ở tầng nào + các tầng đã thất bại.
        report["deviceKeyDiagnostics"] = DeviceKey.shared.diagnostics

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
        if let sigData = Data(base64Encoded: sig) {
            report["swiftVerify"] = verifyInSwift(challenge: challengeBytes, signature: sigData)
        } else {
            report["swiftVerify"] = false
        }

        // --- ĐIỂM MẤU CHỐT CỦA LỖI iOS -------------------------------------
        // `e0()` của bản Node/Windows ký được CẢ payload RỖNG (Buffer.from('',
        // 'base64') không bao giờ lỗi). iOS trước đây trả về "" -> app.js báo
        // "Thiết bị không hỗ trợ xác thực". Phải luôn có chữ ký.
        let emptySig = signChallenge("")
        report["sigForEmptyInput"] = emptySig
        report["sigForEmptyInput_isDER"] = (Data(base64Encoded: emptySig)?.first ?? 0) == 0x30
        report["swiftVerifyEmpty"] = verifyInSwift(challenge: Data(),
                                                   signature: Data(base64Encoded: emptySig) ?? Data())

        // --- Bảng đối chiếu bộ giải mã base64 với Node ---------------------
        // Node dùng Buffer.from(x,'base64') rất dễ tính; Swift phải cho ra
        // ĐÚNG TỪNG BYTE như vậy, nếu không chữ ký của iOS sẽ khác Android.
        let samples = [
            "aGVsbG8td29ybGQ=",
            "aGVsbG8td29ybGQ",
            "aGVsbG8td29ybGQ_",
            "n8Kd2-sX91_qW",
            String(repeating: "ab", count: 32),
            "",
            "!!!",
            "a",
            "ab",
            "abc",
            "abcd",
            "abcde",
            "abcdef",
            "abcdefg",
            "abcdefgh",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "dG9rZW4td2l0aC1kYXNoZXMtYW5kLW5vLXBhZGRpbmctMQ",
            "a=b=c",
            " A G V s b G 8 ",
            "QUJDRA==QQ",
            "Eqa8elAwNrjCZ8dAR5UTvU0fbJ9q7gFaiSXckN99CLc="
        ]
        var table: [String: String] = [:]
        for sample in samples {
            table[sample] = JVHDCrypto.decodeBase64NodeCompatible(sample)
                .map { String(format: "%02x", $0) }.joined()
        }
        report["nodeCompatHex"] = table

        // Mỗi mẫu cũng phải ký ra được chữ ký (không rỗng) như Node.
        var signResults: [String: Bool] = [:]
        for sample in samples { signResults[sample] = !signChallenge(sample).isEmpty }
        report["signNotEmpty"] = signResults

        let json = (try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])) ?? Data()
        print("SWIFT_RESULT " + (String(data: json, encoding: .utf8) ?? "{}"))
        return 0
    }

    /// Verify bằng khoá công khai của chính DeviceKey (mọi tầng backend).
    private static func verifyInSwift(challenge: Data, signature: Data) -> Bool {
        guard !signature.isEmpty else { return false }
        let pubB64 = DeviceKey.shared.publicKeyBase64()
        guard let raw = Data(base64Encoded: pubB64), raw.count == 65 else { return false }
        if let key = DeviceKey.shared.privateKey(), let pubKey = SecKeyCopyPublicKey(key) {
            var error: Unmanaged<CFError>?
            return SecKeyVerifySignature(pubKey, .ecdsaSignatureMessageX962SHA256,
                                         challenge as CFData, signature as CFData, &error)
        }
        // Tầng CryptoKit: dựng lại khoá công khai từ 65 byte raw.
        guard let pubKey = try? P256.Signing.PublicKey(rawRepresentation: raw) else { return false }
        guard let ecdsa = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
        return pubKey.isValidSignature(ecdsa, for: challenge)
    }

    /// Đếm số byte mà `Buffer.from(x,'base64')` của Node sẽ tạo ra (tham khảo).
    static func nodeBase64Len(_ text: String) -> Int {
        let table = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_")
        let chars = text.filter { table.contains($0) }
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
