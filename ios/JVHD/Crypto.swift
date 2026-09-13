/*
 * Crypto.swift
 * c0(name) = SHA-256( name.trim().lowercased() + salt ) — khớp 100% bản
 * Node.js (`src/crypto-bridge.js`) và libbtcore.so bản gốc.
 *
 * Chữ ký (e0) nằm trong DeviceKey.swift vì cần khoá riêng trong
 * Secure Enclave.
 */

import Foundation
import CryptoKit

enum JVHDCrypto {

    static func sha256Hex(_ text: String) -> String {
        let digest = SHA256.hash(data: Data(text.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// c0(): cùng công thức với bản Windows — trim + lowercase, rồi nối salt.
    static func c0(_ rawName: String) -> String {
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let salt = JVHDConfig.salt
        let payload = JVHDConfig.concat == "prefix" ? (salt + name) : (name + salt)
        return sha256Hex(payload)
    }

    // MARK: - Base64

    /// Giải mã base64 "dễ tính" giống Buffer.from(x, 'base64') của Node:
    /// chấp nhận cả biến thể URL-safe và thiếu đệm '='.
    static func decodeBase64Loose(_ text: String) -> Data? {
        var cleaned = text
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = cleaned.count % 4
        if remainder > 0 {
            cleaned.append(String(repeating: "=", count: 4 - remainder))
        }
        guard let data = Data(base64Encoded: cleaned), !data.isEmpty else { return nil }
        return data
    }

    static func encodeBase64(_ text: String) -> String {
        return Data(text.utf8).base64EncodedString()
    }
}
