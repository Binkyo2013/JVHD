/*
 * tools/ios_crypto_check/main.swift
 * ============================================================================
 * Chạy trong CI (workflow build-ipa.yml, bước "Kiểm thuật toán iOS").
 *
 * Mã được kiểm: `JVHDCrypto.derEncodeRS()`, `derDecodeRS()` và
 * `decodeBase64NodeCompatible()` — định dạng chữ ký (X9.62 -> ASN.1 DER) và
 * luật base64 kiểu Node mà BẢN iOS phải khớp với Android/máy chủ:
 *
 *   · máy chủ verifySig() = `crypto.createVerify("SHA256")…verify(key, sig)`
 *     CHỈ đọc DER; `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)`
 *     lại chỉ xuất X9.62 (r||s) -> bắt buộc có bước chuyển, và bước này
 *     KHÔNG thể kiểm trên runner macOS bằng probe DeviceKey (ở đó Secure
 *     Enclave không tồn tại nên luôn rơi xuống nhánh CryptoKit vốn đã trả
 *     `derRepresentation`). Vì vậy kiểm trực tiếp hàm chuyển đổi.
 *
 * Số liệu đối chiếu: `test/der_fixtures.json` do `node test/gen_der_fixtures.js`
 * sinh từ Node/OpenSSL — fixture bị loại nếu DER của nó không pass đúng
 * `verify` của server, nên chuẩn không đến từ code iOS.
 *
 * Cách chạy thủ công trên máy Mac:
 *   swiftc -O ios/JVHD/Config.swift ios/JVHD/Crypto.swift \
 *     tools/ios_crypto_check/main.swift -o /tmp/ios_crypto_check
 *   /tmp/ios_crypto_check test/der_fixtures.json
 */

import Foundation

enum IOSCryptoCheck {

    private static func die(_ message: String) -> Never {
        FileHandle.standardError.write(Data("[ios-crypto-check] LỖI: " + message + "\n".utf8))
        exit(1)
    }

    private static func hexToData(_ text: String) -> Data? {
        let characters = Array(text)
        guard !characters.isEmpty, characters.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(characters.count / 2)
        var index = 0
        while index < characters.count {
            guard let value = UInt8(String(characters[index]) + String(characters[index + 1]), radix: 16) else { return nil }
            bytes.append(value)
            index += 2
        }
        return Data(bytes)
    }

    private static func hexOf(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }

    static func run() -> Int32 {
        let argument = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "test/der_fixtures.json"
        guard let fileData = FileManager.default.contents(atPath: argument) else {
            die("không đọc được fixture tại " + argument)
        }
        guard let object = try? JSONSerialization.jsonObject(with: fileData, options: []) else {
            die("fixture không phải JSON hợp lệ")
        }
        guard let root = object as? [String: Any] else {
            die("fixture phải là một object JSON")
        }

        var problems = 0

        // ------------------------------------------------------ chữ ký X9.62↔DER
        guard let signatures = root["signatures"] as? [[String: Any]], !signatures.isEmpty else {
            die("fixture không có mục 'signatures'")
        }
        for item in signatures {
            let name = item["name"] as? String ?? "(khuyết tên)"
            guard let raw = hexToData(item["raw"] as? String ?? "") else {
                die("mẫu \(name): trường 'raw' không phải hex")
            }
            guard let expected = hexToData(item["der"] as? String ?? "") else {
                die("mẫu \(name): trường 'der' không phải hex")
            }
            guard let encoded = JVHDCrypto.derEncodeRS(raw) else {
                problems += 1
                print("  LỖI  \(name): derEncodeRS trả nil")
                continue
            }
            if encoded != expected {
                problems += 1
                print("  LỆCH  \(name): DER Swift sinh ra ≠ fixture chuẩn OpenSSL")
                print("        swift   = \(hexOf(encoded))")
                print("        fixture = \(hexOf(expected))")
            }
            // Round-trip phải đúng theo CẢ HAI đường: DER do Swift sinh và DER
            // do Node sinh (fixture) — nếu một trong hai đọc sai thì server sẽ
            // không verify được chữ ký của iOS.
            if JVHDCrypto.derDecodeRS(encoded) != raw {
                problems += 1
                print("  LỆCH  \(name): derDecodeRS(derEncodeRS(r||s)) != r||s")
            }
            if JVHDCrypto.derDecodeRS(expected) != raw {
                problems += 1
                print("  LỆCH  \(name): derDecodeRS(DER của Node) != r||s")
            }
        }
        let signatureVerdict = problems == 0 ? "khớp hết" : "CÓ LỆCH"
        print("Chữ ký: \(signatures.count) mẫu (r||s ↔ ASN.1 DER) — \(signatureVerdict)")

        // ---------------------------------------------------------------- base64
        var base64Problems = 0
        if let cases = root["base64"] as? [[String: Any]], !cases.isEmpty {
            for item in cases {
                let name = item["name"] as? String ?? "(khuyết tên)"
                let input = item["input"] as? String ?? ""
                let expectedHex = item["out"] as? String ?? ""
                // Node trả buffer rỗng cho nhiều chuỗi (hex "") — đó là giá trị hợp lệ.
                let expected: Data = expectedHex.isEmpty ? Data() : (hexToData(expectedHex) ?? Data())
                let decoded = JVHDCrypto.decodeBase64NodeCompatible(input)
                if decoded != expected {
                    base64Problems += 1
                    print("  LỆCH  \(name): input = \(String(reflecting: input))")
                    print("        swift = \(hexOf(decoded))")
                    print("        node  = \(hexOf(expected))")
                }
            }
            let base64Verdict = base64Problems == 0 ? "khớp hết" : "CÓ LỆCH"
            print("Base64: \(cases.count) mẫu theo luật Buffer.from(text,'base64') — \(base64Verdict)")
        } else {
            print("Base64: fixture không có mục 'base64' (bỏ qua)")
        }

        if problems + base64Problems > 0 {
            print("[ios-crypto-check] THẤT BẠI: \(problems + base64Problems) mẫu không khớp chuẩn Node/OpenSSL")
            return 1
        }
        print("[ios-crypto-check] OK — thuật toán DER/base64 của bản iOS khớp chuẩn Node/OpenSSL.")
        return 0
    }
}

// Một lệnh duy nhất ở top-level (giống tools/native_crypto_main.swift) để tránh
// mọi ràng buộc của "top-level code" trong Swift.
exit(IOSCryptoCheck.run())
