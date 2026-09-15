/*
 * tools/ios_crypto_check/main.swift
 * ============================================================================
 * Chạy trong CI (workflow build-ipa.yml, bước "Tự kiểm thuật toán iOS").
 *
 * Mã được kiểm: `JVHDCrypto.derEncodeRS()`, `derDecodeRS()`,
 * `decodeBase64NodeLike()` — tức hai phần BẢN iOS từng thiếu so với Android:
 *   · đóng gói chữ ký X9.62 (r||s) thành ASN.1 DER mà máy chủ verifySig() chấp nhận
 *   · giải mã base64 theo đúng luật Buffer.from(text,'base64') của Node
 *
 * Số liệu đối chiếu: test/der_fixtures.json, do `node test/gen_der_fixtures.js`
 * sinh từ Node/OpenSSL (không sinh bởi code iOS) — xem ghi chú trong file đó.
 *
 * Cách chạy cục bộ (máy macOS):
 *   xcrun swiftc ios/JVHD/Crypto.swift tools/ios_crypto_check/main.swift -o /tmp/check
 *   /tmp/check test/der_fixtures.json
 */

import Foundation

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data("[ios-crypto-check] LỖI: " + message + "\n".utf8))
    exit(1)
}

func hexToData(_ text: String) -> Data? {
    let characters = Array(text)
    guard !characters.isEmpty, characters.count % 2 == 0 else { return nil }
    var bytes: [UInt8] = []
    var index = 0
    while index < characters.count {
        var value = 0
        for step in 0..<2 {
            guard let digit = Int(String(characters[index + step]), radix: 16) else { return nil }
            value = value * 16 + digit
        }
        bytes.append(UInt8(value))
        index += 2
    }
    return Data(bytes)
}

func hexOf(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

let argument = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "test/der_fixtures.json"
guard let fileData = FileManager.default.contents(atPath: argument),
      let root = try? JSONSerialization.jsonObject(with: fileData) as? [String: Any] else {
    die("không đọc được fixture tại " + argument)
}

var problems = 0

// ---------------------------------------------------------------- chữ ký DER
guard let signatures = root["signatures"] as? [[String: Any]], !signatures.isEmpty else {
    die("fixture không có mục 'signatures'")
}
for item in signatures {
    let name = item["name"] as? String ?? "(khuyết tên)"
    guard let raw = hexToData(item["raw"] as? String ?? "") else { die("mẫu \(name): 'raw' không phải hex") }
    guard let expected = hexToData(item["der"] as? String ?? "") else { die("mẫu \(name): 'der' không phải hex") }

    guard let encoded = JVHDCrypto.derEncodeRS(raw) else {
        problems += 1
        print("  LECH  \(name): derEncodeRS trả nil")
        continue
    }
    if encoded != expected {
        problems += 1
        print("  LECH  \(name): DER Swift sinh ra ≠ fixture")
        print("        swift   = \(hexOf(encoded))")
        print("        fixture = \(hexOf(expected))")
    }
    // Round-trip: đọc lại DER phải ra đúng (r||s) ban đầu — cả với DER của fixture.
    if JVHDCrypto.derDecodeRS(encoded) != raw {
        problems += 1
        print("  LECH  \(name): derDecodeRS(derEncodeRS(r||s)) != r||s")
    }
    if JVHDCrypto.derDecodeRS(expected) != raw {
        problems += 1
        print("  LECH  \(name): derDecodeRS(DER của Node) != r||s")
    }
}
print("Chữ ký: \(signatures.count) mẫu (r||s ↔ ASN.1 DER) — \(problems == 0 ? "khớp hết" : "CÓ LỆCH")")

// --------------------------------------------------------------------- base64
var base64Problems = 0
if let cases = root["base64"] as? [[String: Any]] {
    for item in cases {
        let name = item["name"] as? String ?? "(khuyết tên)"
        let input = item["input"] as? String ?? ""
        let expectedHex = item["out"] as? String ?? ""
        // Node trả về buffer rỗng cho nhiều chuỗi (hex ""), đó là giá trị hợp lệ.
        let expected: Data = expectedHex.isEmpty ? Data() : (hexToData(expectedHex) ?? Data())
        let decoded = JVHDCrypto.decodeBase64NodeLike(input)
        if decoded != expected {
            base64Problems += 1
            print("  LECH  \(name): input=\(String(reflecting: input))")
            print("        swift   = \(hexOf(decoded))")
            print("        node    = \(hexOf(expected))")
        }
    }
    print("Base64: \(cases.count) mẫu theo luật Buffer.from(text,'base64') — \(base64Problems == 0 ? "khớp hết" : "CÓ LỆCH")")
} else {
    print("Base64: fixture không có mục 'base64' (bỏ qua)")
}

if problems + base64Problems > 0 {
    die("\(problems + base64Problems) mẫu không khớp chuẩn Node/OpenSSL")
}
print("[ios-crypto-check] OK — thuật toán DER/base64 của bản iOS khớp chuẩn Node/OpenSSL.")
