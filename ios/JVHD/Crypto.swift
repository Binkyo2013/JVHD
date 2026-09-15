/*
 * Crypto.swift
 * c0(name) = SHA-256( name.trim().lowercased() + salt ) — khớp 100% bản
 * Node.js (`src/crypto-bridge.js`) và libbtcore.so bản gốc.
 *
 * Ba hàm định dạng dưới đây là chỗ BẢN iOS từng lệch hợp đồng Android/server:
 *   · decodeBase64NodeCompatible() — mô phỏng đúng `Buffer.from(text,'base64')`
 *     mà bản Windows/Android dùng cho challenge: KHÔNG "hỏng" khi chuỗi rỗng hoặc
 *     có ký tự lạ, chuỗi rỗng vẫn ký được như Node. (Thêm ở PR trước.)
 *   · derEncodeRS()          — đóng gói chữ ký ANSI X9.62 (r||s do
 *     `SecKeyCreateSignature` sinh ra) thành ASN.1 DER như `sigFormat:"der-b64"`.
 *   · derDecodeRS()          — chiều ngược lại, dùng cho tự kiểm tra round-trip.
 * Ba hàm này là mã thuần (không phụ thuộc Keychain) nên được CI kiểm bằng
 * fixture sinh từ Node/OpenSSL: xem test/gen_der_fixtures.js +
 * tools/ios_crypto_check/.
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
    ///
    /// CHỈ dùng cho những giá trị mà app tự sinh ra (tham số `u=` của proxy),
    /// nơi trả về `nil` khi dữ liệu sai là hành vi mong muốn.
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

    // MARK: - Base64 tương thích TUYỆT ĐỐI với Node

    /// Bảng chữ cái base64 mà `Buffer.from(x, 'base64')` của Node chấp nhận,
    /// kèm cả biến thể URL-safe ('-' -> 62, '_' -> 63).
    private static let base64Values: [UInt8: UInt8] = {
        var table: [UInt8: UInt8] = [:]
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
        for (index, character) in alphabet.enumerated() { table[character] = UInt8(index) }
        table[UInt8(ascii: "-")] = 62
        table[UInt8(ascii: "_")] = 63
        return table
    }()

    /// Giải mã base64 THEO ĐÚNG NGỮ NGHĨA `Buffer.from(text, 'base64')` của
    /// Node.js — hàm mà bản Windows/Android dùng trong
    /// `src/crypto-bridge.js:e0()`.
    ///
    /// Ngữ nghĩa của Node (đã kiểm chứng bằng `node -e`):
    ///   · bỏ qua MỌI ký tự không thuộc bảng chữ cái base64 (kể cả khoảng trắng);
    ///   · chấp nhận cả '-'/'_' (URL-safe);
    ///   · dừng ngay tại dấu '=' đầu tiên (phần đệm);
    ///   · nhóm cuối chỉ có 1 ký tự thì bị bỏ;
    ///   · KHÔNG BAO GIỜ báo lỗi — chuỗi rỗng cho ra `Data()` rỗng.
    ///
    /// Vì sao bắt buộc phải có hàm này:
    /// `Data(base64Encoded:)` của Foundation THẤT BẠI (trả nil) với chuỗi rỗng
    /// hoặc chuỗi có ký tự lạ, trong khi Node vẫn trả về một vùng nhớ (có thể
    /// rỗng) và `crypto.sign` vẫn ký được. Hệ quả là `e0()` của iOS trả về ""
    /// -> `app.js` coi là "thiết bị không hỗ trợ xác thực" và chặn đăng nhập,
    /// còn Android vẫn ký và đăng nhập bình thường.
    static func decodeBase64NodeCompatible(_ text: String) -> Data {
        var sextets = [UInt8]()
        sextets.reserveCapacity(text.utf8.count)
        for byte in text.utf8 {
            // Dừng tại dấu '=' đầu tiên, giống hệt Node.
            if byte == UInt8(ascii: "=") { break }
            if let value = base64Values[byte] { sextets.append(value) }
        }
        // Node sinh ra đúng floor(số_sextet * 6 / 8) byte:
        //   1 sextet -> 0 byte · 2 -> 1 byte · 3 -> 2 byte · 4 -> 3 byte.
        let byteCount = (sextets.count * 6) / 8
        var out = Data(count: byteCount)
        var bitBuffer = 0
        var bitsInBuffer = 0
        var written = 0
        for sextet in sextets {
            bitBuffer = (bitBuffer << 6) | Int(sextet)
            bitsInBuffer += 6
            while bitsInBuffer >= 8 && written < byteCount {
                bitsInBuffer -= 8
                out[written] = UInt8((bitBuffer >> bitsInBuffer) & 0xff)
                written += 1
            }
        }
        return out
    }

    static func encodeBase64(_ text: String) -> String {
        return Data(text.utf8).base64EncodedString()
    }

    // MARK: - Định dạng chữ ký ECDSA (X9.62 <-> DER)

    /// INTEGER ASN.1 tối thiểu: bỏ 0 đệm thừa, thêm 0x00 nếu byte cao có bit dấu.
    private static func derInteger(_ value: [UInt8]) -> [UInt8] {
        var bytes = value
        while bytes.count > 1, bytes.first == 0x00 { bytes.removeFirst() }
        if let first = bytes.first, (first & 0x80) != 0 { bytes.insert(0x00, at: 0) }
        return [0x02] + derLength(bytes.count) + bytes
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 0x80 { return [UInt8(length)] }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [UInt8(0x80 | bytes.count)] + bytes
    }

    /// ANSI X9.62 (`r||s`, mỗi thành phần 32 byte với P-256) -> ASN.1 DER.
    /// Đây là bước mà BẢN iOS còn thiếu trên máy thật: `SecKeyCreateSignature`
    /// chỉ xuất X9.62, còn máy chủ và bản Android/Windows dùng DER.
    static func derEncodeRS(_ raw: Data) -> Data? {
        let bytes = [UInt8](raw)
        guard bytes.count >= 8, bytes.count % 2 == 0 else { return nil }
        let half = bytes.count / 2
        let body = derInteger(Array(bytes[0..<half])) + derInteger(Array(bytes[half..<bytes.count]))
        return Data([0x30] + derLength(body.count) + body)
    }

    /// ASN.1 DER -> `r||s` (mỗi thành phần `width` byte). Dùng để tự kiểm tra.
    static func derDecodeRS(_ der: Data, width: Int = 32) -> Data? {
        let bytes = [UInt8](der)
        guard bytes.count > 2, bytes[0] == 0x30 else { return nil }
        var position = 1
        var total = Int(bytes[position]); position += 1
        if (total & 0x80) != 0 {
            let countOfLength = (total & 0x7f)
            guard countOfLength > 0, countOfLength <= 3, position + countOfLength <= bytes.count else { return nil }
            total = 0
            for _ in 0..<countOfLength {
                total = (total << 8) | Int(bytes[position]); position += 1
            }
        }
        guard position + total <= bytes.count else { return nil }
        let end = position + total

        var parts: [[UInt8]] = []
        for _ in 0..<2 {
            guard position < end, bytes[position] == 0x02 else { return nil }
            position += 1
            guard position < end else { return nil }
            var length = Int(bytes[position]); position += 1
            if (length & 0x80) != 0 {
                let countOfLength = (length & 0x7f)
                guard countOfLength > 0, countOfLength <= 3, position + countOfLength <= end else { return nil }
                length = 0
                for _ in 0..<countOfLength {
                    length = (length << 8) | Int(bytes[position]); position += 1
                }
            }
            guard length >= 0, position + length <= end else { return nil }
            parts.append(Array(bytes[position..<(position + length)]))
            position += length
        }
        guard position == end else { return nil }

        var output: [UInt8] = []
        for part in parts {
            var value = part
            while value.count > 1, value.first == 0x00 { value.removeFirst() }
            if value.count > width { return nil }
            output.append(contentsOf: [UInt8](repeating: 0, count: width - value.count))
            output.append(contentsOf: value)
        }
        return Data(output)
    }
}
