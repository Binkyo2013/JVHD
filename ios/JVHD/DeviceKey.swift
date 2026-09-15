/*
 * DeviceKey.swift
 * Khoá thiết bị ECDSA P-256 — tương đương `BtK.pk()/BtK.sg()` của bản Android
 * (libbtcore.so + Android Keystore) và `src/crypto-bridge.js` của bản Windows.
 *
 *   d0() = base64(0x04 || X || Y)          (pubKeyFormat = "raw-uncompressed-b64")
 *   e0() = base64(ECDSA/SHA-256) theo DER  (sigFormat   = "der-b64")
 *
 * Ba nguồn khoá, thử theo thứ tự (lưu ý điểm số 3):
 *   1. Secure Enclave  — an toàn nhất, chỉ máy thật.
 *   2. Keychain thường — máy giả lập / máy không có Secure Enclave.
 *   3. Tệp trong Application Support (khoá P-256 của CryptoKit).
 *
 * Số 3 là bản sao đúng cách bản Windows làm (`ensureDeviceKey()` ghi PEM vào
 * tệp): TRƯỚC BẢN SỬA NÀY, iOS chỉ có 1 và 2. Khi Keychain không dùng được
 * (IPA không ký / ký lại bằng chứng thư cá nhân không cấp `keychain-access-groups`,
 * app bị cài đè làm đổi access group, ...) `publicKeyBase64()` trả chuỗi rỗng,
 * `LocalServer` trả 500, `ios-bridge.js` trả "" cho `d0()/e0()`, và `app.js`
 * fail-closed in ra đúng câu "Thiết bị không hỗ trợ xác thực, không thể tiếp tục"
 * — thiết bị mới không bao giờ bind được, dù tài khoản hợp lệ.
 *
 * Khóa riêng KHÔNG BAO GIỜ rời khỏi thiết bị: chỉ chữ ký và khoá công khai được
 * gửi đi. Tệp khoá được ghi với Data Protection `completeUnlessOpen` và chỉ
 * đọc được bởi đúng app này.
 */

import Foundation
import Security
import CryptoKit

final class DeviceKey {

    static let shared = DeviceKey()

    // MARK: Trạng thái (phục vụ chẩn đoán — xem /__native/diag)

    enum Backend: String {
        case secureEnclave = "secure-enclave"
        case keychain = "keychain"
        case file = "file"
        case none = "none"
    }

    private let lock = NSLock()
    private let applicationTag = "vn.jvhd.ios.devicekey".data(using: .utf8)!
    private let fileName = "jvhd-device-key.raw"

    /// Khoá lấy từ Keychain (Secure Enclave hoặc Keychain thường).
    private var cachedKey: SecKey?
    /// Khoá dự phòng lưu trong tệp (CryptoKit), chỉ dùng khi Keychain hỏng.
    private var cachedFileKey: P256.Signing.PrivateKey?
    private var didTryFileKey = false

    private(set) var backend: Backend = .none
    private(set) var lastError: String = ""

    private init() {}

    // MARK: - Đường dẫn tệp khoá dự phòng

    private var keyFileURL: URL? {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let directory = support.appendingPathComponent("JVHD", isDirectory: true)
        if !FileManager.default.fileExists(atPath: directory.path) {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        return directory.appendingPathComponent(fileName)
    }

    // MARK: - Keychain / Secure Enclave

    /// Trả về khoá riêng P-256 trong Secure Enclave/Keychain, tạo mới nếu chưa có.
    /// Trả nil khi Keychain không dùng được — khi đó còn tệp khoá dự phòng.
    func privateKey() -> SecKey? {
        lock.lock()
        defer { lock.unlock() }
        if let cached = cachedKey { return cached }
        let key = loadKey(requiringSecureEnclave: true)
            ?? loadKey(requiringSecureEnclave: false)
            ?? createKey()
        cachedKey = key
        return key
    }

    private func baseQuery(requiringSecureEnclave: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if requiringSecureEnclave {
            query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        return query
    }

    private func loadKey(requiringSecureEnclave: Bool) -> SecKey? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(baseQuery(requiringSecureEnclave: requiringSecureEnclave) as CFDictionary, &result)
        guard status == errSecSuccess, let found = result else { return nil }
        // `as! SecKey` từng làm crash app nếu Keychain trả về đối tượng khác;
        // ở đây ép kiểu an toàn và ghi lại lý do.
        guard let key = found as? SecKey else {
            lastError = "keychain trả về đối tượng không phải SecKey"
            return nil
        }
        if requiringSecureEnclave { backend = .secureEnclave } else { backend = .keychain }
        return key
    }

    private func createKey() -> SecKey? {
        // Thử Secure Enclave trước (chỉ có trên máy thật).
        if let secureEnclaveKey = createSecureEnclaveKey() {
            backend = .secureEnclave
            return secureEnclaveKey
        }
        let enclaveError = lastError
        // Dự phòng: khoá Keychain thường (chạy được cả trên Simulator).
        if let keychainKey = createKeychainKey() {
            backend = .keychain
            return keychainKey
        }
        lastError = "không tạo được khoá trong Keychain (Secure Enclave: \(enclaveError); Keychain: \(lastError))"
        return nil
    }

    private func createSecureEnclaveKey() -> SecKey? {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            lastError = "SecAccessControl lỗi: \describe(accessError)"
            return nil
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrIsPermanent as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            lastError = "SecKeyCreateRandomKey(Secure Enclave) lỗi: \describe(error)"
            return nil
        }
        return key
    }

    private func createKeychainKey() -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrIsPermanent as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            lastError = "SecKeyCreateRandomKey(Keychain) lỗi: \describe(error)"
            return nil
        }
        return key
    }

    private func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "không rõ" }
        let ns = error as NSError
        return "\(ns.domain)#\(ns.code)"
    }

    private func describe(_ error: Error) -> String {
        let ns = error as NSError
        return "\(ns.domain)#\(ns.code)"
    }

    // MARK: - Tệp khoá dự phòng (giống cách bản Windows giữ file PEM)

    /// Khoá P-256 trong tệp. Tạo tệp ở lần chạy đầu; các lần sau đọc lại để
    /// khoá KHÔNG đổi (nếu đổi, máy chủ sẽ báo "thiết bị không khớp").
    private func fileKey() -> P256.Signing.PrivateKey? {
        lock.lock()
        defer { lock.unlock() }
        if let cached = cachedFileKey { return cached }
        if didTryFileKey { return nil }
        didTryFileKey = true

        guard let url = keyFileURL else {
            lastError = "không tìm được Application Support để lưu khoá dự phòng"
            return nil
        }

        if let saved = try? Data(contentsOf: url), saved.count == 32 {
            do {
                let key = try P256.Signing.PrivateKey(rawRepresentation: saved)
                cachedFileKey = key
                backend = .file
                return key
            } catch {
                lastError = "tệp khoá hỏng, tạo lại: \describe(error)"
            }
        }

        // Tạo khoá mới rồi ghi tệp. Chỉ ghi khi đọc-ghi an toàn (Data Protection).
        let fresh = P256.Signing.PrivateKey()
        do {
            var mutableURL = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? mutableURL.setResourceValues(values)
            try fresh.rawRepresentation.write(to: mutableURL, options: .atomic)
            try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUnlessOpen],
                                                   ofItemAtPath: mutableURL.path)
            cachedFileKey = fresh
            backend = .file
            return fresh
        } catch {
            lastError = "không ghi được tệp khoá dự phòng"
            return nil
        }
    }

    // MARK: - d0(): khoá công khai

    /// base64( 0x04 || X(32) || Y(32) ) — `pubKeyFormat = "raw-uncompressed-b64"`,
    /// đúng 65 byte mà máy chủ kiểm tra (`pubFromRaw`: length==65 && raw[0]==4).
    func publicKeyBase64() -> String {
        if let privateKey = privateKey() {
            if let publicKey = SecKeyCopyPublicKey(privateKey),
               let raw = SecKeyCopyExternalRepresentation(publicKey, nil) {
                let data = raw as Data
                if data.count == 65, data.first == 0x04 {
                    return data.base64EncodedString()
                }
                lastError = "Secure Enclave/Keychain trả khoá công khai \(data.count) byte (cần 65)"
            }
        }
        if let key = fileKey() {
            // x963Representation của CryptoKit chính là 0x04 || X || Y.
            let data = key.publicKey.x963Representation
            if data.count == 65, data.first == 0x04 {
                return (data as Data).base64EncodedString()
            }
            lastError = "khoá tệp trả khoá công khai \(data.count) byte (cần 65)"
        }
        if lastError.isEmpty { lastError = "không có khoá thiết bị" }
        NSLog("[JVHD][DeviceKey] d0() thất bại: %@", lastError)
        return ""
    }

    // MARK: - e0(): chữ ký

    /// Định dạng chữ ký theo `JVHDConfig.sigFormat`, trả base64 (hoặc hex).
    ///
    /// Điều QUAN TRỌNG nhất của hàm này: `SecKeyCreateSignature` chỉ tạo được
    /// chữ ký dạng **ANSI X9.62** (nối `r||s`, 64 byte), trong khi máy chủ xác
    /// thực và bản Android/Windows dùng **ASN.1 DER** (`der-b64`;
    /// `tools/tool.js selfcheck` kiểm bằng `verify(..., "der")`). Nếu gửi nguyên
    /// X9.62 thì `verifySig()` của server LUÔN trả false -> mọi lần đăng nhập iOS
    /// bị từ chối. Vì vậy ở đây chuyển X9.62 -> DER (xem `JVHDCrypto.derEncodeRS`).
    func signatureBase64(message: Data) -> String {
        let format = JVHDConfig.sigFormat.lowercased()
        let wantDer = !format.hasPrefix("raw")

        if let key = privateKey() {
            var error: Unmanaged<CFError>?
            let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
            if let signature = SecKeyCreateSignature(key, algorithm, message as CFData, &error) {
                let body = signature as Data
                if wantDer {
                    if let der = JVHDCrypto.derEncodeRS(body) {
                        return encodeSignature(der, format: format)
                    }
                    lastError = "chuyển X9.62 -> DER thất bại (\(body.count) byte)"
                } else {
                    return encodeSignature(body, format: format)
                }
            } else {
                lastError = "SecKeyCreateSignature lỗi: \describe(error)"
            }
        }

        if let key = fileKey() {
            do {
                let signature = try key.signature(for: message)
                let body: Data = wantDer
                    ? (signature.derRepresentation as Data)
                    : (signature.rawRepresentation as Data)
                return encodeSignature(body, format: format)
            } catch {
                lastError = "CryptoKit ký thất bại: \describe(error)"
            }
        }

        if lastError.isEmpty { lastError = "không có khoá để ký" }
        NSLog("[JVHD][DeviceKey] e0() thất bại: %@", lastError)
        return ""
    }

    private func encodeSignature(_ body: Data, format: String) -> String {
        if format.contains("-hex") {
            return body.map { String(format: "%02x", $0) }.joined()
        }
        return body.base64EncodedString()
    }

    /// Bản tin chẩn đoán cho `/__native/diag`.
    func statusDictionary() -> [String: Any] {
        let publicValue = publicKeyBase64()
        let probe = signatureBase64(message: Data("jvhd-self-probe".utf8))
        var info: [String: Any] = [
            "backend": backend.rawValue,
            "keychainAvailable": privateKey() != nil,
            "fileFallback": backend == .file,
            "pubkeyBytes": Data(base64Encoded: publicValue)?.count ?? 0,
            "pubkeyPrefix": String(publicValue.prefix(8)),
            "sigFormat": JVHDConfig.sigFormat,
            "signDigest": JVHDConfig.signDigest,
            "challengeEncoding": JVHDConfig.challengeEncoding,
            "signatureOk": !probe.isEmpty,
            "signatureBytes": probe.isEmpty ? 0 : (Data(base64Encoded: probe)?.count ?? -1),
            "lastError": lastError.isEmpty ? "không có lỗi" : lastError
        ]
        // Chữ ký DER hợp lệ phải bắt đầu bằng 0x30 (SEQUENCE) — kiểm tại chỗ để
        // phát hiện ngay nếu định dạng lại lệch so với server.
        if let decoded = Data(base64Encoded: probe), let first = decoded.first {
            info["signatureIsDer"] = (first == 0x30)
        } else {
            info["signatureIsDer"] = false
        }
        return info
    }
}
