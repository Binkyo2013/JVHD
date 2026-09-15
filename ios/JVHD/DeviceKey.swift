/*
 * DeviceKey.swift
 * Khoá thiết bị ECDSA P-256:
 *   - Tạo trong Secure Enclave (nếu máy hỗ trợ), dự phòng: Keychain thường,
 *     dự phòng cuối: khoá CryptoKit lưu trong Application Support (đúng mô
 *     hình `ensureDeviceKey()` của bản Node/Windows — ghi khoá PEM ra đĩa).
 *   - Khoá riêng KHÔNG BAO GIỜ được đưa vào WebView.
 *   - d0() = base64(0x04 || X || Y)   ·   e0(data) = ECDSA(SHA-256(data)) DER/base64
 *
 * Tương đương `src/crypto-bridge.js` + libbtcore.so của bản Android/Windows.
 *
 * HỢP ĐỒNG PHẢI GIỐNG HỆT BẢN ANDROID/NODE:
 *   `ensureDeviceKey()` của Node LUÔN trả về một khoá (tạo mới + ghi file nếu
 *   chưa có) và `e0()` LUÔN trả về chữ ký. iOS phải y như vậy: d0()/e0()
 *   không bao giờ được trả về chuỗi rỗng, vì `app.js` diễn giải chuỗi rỗng là
 *   "Thiết bị không hỗ trợ xác thực, không thể tiếp tục" và chặn đăng nhập.
 */

import CryptoKit
import Foundation
import Security

final class DeviceKey {

    static let shared = DeviceKey()

    private let applicationTag = "vn.jvhd.ios.devicekey".data(using: .utf8)!
    private let lock = NSLock()
    private var cached: Backend?

    /// Chẩn đoán lần khởi tạo khoá gần nhất (đưa lên `/__native/env` để không
    /// bao giờ phải đoán mò khi đăng nhập lỗi nữa).
    private(set) var diagnostics: [String: Any] = [:]

    enum Backend {
        case secureEnclave(SecKey)
        case keychain(SecKey)
        case cryptoKit(P256.Signing.PrivateKey)

        var name: String {
            switch self {
            case .secureEnclave: return "secure-enclave"
            case .keychain: return "keychain"
            case .cryptoKit: return "cryptokit-file"
            }
        }
    }

    private init() {}

    // MARK: - Khoá riêng

    /// Trả về khoá riêng P-256 (tạo/lần đầu nếu chưa có). Không bao giờ nil
    /// trừ khi cả ba tầng dự phòng đều hỏng.
    func privateKey() -> SecKey? {
        switch backend() {
        case .secureEnclave(let key), .keychain(let key): return key
        case .cryptoKit, .none: return nil
        }
    }

    /// Khoá đang dùng + tầng dự phòng đã sinh ra nó.
    func backend() -> Backend? {
        lock.lock()
        defer { lock.unlock() }
        if let cached = cached { return cached }
        let resolved = loadExisting() ?? createKey()
        cached = resolved
        diagnostics["activeBackend"] = resolved?.name ?? "none"
        diagnostics["hasKey"] = resolved != nil
        return resolved
    }

    // MARK: - Nạp khoá đã có

    private func loadExisting() -> Backend? {
        if let key = loadKeychainKey() {
            diagnostics["loadedFrom"] = "keychain"
            return key.isSecureEnclaveBacked ? .secureEnclave(key) : .keychain(key)
        }
        if let key = loadCryptoKitKey() {
            diagnostics["loadedFrom"] = "cryptokit-file"
            return .cryptoKit(key)
        }
        return nil
    }

    private func baseQuery() -> [String: Any] {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
    }

    private func loadKeychainKey() -> SecKey? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(baseQuery() as CFDictionary, &result)
        guard status == errSecSuccess, let result = result else {
            diagnostics["loadKeychainStatus"] = Int(status)
            return nil
        }
        // CFTypeRef của một key item phải là SecKey — kiểm tra kiểu trước khi ép
        // để không bao giờ crash app chỉ vì một item lạ trong Keychain.
        guard CFGetTypeID(result) == SecKeyGetTypeID() else { return nil }
        return (result as! SecKey)
    }

    // MARK: - Tạo khoá mới (chuỗi dự phòng)

    private func createKey() -> Backend? {
        // 1) Secure Enclave — tốt nhất: khoá không thể trích xuất.
        if let key = createSecureEnclaveKey() { return .secureEnclave(key) }
        // 2) Keychain phần mềm — chạy cả trên Simulator / máy không có SE.
        if let key = createKeychainKey() { return .keychain(key) }
        // 3) CryptoKit + file trong Application Support — tương đương
        //    `ensureDeviceKey()` của bản Node (ghi khoá ra đĩa, mode 0600).
        //    Tầng này đảm bảo iOS KHÔNG BAO GIỜ hết khoá, giống Android.
        if let key = createCryptoKitKey() { return .cryptoKit(key) }
        return nil
    }

    private func createSecureEnclaveKey() -> SecKey? {
        // Thử có access control trước (khoá đòi mở máy), rồi thử không access
        // control — một số cấu hình ký IPA không cho phép SecAccessControl.
        var accessError: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        )
        if access == nil {
            diagnostics["secureEnclaveAccessControlError"] = describe(accessError)
        }

        if let access = access, let key = makeSecureEnclaveKey(accessControl: access, label: "withAccessControl") {
            return key
        }
        if let key = makeSecureEnclaveKey(accessControl: nil, label: "noAccessControl") {
            return key
        }
        return nil
    }

    private func makeSecureEnclaveKey(accessControl: SecAccessControl?, label: String) -> SecKey? {
        // Chỉ dùng đúng các khoá thuộc tính hợp lệ ở cấp cao nhất của
        // SecKeyCreateRandomKey (kSecAttrKeyType/kSecAttrKeySizeInBits/
        // kSecAttrTokenID/kSecPrivateKeyAttrs) — các khoá lạ ở cấp này khiến
        // một số bản iOS trả errSecParam.
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag
        ]
        if let accessControl = accessControl {
            privateAttrs[kSecAttrAccessControl as String] = accessControl
        } else {
            privateAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateAttrs
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            diagnostics["secureEnclave_\(label)"] = describe(error)
            return nil
        }
        diagnostics["secureEnclave_\(label)"] = "ok"
        return key
    }

    private func createKeychainKey() -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            diagnostics["keychainCreate"] = describe(error)
            return nil
        }
        diagnostics["keychainCreate"] = "ok"
        return key
    }

    // MARK: - Dự phòng cuối: CryptoKit + file (giống ensureDeviceKey của Node)

    private var keyFileURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let directory = base.appendingPathComponent("JVHD", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("device-key.bin")
    }

    private func loadCryptoKitKey() -> P256.Signing.PrivateKey? {
        let url = keyFileURL
        guard let raw = try? Data(contentsOf: url) else {
            diagnostics["cryptoKitFile"] = "not-found"
            return nil
        }
        do {
            let key = try P256.Signing.PrivateKey(rawRepresentation: raw)
            diagnostics["cryptoKitFile"] = "loaded"
            return key
        } catch {
            diagnostics["cryptoKitFile"] = "corrupt: \(error.localizedDescription)"
            return nil
        }
    }

    private func createCryptoKitKey() -> P256.Signing.PrivateKey? {
        let key = P256.Signing.PrivateKey()
        let url = keyFileURL
        do {
            try key.rawRepresentation.write(to: url, options: [.completeFileProtection])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            diagnostics["cryptoKitFile"] = "created"
        } catch {
            // Không ghi được file thì vẫn dùng khoá trong phiên chạy này —
            // thà phải bind lại còn hơn là không đăng nhập được.
            diagnostics["cryptoKitFile"] = "in-memory (\(error.localizedDescription))"
        }
        return key
    }

    // MARK: - d0(): khoá công khai

    /// base64( 0x04 || X(32) || Y(32) ) — đúng định dạng `pubKeyFormat = "raw-uncompressed-b64"`.
    /// `P256.Signing.PublicKey.rawRepresentation` của CryptoKit cũng đúng 65
    /// byte dạng này, nên cả ba tầng cho ra CHUỖI CÙNG ĐỊNH DẠNG.
    func publicKeyBase64() -> String {
        switch backend() {
        case .secureEnclave(let key), .keychain(let key):
            guard let publicKey = SecKeyCopyPublicKey(key) else {
                diagnostics["publicKeyError"] = "SecKeyCopyPublicKey thất bại"
                return ""
            }
            var error: Unmanaged<CFError>?
            guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) else {
                diagnostics["publicKeyError"] = describe(error)
                return ""
            }
            return (raw as Data).base64EncodedString()
        case .cryptoKit(let key):
            return Data(key.publicKey.rawRepresentation).base64EncodedString()
        case .none:
            diagnostics["publicKeyError"] = "không tạo được khoá thiết bị"
            return ""
        }
    }

    // MARK: - e0(): chữ ký

    /// Ký dữ liệu thô (đã decode base64) bằng SHA-256 + ECDSA, trả về DER/base64.
    /// Giống `crypto.sign('sha256', payload, key)` của bản Node: kể cả khi
    /// `message` RỖNG vẫn phải trả về một chữ ký hợp lệ.
    ///
    /// [BẢN SỬA NÀY] Đường Secure Enclave/Keychain trước đây trả NGUYÊN
    /// `(signature as Data)` — tức định dạng **ANSI X9.62** (`r||s`, 64 byte) do
    /// `SecKeyCreateSignature` sinh ra, trong khi `JVHDConfig.sigFormat` là
    /// `"der-b64"` và máy chủ xác thực kiểm bằng
    /// `crypto.createVerify("SHA256").update(data).verify(key, sig)` (chỉ đọc DER).
    /// Trên iPhone thật, khoá LUÔN nằm ở Secure Enclave, nên mọi chữ ký iOS gửi lên
    /// bị `verifySig()` trả `false`: thiết bị mới nhận `{status:"bad"}` (app báo
    /// "Phiên xác thực hết hạn…"), thiết bị đã bind nhận `denied` ("Thiết bị không
    /// khớp thiết bị đã đăng ký"). Máy build macOS không thấy được lỗi này vì ở đó
    /// SecEnclave không khả dụng, `DeviceKey` rơi xuống nhánh CryptoKit (vốn đã trả
    /// `derRepresentation`) — vì vậy bắt buộc phải có `derEncodeRS` + fixture check
    /// trong CI (tools/ios_crypto_check) thay vì chỉ trông vào probe trên runner.
    func signBase64(message: Data) -> String {
        let format = JVHDConfig.sigFormat.lowercased()
        let wantDer = !format.hasPrefix("raw")
        switch backend() {
        case .secureEnclave(let key), .keychain(let key):
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(
                key,
                .ecdsaSignatureMessageX962SHA256,
                message as CFData,
                &error
            ) else {
                diagnostics["signError"] = describe(error)
                NSLog("[JVHD][DeviceKey] ký thất bại: %@", describe(error))
                return ""
            }
            let x962 = signature as Data
            guard wantDer else { return encodeSignature(x962, format: format) }
            guard let der = JVHDCrypto.derEncodeRS(x962) else {
                let reason = "chuyển X9.62 (\(x962.count) byte) -> DER thất bại"
                diagnostics["signError"] = reason
                NSLog("[JVHD][DeviceKey] %@", reason)
                return ""
            }
            return encodeSignature(der, format: format)
        case .cryptoKit(let key):
            do {
                // `derRepresentation` đúng bằng chữ ký ASN.1 DER mà
                // `crypto.sign(...)` của Node sinh ra (sigFormat = "der-b64").
                let signature = try key.signature(for: message)
                let body: Data = wantDer
                    ? Data(signature.derRepresentation)
                    : Data(signature.rawRepresentation)
                return encodeSignature(body, format: format)
            } catch {
                diagnostics["signError"] = error.localizedDescription
                return ""
            }
        case .none:
            diagnostics["signError"] = "không có khoá thiết bị"
            return ""
        }
    }

    /// Base64 (mặc định) hoặc hex, theo hậu tố của `JVHDConfig.sigFormat`
    /// — cùng quy tắc `crypto-bridge.js` dùng cho bản Windows/Android.
    private func encodeSignature(_ body: Data, format: String) -> String {
        if format.contains("-hex") {
            return body.map { String(format: "%02x", $0) }.joined()
        }
        return body.base64EncodedString()
    }

    // MARK: - Tiện ích

    private func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error else { return "(không rõ)" }
        let cfError = error.takeRetainedValue()
        return "CFError \(CFErrorGetCode(cfError)): \(cfError.localizedDescription)"
    }
}

private extension SecKey {
    /// Khoá này có nằm trong Secure Enclave không (chỉ để ghi chẩn đoán).
    var isSecureEnclaveBacked: Bool {
        guard let attributes = SecKeyCopyAttributes(self) as? [String: Any] else { return false }
        let token = attributes[kSecAttrTokenID as String] as? String
        return token == (kSecAttrTokenIDSecureEnclave as String)
    }
}
