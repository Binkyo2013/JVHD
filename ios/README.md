# JVHD for iOS

Phiên bản iOS của JVHD: một ứng dụng Swift native bọc `WKWebView` quanh đúng bộ
giao diện web hiện có trong thư mục [`www/`](../www), kèm **máy chủ HTTP cục bộ
viết bằng Swift** để thay thế hoàn toàn phần Node.js/Electron của bản Windows.

> Bản Windows (`main.js`, `src/server.js`, `JVHD.bat`, `JVHD-nocmd.vbs`) vẫn
> giữ nguyên và chạy như cũ. Thư mục `ios/` là bản song song, **không** chỉnh
> sửa gì trong `www/` ngoài 2 tệp mới (`ios-bridge.js`, `ios-bridge.css`) vốn
> chỉ được kích hoạt khi chạy trong app iOS.

## 1. Kiến trúc

```
┌──────────────────────────────────────────────────────────────┐
│ JVHD.app (Swift, iOS 16+)                                    │
│                                                              │
│  MainViewController                                          │
│   ├── WKWebView ──► http://127.0.0.1:<port>/index.html       │
│   │      · allowsInlineMediaPlayback = true                  │
│   │      · autoplay (mediaTypesRequiringUserAction = [])     │
│   │      · WKScriptMessageHandler "jvhdNative" ──► AVPlayer  │
│   │                                                          │
│   ├── LocalServer (NWListener, chỉ nghe 127.0.0.1)           │
│   │      · /                  tệp tĩnh trong www/ (bundle)   │
│   │      · /jvhd-media/?u=&r= proxy nội dung + bẻ HLS        │
│   │      · /__native/api?u=   chuyển tiếp API (đăng nhập)    │
│   │      · /__native/c0|d0|e0 hàm mật mã thiết bị            │
│   │                                                          │
│   └── DeviceKey (Secure Enclave P-256, d0/e0)                │
└──────────────────────────────────────────────────────────────┘
```

| Thành phần Windows (bỏ đi)        | Thay thế trên iOS                                   |
|-----------------------------------|-----------------------------------------------------|
| `JVHD.bat`, `JVHD-nocmd.vbs`      | Không cần — app là file `.ipa`                      |
| Node.js + Electron                | Swift native (`UIKit`, `WebKit`, `Network`)         |
| `src/server.js` (Node HTTP)       | `LocalServer.swift` (Network.framework)             |
| `src/crypto-bridge.js` (node crypto) | `DeviceKey.swift` (Secure Enclave) + `Crypto.swift` |
| `preload.js` (`contextBridge`)    | `www/ios-bridge.js` (chèn lúc phục vụ `index.html`) |
| CORS injector của Electron        | XHR chéo nguồn tự đi qua máy chủ cục bộ (xem dưới)  |
| Cửa sổ ẩn vượt WAF                | **Không chuyển sang iOS** (xem mục 5)               |

## 2. Những gì đã làm cho đúng chuẩn iPhone

* **Vùng an toàn / notch**: `viewport-fit=cover` + `env(safe-area-inset-*)` trong
  `www/ios-bridge.css`; các lớp phủ toàn màn hình tự lùi vào vùng an toàn.
* **Co vừa màn hình**: giao diện được thiết kế cho TV 1920×1080, app tự tính
  tỉ lệ `min(sw/1920, sh/1080)` (giống `fitToScreen` bản Windows) và cập nhật
  lại khi xoay màn hình. **Pinch** để phóng to/thu nhỏ (tự nhớ), **lắc máy** để
  tải lại, **chạm 3 ngón** để mở menu (tải lại / về tỉ lệ gốc / xoá cache).
* **Cảm ứng**: bỏ highlight xanh, `touch-action: manipulation`, cuộn mượt; các
  thẻ nguồn và lưới phim trong `app.js` vốn đã có sự kiện `click` nên chạm được
  ngay.
* **Phát video**: `allowsInlineMediaPlayback = true` + tự phát; hls.js chạy bình
  thường trên iOS 17.1+ (ManagedMediaSource). Trên iOS 16, `www/ios-bridge.js`
  tự thay lớp `Hls` bằng cầu nối sang **AVPlayer native** (hỗ trợ PiP, AirPlay),
  đồng thời có watchdog: `<video>` lỗi 2 lần với `.m3u8` cũng chuyển sang
  AVPlayer.

## 3. Cách giao tiếp web ↔ native

`app.js` (bản gốc) yêu cầu các hàm **đồng bộ** của `window.AndroidBridge`:

| Hàm                        | Cài đặt trên iOS                                                   |
|----------------------------|--------------------------------------------------------------------|
| `proxyMedia(url, referer)` | Tạo URL `/jvhd-media/?u=<b64>&r=<b64>` ngay trong JS                |
| `c0(name)`                 | SHA-256 thuần JS (đã kiểm chứng khớp `crypto-bridge.js`, test vector `Admin2 → 37b5d924…`) |
| `d0()`                     | XHR **đồng bộ** tới `/__native/d0` → khoá công khai của khoá đang ký (Secure Enclave → Keychain → tệp). Bản Swift chèn sẵn chỉ dùng khi native không trả lời |
| `e0(data)`                 | XHR **đồng bộ** tới `http://127.0.0.1/__native/e0` → ký ECDSA, xuất **ASN.1 DER** theo `sigFormat:"der-b64"` |
| `exitApp()`                | iOS không cho phép app tự thoát → hiện thông báo                     |

Khoá riêng **không bao giờ** rời khỏi thiết bị và không bao giờ được đưa vào
WebView.

**Chống lỗi CORS**: WKWebView không cho phép tắt CORS như Electron
(`webSecurity: false`) hay WebView Android, nên `ios-bridge.js` bọc
`XMLHttpRequest` và cho mọi request chéo nguồn đi nhờ máy chủ cục bộ theo
**hai kênh tách biệt**:

| Method      | Kênh               | Hành vi                                                       |
|-------------|--------------------|---------------------------------------------------------------|
| `GET`/`HEAD`| `/jvhd-media/?u=&r=`| Proxy nội dung: giả UA iPhone, giữ Referer, bẻ lại playlist HLS |
| `POST`/…    | `/__native/api?u=`  | Chuyển tiếp **đúng method + body + Content-Type** lên máy chủ thật, trả nguyên trạng thái & phản hồi |

Đồng thời `responseURL` được trả lại URL gốc để logic origin của `app.js` hoạt
động y hệt bản Windows.

> **Vì sao phải tách hai kênh (lỗi đăng nhập iOS đã sửa):**
> trước đây *mọi* request chéo nguồn — kể cả `POST /auth/start` — đều bị đẩy
> sang `/jvhd-media`. Proxy nội dung ép `httpMethod = "GET"`
> (`MediaProxy.swift`) và không hề đọc body, nên máy chủ xác thực nhận một
> `GET /auth/start` **rỗng** thay vì `POST` kèm JSON `{h: <hash>}`. Nó trả lỗi
> → `app.js` rơi vào `jvhdUserAuthNetworkError()` và hiện đúng thông báo
> *“Không kết nối được máy chủ xác thực, thử lại”*. Bản Android không bị vì
> WebView Android chạy không bắt buộc CORS nên `app.js` gọi thẳng máy chủ.
> `/jvhd-media` vẫn giữ nguyên 100% hành vi cũ cho nội dung/HLS.

### Kiểm thử

```bash
node test/node_test.js       # bản Windows: crypto + local server + proxy HLS
node test/ios_auth_test.js   # bản iOS: nạp THẬT www/ios-bridge.js rồi chạy
                             # đúng luồng POST /auth/start → e0 → /auth/verify
```

`ios_auth_test.js` dựng lại môi trường WKWebView (stub `XMLHttpRequest`) cùng
bảng định tuyến của `LocalServer.swift`, rồi soi chính xác method/body/
Content-Type mà máy chủ xác thực nhận được — nên nó bắt lại được đúng lỗi kể
trên và khoá không cho tái diễn.

### Lỗi “Thiết bị không hỗ trợ xác thực, không thể tiếp tục” (iOS) — nguyên nhân & cách sửa

Câu này trong `www/app.js` **không** nghĩa là máy chủ từ chối tài khoản. Nó là
nhánh *fail-closed* in ra khi **chính máy** không tạo được khoá/chữ ký, tức
`bridge.d0()` hoặc `bridge.e0()` trả chuỗi rỗng:

```js
if (!devicePub || !bindSig) { jvhdUserAuthHardError(); return; }   // nhánh bind
if (!sig)                  { jvhdUserAuthHardError(); return; }   // nhánh challenge
```

Ba khiếm khuyết phía iOS đã được sửa (`DeviceKey.swift`, `Crypto.swift`,
`LocalServer.swift`, `ios-bridge.js`); server xác thực và JSONBin **không đổi**:

| # | Khiếm khuyết trên iOS (Android/Windows không có) | Hệ quả | Bản sửa |
|---|---|---|---|
| 1 | Khoá thiết bị chỉ lấy được từ **Secure Enclave/Keychain**. IPA không ký / ký lại bằng chứng thư cá nhân không cấp `keychain-access-groups`, hoặc app bị cài đè làm đổi access group ⇒ Keychain trả lỗi, `publicKeyBase64()` trả `""`. | `d0()` rỗng → **đúng câu lỗi người dùng thấy**, thiết bị mới không bao giờ bind được | Thêm nguồn khoá thứ 3: **tệp** `Application Support/JVHD/jvhd-device-key.raw` (khoá P-256 của CryptoKit, Data Protection `completeUnlessOpen`) — y như cách bản Windows giữ tệp PEM trong `ensureDeviceKey()`. Thứ tự: Secure Enclave → Keychain → tệp |
| 2 | `Config.swift` hứa `sigFormat = "der-b64"` nhưng `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` chỉ xuất **ANSI X9.62** (`r‖s`, 64 byte) — chữ ký được gửi **nguyên trạng** | `verifySig()` của server luôn `false` → bind báo *“Phiên xác thực hết hạn, vui lòng thử lại”*, thiết bị đã bind báo *“Thiết bị không khớp thiết bị đã đăng ký”* (và đếm vào khoá 3 phút) | `JVHDCrypto.derEncodeRS()` chuyển X9.62 → **ASN.1 DER**; `sigFormat`/`signDigest`/`challengeEncoding` giờ được tôn trọng thật sự, giống `crypto-bridge.js` |
| 3 | `signChallenge()` dùng `decodeBase64Loose()` + `guard … else return ""`: chuỗi rỗng hoặc có ký tự ngoài bảng ⇒ **không ký** ⇒ HTTP 500 ⇒ `e0()` = `""` | Mọi lệch nhỏ về định dạng challenge/nonce biến thành câu “thiết bị không hỗ trợ xác thực”, không thử lại được | `JVHDCrypto.decodeBase64NodeLike()`: mô phỏng **đúng** `Buffer.from(text,'base64')` (bỏ ký tự lạ, dừng ở `=`, vẫn ký dữ liệu rỗng). Luật này đã kiểm 4020 mẫu khớp Node |

Vì sao Android không vướng: `BtK.pk()/BtK.sg()` trong `libbtcore.so` lấy khoá từ
Android Keystore (luôn có) và ký ra DER; bản Windows dùng `crypto.sign` (cũng
DER) với khoá trong tệp. Cả ba giờ đây tạo **cùng một loại dữ liệu**
`{h, k, nonce, sig}` và chỉ ghi đúng một bản ghi `{k, at}` như trước.

**Chẩn đoán trên máy thật** (lần đầu tiên câu lỗi này nói cho bạn biết hỏng ở đâu):

* màn hình xác thực giờ hiển thị thêm `— iOS: c0=ok · pubkey=… · base=ok · lý-do=…`;
* `GET http://127.0.0.1:<cổng>/__native/diag` trả JSON: `backend`
  (`secure-enclave` / `keychain` / `file`), `pubkeyBytes` (phải = 65),
  `signatureIsDer` (phải = `true`), `lastError`.

### Kiểm thử

```bash
node test/node_test.js            # bản Windows: crypto + local server + proxy HLS
node test/ios_auth_test.js        # cầu nối iOS: method/body/Content-Type tới server
node test/ios_auth_flow_test.js   # CẢ LUỒNG bind/verify bằng quy tắc THẬT của server
node test/gen_der_fixtures.js     # sinh lại mẫu DER/base64 chuẩn Node/OpenSSL
```

`ios_auth_flow_test.js` chép nguyên văn quy tắc của máy chủ xác thực
(`hkrmta-code/jvhd-auth` commit `d61e85787`: `CRYPTO_HASH_RE`, `pubFromRaw`,
`verifySig`, `newNonce`, `takeNonce`, `handleStart/Bind/Verify`) để kiểm **end-to-end**:

* thiết bị iOS mới: `start → bind → ok`, `k` đúng 65 byte, server ghi đúng
  `{k, at}` và **chỉ 1** bản ghi;
* lần mở sau: `start → challenge → verify → ok`, không ghi thêm gì;
* thiết bị thứ hai dùng cùng tài khoản: vẫn bị `denied`, binding cũ không bị đè;
* mô phỏng đúng bản cũ (X9.62 / Keychain hỏng) để chứng minh hai lỗi trên là
  nguyên nhân, và để không ai tái phạm;
* **không** có request nào tới `api.jsonbin.io` từ cầu nối iOS.

Định dạng DER/base64 của Swift còn được kiểm trong CI bằng `swiftc` thật:

```bash
xcrun --sdk macosx swiftc -O -o build/ios-crypto-check \
  ios/JVHD/Crypto.swift tools/ios_crypto_check/main.swift && ./build/ios-crypto-check test/der_fixtures.json
```

## 4. Build

### Bằng GitHub Actions (khuyên dùng)

Mỗi lần build trên `main`, workflow tự đăng `JVHD.ipa` lên GitHub Release
`ipa-latest`. Link **cố định**, mở bằng trình duyệt là tải về ngay — kể cả trên
điện thoại, không cần đăng nhập, không cần cài `gh`/`git`:

```
https://github.com/Binkyo2013/JVHD/releases/download/ipa-latest/JVHD.ipa
```

Trang release (xem phiên bản, dung lượng, commit, ngày đóng gói):
<https://github.com/Binkyo2013/JVHD/releases/tag/ipa-latest>

Build thủ công và lấy qua artifact (cần máy tính):

```bash
gh workflow run build-ipa.yml            # hoặc push lên nhánh main
gh run watch                             # theo dõi
gh run download <run-id> -n JVHD-unsigned-ipa
```

Artifact `JVHD-unsigned-ipa` chứa `JVHD.ipa` (giữ 30 ngày, phải đăng nhập
GitHub mới tải được — vì vậy nên dùng link Release ở trên).

### Bằng Xcode trên máy Mac

```bash
open ios/JVHD.xcodeproj
# Chọn team ký (Signing & Capabilities) → Product ▸ Archive
```

Hoặc dòng lệnh (không ký):

```bash
xcodebuild -project ios/JVHD.xcodeproj -scheme JVHD -configuration Release \
  -sdk iphoneos -archivePath build/JVHD.xcarchive archive \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""
mkdir -p build/Payload && cp -R build/JVHD.xcarchive/Products/Applications/JVHD.app build/Payload/
(cd build && zip -qry ../JVHD.ipa Payload)
```

Project file `ios/JVHD.xcodeproj/project.pbxproj` được sinh bởi
`python3 tools/gen_xcodeproj.py` (UUID cố định → diff sạch). Sau khi thêm/xoá
file nguồn, sửa danh sách `SOURCE_FILES` trong script rồi chạy lại.

### Cài lên iPhone

| Cách                        | Yêu cầu                                  |
|-----------------------------|------------------------------------------|
| Xcode (macOS)               | Apple ID miễn phí, ký 7 ngày, cần UDID   |
| AltStore / SideStore        | IPA không ký + máy tính để cài lần đầu   |
| Sideloadly (Win/macOS)      | Apple ID miễn phí, ký 7 ngày             |
| TrollStore / jailbreak      | Cài vĩnh viễn không cần ký               |
| TestFlight / App Store      | Tài khoản Apple Developer trả phí        |

> IPA **không ký** không cài được bằng cách mở trực tiếp trên iPhone thường —
> bắt buộc phải có một trong các công cụ trên để ký lại.

## 5. Khác biệt & giới hạn đã biết

* **Không chuyển** cơ chế "cửa sổ ẩn tự bấm nút 18+/đồng ý" của bản Windows:
  đó là thao tác tự động vượt lớp xác thực của trang thứ ba, không phù hợp để
  đưa lên App Store và cũng không có API tương đương trên WKWebView. Vì vậy một
  số nguồn phát trực tiếp có thể cần mở bằng Safari trước khi xem trong app.
* Live source lấy dữ liệu qua proxy cục bộ; nếu nhà mạng chặn DNS, proxy vẫn
  hoạt động vì dùng mạng di động của thiết bị với UA iPhone Safari.
* Giao diện được thiết kế ngang (16:9) → app sẽ nhắc xoay ngang khi đang ở chế
  độ dọc; vẫn hiển thị được nhưng nhỏ.

## 6. Cấu hình

`ios/JVHD/Config.swift` là bản sao của `jvhd.config.js` (salt, máy chủ xác
thực, user-agent proxy…). Phải khớp với máy chủ xác thực của bạn, nếu không
đăng nhập sẽ bị từ chối giống hệt bản Windows.
