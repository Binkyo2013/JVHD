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
| `d0()`                     | Khoá công khai do Swift chèn sẵn (lấy từ Secure Enclave lúc mở app) |
| `e0(data)`                 | XHR **đồng bộ** tới `http://127.0.0.1/__native/e0` → ký bằng Secure Enclave |
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

> **Lỗi “Thiết bị không hỗ trợ xác thực, không thể tiếp tục” (đã sửa):**
> `app.js` chỉ hiện câu này khi `c0/d0/e0` thiếu **hoặc khi `d0()`/`e0()` trả
> về chuỗi RỖNG**. Hợp đồng của bản Android/Windows
> (`src/crypto-bridge.js`) là *không bao giờ rỗng*: `ensureDeviceKey()` luôn
> tạo khoá (ghi PEM ra đĩa nếu chưa có) và `e0()` dùng
> `Buffer.from(x, 'base64')` — hàm này **không bao giờ lỗi**, kể cả với chuỗi
> rỗng, nên luôn có chữ ký. iOS vi phạm đúng hai chỗ đó:
>
> 1. **`e0()`** — `LocalServer.signChallenge()` giải mã nonce/challenge bằng
>    `Data(base64Encoded:)`. Foundation trả `nil` cho chuỗi rỗng hoặc chuỗi
>    không phải base64 chuẩn → bỏ qua bước ký → `e0()` = `""` → `app.js` chặn
>    đăng nhập. Android với cùng dữ liệu đó vẫn ký và vẫn vào được.
> 2. **`d0()`** — tạo khoá Secure Enclave **thất bại với `errSecMissingEntitlement`
>    (-34018)** trên IPA không có entitlement (đúng cấu hình build của kho này:
>    `CODE_SIGNING_ALLOWED=NO`, ký lại bằng AltStore/Sideloadly). Khi tầng dự
>    phòng cũng trượt, `DeviceKey` trả `""` và `/__native/d0` đáp `HTTP 500`
>    → `d0()` = `""` → cùng một thông báo lỗi.
>
> Cách sửa (chỉ phía iOS, không đụng Android/Windows/JSONBin):
> `Crypto.decodeBase64NodeCompatible()` tái hiện **đúng từng byte** ngữ nghĩa
> `Buffer.from(x,'base64')` của Node; `DeviceKey` có ba tầng dự phòng
> (Secure Enclave → Keychain → khoá CryptoKit lưu file, tương đương PEM của
> bản Node) kèm chẩn đoán; `ios-bridge.js` thử lại lời gọi native một lần và
> luôn trả về chuỗi. Kiểm tra tầng khoá đang dùng ngay trên máy:
> mở Safari → Web Inspector → console → `__jvhdNativeDiagnostics()`, hoặc
> `http://127.0.0.1:<cổng>/__native/env` (mục `deviceKey`).

> **Lỗi thứ ba của cùng triệu chứng — CHỈ xảy ra trên máy thật (PR này sửa):**
> hai mục trên giải quyết việc *không có khoá* và *base64 lệch Node*, nhưng
> `Config.swift` còn hứa `sigFormat = "der-b64"` mà `DeviceKey.signBase64()`
> không giữ lời ở nhánh **Secure Enclave/Keychain**:
> `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` trả chữ ký dạng
> **ANSI X9.62** (`r‖s`, 64 byte) và code cũ `return (signature as Data)
> .base64EncodedString()` — gửi nguyên trạng lên server. Máy chủ kiểm bằng
> `crypto.createVerify("SHA256")…verify(key, sig)` (chỉ đọc **ASN.1 DER**) nên
> `verifySig()` luôn `false`:
>
> | Tình huống máy | Chữ ký iOS gửi lên | Server trả | Câu lỗi trên màn hình |
> |---|---|---|---|
> | iPhone thật, khoá trong Secure Enclave | X9.62 `r‖s` (sai) | `bad` / `denied` | “Phiên xác thực hết hạn, vui lòng thử lại” hoặc “Thiết bị không khớp thiết bị đã đăng ký” (+đếm vào khoá 3 phút) |
> | Máy build macOS / Keychain bị chặn | `derRepresentation` của CryptoKit (đúng) | `ok` | đăng nhập bình thường |
>
> Đây cũng là lý do `tools/native_crypto_main.swift` (check trong CI của PR trước)
> **không** phát hiện ra: trên runner macOS, `DeviceKey` không bao giờ lấy được
> khoá Secure Enclave (`errSecMissingEntitlement`) nên chữ ký sinh ra từ tầng
> khác — tầng này tình cờ đã đúng định dạng. Nói cách khác: CI xanh, iPhone vẫn
> không đăng nhập được. Muốn thấy lỗi này phải kiểm hàm chuyển đổi bằng fixture
> (`tools/ios_crypto_check`), không thể chỉ “ký xong tự kiểm” trên máy build.
>
> Cách sửa: `JVHDCrypto.normalizedSignature()` gọi `derEncodeRS()` /
> `derDecodeRS()` để đóng gói X9.62 → DER theo đúng quy tắc INTEGER của ASN.1
> (bỏ 0 đệm thừa, thêm `0x00` khi byte cao có bit dấu), và `signBase64()` tôn
> trọng `sigFormat` (`der-*` / `raw*` / `-hex`) ở **cả ba** tầng khoá.
>
> **Vì sao phải *nhận diện* chứ không bọc vô điều kiện:** bản thân
> `SecKeyCreateSignature` không cho ra một định dạng duy nhất. Nhật ký CI cho thấy
> khi `d0` chạy ở tầng `keychain` (máy build macOS) thì chữ ký đã là **DER sẵn,
> 71 byte**, còn chữ ký của khoá Secure Enclave trên iPhone là **X9.62, 64 byte**.
> Bọc chồng lên một blob đã là DER sẽ sinh ra `30 4a 02 23 30 44 …` — “DER lồng
> DER” mà server không đọc được; đúng sự cố này đã xảy ra ở lượt build
> `34918047184` và log nằm trong comment của PR #5. Nên `looksLikeDERSignature()`
> phải kiểm cấu trúc `SEQUENCE{INTEGER,INTEGER}` dùng hết dữ liệu rồi mới quyết
> định bọc hay giữ nguyên.
>
> Định dạng được kiểm bằng fixture do OpenSSL sinh (`test/der_fixtures.json`,
> 46 mẫu), không phải do code iOS tự sinh rồi tự nhận đúng.

Hai điểm phụ cũng sửa trong PR này:

* **`d0()` luôn hỏi native trước.** Giá trị `__JVHD_PUBKEY__` Swift chèn vào
  `ios-bridge.js` chỉ là ảnh chụp lúc phục vụ trang; nếu khoá được tạo muộn hơn
  (lần mở đầu tiên) hoặc được tạo lại sau khi cài đè/ký lại app, ảnh chụp đó lệch
  với khoá thật dùng để ký → server lưu một binding không bao giờ verify được.
  Giờ native là nguồn chính thức, ảnh chụp chỉ còn là dự phòng.
* **Lý do hỏng xuất hiện ngay trên màn hình.** `/__native/d0` và `/__native/e0`
  khi thất bại trả body `ERR: backend=… · keychain=OSStatus -34018 · d0=…`
  (trước đây body rỗng, lý do chỉ nằm trong NSLog), `ios-bridge.js` bóc chuỗi đó
  và `app.js` — **chỉ trên iOS**, chặn sau cờ `window.__JVHD_IOS__` — nối vào câu
  lỗi: *“Thiết bị không hỗ trợ xác thực, không thể tiếp tục — iOS: c0=ok ·
  pubkey=ok · base=ok · lý-do=…”*. Android/Windows/Tizen giữ nguyên 100% câu chữ.

### Kiểm thử

```bash
node test/node_test.js            # bản Windows: crypto + local server + proxy HLS
node test/ios_auth_test.js        # bản iOS: nạp THẬT www/ios-bridge.js rồi chạy
                                  # đúng luồng POST /auth/start → e0 → /auth/verify
                                  # và cả nhánh /auth/bind của thiết bị MỚI
node test/ios_auth_flow_test.js   # CẢ LUỒNG bằng quy tắc THẬT của máy chủ xác thực
node test/gen_der_fixtures.js     # sinh lại mẫu DER/base64 chuẩn OpenSSL (khi cần)
```

`test/ios_auth_flow_test.js` chép nguyên văn `pubFromRaw` / `verifySig` /
`newNonce` / `takeNonce` / `handleStart|Bind|Verify` của máy chủ xác thực
(`hkrmta-code/jvhd-auth`, commit `d61e85787`) rồi chạy `www/ios-bridge.js` **thật**
qua từng nhánh, nên nó khẳng định được những điều mà check “mô phỏng” không thấy:

| Kịch bản | Điều phải đúng |
|---|---|
| Thiết bị iOS mới | `start → bind → ok`; `k` đúng 65 byte `0x04‖X‖Y`; server ghi `{k, at}` và **chỉ 1** bản ghi |
| Mở lại lần sau | `start → challenge → verify → ok`, **không** ghi thêm gì |
| Thiết bị thứ hai cùng tài khoản | vẫn `denied`, binding cũ **không bị đè** |
| Mô phỏng bản cũ (X9.62 / Keychain hỏng / `e0('')`) | tái hiện đúng từng câu lỗi, và **không** tạo bản ghi rác |
| JSONBin | **không** có request nào tới `api.jsonbin.io` từ cầu nối iOS; iOS chỉ dùng `/auth/start`, `/auth/bind`, `/auth/verify` |

`ios_auth_test.js` dựng lại môi trường WKWebView (stub `XMLHttpRequest`) cùng
bảng định tuyến của `LocalServer.swift`, rồi soi chính xác method/body/
Content-Type mà máy chủ xác thực nhận được — nên nó bắt lại được đúng lỗi kể
trên và khoá không cho tái diễn.

Ngoài ra, **mỗi lần build IPA** workflow chạy thêm
`tools/native_crypto_main.swift`: biên dịch THẬT `Config.swift` + `Crypto.swift`
+ `DeviceKey.swift` rồi in `d0()`/`e0()` ra để `tools/verify_swift_sig.js`
kiểm chứng bằng `crypto` của Node — chính thư viện bản Android/Windows dùng.
Ba điều bắt buộc đúng, sai là build dừng:

| Kiểm tra | Ý nghĩa |
|----------|---------|
| `d0()` = 65 byte `0x04‖X‖Y`, Node đọc thành khoá P-256 | khớp `pubKeyFormat` |
| Node `crypto.verify` được chữ ký Swift | khớp `sigFormat` + `challengeEncoding` |
| `e0('')` **khác rỗng** và verify được trên message rỗng | parity với `Buffer.from(x,'base64')` của Node — đây chính là điều kiện gây ra lỗi *“Thiết bị không hỗ trợ xác thực”* |

`tools/auth_probe.js` (chạy tay: `node tools/auth_probe.js <hash>`) đọc hợp đồng
của máy chủ xác thực đang chạy — `POST /auth/start` trả
`{status:"challenge"|"bind"|"unknown", …}`. Nó **không bao giờ** gọi
`/auth/bind`, nên không thể tạo/ghi đè/xoá ràng buộc thiết bị trên JSONBin.

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
