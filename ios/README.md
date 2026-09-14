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
| CORS injector của Electron        | XHR chéo nguồn tự đi qua `/jvhd-media` (xem dưới)   |
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
(`webSecurity: false`), nên `ios-bridge.js` bọc `XMLHttpRequest`: mọi request
chéo nguồn tự đi qua proxy cục bộ, đồng thời `responseURL` được trả lại URL gốc
để logic origin của `app.js` hoạt động y hệt bản Windows.

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
