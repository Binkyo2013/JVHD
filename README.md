# JVHD

JVHD là một ứng dụng xem phim / phát trực tiếp dạng TV launcher (giao diện web
1920×1080 trong thư mục [`www/`](www)). Kho này hiện có **hai bản chạy song
song** từ cùng một bộ mã giao diện web:

| Bản | Thư mục | Chạy bằng | Tài liệu |
|-----|---------|-----------|----------|
| Windows (gốc) | `main.js`, `src/`, `JVHD.bat` | Node.js + Electron | `JVHD.bat` |
| **iOS (mới)** | [`ios/`](ios/README.md) | Swift native + WKWebView | [`ios/README.md`](ios/README.md) |

## Bản iOS

**Tải file `.ipa` (bấm là tải, dùng được trên điện thoại, không cần đăng nhập):**

> <https://github.com/Binkyo2013/JVHD/releases/download/ipa-latest/JVHD.ipa>

Trang release: <https://github.com/Binkyo2013/JVHD/releases/tag/ipa-latest> — link
này **cố định**, GitHub Actions tự ghi đè bằng bản build mới nhất mỗi lần có
thay đổi trong `ios/`, `www/` hoặc workflow được đưa lên `main`.

```bash
python3 tools/gen_xcodeproj.py   # sinh lại ios/JVHD.xcodeproj (nếu đổi danh sách file)
gh workflow run build-ipa.yml    # build .ipa thủ công trên GitHub Actions
gh run download <run-id> -n JVHD-unsigned-ipa   # (cách cũ, cần máy tính + gh)
```

Chi tiết kiến trúc, cách ký/cài lên iPhone và các giới hạn:
**[ios/README.md](ios/README.md)**.

Tóm tắt:

* Ứng dụng Swift thuần (iOS 16+) bọc `WKWebView` quanh `www/index.html`.
* Máy chủ HTTP cục bộ viết bằng Swift (`LocalServer.swift`) thay cho Node.js:
  phục vụ tệp tĩnh, proxy nội dung `/jvhd-media` (bẻ lại playlist HLS, giữ
  Referer/UA, hỗ trợ Range) và các endpoint mật mã `/__native/*`.
* Khoá thiết bị ECDSA P-256 trong **Secure Enclave** thay cho
  `libbtcore.so`/Keystore của Android và `crypto` của Node.
* Cầu nối `WKScriptMessageHandler` sang **AVPlayer native** khi hls.js không
  khả dụng (iOS < 17.1).
* Không còn bất kỳ phụ thuộc Windows nào (`.bat`, `.vbs`, lệnh cmd).

## Bản Windows (giữ nguyên)

Double-click `JVHD.bat` (cần Node.js LTS). Cấu hình trong `jvhd.config.js`:

```bash
node tools/tool.js hash <username>   # tính SHA-256(name + salt)
node tools/tool.js selfcheck         # tự kiểm tra khoá/chữ ký
node test/node_test.js               # chạy bộ kiểm thử không cần giao diện
```

## Giao diện web

* `www/index.html`, `www/app.js`, `www/style.css` — ứng dụng (thiết kế cho TV).
* `www/tizen_shim.js` — giả lập API Tizen cho môi trường không phải Samsung TV.
* `www/hls.min.js` — hls.js 1.5.20.
* `www/ios-bridge.js`, `www/ios-bridge.css` — lớp tương thích iOS; **chỉ** được
  chèn vào trang bởi máy chủ cục bộ của app iOS, bản Windows không đụng tới.
