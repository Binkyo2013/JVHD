/*
 * JVHD Desktop - CẤU HÌNH
 * ================================================================
 * File này bạn CHỈNH SỬA ĐƯỢC. Sau khi sửa -> lưu lại -> chạy lại JVHD.bat.
 *
 * Phần quan trọng nhất là mục `auth` bên dưới: nó quyết định lớp xác thực
 * "thiết bị/user" có khớp với máy chủ của BẠN hay không.
 *
 * Khi chạy trong MuMuPlayer (.apk), các hàm này được thực hiện bởi thư viện
 * Android gốc (libbtcore.so + Android Keystore). Trên Windows ta thay thế
 * chúng bằng code Node.js trong file này. Để đăng nhập được, bạn phải làm
 * cho các giá trị dưới đây KHỚP với mã gốc / máy chủ onrender của bạn.
 */

module.exports = {
  // -------------------------------------------------------------------
  // CỔNG server web + proxy cục bộ (mở trong chính app, không cần để ý
  // trừ khi bị trùng cổng -> app tự tăng lên cổng kế tiếp).
  // -------------------------------------------------------------------
  bindHost: "127.0.0.1",
  localPort: 38755,

  // -------------------------------------------------------------------
  // GIAO DIỆN CỬA SỔ
  // -------------------------------------------------------------------
  window: {
    // Tự co tỉ lệ nội dung 1920x1080 cho khớp màn hình (thích hợp laptop
    // nhỏ). Tắt (false) nếu bạn dùng màn hình >=1920x1080.
    fitToScreen: true,
    // Cho phép toàn màn hình bằng phím F11
    allowFullscreen: true
  },

  // -------------------------------------------------------------------
  // XÁC THỰC (phải khớp với mã gốc / máy chủ của bạn)
  // -------------------------------------------------------------------
  auth: {
    // Máy chủ xác thực. Giữ nguyên nếu bạn vẫn chạy server onrender.
    server: "https://jvhd-auth.onrender.com",

    // c0(name) = SHA-256( name + salt ).
    // Công thức KHỚP 100% native (libbtcore.so / n0), đã xác minh bằng test
    // vector jsonbin (Admin2 -> 37b5d924...):
    //   name = trim() + toLowerCase()
    //   input = name + salt   (salt nối dạng VĂN BẢN, KHÔNG decode hex)
    //   c0   = SHA-256(input) hex 64 ký tự
    // SALT thật = '4f4e804da5c307dd7d88d2b58e1a44c6b312c1430ff4d29d'
    //   (chuỗi 48 ký tự hex dùng như plaintext để nối, không bẻ thành byte)
    salt: "4f4e804da5c307dd7d88d2b58e1a44c6b312c1430ff4d29d",

    // Cách nối: "suffix" = sha256(name + salt) · "prefix" = sha256(salt + name)
    concat: "suffix",

    // d0(): khóa công khai gửi lên server (khớp chính xác BtK.pk() bản gốc)
    // = base64( 0x04 || X(32) || Y(32) )  -> "raw-uncompressed-b64"
    pubKeyFormat: "raw-uncompressed-b64",

    // e0(data): chữ ký ECDSA, khớp chính xác BtK.sg() bản gốc:
    //   - data là chuỗi BASE64 (server gửi challenge/nonce dạng base64)
    //   -> e0 Base64-DECODE data rồi SHA-256 rồi ký bằng ECDSA P-256
    //   - trả về chữ ký DER dạng base64
    sigFormat: "der-b64",
    signDigest: "sha256",
    challengeEncoding: "base64",

    // Bỏ qua mạng lưới khóa 3 phút khi thử trong lúc phát triển (tùy chọn).
    disableBruteForceLock: false
  },

  // -------------------------------------------------------------------
  // PROXY NỘI DUNG (giả lập MediaProxyServer bản gốc)
  // -------------------------------------------------------------------
  proxy: {
    // User-Agent giả trình duyệt khi proxy đi lấy nguồn (tránh WAF chặn UA TV)
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    timeoutMs: 25000,
    maxRedirects: 6,
    // Tự nối lại danh sách phát HLS (bẻ segment) để hls.js không gặp CORS.
    rewriteHls: true
  }
};
