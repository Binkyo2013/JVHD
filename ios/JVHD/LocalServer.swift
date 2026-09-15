/*
 * LocalServer.swift
 * Máy chủ HTTP cục bộ chạy TRONG app (thay cho `src/server.js` của bản Node).
 *
 *   GET  /                      -> tệp tĩnh trong thư mục www (đóng gói trong app)
 *   GET  /jvhd-media/?u=&r=     -> proxy nội dung (bẻ lại playlist HLS, giữ Referer)
 *   GET  /__health              -> "ok"
 *   GET  /__native/c0?n=<name>  -> SHA-256(name + salt) hex
 *   GET  /__native/d0           -> khoá công khai thiết bị (base64)
 *   POST /__native/e0           -> chữ ký ECDSA (base64 DER)
 *   GET  /__native/diag         -> chẩn đoán khoá thiết bị / định dạng chữ ký
 *   ANY  /__native/api?u=       -> chuyển tiếp API chéo nguồn (đăng nhập),
 *                                  GIỮ NGUYÊN method + body + Content-Type
 *   GET  /__native/env          -> thông tin môi trường (debug)
 *
 * Chỉ lắng nghe 127.0.0.1 — không bao giờ mở ra ngoài thiết bị.
 */

import Foundation
import Network
import UIKit

// MARK: - StreamWriter (ghi phản hồi theo từng khối, dùng cho proxy media)

final class StreamWriter {

    private let connection: NWConnection
    private let queue: DispatchQueue
    private var pending: [Data] = []
    private var pendingBytes = 0
    private var isSending = false
    private var didFinish = false
    private var didClose = false
    var onFinish: (() -> Void)?

    /// Giới hạn bộ nhớ đệm: ~96 MB (vượt quá thì huỷ kết nối).
    private let backlogLimit = 96 * 1024 * 1024

    init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    func write(_ data: Data) {
        if data.isEmpty { return }
        queue.async {
            guard !self.didClose else { return }
            if self.pendingBytes > self.backlogLimit {
                NSLog("[JVHD][StreamWriter] quá tải bộ đệm, huỷ kết nối")
                self.connection.cancel()
                self.didClose = true
                self.pending.removeAll()
                return
            }
            self.pending.append(data)
            self.pendingBytes += data.count
            self.pump()
        }
    }

    func finish() {
        queue.async {
            self.didFinish = true
            self.pump()
        }
    }

    func abort() {
        queue.async {
            self.didClose = true
            self.pending.removeAll()
            self.pendingBytes = 0
            self.connection.cancel()
        }
    }

    private func pump() {
        guard !didClose else { return }
        if isSending { return }
        if pending.isEmpty {
            if didFinish && !isSending {
                didFinish = false
                let callback = onFinish
                onFinish = nil
                callback?()
            }
            return
        }
        let chunk = pending.removeFirst()
        pendingBytes -= chunk.count
        isSending = true
        connection.send(content: chunk, completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            self.queue.async {
                self.isSending = false
                if error != nil {
                    self.didClose = true
                    self.pending.removeAll()
                    self.pendingBytes = 0
                    let callback = self.onFinish
                    self.onFinish = nil
                    callback?()
                    return
                }
                self.pump()
            }
        })
    }
}

// MARK: - HTTPConnection

final class HTTPConnection {

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let handler: (HTTPRequest, HTTPConnection) -> Void
    private var buffer = Data()
    private var isClosed = false
    private var keepAlive = false
    private var handling = false
    /// Được gọi (trên `queue`) khi kết nối đóng để máy chủ dọn danh sách.
    var onClose: ((HTTPConnection) -> Void)?

    init(connection: NWConnection,
         queue: DispatchQueue,
         handler: @escaping (HTTPRequest, HTTPConnection) -> Void) {
        self.connection = connection
        self.queue = queue
        self.handler = handler
    }

    func begin() {
        connection.start(queue: queue)
        readNext()
    }

    // MARK: Đọc

    private func readNext() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            self.queue.async {
                if let data = data, !data.isEmpty { self.buffer.append(data) }
                if let error = error {
                    if !self.isClosed { self.isClosed = true; self.connection.cancel() }
                    return
                }
                if self.buffer.isEmpty {
                    if isComplete { self.close() } else { self.readNext() }
                    return
                }
                self.drain()
                if isComplete && self.buffer.isEmpty && !self.handling { self.close() }
            }
        }
    }

    private func drain() {
        guard !isClosed, !handling else { return }
        switch HTTPParser.parse(buffer) {
        case .incomplete:
            readNext()
        case .invalid:
            buffer.removeAll()
            respond(status: 400, headers: ["Content-Type": "text/plain; charset=utf-8"], body: Data("Bad Request".utf8), keepAlive: false)
        case .request(let request, let consumed):
            if consumed > 0 && consumed <= buffer.count { buffer.removeSubrange(0..<consumed) }
            handling = true
            keepAlive = request.isKeepAlive
            handler(request, self)
        }
    }

    // MARK: Ghi

    func respond(status: Int, headers: [String: String], body: Data, keepAlive: Bool) {
        var head = headers
        head["Content-Length"] = String(body.count)
        writeHead(status: status, headers: head, keepAlive: keepAlive)
        if body.isEmpty {
            finish(keepAlive: keepAlive)
            return
        }
        write(body) {
            self.finish(keepAlive: keepAlive)
        }
    }

    /// Bắt đầu phản hồi dạng luồng (không biết trước Content-Length).
    func beginStream(status: Int, headers: [String: String], keepAlive: Bool) -> StreamWriter {
        var head = headers
        head.removeValue(forKey: "Content-Length")
        writeHead(status: status, headers: head, keepAlive: keepAlive)
        let writer = StreamWriter(connection: connection, queue: queue)
        writer.onFinish = { [weak self] in
            self?.finish(keepAlive: keepAlive)
        }
        return writer
    }

    private func writeHead(status: Int, headers: [String: String], keepAlive: Bool) {
        var text = "HTTP/1.1 \(status) \(statusText(status))\r\n"
        for (name, value) in headers { text += "\(name): \(value)\r\n" }
        text += keepAlive ? "Connection: keep-alive\r\n" : "Connection: close\r\n"
        text += "\r\n"
        write(Data(text.utf8), completion: nil)
    }

    private func write(_ data: Data, completion: (() -> Void)?) {
        queue.async {
            guard !self.isClosed else { completion?(); return }
            self.connection.send(content: data, completion: .contentProcessed { [weak self] error in
                guard let self = self else { completion?(); return }
                if error != nil {
                    self.queue.async { self.close() }
                    return
                }
                completion?()
            })
        }
    }

    private func finish(keepAlive: Bool) {
        queue.async {
            self.handling = false
            if keepAlive && !self.isClosed {
                self.drain()
                if !self.handling { self.readNext() }
            } else {
                self.close()
            }
        }
    }

    func close() {
        if isClosed { return }
        isClosed = true
        buffer.removeAll()
        connection.cancel()
        onClose?(self)
    }

    private func statusText(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 204: return "No Content"
        case 206: return "Partial Content"
        case 302: return "Found"
        case 400: return "Bad Request"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 500: return "Internal Server Error"
        case 502: return "Bad Gateway"
        default: return "Status \(status)"
        }
    }
}

// MARK: - LocalServer

final class LocalServer: NSObject {

    static let shared = LocalServer()

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "vn.jvhd.localserver", qos: .userInitiated)
    private var connections: [HTTPConnection] = []
    private(set) var port: UInt16 = 0
    private var isStarting = false

    var baseURLString: String { "http://\(JVHDConfig.bindHost):\(port)" }
    var isRunning: Bool { port > 0 }

    /// Cung cấp kích thước màn hình (đơn vị point) để tính tỉ lệ co giao diện.
    /// MainViewController gán lại bằng bounds thật của view khi xoay màn hình.
    static var viewportSizeProvider: () -> CGSize = { UIScreen.main.bounds.size }

    private let mimeTypes: [String: String] = [
        ".html": "text/html; charset=utf-8",
        ".htm": "text/html; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".mjs": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".woff2": "font/woff2",
        ".woff": "font/woff",
        ".ttf": "font/ttf",
        ".map": "application/json; charset=utf-8",
        ".m3u8": "application/vnd.apple.mpegurl",
        ".ts": "video/mp2t",
        ".mp4": "video/mp4",
        ".txt": "text/plain; charset=utf-8"
    ]

    private override init() { super.init() }

    // MARK: Khởi động

    func start(completion: @escaping (Result<UInt16, Error>) -> Void) {
        if let listener = listener, port > 0 {
            completion(.success(port))
            return
        }
        if isStarting { completion(.success(port)); return }
        isStarting = true
        startAttempt(preferred: true, completion: completion)
    }

    private func startAttempt(preferred: Bool, completion: @escaping (Result<UInt16, Error>) -> Void) {
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        let portToUse = preferred ? JVHDConfig.preferredPort : UInt16(0)
        if let loopback = IPv4Address(JVHDConfig.bindHost),
           let nwPort = NWEndpoint.Port(rawValue: portToUse) {
            parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(loopback), port: nwPort)
        }

        var listener: NWListener
        do {
            listener = try NWListener(using: parameters)
        } catch {
            isStarting = false
            completion(.failure(error))
            return
        }

        var finished = false
        listener.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                guard !finished else { return }
                finished = true
                self.isStarting = false
                self.port = listener.port?.rawValue ?? 0
                NSLog("[JVHD] Local server sẵn sàng tại %@", self.baseURLString)
                DispatchQueue.main.async { completion(.success(self.port)) }
            case .failed(let error):
                guard !finished else { return }
                finished = true
                listener.cancel()
                if preferred {
                    NSLog("[JVHD] Cổng %d bận, thử cổng tự do…", JVHDConfig.preferredPort)
                    self.isStarting = true
                    self.queue.asyncAfter(deadline: .now() + 0.1) {
                        self.startAttempt(preferred: false, completion: completion)
                    }
                } else {
                    self.isStarting = false
                    NSLog("[JVHD] Không khởi động được local server: %@", String(describing: error))
                    DispatchQueue.main.async { completion(.failure(error)) }
                }
            case .cancelled:
                self.port = 0
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener.start(queue: queue)
        self.listener = listener
    }

    private func accept(_ connection: NWConnection) {
        let httpConnection = HTTPConnection(connection: connection, queue: queue) { [weak self] request, conn in
            self?.route(request, conn)
        }
        connections.append(httpConnection)
        // Dọn kết nối đã đóng để không giữ bộ nhớ vô hạn.
        httpConnection.onClose = { [weak self] conn in
            guard let self = self else { return }
            self.connections.removeAll { $0 === conn }
        }
        httpConnection.begin()
    }

    // MARK: Định tuyến

    private func route(_ request: HTTPRequest, _ connection: HTTPConnection) {
        let path = request.path
        switch path {
        case "/__health":
            connection.respond(status: 200,
                               headers: corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                               body: Data("ok".utf8),
                               keepAlive: request.isKeepAlive)
        case "/__native/c0":
            let name = request.query["n"] ?? ""
            let digest = JVHDCrypto.c0(name)
            connection.respond(status: 200,
                               headers: corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                               body: Data(digest.utf8),
                               keepAlive: request.isKeepAlive)
        case "/__native/d0":
            // Chuỗi trả về là khoá công khai (kênh thành công) hoặc lý do bắt
            // đầu bằng "ERR:" (kênh lỗi) — ios-bridge.js đọc cả hai để hiển thị
            // đúng bước hỏng thay vì chỉ báo "thiết bị không hỗ trợ".
            let pub = DeviceKey.shared.publicKeyBase64()
            if pub.isEmpty {
                connection.respond(status: 503,
                                   headers: corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                                   body: Data(errorText().utf8),
                                   keepAlive: request.isKeepAlive)
            } else {
                connection.respond(status: 200,
                                   headers: corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                                   body: Data(pub.utf8),
                                   keepAlive: request.isKeepAlive)
            }
        case "/__native/e0":
            let payload = request.body.isEmpty ? (request.query["d"] ?? "") : (String(data: request.body, encoding: .utf8) ?? "")
            let signature = signChallenge(payload)
            if signature.isEmpty {
                connection.respond(status: 503,
                                   headers: corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                                   body: Data(errorText().utf8),
                                   keepAlive: request.isKeepAlive)
            } else {
                connection.respond(status: 200,
                                   headers: corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                                   body: Data(signature.utf8),
                                   keepAlive: request.isKeepAlive)
            }
        case "/__native/diag":
            let diag = diagnosticJSON()
            connection.respond(status: 200,
                               headers: corsHeaders(["Content-Type": "application/json; charset=utf-8"]),
                               body: Data(diag.utf8),
                               keepAlive: request.isKeepAlive)
        case "/__native/env":
            let env = environmentJSON()
            connection.respond(status: 200,
                               headers: corsHeaders(["Content-Type": "application/json; charset=utf-8"]),
                               body: Data(env.utf8),
                               keepAlive: request.isKeepAlive)
        case "/__native/log":
            if let text = String(data: request.body, encoding: .utf8) {
                NSLog("[JVHD][web] %@", text)
            }
            connection.respond(status: 204, headers: corsHeaders([:]), body: Data(), keepAlive: request.isKeepAlive)
        case "/__native/api":
            relayAPI(request, connection)
        case "/jvhd-media", "/jvhd-media/":
            MediaProxy.shared.handle(request, connection)
        default:
            serveStatic(request, connection)
        }
    }

    // MARK: - Kênh API (đăng nhập / xác thực)

    /// Phiên mạng riêng cho lời gọi API ngắn (không dùng chung với MediaProxy
    /// vốn cấu hình cho luồng phát `avStreaming`).
    private lazy var apiSession: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = JVHDConfig.authTimeout
        configuration.timeoutIntervalForResource = 30
        return URLSession(configuration: configuration)
    }()

    /// Chuyển tiếp lời gọi API chéo nguồn (POST /auth/start, /auth/verify…).
    ///
    /// WKWebView KHÔNG cho tắt CORS (khác WebView Android và Electron với
    /// `webSecurity: false`), nên `ios-bridge.js` đổi lời gọi chéo nguồn thành
    /// request CÙNG NGUỒN tới đây kèm body gốc. Nhiệm vụ của hàm này là gửi lại
    /// ĐÚNG method + body + Content-Type lên máy chủ thật rồi trả nguyên trạng
    /// thái/phản hồi về WebView.
    ///
    /// Lưu ý: KHÔNG được đẩy lời gọi này sang `/jvhd-media` — proxy nội dung ép
    /// `httpMethod = "GET"` và không đọc body, khiến máy chủ xác thực nhận GET
    /// rỗng và trả lỗi => app báo "không kết nối được máy chủ xác thực".
    private func relayAPI(_ request: HTTPRequest, _ connection: HTTPConnection) {
        let keepAlive = request.isKeepAlive
        guard let encodedTarget = request.query["u"],
              let decodedData = JVHDCrypto.decodeBase64Loose(encodedTarget),
              let target = String(data: decodedData, encoding: .utf8),
              let url = URL(string: target),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https" else {
            connection.respond(status: 400,
                               headers: corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                               body: Data("bad target".utf8),
                               keepAlive: keepAlive)
            return
        }

        var upstream = URLRequest(url: url,
                                  cachePolicy: .reloadIgnoringLocalCacheData,
                                  timeoutInterval: JVHDConfig.authTimeout)
        upstream.httpMethod = request.method
        if let contentType = request.headers["content-type"], !contentType.isEmpty {
            upstream.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }
        if let accept = request.headers["accept"], !accept.isEmpty {
            upstream.setValue(accept, forHTTPHeaderField: "Accept")
        }
        if !request.body.isEmpty { upstream.httpBody = request.body }

        apiSession.dataTask(with: upstream) { [weak self] data, response, error in
            guard let self = self else { return }
            if let error = error {
                NSLog("[JVHD][api] lỗi chuyển tiếp %@ : %@", target, error.localizedDescription)
                connection.respond(status: 502,
                                   headers: self.corsHeaders(["Content-Type": "text/plain; charset=utf-8"]),
                                   body: Data("API error: \(error.localizedDescription)".utf8),
                                   keepAlive: keepAlive)
                return
            }
            let http = response as? HTTPURLResponse
            let status = http?.statusCode ?? 200
            let upstreamType = (http?.allHeaderFields["Content-Type"] as? String) ?? ""
            let contentType = upstreamType.isEmpty ? "application/json; charset=utf-8" : upstreamType
            connection.respond(status: status,
                               headers: self.corsHeaders(["Content-Type": contentType]),
                               body: data ?? Data(),
                               keepAlive: keepAlive)
        }.resume()
    }

    /// Chuyển challenge/nonce thành đúng từng byte mà bản Android/Windows ký.
    ///
    /// Điểm số 3 của bản sửa lỗi: TRƯỚC ĐÂY hàm này dùng `decodeBase64Loose()`
    /// (trả nil khi chuỗi rỗng hoặc có ký tự ngoài bảng) rồi `guard ... else
    /// return ""`, nghĩa là mọi lệch nhỏ về định dạng biến "ký không được"
    /// thành "thiết bị không hỗ trợ xác thực" — trong khi Node
    /// `Buffer.from(text,'base64')` luôn bỏ qua ký tự lạ và vẫn ký cả dữ liệu
    /// rỗng. Giờ dùng `decodeBase64NodeLike()`: iOS ký ĐÚNG như Android, và
    /// chỉ còn báo lỗi khi thực sự không lấy được khoá.
    private func signChallenge(_ payload: String) -> String {
        let encoding = JVHDConfig.challengeEncoding.lowercased()
        let message: Data
        if encoding == "base64" {
            message = JVHDCrypto.decodeBase64NodeLike(payload)
        } else if encoding == "hex" {
            message = Data(hexString: payload) ?? Data(payload.utf8)
        } else {
            message = Data(payload.utf8)
        }
        return DeviceKey.shared.signatureBase64(message: message)
    }

    /// Lý do kỹ thuật gần nhất, mở đầu bằng "ERR:" để phía JS nhận diện.
    private func errorText() -> String {
        let reason = DeviceKey.shared.lastError
        return reason.isEmpty ? "ERR: không rõ lý do" : "ERR: " + reason
    }

    /// JSON chẩn đoán cho `/__native/diag` (mở bằng Safari trong app hoặc
    /// `curl http://127.0.0.1:<cổng>/__native/diag` khi dev).
    private func diagnosticJSON() -> String {
        var info = DeviceKey.shared.statusDictionary()
        info["authServer"] = JVHDConfig.authServer
        info["base"] = baseURLString
        info["system"] = UIDevice.current.systemVersion
        info["device"] = UIDevice.current.model
        guard let data = try? JSONSerialization.data(withJSONObject: info, options: [.prettyPrinted]),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    private func environmentJSON() -> String {
        let dict: [String: Any] = [
            "base": baseURLString,
            "pubkey": DeviceKey.shared.publicKeyBase64(),
            "keyBackend": DeviceKey.shared.backend.rawValue,
            "salt": JVHDConfig.salt,
            "concat": JVHDConfig.concat,
            "authServer": JVHDConfig.authServer,
            "device": UIDevice.current.model,
            "system": UIDevice.current.systemVersion
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    // MARK: Tệp tĩnh

    private func serveStatic(_ request: HTTPRequest, _ connection: HTTPConnection) {
        var relativePath = request.path
        if relativePath == "/" || relativePath.isEmpty { relativePath = "/index.html" }
        relativePath = relativePath.removingPercentEncoding ?? relativePath
        let relative = relativePath.hasPrefix("/") ? String(relativePath.dropFirst()) : relativePath

        guard let root = Bundle.main.url(forResource: "www", withExtension: nil) else {
            connection.respond(status: 500,
                               headers: ["Content-Type": "text/plain; charset=utf-8"],
                               body: Data("Thiếu thư mục www trong app bundle".utf8),
                               keepAlive: false)
            return
        }
        let fileURL = root.appendingPathComponent(relative).standardizedFileURL
        // Chống path traversal.
        guard fileURL.path.hasPrefix(root.standardizedFileURL.path) else {
            connection.respond(status: 403,
                               headers: ["Content-Type": "text/plain; charset=utf-8"],
                               body: Data("Forbidden".utf8),
                               keepAlive: false)
            return
        }
        var payload: Data
        if let raw = try? Data(contentsOf: fileURL) {
            payload = raw
        } else {
            connection.respond(status: 404,
                               headers: ["Content-Type": "text/plain; charset=utf-8"],
                               body: Data("Not found: \(relativePath)".utf8),
                               keepAlive: false)
            return
        }

        // [iOS] Chèn lớp tương thích iOS vào đúng 2 tệp, mọi tệp khác giữ nguyên.
        if relative == "index.html" || relative.hasSuffix("/index.html") {
            if let html = String(data: payload, encoding: .utf8) {
                payload = Data(injectIOSRuntime(html).utf8)
            }
        } else if relative == "ios-bridge.js" {
            if let script = String(data: payload, encoding: .utf8) {
                payload = Data(substituteRuntimePlaceholders(script).utf8)
            }
        }

        let ext = (fileURL.pathExtension.isEmpty ? "" : "." + fileURL.pathExtension).lowercased()
        let contentType = mimeTypes[ext] ?? "application/octet-stream"
        var headers = ["Content-Type": contentType, "Cache-Control": "no-cache"]
        if payload.count > 0 { headers["Content-Length"] = String(payload.count) }
        if request.method == "HEAD" {
            connection.respond(status: 200, headers: headers, body: Data(), keepAlive: request.isKeepAlive)
            return
        }
        connection.respond(status: 200, headers: headers, body: payload, keepAlive: request.isKeepAlive)
    }

    // MARK: Chèn lớp tương thích iOS vào trang web

    /// Tỉ lệ co giao diện 1920x1080 cho vừa màn hình iPhone (giống fitToScreen
    /// của bản Windows): scale = min(sw/1920, sh/1080), layout rộng = sw/scale.
    func currentFit() -> (scale: CGFloat, layoutWidth: CGFloat) {
        let size = LocalServer.viewportSizeProvider()
        guard size.width > 0, size.height > 0 else { return (1, JVHDConfig.designWidth) }
        let base = min(size.width / JVHDConfig.designWidth, size.height / JVHDConfig.designHeight)
        let scale = min(JVHDConfig.maxFitScale, max(JVHDConfig.minFitScale, base))
        return (scale, size.width / scale)
    }

    private func injectIOSRuntime(_ html: String) -> String {
        var output = html
        let fit = currentFit()
        let viewport = String(format:
            "<meta name=\"viewport\" content=\"width=%.0f, initial-scale=%.5f, minimum-scale=%.5f, maximum-scale=%.5f, user-scalable=no, viewport-fit=cover\" />",
            fit.layoutWidth, fit.scale, fit.scale, fit.scale)

        if let regex = try? NSRegularExpression(pattern: "<meta\\s+name=[\"']viewport[\"'][^>]*>",
                                                options: [.caseInsensitive]),
           let match = regex.firstMatch(in: output, options: [],
                                        range: NSRange(location: 0, length: (output as NSString).length)),
           let range = Range(match.range, in: output) {
            output.replaceSubrange(range, with: viewport)
        } else if let headRange = output.range(of: "<head>", options: .caseInsensitive) {
            output.replaceSubrange(headRange, with: "<head>\n    " + viewport)
        }

        let cssTag = "<link rel=\"stylesheet\" href=\"/ios-bridge.css\" />"
        if let headClose = output.range(of: "</head>", options: .caseInsensitive) {
            output.replaceSubrange(headClose, with: "    " + cssTag + "\n" + "</head>")
        }

        let bridgeTag = "<script src=\"/ios-bridge.js\"></script>"
        if let appScript = output.range(of: "<script src=\"app.js\"></script>", options: .caseInsensitive) {
            output.replaceSubrange(appScript, with: bridgeTag + "\n    " + "<script src=\"app.js\"></script>")
        } else if let headClose = output.range(of: "</head>", options: .caseInsensitive) {
            output.replaceSubrange(headClose, with: bridgeTag + "\n" + "</head>")
        }
        return output
    }

    private func substituteRuntimePlaceholders(_ script: String) -> String {
        var output = script
        output = output.replacingOccurrences(of: "__JVHD_BASE_URL__", with: baseURLString)
        output = output.replacingOccurrences(of: "__JVHD_PUBKEY__", with: DeviceKey.shared.publicKeyBase64())
        output = output.replacingOccurrences(of: "__JVHD_SALT__", with: JVHDConfig.salt)
        output = output.replacingOccurrences(of: "__JVHD_CONCAT__", with: JVHDConfig.concat)
        return output
    }

    // MARK: Tiện ích

    func corsHeaders(_ extra: [String: String]) -> [String: String] {
        var headers = extra
        headers["Access-Control-Allow-Origin"] = "*"
        headers["Access-Control-Allow-Methods"] = "GET, HEAD, POST, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "*"
        return headers
    }

    /// Tạo URL proxy cho một URL nguồn (dùng bởi JS bridge và native player).
    func proxyURL(for url: String, referer: String?) -> String {
        let target = JVHDCrypto.encodeBase64(url)
        let ref = JVHDCrypto.encodeBase64(referer?.isEmpty == false ? referer! : url)
        guard let encodedTarget = target.addingPercentEncoding(withAllowedCharacters: .alphanumerics),
              let encodedRef = ref.addingPercentEncoding(withAllowedCharacters: .alphanumerics) else {
            return url
        }
        return "\(baseURLString)/jvhd-media/?u=\(encodedTarget)&r=\(encodedRef)"
    }
}

// MARK: - Data hex

extension Data {
    init?(hexString: String) {
        let text = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        let length = text.count
        guard length % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length / 2)
        var index = text.startIndex
        for _ in 0..<(length / 2) {
            let next = text.index(index, offsetBy: 2)
            guard let value = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(value)
            index = next
        }
        self = Data(bytes)
    }
}
