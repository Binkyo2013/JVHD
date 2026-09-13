/*
 * MediaProxy.swift
 * Proxy nội dung — bản Swift của `src/server.js` (endpoint /jvhd-media).
 *
 *  - Giả User-Agent iPhone Safari để vượt WAF chặn UA TV/Android.
 *  - Giữ Referer gốc (chống anti-hotlink), chuyển tiếp Range (tua được mp4).
 *  - Tự bẻ lại playlist HLS: mọi variant/segment/key đều quay về proxy cục bộ
 *    => hls.js và AVPlayer không bao giờ gặp lỗi CORS.
 */

import Foundation

private final class UpstreamHandler {

    enum Mode {
        case unknown
        case playlist
        case stream
    }

    let connection: HTTPConnection
    let target: String
    let referer: String
    var mode: Mode = .unknown
    var head: HTTPURLResponse?
    var writer: StreamWriter?
    var buffer = Data()
    var task: URLSessionDataTask?
    var finished = false

    init(connection: HTTPConnection, target: String, referer: String) {
        self.connection = connection
        self.target = target
        self.referer = referer
    }

    func cancel() {
        task?.cancel()
    }
}

final class MediaProxy: NSObject, URLSessionDataDelegate {

    static let shared = MediaProxy()

    private var handlers: [Int: UpstreamHandler] = [:]
    private var redirectCounts: [Int: Int] = [:]
    private var cookies: [String: [String: String]] = [:]
    private let lock = NSLock()

    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = JVHDConfig.proxyTimeout
        configuration.timeoutIntervalForResource = 120
        configuration.networkServiceType = .avStreaming
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    private let uriRegex: NSRegularExpression? = {
        return try? NSRegularExpression(pattern: "URI\\s*=\\s*\"([^\"]+)\"", options: [.caseInsensitive])
    }()

    private override init() { super.init() }

    // MARK: - Điểm vào

    func handle(_ request: HTTPRequest, _ connection: HTTPConnection) {
        guard let encodedTarget = request.query["u"],
              let decoded = String(data: Data(base64Encoded: normalizeBase64(encodedTarget)) ?? Data(), encoding: .utf8),
              decoded.hasPrefix("http") else {
            connection.respond(status: 400,
                               headers: ["Content-Type": "text/plain; charset=utf-8"],
                               body: Data("bad target".utf8),
                               keepAlive: false)
            return
        }
        guard let url = URL(string: decoded) else {
            connection.respond(status: 400,
                               headers: ["Content-Type": "text/plain; charset=utf-8"],
                               body: Data("bad url".utf8),
                               keepAlive: false)
            return
        }
        let encodedReferer = request.query["r"] ?? ""
        let referer = (String(data: Data(base64Encoded: normalizeBase64(encodedReferer)) ?? Data(), encoding: .utf8) ?? "")
        let effectiveReferer = referer.isEmpty ? decoded : referer

        var urlRequest = URLRequest(url: url,
                                    cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                                    timeoutInterval: JVHDConfig.proxyTimeout)
        urlRequest.httpMethod = "GET"
        urlRequest.setValue(JVHDConfig.proxyUserAgent, forHTTPHeaderField: "User-Agent")
        urlRequest.setValue("*/*", forHTTPHeaderField: "Accept")
        urlRequest.setValue("vi,en;q=0.8", forHTTPHeaderField: "Accept-Language")
        urlRequest.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        if effectiveReferer.hasPrefix("http") {
            urlRequest.setValue(effectiveReferer, forHTTPHeaderField: "Referer")
        }
        if let range = request.headers["range"], !range.isEmpty {
            urlRequest.setValue(range, forHTTPHeaderField: "Range")
        }
        if let cookie = cookieHeader(for: url) {
            urlRequest.setValue(cookie, forHTTPHeaderField: "Cookie")
        }

        let handler = UpstreamHandler(connection: connection, target: decoded, referer: effectiveReferer)
        let task = session.dataTask(with: urlRequest)
        handler.task = task
        lock.lock()
        handlers[task.taskIdentifier] = handler
        redirectCounts[task.taskIdentifier] = 0
        lock.unlock()
        task.resume()
    }

    // MARK: - URLSessionDataDelegate

    func urlSession(_ session: URLSession,
                    task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        storeCookies(from: response)

        lock.lock()
        let count = (redirectCounts[task.taskIdentifier] ?? 0) + 1
        redirectCounts[task.taskIdentifier] = count
        lock.unlock()

        guard count <= JVHDConfig.maxRedirects, let url = request.url else {
            completionHandler(nil)
            return
        }
        var nextRequest = request
        nextRequest.setValue(JVHDConfig.proxyUserAgent, forHTTPHeaderField: "User-Agent")
        if let cookie = cookieHeader(for: url) {
            nextRequest.setValue(cookie, forHTTPHeaderField: "Cookie")
        }
        completionHandler(nextRequest)
    }

    func urlSession(_ session: URLSession,
                    dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let handler = handler(for: dataTask) else {
            completionHandler(.cancel)
            return
        }
        if let httpResponse = response as? HTTPURLResponse {
            handler.head = httpResponse
            storeCookies(from: httpResponse)
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let handler = handler(for: dataTask) else { return }
        if handler.mode == .unknown {
            handler.buffer.append(data)
            let contentType = handler.head?.allHeaderFields["Content-Type"] as? String ?? ""
            let isMpegUrl = contentType.lowercased().contains("mpegurl")
            let sniff = String(data: Data(handler.buffer.prefix(512)), encoding: .utf8) ?? ""
            let looksLikePlaylist = sniff
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .hasPrefix("#EXTM3U")
            if JVHDConfig.rewriteHLS && (isMpegUrl || looksLikePlaylist) {
                handler.mode = .playlist
                return
            }
            if JVHDConfig.rewriteHLS && !isMpegUrl && handler.buffer.count < 512 {
                // Chưa đủ dữ liệu để sniff playlist, chờ thêm (completion sẽ xả ra).
                return
            }
            handler.mode = .stream
            startStreaming(handler)
            return
        }
        if handler.mode == .playlist {
            handler.buffer.append(data)
            return
        }
        handler.writer?.write(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let handler = handler(for: task) else { return }
        lock.lock()
        handlers.removeValue(forKey: task.taskIdentifier)
        redirectCounts.removeValue(forKey: task.taskIdentifier)
        lock.unlock()

        if let error = error {
            if (error as NSError).code == NSURLErrorCancelled { return }
            NSLog("[JVHD][proxy] lỗi tải %@ : %@", handler.target, error.localizedDescription)
            if handler.mode == .stream, let writer = handler.writer {
                writer.finish()
                return
            }
            handler.connection.respond(status: 502,
                                       headers: ["Content-Type": "text/plain; charset=utf-8"],
                                       body: Data("Proxy error: \(error.localizedDescription)".utf8),
                                       keepAlive: false)
            return
        }

        if handler.mode == .playlist {
            finishPlaylist(handler)
            return
        }
        if handler.mode == .stream {
            handler.writer?.finish()
            return
        }
        // Không có body: trả nguyên trạng thái upstream.
        let status = handler.head?.statusCode ?? 200
        handler.connection.respond(status: status,
                                   headers: responseHeaders(from: handler.head, contentLength: 0),
                                   body: Data(),
                                   keepAlive: false)
    }

    // MARK: - Xử lý phản hồi

    private func startStreaming(_ handler: UpstreamHandler) {
        let head = handler.head
        let contentType = head?.allHeaderFields["Content-Type"] as? String ?? "application/octet-stream"
        var headers: [String: String] = ["Content-Type": contentType, "Cache-Control": "no-store"]
        headers["Access-Control-Allow-Origin"] = "*"
        headers["Access-Control-Allow-Headers"] = "*"
        if let contentLength = head?.allHeaderFields["Content-Length"] as? String { headers["Content-Length"] = contentLength }
        if let contentRange = head?.allHeaderFields["Content-Range"] as? String { headers["Content-Range"] = contentRange }
        if let acceptRanges = head?.allHeaderFields["Accept-Ranges"] as? String { headers["Accept-Ranges"] = acceptRanges }
        if let disposition = head?.allHeaderFields["Content-Disposition"] as? String { headers["Content-Disposition"] = disposition }

        let status = head?.statusCode ?? 200
        let writer = handler.connection.beginStream(status: status, headers: headers, keepAlive: true)
        handler.writer = writer
        if !handler.buffer.isEmpty {
            writer.write(handler.buffer)
            handler.buffer.removeAll()
        }
    }

    private func finishPlaylist(_ handler: UpstreamHandler) {
        let text = String(data: handler.buffer, encoding: .utf8) ?? ""
        let baseURL = handler.head?.url ?? URL(string: handler.target) ?? URL(string: "https://localhost")!
        let rewritten = rewritePlaylist(text, baseURL: baseURL, referer: handler.referer)
        let body = Data(rewritten.utf8)
        let contentType = handler.head?.allHeaderFields["Content-Type"] as? String ?? "application/vnd.apple.mpegurl"
        var headers: [String: String] = [
            "Content-Type": contentType.contains("mpegurl") ? contentType : "application/vnd.apple.mpegurl",
            "Cache-Control": "no-store"
        ]
        headers["Access-Control-Allow-Origin"] = "*"
        headers["Access-Control-Allow-Headers"] = "*"
        handler.connection.respond(status: handler.head?.statusCode ?? 200,
                                   headers: headers,
                                   body: body,
                                   keepAlive: true)
    }

    /// Bẻ playlist: mọi URI con (variant/segment/key) đều bọc về proxy cục bộ.
    private func rewritePlaylist(_ text: String, baseURL: URL, referer: String) -> String {
        let lines = text.components(separatedBy: "\n")
        let output: [String] = lines.map { rawLine in
            var line = rawLine
            if line.hasSuffix("\r") { line = String(line.dropLast()) }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { return line }
            if trimmed.hasPrefix("#") {
                if trimmed.range(of: "URI\\s*=", options: [.regularExpression, .caseInsensitive]) != nil {
                    return rewriteURIs(in: line, base: baseURL, referer: referer)
                }
                return line
            }
            guard let absolute = URL(string: trimmed, relativeTo: baseURL)?.absoluteString else { return line }
            return LocalServer.shared.proxyURL(for: absolute, referer: referer)
        }
        return output.joined(separator: "\n")
    }

    private func rewriteURIs(in line: String, base: URL, referer: String) -> String {
        guard let regex = uriRegex else { return line }
        let nsLine = line as NSString
        let matches = regex.matches(in: line, options: [], range: NSRange(location: 0, length: nsLine.length))
        guard !matches.isEmpty else { return line }
        var result = line
        for match in matches.reversed() {
            guard match.numberOfRanges >= 2 else { continue }
            let range = match.range(at: 1)
            let raw = nsLine.substring(with: range)
            guard let absolute = URL(string: raw, relativeTo: base)?.absoluteString else { continue }
            let proxied = LocalServer.shared.proxyURL(for: absolute, referer: referer)
            guard let stringRange = Range(range, in: result) else { continue }
            result.replaceSubrange(stringRange, with: proxied)
        }
        return result
    }

    private func responseHeaders(from head: HTTPURLResponse?, contentLength: Int) -> [String: String] {
        var headers: [String: String] = ["Content-Type": "application/octet-stream", "Cache-Control": "no-store"]
        if let contentType = head?.allHeaderFields["Content-Type"] as? String { headers["Content-Type"] = contentType }
        if contentLength > 0 { headers["Content-Length"] = String(contentLength) }
        headers["Access-Control-Allow-Origin"] = "*"
        return headers
    }

    // MARK: - cookie jar

    private func cookieHeader(for url: URL) -> String? {
        guard let host = url.host else { return nil }
        lock.lock()
        let stored = cookies[host]
        lock.unlock()
        guard let stored = stored, !stored.isEmpty else { return nil }
        return stored.map { "\($0.key)=\($0.value)" }.joined(separator: "; ")
    }

    private func storeCookies(from response: HTTPURLResponse) {
        guard let url = response.url, let host = url.host else { return }
        var headerStrings: [String: String] = [:]
        for (key, value) in response.allHeaderFields {
            if let name = key as? String, let stringValue = value as? String {
                headerStrings[name] = stringValue
            }
        }
        let parsed = HTTPCookie.cookies(withResponseHeaderFields: headerStrings, for: url)
        guard !parsed.isEmpty else { return }
        lock.lock()
        var jar = cookies[host] ?? [:]
        for cookie in parsed { jar[cookie.name] = cookie.value }
        cookies[host] = jar
        lock.unlock()
    }

    // MARK: - tiện ích

    private func handler(for task: URLSessionTask) -> UpstreamHandler? {
        lock.lock()
        let handler = handlers[task.taskIdentifier]
        lock.unlock()
        return handler
    }

    private func normalizeBase64(_ text: String) -> String {
        var value = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = value.count % 4
        if remainder > 0 { value.append(String(repeating: "=", count: 4 - remainder)) }
        return value
    }
}
