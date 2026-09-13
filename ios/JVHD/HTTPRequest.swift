/*
 * HTTPRequest.swift
 * Phân tích HTTP/1.1 tối giản cho máy chủ cục bộ (chỉ phục vụ WebView của app).
 */

import Foundation

struct HTTPRequest {
    var method: String = "GET"
    var path: String = "/"
    var query: [String: String] = [:]
    var headers: [String: String] = [:]
    var body: Data = Data()
    var version: String = "HTTP/1.1"

    var isKeepAlive: Bool {
        let connection = headers["connection"]?.lowercased() ?? ""
        if connection.contains("close") { return false }
        if connection.contains("keep-alive") { return true }
        return version.uppercased() == "HTTP/1.1"
    }
}

enum HTTPParseResult {
    case incomplete
    case request(HTTPRequest, consumedBytes: Int)
    case invalid
}

enum HTTPParser {

    private static let terminatorBytes: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]

    /// Tìm "\r\n\r\n" thủ công (không phụ thuộc API Data.range(of:) theo phiên bản).
    private static func terminatorRange(in buffer: Data) -> Range<Int>? {
        let bytes = [UInt8](buffer)
        guard bytes.count >= terminatorBytes.count else { return nil }
        var matched = 0
        for index in 0..<bytes.count {
            if bytes[index] == terminatorBytes[matched] {
                matched += 1
                if matched == terminatorBytes.count {
                    let upper = index + 1
                    return (upper - terminatorBytes.count)..<upper
                }
            } else {
                matched = (bytes[index] == terminatorBytes[0]) ? 1 : 0
            }
        }
        return nil
    }

    static func parse(_ buffer: Data) -> HTTPParseResult {
        guard let range = terminatorRange(in: buffer) else {
            // Chưa đọc đủ phần đầu.
            return buffer.count > 1 << 20 ? .invalid : .incomplete
        }
        let headData = buffer.subdata(in: 0..<range.lowerBound)
        guard let head = String(data: headData, encoding: .utf8) else { return .invalid }

        var lines = head.components(separatedBy: "\r\n")
        let requestLine = lines.removeFirst()
        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return .invalid }

        var request = HTTPRequest()
        request.method = parts[0].uppercased()
        let target = parts[1]
        if parts.count >= 3 { request.version = parts[2] }

        if let questionMark = target.firstIndex(of: "?") {
            request.path = String(target[target.startIndex..<questionMark])
            let queryString = String(target[target.index(after: questionMark)...])
            request.query = parseQuery(queryString)
        } else {
            request.path = target
        }

        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if name.isEmpty { continue }
            if let existing = request.headers[name] {
                request.headers[name] = existing + ", " + value
            } else {
                request.headers[name] = value
            }
        }

        let headerEnd = range.upperBound
        let contentLength = Int(request.headers["content-length"] ?? "") ?? 0
        let total = headerEnd + contentLength
        if buffer.count < total { return .incomplete }
        request.body = buffer.subdata(in: headerEnd..<min(total, buffer.count))
        return .request(request, consumedBytes: total)
    }

    static func parseQuery(_ query: String) -> [String: String] {
        var result: [String: String] = [:]
        for pair in query.components(separatedBy: "&") {
            if pair.isEmpty { continue }
            let pieces = pair.components(separatedBy: "=")
            let key = pieces[0].removingPercentEncoding ?? pieces[0]
            let value = pieces.count > 1
                ? (pieces[1...].joined(separator: "=").removingPercentEncoding ?? "")
                : ""
            result[key] = value
        }
        return result
    }
}
