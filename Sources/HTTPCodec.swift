// HTTPCodec.swift - HTTP/1.1 codec for SoftEther handshake
// Handles HTTP request/response during initial connection phase

import Foundation
import NIOCore
import os.log

private let httpLog = OSLog(subsystem: "com.worxvpn.softether", category: "http")

/// Simple HTTP response
public struct HTTPResponse {
    public let statusCode: Int
    public let headers: [String: String]
    public let body: Data
    
    public var isSuccess: Bool { statusCode >= 200 && statusCode < 300 }
}

/// HTTP request builder
public struct HTTPRequest {
    public let method: String
    public let path: String
    public let headers: [String: String]
    public let body: Data
    
    public init(method: String = "POST", path: String, headers: [String: String] = [:], body: Data = Data()) {
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
    }
    
    /// Build HTTP/1.1 request bytes
    public func toData(host: String) -> Data {
        var lines = ["\(method) \(path) HTTP/1.1"]
        
        lines.append("Host: \(host)")
        
        // Add Content-Type header first (important for signature)
        if let contentType = headers["Content-Type"] {
            lines.append("Content-Type: \(contentType)")
        }
        
        // Connection header
        if let connection = headers["Connection"] {
            lines.append("Connection: \(connection)")
        } else {
            lines.append("Connection: Keep-Alive")
        }
        
        // For Pack data requests (/vpnsvc/vpn.cgi), add Date and Keep-Alive headers
        if path.contains("vpn.cgi") {
            let dateStr = formatHTTPDate()
            lines.append("Date: \(dateStr)")
            lines.append("Keep-Alive: timeout=15; max=19")
        }
        
        // Add custom headers (skip ones we handle specially)
        for (key, value) in headers where key != "Content-Length" && key != "Connection" && key != "Content-Type" {
            lines.append("\(key): \(value)")
        }
        
        // Always add Content-Length for body
        lines.append("Content-Length: \(body.count)")
        
        // End of headers (empty line)
        lines.append("")
        
        var data = lines.joined(separator: "\r\n").data(using: .utf8) ?? Data()
        data.append(contentsOf: [0x0D, 0x0A])  // Final \r\n after empty line
        data.append(body)
        
        return data
    }
    
    /// Format current date as HTTP date string: "Sat, 20 Dec 2025 13:31:23 GMT"
    private func formatHTTPDate() -> String {
        let now = Date()
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: now)
    }
}

/// HTTP response decoder state machine (thread-safe)
public final class HTTPResponseDecoder: @unchecked Sendable {
    private enum State {
        case idle
        case parsingStatusLine
        case parsingHeaders
        case parsingBody(contentLength: Int)
        case complete
    }
    
    private let lock = NSLock()
    private var state: State = .idle
    private var buffer = Data()
    
    private var statusCode: Int = 0
    private var headers: [String: String] = [:]
    private var body = Data()
    
    public init() {}
    
    /// Feed data into the decoder
    /// Returns the parsed response when complete, or nil if more data needed
    public func feed(_ data: Data) -> HTTPResponse? {
        lock.lock()
        defer { lock.unlock() }
        
        buffer.append(data)
        os_log(.debug, log: httpLog, "feed: buffer now %{public}d bytes", buffer.count)
        
        // Safety limit to prevent infinite loops
        var iterations = 0
        let maxIterations = 1000
        
        while iterations < maxIterations {
            iterations += 1
            
            switch state {
            case .idle:
                state = .parsingStatusLine
                continue
                
            case .parsingStatusLine:
                guard buffer.count >= 2 else { return nil }
                guard let lineEnd = findCRLF() else { return nil }
                guard lineEnd + 2 <= buffer.count else { return nil }
                
                // Safe data extraction
                let lineData = Data(buffer.prefix(lineEnd))
                let line = String(data: lineData, encoding: .utf8) ?? ""
                
                // Safe removal
                if buffer.count >= lineEnd + 2 {
                    buffer.removeFirst(lineEnd + 2)
                } else {
                    return nil
                }
                
                os_log(.default, log: httpLog, "Status line: %{public}s", line)
                
                // Parse "HTTP/1.1 200 OK"
                let parts = line.split(separator: " ", maxSplits: 2)
                if parts.count >= 2, let code = Int(parts[1]) {
                    statusCode = code
                }
                
                os_log(.default, log: httpLog, "Transitioning to parsingHeaders, buffer remaining: %{public}d bytes", buffer.count)
                state = .parsingHeaders
                continue
                
            case .parsingHeaders:
                os_log(.debug, log: httpLog, "parsingHeaders: buffer has %{public}d bytes", buffer.count)
                guard let lineEnd = findCRLF() else {
                    os_log(.debug, log: httpLog, "parsingHeaders: no CRLF found, need more data")
                    return nil
                }
                os_log(.debug, log: httpLog, "parsingHeaders: found CRLF at position %{public}d", lineEnd)
                
                if lineEnd == 0 {
                    // Empty line - end of headers
                    guard buffer.count >= 2 else {
                        os_log(.debug, log: httpLog, "parsingHeaders: buffer too small for empty line")
                        return nil
                    }
                    buffer.removeFirst(2)  // Remove \r\n
                    
                    let contentLength = headers["Content-Length"].flatMap(Int.init) ?? 0
                    os_log(.default, log: httpLog, "Headers done, Content-Length=%{public}d", contentLength)
                    if contentLength > 0 {
                        state = .parsingBody(contentLength: contentLength)
                    } else {
                        // Check for Transfer-Encoding: chunked
                        if headers["Transfer-Encoding"]?.lowercased().contains("chunked") == true {
                            // For now, read all available data
                            state = .parsingBody(contentLength: -1)
                        } else {
                            state = .complete
                        }
                    }
                    continue
                }
                
                guard lineEnd + 2 <= buffer.count else {
                    os_log(.debug, log: httpLog, "parsingHeaders: lineEnd+2 > buffer.count")
                    return nil
                }
                
                // Safe substring extraction using prefix
                let headerData = Data(buffer.prefix(lineEnd))
                let line = String(data: headerData, encoding: .utf8) ?? ""
                buffer.removeFirst(lineEnd + 2)
                os_log(.debug, log: httpLog, "Header: %{public}s", line)
                
                // Parse header
                if let colonIdx = line.firstIndex(of: ":") {
                    let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                    let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                    headers[key] = value
                }
                continue
                
            case .parsingBody(let contentLength):
                if contentLength >= 0 {
                    guard buffer.count >= contentLength else { return nil }
                    // Safe body extraction using prefix
                    body = Data(buffer.prefix(contentLength))
                    buffer.removeFirst(contentLength)
                    state = .complete
                    os_log(.default, log: httpLog, "Body complete: %{public}d bytes", body.count)
                    continue
                } else {
                    // Chunked or unknown length - try to read as much as possible
                    // For SoftEther, responses are typically complete
                    body = buffer
                    buffer.removeAll()
                    state = .complete
                    continue
                }
                
            case .complete:
                let response = HTTPResponse(statusCode: statusCode, headers: headers, body: body)
                os_log(.default, log: httpLog, "Response complete: HTTP %{public}d, body %{public}d bytes", statusCode, body.count)
                reset()
                return response
            }
        }
        
        // Fallback if we exit the loop (shouldn't happen normally)
        os_log(.error, log: httpLog, "feed: exceeded %{public}d iterations, returning nil", maxIterations)
        return nil
    }
    
    private func findCRLF() -> Int? {
        // Safe bounds checking
        guard buffer.count >= 2 else { return nil }
        
        // Use indices to safely iterate through Data
        let bytes = [UInt8](buffer)
        for i in 0..<(bytes.count - 1) {
            if bytes[i] == 0x0D && bytes[i + 1] == 0x0A {  // \r\n
                return i
            }
        }
        return nil
    }
    
    private func reset() {
        state = .idle
        statusCode = 0
        headers.removeAll()
        body.removeAll()
    }
    
    /// Public reset for external callers
    public func resetState() {
        lock.lock()
        defer { lock.unlock() }
        reset()
        buffer.removeAll()
    }
}

/// Thread-safe HTTP response reader for async/await
/// Uses locks instead of actors for NIO compatibility
public final class HTTPResponseReader: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<HTTPResponse, Error>?
    private var pendingResponse: HTTPResponse?
    private var pendingError: Error?
    private let decoder = HTTPResponseDecoder()
    
    public init() {}
    
    /// Synchronously access state under lock
    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
    
    /// Wait for an HTTP response (call from async context)
    public func waitForResponse() async throws -> HTTPResponse {
        // Check if we already have a response buffered
        let buffered: (response: HTTPResponse?, error: Error?) = withLock {
            if let response = pendingResponse {
                pendingResponse = nil
                return (response, nil)
            }
            if let error = pendingError {
                pendingError = nil
                return (nil, error)
            }
            return (nil, nil)
        }
        
        if let response = buffered.response {
            return response
        }
        if let error = buffered.error {
            throw error
        }
        
        // Wait for data to arrive
        return try await withCheckedThrowingContinuation { cont in
            self.lock.lock()
            // Double-check for pending response
            if let response = self.pendingResponse {
                self.pendingResponse = nil
                self.lock.unlock()
                cont.resume(returning: response)
                return
            }
            if let error = self.pendingError {
                self.pendingError = nil
                self.lock.unlock()
                cont.resume(throwing: error)
                return
            }
            self.continuation = cont
            self.lock.unlock()
        }
    }
    
    /// Feed received data (call from any thread - NIO safe)
    public func receive(_ data: Data) {
        lock.lock()
        
        guard let response = decoder.feed(data) else {
            lock.unlock()
            return // Need more data
        }
        
        // Grab continuation if exists, then unlock BEFORE resuming
        let cont = continuation
        if cont != nil {
            continuation = nil
        }
        
        if cont == nil {
            // Buffer the response for later
            pendingResponse = response
        }
        lock.unlock()
        
        // Resume AFTER unlocking to avoid deadlocks
        cont?.resume(returning: response)
    }
    
    /// Signal error (call from any thread - NIO safe)
    public func error(_ error: Error) {
        lock.lock()
        
        // Grab continuation if exists, then unlock BEFORE resuming
        let cont = continuation
        if cont != nil {
            continuation = nil
        }
        
        if cont == nil {
            pendingError = error
        }
        lock.unlock()
        
        // Resume AFTER unlocking to avoid deadlocks
        cont?.resume(throwing: error)
    }
    
    /// Reset state for new request/response cycle
    public func reset() {
        lock.lock()
        pendingResponse = nil
        pendingError = nil
        continuation = nil
        decoder.resetState()  // Also reset decoder state
        lock.unlock()
    }
}
