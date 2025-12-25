// SoftEtherClient.swift - Pure Swift SoftEther VPN Client
// Using NIOTransportServices (Network.framework) for iOS sandbox compatibility

import Foundation
import NIOCore
import NIOTransportServices
import Crypto
import Network
import Security
import os.log

// Public logger for debugging
private let seLog = OSLog(subsystem: "com.worxvpn.softether", category: "client")

/// Client connection state
public enum ConnectionState: CustomStringConvertible {
    case disconnected
    case connecting
    case handshaking
    case authenticating
    case connected
    case disconnecting
    case error(Error)
    
    public var description: String {
        switch self {
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .handshaking: return "handshaking"
        case .authenticating: return "authenticating"
        case .connected: return "connected"
        case .disconnecting: return "disconnecting"
        case .error(let err): return "error: \(err.localizedDescription)"
        }
    }
}

/// Session information from server
public struct SessionInfo {
    public let sessionKey: Data
    public let serverVersion: UInt32
    public let serverBuild: UInt32
    public let serverString: String
    public let assignedIP: UInt32
    public let subnetMask: UInt32
    public let gatewayIP: UInt32
    public let dnsServers: [UInt32]
    /// The actual IP address we're connected to (may differ from initial host after redirect)
    public let connectedServerIP: String
    
    public init(
        sessionKey: Data = Data(),
        serverVersion: UInt32 = 0,
        serverBuild: UInt32 = 0,
        serverString: String = "",
        assignedIP: UInt32 = 0,
        subnetMask: UInt32 = 0,
        gatewayIP: UInt32 = 0,
        dnsServers: [UInt32] = [],
        connectedServerIP: String = ""
    ) {
        self.sessionKey = sessionKey
        self.serverVersion = serverVersion
        self.serverBuild = serverBuild
        self.serverString = serverString
        self.assignedIP = assignedIP
        self.subnetMask = subnetMask
        self.gatewayIP = gatewayIP
        self.dnsServers = dnsServers
        self.connectedServerIP = connectedServerIP
    }
}

/// VPN configuration
public struct VPNConfiguration {
    public let host: String
    public let port: Int
    public let hubName: String
    public let username: String
    public let passwordHash: String  // Base64 encoded SHA0 hash
    public let useTLS: Bool
    public let sniHostname: String?  // Optional SNI hostname for TLS (uses host if nil)
    
    public init(
        host: String,
        port: Int = 443,
        hubName: String,
        username: String,
        passwordHash: String,
        useTLS: Bool = true,
        sniHostname: String? = nil
    ) {
        self.host = host
        self.port = port
        self.hubName = hubName
        self.username = username
        self.passwordHash = passwordHash
        self.useTLS = useTLS
        self.sniHostname = sniHostname
    }
}

/// Protocol constants
public enum SoftEtherProtocol {
    public static let vpnTarget = "/vpnsvc/vpn.cgi"
    public static let signatureTarget = "/vpnsvc/connect.cgi"
    public static let contentTypeSignature = "image/jpeg"
    public static let contentTypePack = "application/octet-stream"
    public static let clientString = "SoftEther VPN Client"
    public static let clientVersion: UInt32 = 444
    public static let clientBuild: UInt32 = 9807
    public static let sha1Size = 20
}

/// Authentication type
public enum AuthType: UInt32 {
    case anonymous = 0
    case password = 1
    case plainPassword = 2
    case certificate = 3
    case ticket = 99
}

/// Delegate for VPN client events
public protocol SoftEtherClientDelegate: AnyObject {
    func clientDidConnect(_ client: SoftEtherClient, session: SessionInfo)
    func clientDidDisconnect(_ client: SoftEtherClient, error: Error?)
    func client(_ client: SoftEtherClient, didReceivePacket data: Data)
    func client(_ client: SoftEtherClient, stateChanged state: ConnectionState)
}

/// SoftEther VPN Client using NIOTransportServices (Network.framework)
/// Uses Apple's Network.framework for iOS sandbox compatibility
public class SoftEtherClient {
    
    private let config: VPNConfiguration
    private let eventLoopGroup: NIOTSEventLoopGroup
    fileprivate var channel: Channel?  // fileprivate so handlers can check if they're still active
    
    private var state: ConnectionState = .disconnected {
        didSet {
            delegate?.client(self, stateChanged: state)
        }
    }
    
    // Virtual adapter
    private let macAddress: [UInt8]
    private var dhcpClient: DHCPClient?
    private var arpHandler: ARPHandler?
    
    // Session state
    private var serverRandom: [UInt8] = []
    private var sessionKey: Data?
    private var sessionInfo: SessionInfo?
    
    /// The actual IP address we're connected to (after any redirect)
    private var actualConnectedIP: String = ""
    
    // HTTP response handling (thread-safe via locks)
    fileprivate let httpResponseReader = HTTPResponseReader()
    
    public weak var delegate: SoftEtherClientDelegate?
    
    /// Data callback for received Ethernet frames
    public var onDataReceived: ((Data) -> Void)?
    
    /// Get the resolved gateway MAC address (learned from ARP)
    public var gatewayMAC: [UInt8]? {
        return arpHandler?.resolvedGatewayMAC
    }
    
    /// Initialize with configuration
    public init(config: VPNConfiguration) {
        self.config = config
        // NIOTSEventLoopGroup uses Network.framework - iOS sandbox safe!
        self.eventLoopGroup = NIOTSEventLoopGroup()
        
        // Generate MAC address (5E:xx:xx:xx:xx:xx for local addresses)
        self.macAddress = SoftEtherAuth.generateMACAddress()
    }
    
    deinit {
        try? disconnect()
        try? eventLoopGroup.syncShutdownGracefully()
    }
    
    // MARK: - Network Helpers
    
    /// Resolve hostname to IPv4 address string
    private func resolveHostToIPv4(_ host: String) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_INET  // IPv4 only
        hints.ai_socktype = SOCK_STREAM
        
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        defer { if result != nil { freeaddrinfo(result) } }
        
        guard status == 0, let addrInfo = result else {
            return nil
        }
        
        if let sockaddr = addrInfo.pointee.ai_addr {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            let addr4 = sockaddr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0 }
            var sin_addr = addr4.pointee.sin_addr
            if inet_ntop(AF_INET, &sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                return String(cString: buffer)
            }
        }
        
        return nil
    }
    
    /// Resolve IPv4 address to IPv6 if on NAT64 network
    /// iOS synthesizes IPv6 addresses for IPv4-only hosts using NAT64
    private func resolveWithNAT64(_ ipv4String: String) -> String {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC  // Allow both IPv4 and IPv6
        hints.ai_flags = AI_DEFAULT  // Use system default behavior (includes synthesis)
        
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(ipv4String, nil, &hints, &result)
        defer { if result != nil { freeaddrinfo(result) } }
        
        guard status == 0, let addrInfo = result else {
            os_log(.default, log: seLog, "getaddrinfo failed for %{public}s: %{public}d", ipv4String, status)
            return ipv4String
        }
        
        // Look for IPv6 synthesized address first, then fallback to IPv4
        var ipv6Found: String?
        var current = addrInfo
        
        while true {
            if current.pointee.ai_family == AF_INET6,
               let sockaddr = current.pointee.ai_addr {
                sockaddr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { addr6 in
                    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    var sin6_addr = addr6.pointee.sin6_addr
                    if inet_ntop(AF_INET6, &sin6_addr, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                        ipv6Found = String(cString: buffer)
                    }
                }
            }
            
            guard let next = current.pointee.ai_next else { break }
            current = next
        }
        
        if let ipv6 = ipv6Found {
            os_log(.default, log: seLog, "NAT64 synthesized %{public}s -> %{public}s", ipv4String, ipv6)
            return ipv6
        }
        
        return ipv4String
    }
    
    // MARK: - Connection
    
    /// Connect to VPN server
    public func connect() async throws {
        guard case .disconnected = state else {
            throw SoftEtherError.alreadyConnected
        }
        
        state = .connecting
        
        do {
            // Use NIOTSConnectionBootstrap which uses Network.framework
            // This is iOS sandbox compatible (unlike BSD sockets)
            var bootstrap = NIOTSConnectionBootstrap(group: eventLoopGroup)
                .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .channelInitializer { [weak self] channel in
                    guard let self = self else {
                        return channel.eventLoop.makeSucceededVoidFuture()
                    }
                    return self.configureChannel(channel)
                }
            
            // Add TLS if needed (Network.framework handles TLS natively)
            if config.useTLS {
                let tlsOptions = NWProtocolTLS.Options()
                
                // Configure to allow self-signed/invalid certificates
                // SoftEther servers typically use self-signed certs
                sec_protocol_options_set_verify_block(
                    tlsOptions.securityProtocolOptions,
                    { (sec_protocol_metadata, sec_trust, sec_protocol_verify_complete) in
                        // Accept all certificates (SoftEther uses self-signed certs)
                        sec_protocol_verify_complete(true)
                    },
                    DispatchQueue.global()
                )
                
                bootstrap = bootstrap.tlsOptions(tlsOptions)
            }
            
            channel = try await bootstrap.connect(host: config.host, port: config.port).get()
            
            // Track the initial server IP (resolve hostname to IP for route exclusion)
            actualConnectedIP = resolveHostToIPv4(config.host) ?? config.host
            os_log(.default, log: seLog, "Connected, actualConnectedIP=%{public}s", actualConnectedIP)
            
            state = .handshaking
            
            // Perform protocol handshake
            try await performHandshake()
            
            state = .connected
            
            // Notify delegate
            if let sessionInfo = sessionInfo {
                delegate?.clientDidConnect(self, session: sessionInfo)
            }
            
        } catch {
            state = .error(error)
            throw error
        }
    }
    
    /// Disconnect from VPN server
    public func disconnect() throws {
        guard let channel = channel else { return }
        
        state = .disconnecting
        
        try channel.close().wait()
        self.channel = nil
        
        state = .disconnected
        delegate?.clientDidDisconnect(self, error: nil)
    }
    
    /// Send Ethernet frame through tunnel
    public func sendPacket(_ data: Data) throws {
        guard case .connected = state, let channel = channel else {
            throw SoftEtherError.notConnected
        }
        
        try sendPacketInternal(data, channel: channel)
    }
    
    /// Internal send function - doesn't check state (for use during handshake)
    private func sendPacketInternal(_ data: Data, channel: Channel) throws {
        // Frame format: [4 bytes num_blocks] [4 bytes block_size] [data]
        var buffer = channel.allocator.buffer(capacity: 8 + data.count)
        buffer.writeInteger(UInt32(1), endianness: .big)  // 1 block
        buffer.writeInteger(UInt32(data.count), endianness: .big)
        buffer.writeBytes(data)
        
        channel.writeAndFlush(buffer, promise: nil)
    }
    
    /// Send keep-alive
    public func sendKeepalive() throws {
        guard case .connected = state, let channel = channel else {
            throw SoftEtherError.notConnected
        }
        
        // Keep-alive: [0xFFFFFFFF] [size] [padding]
        let size: UInt32 = 64  // Small padding
        var buffer = channel.allocator.buffer(capacity: Int(8 + size))
        buffer.writeInteger(UInt32(0xFFFFFFFF), endianness: .big)
        buffer.writeInteger(size, endianness: .big)
        
        // Write random padding
        var padding = [UInt8](repeating: 0, count: Int(size))
        for i in 0..<Int(size) {
            padding[i] = UInt8.random(in: 0...255)
        }
        buffer.writeBytes(padding)
        
        channel.writeAndFlush(buffer, promise: nil)
    }
    
    /// Get DHCP configuration
    public var dhcpConfig: (ip: UInt32, mask: UInt32, gateway: UInt32, dns: [UInt32])? {
        guard let dhcp = dhcpClient, dhcp.config.isValid else { return nil }
        let c = dhcp.config
        return (c.ipAddress, c.subnetMask, c.gateway, [c.dns1, c.dns2].filter { $0 != 0 })
    }
    
    // MARK: - Private
    
    private func configureChannel(_ channel: Channel) -> EventLoopFuture<Void> {
        // Note: TLS is handled by Network.framework via NIOTSConnectionBootstrap.tlsOptions
        // We only need the raw data handler for the handshake
        return channel.pipeline.addHandler(RawDataHandler(client: self), name: "rawData")
    }
    
    private func performHandshake() async throws {
        guard let channel = channel else {
            throw SoftEtherError.notConnected
        }
        
        os_log(.default, log: seLog, "Step 1: Uploading signature...")
        
        // Step 1: Upload signature (POST to /vpnsvc/connect.cgi)
        // This triggers the server to send back the Hello response
        do {
            try await uploadSignature(channel: channel)
        } catch {
            os_log(.error, log: seLog, "uploadSignature failed: %{public}s", error.localizedDescription)
            throw error
        }
        
        os_log(.default, log: seLog, "Signature uploaded, waiting for Hello response...")
        
        // Step 2: Download Hello (get server random)
        // The server responds to the signature with the Hello Pack
        let helloResponse: HTTPResponse
        do {
            helloResponse = try await waitForHTTPResponse()
        } catch {
            os_log(.error, log: seLog, "waitForHTTPResponse (Hello) failed: %{public}s", error.localizedDescription)
            throw error
        }
        os_log(.default, log: seLog, "Hello response received: HTTP %{public}d, body %{public}d bytes", helloResponse.statusCode, helloResponse.body.count)
        guard helloResponse.isSuccess else {
            throw SoftEtherError.serverError(helloResponse.statusCode)
        }
        
        os_log(.default, log: seLog, "Parsing Hello response...")
        let hello: HelloResponse
        do {
            hello = try parseHelloResponse(helloResponse)
        } catch {
            os_log(.error, log: seLog, "parseHelloResponse failed: %{public}s", error.localizedDescription)
            throw error
        }
        serverRandom = hello.random
        os_log(.default, log: seLog, "Hello parsed: version=%{public}u, build=%{public}u, random=%{public}d bytes", hello.serverVersion, hello.serverBuild, hello.random.count)
        
        // Reset HTTP reader for next request
        httpResponseReader.reset()
        
        // Step 3: Upload authentication (POST to /vpnsvc/vpn.cgi)
        state = .authenticating
        os_log(.default, log: seLog, "Step 3: Uploading authentication...")
        do {
            try await uploadAuth(channel: channel, serverRandom: hello.random)
        } catch {
            os_log(.error, log: seLog, "uploadAuth failed: %{public}s", error.localizedDescription)
            throw error
        }
        
        os_log(.default, log: seLog, "Auth uploaded, waiting for response...")
        // Step 4: Get auth response
        let authResponse: HTTPResponse
        do {
            authResponse = try await waitForHTTPResponse()
        } catch {
            os_log(.error, log: seLog, "waitForHTTPResponse (Auth) failed: %{public}s", error.localizedDescription)
            throw error
        }
        os_log(.default, log: seLog, "Auth response: HTTP %{public}d, body %{public}d bytes", authResponse.statusCode, authResponse.body.count)
        guard authResponse.isSuccess else {
            throw SoftEtherError.authenticationFailed("HTTP \(authResponse.statusCode)")
        }
        
        var authResult = try parseAuthResponse(authResponse)
        
        // Handle cluster redirect
        if let redirect = authResult.redirect {
            // Need to reconnect to cluster server with ticket auth
            authResult = try await handleClusterRedirect(redirect: redirect, hello: hello)
        }
        
        guard authResult.success else {
            throw SoftEtherError.authenticationFailed(authResult.errorMessage ?? "Unknown error")
        }
        
        sessionKey = authResult.sessionKey
        
        // Step 5: Initialize DHCP and ARP
        dhcpClient = DHCPClient(mac: macAddress)
        arpHandler = ARPHandler(mac: macAddress)
        
        // Get the current channel (may have changed due to redirect)
        os_log(.default, log: seLog, "Checking channel after auth: channel=%{public}s", self.channel != nil ? "SET" : "NIL")
        guard let currentChannel = self.channel else {
            os_log(.error, log: seLog, "Channel is nil after successful auth!")
            throw SoftEtherError.notConnected
        }
        
        os_log(.default, log: seLog, "Channel isActive=%{public}s", currentChannel.isActive ? "YES" : "NO")
        
        // Remove raw data handler and add tunnel handlers
        do {
            try await currentChannel.pipeline.removeHandler(name: "rawData").get()
            os_log(.default, log: seLog, "Removed rawData handler")
        } catch {
            os_log(.error, log: seLog, "Failed to remove rawData handler: %{public}s", error.localizedDescription)
            throw error
        }
        
        let decoder = TunnelFrameDecoder()
        do {
            try await currentChannel.pipeline.addHandler(ByteToMessageHandler(decoder), name: "tunnelDecoder").get()
            try await currentChannel.pipeline.addHandler(TunnelDataHandler(client: self), name: "tunnelHandler").get()
            os_log(.default, log: seLog, "Added tunnel handlers")
        } catch {
            os_log(.error, log: seLog, "Failed to add tunnel handlers: %{public}s", error.localizedDescription)
            throw error
        }
        
        // Perform DHCP to get IP
        try await performDHCP()
        
        // Create session info (includes actual connected IP for route exclusion)
        sessionInfo = SessionInfo(
            sessionKey: sessionKey ?? Data(),
            serverVersion: hello.serverVersion,
            serverBuild: hello.serverBuild,
            serverString: hello.serverString,
            assignedIP: dhcpClient?.config.ipAddress ?? 0,
            subnetMask: dhcpClient?.config.subnetMask ?? 0,
            gatewayIP: dhcpClient?.config.gateway ?? 0,
            dnsServers: [dhcpClient?.config.dns1 ?? 0, dhcpClient?.config.dns2 ?? 0].filter { $0 != 0 },
            connectedServerIP: actualConnectedIP
        )
        os_log(.default, log: seLog, "Session info created with connectedServerIP=%{public}s", actualConnectedIP)
    }
    
    /// Handle cluster server redirect
    private func handleClusterRedirect(redirect: RedirectInfo, hello: HelloResponse) async throws -> AuthResult {
        // Log redirect info - IP is stored as a 32-bit integer where the bytes directly represent the IP octets
        // Use memory layout (like Zig's @bitCast) to extract bytes correctly
        let ipValue = redirect.ip
        let ipBytes = withUnsafeBytes(of: ipValue) { Array($0) }
        let redirectIPv4 = "\(ipBytes[0]).\(ipBytes[1]).\(ipBytes[2]).\(ipBytes[3])"
        os_log(.default, log: seLog, "Cluster redirect to %{public}s:%{public}d (raw IP: 0x%{public}08x)", redirectIPv4, redirect.port, ipValue)
        
        // Log ticket for debugging
        let ticketHex = redirect.ticket.map { String(format: "%02x", $0) }.joined()
        os_log(.default, log: seLog, "Redirect ticket: %{public}s", ticketHex)
        
        // CRITICAL: Send empty pack to acknowledge redirect before disconnecting
        // This tells the controller we received the redirect info
        os_log(.default, log: seLog, "Sending redirect acknowledgment...")
        if let channel = self.channel {
            let emptyPack = Pack()
            let ackData = emptyPack.toData()
            
            let request = HTTPRequest(
                method: "POST",
                path: SoftEtherProtocol.vpnTarget,
                headers: [
                    "Content-Type": SoftEtherProtocol.contentTypePack,
                    "Connection": "Keep-Alive"
                ],
                body: ackData
            )
            
            let data = request.toData(host: config.host)
            var buffer = channel.allocator.buffer(capacity: data.count)
            buffer.writeBytes(data)
            
            let promise = channel.eventLoop.makePromise(of: Void.self)
            channel.writeAndFlush(buffer, promise: promise)
            try await promise.futureResult.get()
            
            // Wait a moment for server to process
            try await Task.sleep(nanoseconds: 100_000_000) // 100ms
            
            // Clear channel reference BEFORE closing so handlers know to ignore events
            self.channel = nil
            
            // Close current connection
            try? await channel.close().get()
        }
        
        // Reset HTTP response reader for new connection
        httpResponseReader.reset()
        
        // Let iOS Network.framework handle NAT64 synthesis automatically
        // It will synthesize IPv6 addresses for IPv4-only destinations on IPv6-only networks
        let redirectHost = redirectIPv4
        
        // Try redirect server first, then fall back to original server
        let hostsToTry = [redirectHost, config.host]
        var lastError: Error? = nil
        
        for (index, host) in hostsToTry.enumerated() {
            let isRedirect = index == 0
            let port = isRedirect ? Int(redirect.port) : config.port
            
            os_log(.default, log: seLog, "Connecting to %{public}s server: %{public}s:%{public}d",
                   isRedirect ? "redirect" : "original", host, port)
            
            do {
                var bootstrap = NIOTSConnectionBootstrap(group: eventLoopGroup)
                    .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                    .connectTimeout(.seconds(10))
                    .channelInitializer { [weak self] channel in
                        guard let self = self else {
                            return channel.eventLoop.makeSucceededVoidFuture()
                        }
                        return self.configureChannel(channel)
                    }
                
                if config.useTLS {
                    let tlsOptions = NWProtocolTLS.Options()
                    // Use original hostname for SNI verification if we have it
                    if let sniName = self.config.sniHostname ?? (self.config.host.first(where: { $0.isLetter }) != nil ? self.config.host : nil) {
                        sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, sniName)
                    }
                    sec_protocol_options_set_verify_block(
                        tlsOptions.securityProtocolOptions,
                        { (_, _, complete) in complete(true) },
                        DispatchQueue.global()
                    )
                    bootstrap = bootstrap.tlsOptions(tlsOptions)
                }
                
                self.channel = try await bootstrap.connect(host: host, port: port).get()
                // Track the actual connected IP for route exclusion
                self.actualConnectedIP = host
                os_log(.default, log: seLog, "Redirect channel assigned: %{public}s, actualConnectedIP=%{public}s", self.channel != nil ? "SET" : "NIL", host)
                
                guard let newChannel = self.channel else {
                    throw SoftEtherError.connectionFailed
                }
                
                // Perform handshake with ticket auth on new connection
                httpResponseReader.reset()
                
                // Step 1: Upload signature (triggers Hello response)
                try await uploadSignature(channel: newChannel)
                
                // Step 2: Download Hello
                let helloResponse = try await waitForHTTPResponse()
                guard helloResponse.isSuccess else {
                    throw SoftEtherError.serverError(helloResponse.statusCode)
                }
                
                let newHello = try parseHelloResponse(helloResponse)
                serverRandom = newHello.random
                
                // Step 3: Upload ticket auth
                try await uploadTicketAuth(channel: newChannel, serverRandom: newHello.random, ticket: redirect.ticket)
                
                // Step 4: Get auth response
                let authResponse = try await waitForHTTPResponse()
                guard authResponse.isSuccess else {
                    throw SoftEtherError.authenticationFailed("HTTP \(authResponse.statusCode)")
                }
                
                os_log(.default, log: seLog, "Successfully connected to %{public}s server", isRedirect ? "redirect" : "original")
                os_log(.default, log: seLog, "handleClusterRedirect returning, channel=%{public}s", self.channel != nil ? "SET" : "NIL")
                return try parseAuthResponse(authResponse)
                
            } catch {
                os_log(.error, log: seLog, "Failed to connect to %{public}s: %{public}s", host, error.localizedDescription)
                lastError = error
                
                // Clean up before trying next host
                if let channel = self.channel {
                    try? await channel.close().get()
                    self.channel = nil
                }
                httpResponseReader.reset()
            }
        }
        
        throw lastError ?? SoftEtherError.connectionFailed
    }
    
    /// Upload ticket authentication (for cluster redirect)
    private func uploadTicketAuth(channel: Channel, serverRandom: [UInt8], ticket: [UInt8]) async throws {
        let ticketPack = buildTicketAuthPack(serverRandom: serverRandom, ticket: ticket)
        let packData = ticketPack.toData()
        
        let request = HTTPRequest(
            method: "POST",
            path: SoftEtherProtocol.vpnTarget,
            headers: [
                "Content-Type": SoftEtherProtocol.contentTypePack,
                "Content-Length": "\(packData.count)"
            ],
            body: packData
        )
        
        let data = request.toData(host: config.host)
        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        
        let promise = channel.eventLoop.makePromise(of: Void.self)
        channel.writeAndFlush(buffer, promise: promise)
        try await promise.futureResult.get()
    }
    
    /// Build Auth Pack with ticket authentication (for cluster redirect)
    private func buildTicketAuthPack(serverRandom: [UInt8], ticket: [UInt8]) -> Pack {
        let pack = Pack()
        
        // Authentication fields with ticket
        pack.addStr("method", "login")
        pack.addStr("hubname", config.hubName)
        pack.addStr("username", config.username)
        pack.addInt("authtype", AuthType.ticket.rawValue)  // 99 = ticket auth
        
        // Add ticket instead of secure_password
        pack.addData("ticket", Data(ticket))
        
        // PackAddClientVersion fields
        pack.addStr("client_str", SoftEtherProtocol.clientString)
        pack.addInt("client_ver", SoftEtherProtocol.clientVersion)
        pack.addInt("client_build", SoftEtherProtocol.clientBuild)
        
        // Protocol
        pack.addInt("protocol", 0)  // TCP
        
        // Version fields
        pack.addStr("hello", SoftEtherProtocol.clientString)
        pack.addInt("version", SoftEtherProtocol.clientVersion)
        pack.addInt("build", SoftEtherProtocol.clientBuild)
        pack.addInt("client_id", 0)
        
        // Connection options
        pack.addInt("max_connection", 1)
        pack.addBool("use_encrypt", true)
        pack.addBool("use_compress", false)
        pack.addBool("half_connection", false)
        pack.addBool("require_bridge_routing_mode", false)
        pack.addBool("require_monitor_mode", false)
        pack.addBool("qos", true)
        
        // UDP acceleration
        pack.addBool("support_bulk_on_rudp", false)
        pack.addBool("support_hmac_on_bulk_of_rudp", false)
        pack.addBool("support_udp_recovery", false)
        
        // Unique ID
        let uniqueId = SoftEtherAuth.randomBytes(count: 20)
        pack.addData("unique_id", Data(uniqueId))
        
        pack.addInt("rudp_bulk_max_version", 0)
        
        // Cedar->UniqueId
        let cedarUniqueId = SoftEtherAuth.randomBytes(count: 20)
        
        // NodeInfo fields
        pack.addStr("ClientProductName", SoftEtherProtocol.clientString)
        pack.addStr("ServerProductName", "")
        pack.addStr("ClientOsName", "iOS")
        pack.addStr("ClientOsVer", "17.0")
        pack.addStr("ClientOsProductId", "")
        pack.addStr("ClientHostname", "swift-client")
        pack.addStr("ServerHostname", "")
        pack.addStr("ProxyHostname", "")
        pack.addStr("HubName", config.hubName)
        pack.addData("UniqueId", Data(cedarUniqueId))
        pack.addInt("ClientProductVer", SoftEtherProtocol.clientVersion)
        pack.addInt("ClientProductBuild", SoftEtherProtocol.clientBuild)
        pack.addInt("ServerProductVer", 0)
        pack.addInt("ServerProductBuild", 0)
        
        // IP addresses
        addPackIp32(pack, name: "ClientIpAddress", ip: 0)
        pack.addData("ClientIpAddress6", Data(repeating: 0, count: 16))
        pack.addInt("ClientPort", 0)
        addPackIp32(pack, name: "ServerIpAddress", ip: 0)
        pack.addData("ServerIpAddress6", Data(repeating: 0, count: 16))
        pack.addInt("ServerPort2", 0)
        addPackIp32(pack, name: "ProxyIpAddress", ip: 0)
        pack.addData("ProxyIpAddress6", Data(repeating: 0, count: 16))
        pack.addInt("ProxyPort", 0)
        
        // WinVer fields
        pack.addBool("V_IsWindows", false)
        pack.addBool("V_IsNT", false)
        pack.addBool("V_IsServer", false)
        pack.addBool("V_IsBeta", false)
        pack.addInt("V_VerMajor", 17)
        pack.addInt("V_VerMinor", 0)
        pack.addInt("V_Build", 0)
        pack.addInt("V_ServicePack", 0)
        pack.addStr("V_Title", "iOS 17")
        
        // Pencore padding
        let pencoreSize = Int.random(in: 0...1000)
        let pencoreData = SoftEtherAuth.randomBytes(count: pencoreSize)
        pack.addData("pencore", Data(pencoreData))
        
        return pack
    }
    
    private func uploadSignature(channel: Channel) async throws {
        // Send "VPNCONNECT" signature (matching Zig implementation)
        // The official SoftEther client can use either the WaterMark GIF or "VPNCONNECT" string
        let signature = Data("VPNCONNECT".utf8)
        
        let request = HTTPRequest(
            method: "POST",
            path: SoftEtherProtocol.signatureTarget,
            headers: [
                "Content-Type": SoftEtherProtocol.contentTypeSignature,
                "Connection": "Keep-Alive"
            ],
            body: signature
        )
        
        let data = request.toData(host: config.host)
        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        
        let promise = channel.eventLoop.makePromise(of: Void.self)
        channel.writeAndFlush(buffer, promise: promise)
        try await promise.futureResult.get()
    }
    
    private func uploadAuth(channel: Channel, serverRandom: [UInt8]) async throws {
        // Build auth Pack
        let authPack = buildAuthPack(serverRandom: serverRandom)
        let packData = authPack.toData()
        
        let request = HTTPRequest(
            method: "POST",
            path: SoftEtherProtocol.vpnTarget,
            headers: [
                "Content-Type": SoftEtherProtocol.contentTypePack,
                "Content-Length": "\(packData.count)"
            ],
            body: packData
        )
        
        let data = request.toData(host: config.host)
        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        
        let promise = channel.eventLoop.makePromise(of: Void.self)
        channel.writeAndFlush(buffer, promise: promise)
        try await promise.futureResult.get()
    }
    
    private func parseHelloResponse(_ response: HTTPResponse) throws -> HelloResponse {
        os_log(.default, log: seLog, "parseHelloResponse: parsing %{public}d bytes", response.body.count)
        
        // Log first bytes for debugging
        if response.body.count >= 4 {
            let first4 = response.body.prefix(4).map { String(format: "%02x", $0) }.joined()
            os_log(.default, log: seLog, "Body first 4 bytes: %{public}s", first4)
        }
        
        let pack: Pack
        do {
            pack = try Pack.fromData(response.body)
            os_log(.default, log: seLog, "Pack parsed successfully")
        } catch {
            os_log(.error, log: seLog, "Pack parsing failed: %{public}s", error.localizedDescription)
            throw error
        }
        
        // Check for error field (like Zig does)
        if let errorCode = pack.getInt("error"), errorCode != 0 {
            os_log(.error, log: seLog, "Server error in Pack: %{public}u", errorCode)
            throw SoftEtherError.serverError(Int(errorCode))
        }
        
        guard let randomData = pack.getData("random"),
              randomData.count == SoftEtherProtocol.sha1Size else {
            os_log(.error, log: seLog, "No random field or wrong size")
            throw SoftEtherError.invalidResponse
        }
        os_log(.default, log: seLog, "random field found: %{public}d bytes", randomData.count)
        
        return HelloResponse(
            random: Array(randomData),
            serverVersion: pack.getInt("version") ?? 0,
            serverBuild: pack.getInt("build") ?? 0,
            serverString: pack.getStr("hello") ?? "Unknown"
        )
    }
    
    private func parseAuthResponse(_ response: HTTPResponse) throws -> AuthResult {
        let respPack = try Pack.fromData(response.body)
        
        let errorCode = respPack.getInt("error") ?? 0
        if errorCode != 0 {
            let errorMsg = respPack.getStr("error_str") ?? "Error \(errorCode)"
            return AuthResult(
                success: false,
                errorCode: errorCode,
                errorMessage: errorMsg,
                sessionKey: nil,
                redirect: nil
            )
        }
        
        // Check for redirect (cluster server setup)
        let redirectFlag = respPack.getInt("Redirect") ?? 0
        if redirectFlag != 0 {
            let redirectIP = respPack.getInt("Ip") ?? 0
            let redirectPort = UInt16(respPack.getInt("Port") ?? 443)
            
            var ticket = [UInt8](repeating: 0, count: 20)
            if let ticketData = respPack.getData("Ticket") {
                let copyLen = min(ticketData.count, 20)
                for i in 0..<copyLen {
                    ticket[i] = ticketData[i]
                }
            }
            
            return AuthResult(
                success: true,
                errorCode: 0,
                errorMessage: nil,
                sessionKey: nil,
                redirect: RedirectInfo(ip: redirectIP, port: redirectPort, ticket: ticket)
            )
        }
        
        return AuthResult(
            success: true,
            errorCode: 0,
            errorMessage: nil,
            sessionKey: respPack.getData("session_key"),
            redirect: nil
        )
    }
    
    private func buildAuthPack(serverRandom: [UInt8]) -> Pack {
        let pack = Pack()
        
        // Authentication fields (method must be "login", not "auth")
        pack.addStr("method", "login")
        pack.addStr("hubname", config.hubName)
        pack.addStr("username", config.username)
        pack.addInt("authtype", AuthType.password.rawValue)
        
        // Compute secure password
        let securePassword = computeSecurePassword(serverRandom: serverRandom)
        pack.addData("secure_password", securePassword)
        
        // PackAddClientVersion fields
        pack.addStr("client_str", SoftEtherProtocol.clientString)
        pack.addInt("client_ver", SoftEtherProtocol.clientVersion)
        pack.addInt("client_build", SoftEtherProtocol.clientBuild)
        
        // Protocol (0 = TCP, 1 = UDP) - C adds this BEFORE hello/version/build
        pack.addInt("protocol", 0)  // TCP
        
        // Version fields (C adds AFTER protocol)
        pack.addStr("hello", SoftEtherProtocol.clientString)
        pack.addInt("version", SoftEtherProtocol.clientVersion)
        pack.addInt("build", SoftEtherProtocol.clientBuild)
        pack.addInt("client_id", 0)  // Cedar client ID
        
        // Connection options
        pack.addInt("max_connection", 1)
        pack.addBool("use_encrypt", true)
        pack.addBool("use_compress", false)
        pack.addBool("half_connection", false)
        
        // Bridge/monitor mode flags
        pack.addBool("require_bridge_routing_mode", false)
        pack.addBool("require_monitor_mode", false)
        
        // QoS flag
        pack.addBool("qos", true)
        
        // UDP acceleration (disabled for simplicity)
        pack.addBool("support_bulk_on_rudp", false)
        pack.addBool("support_hmac_on_bulk_of_rudp", false)
        pack.addBool("support_udp_recovery", false)
        
        // Unique ID (machine identifier)
        let uniqueId = SoftEtherAuth.randomBytes(count: 20)
        pack.addData("unique_id", Data(uniqueId))
        
        // RUDP bulk max version
        pack.addInt("rudp_bulk_max_version", 0)
        
        // Cedar->UniqueId is SEPARATE from unique_id in C
        let cedarUniqueId = SoftEtherAuth.randomBytes(count: 20)
        
        // Add NodeInfo fields (required by server) - matching Zig implementation
        pack.addStr("ClientProductName", SoftEtherProtocol.clientString)
        pack.addStr("ServerProductName", "")
        pack.addStr("ClientOsName", "iOS")
        pack.addStr("ClientOsVer", "17.0")
        pack.addStr("ClientOsProductId", "")
        pack.addStr("ClientHostname", "swift-client")
        pack.addStr("ServerHostname", "")
        pack.addStr("ProxyHostname", "")
        pack.addStr("HubName", config.hubName)
        pack.addData("UniqueId", Data(cedarUniqueId))
        pack.addInt("ClientProductVer", SoftEtherProtocol.clientVersion)
        pack.addInt("ClientProductBuild", SoftEtherProtocol.clientBuild)
        pack.addInt("ServerProductVer", 0)
        pack.addInt("ServerProductBuild", 0)
        
        // Add IP addresses like C's PackAddIp32 (adds 4 elements each)
        addPackIp32(pack, name: "ClientIpAddress", ip: 0)
        pack.addData("ClientIpAddress6", Data(repeating: 0, count: 16))
        pack.addInt("ClientPort", 0)
        addPackIp32(pack, name: "ServerIpAddress", ip: 0)
        pack.addData("ServerIpAddress6", Data(repeating: 0, count: 16))
        pack.addInt("ServerPort2", 0)
        addPackIp32(pack, name: "ProxyIpAddress", ip: 0)
        pack.addData("ProxyIpAddress6", Data(repeating: 0, count: 16))
        pack.addInt("ProxyPort", 0)
        
        // Add WinVer fields (required by server)
        pack.addBool("V_IsWindows", false)
        pack.addBool("V_IsNT", false)
        pack.addBool("V_IsServer", false)
        pack.addBool("V_IsBeta", false)
        pack.addInt("V_VerMajor", 17)
        pack.addInt("V_VerMinor", 0)
        pack.addInt("V_Build", 0)
        pack.addInt("V_ServicePack", 0)
        pack.addStr("V_Title", "iOS 17")
        
        // Add pencore dummy value (random padding for anti-fingerprinting)
        let pencoreSize = Int.random(in: 0...1000)
        let pencoreData = SoftEtherAuth.randomBytes(count: pencoreSize)
        pack.addData("pencore", Data(pencoreData))
        
        return pack
    }
    
    /// Add IP address to Pack like C's PackAddIp32 does
    /// This adds 4 elements: name@ipv6_bool, name@ipv6_array, name@ipv6_scope_id, name
    private func addPackIp32(_ pack: Pack, name: String, ip: UInt32) {
        pack.addBool("\(name)@ipv6_bool", false)  // Not IPv6
        pack.addData("\(name)@ipv6_array", Data(repeating: 0, count: 16))  // Empty IPv6 addr
        pack.addInt("\(name)@ipv6_scope_id", 0)  // No scope ID
        pack.addInt(name, ip)  // The actual IPv4 address
    }
    
    private func computeSecurePassword(serverRandom: [UInt8]) -> Data {
        // Decode base64 password hash
        os_log(.default, log: seLog, "computeSecurePassword: passwordHash base64 length=%{public}d", config.passwordHash.count)
        
        guard let hashData = Data(base64Encoded: config.passwordHash) else {
            os_log(.error, log: seLog, "Failed to decode base64 password hash")
            return Data(repeating: 0, count: 20)
        }
        
        os_log(.default, log: seLog, "Password hash bytes: %{public}d", hashData.count)
        let hashHex = hashData.map { String(format: "%02x", $0) }.joined()
        os_log(.default, log: seLog, "Password hash: %{public}s", hashHex)
        
        let serverRandomHex = serverRandom.map { String(format: "%02x", $0) }.joined()
        os_log(.default, log: seLog, "Server random: %{public}s", serverRandomHex)
        
        // secure_password = SHA0(password_hash + server_random)
        // SoftEther uses SHA-0, not SHA-1!
        let securePass = SoftEtherAuth.computeSecurePassword(
            passwordHash: Array(hashData),
            serverRandom: serverRandom
        )
        
        let secureHex = securePass.map { String(format: "%02x", $0) }.joined()
        os_log(.default, log: seLog, "Secure password: %{public}s", secureHex)
        
        return Data(securePass)
    }
    
    private func performDHCP() async throws {
        guard let dhcpClient = dhcpClient, let channel = self.channel else { return }
        
        os_log(.default, log: seLog, "Starting DHCP...")
        
        // Send DHCP Discover
        let discover = dhcpClient.buildDiscover()
        try sendPacketInternal(discover, channel: channel)
        os_log(.default, log: seLog, "DHCP DISCOVER sent")
        
        // Wait for DHCP to complete (with timeout)
        let timeout = DispatchTime.now() + .seconds(10)
        
        while !dhcpClient.config.isValid && DispatchTime.now() < timeout {
            try await Task.sleep(nanoseconds: 100_000_000)  // 100ms
        }
        
        guard dhcpClient.config.isValid else {
            os_log(.error, log: seLog, "DHCP failed - no valid config received")
            throw SoftEtherError.dhcpFailed
        }
        
        // Configure ARP handler with obtained IP
        let config = dhcpClient.config
        os_log(.default, log: seLog, "DHCP complete: IP=%{public}@", formatIP(config.ipAddress))
        arpHandler?.configure(myIP: config.ipAddress, gatewayIP: config.gateway)
        
        // Send gratuitous ARP
        if let gratuitousARP = arpHandler?.buildGratuitousARP() {
            try sendPacketInternal(gratuitousARP, channel: channel)
        }
        
        // Send gateway ARP request
        if let gatewayRequest = arpHandler?.buildGatewayRequest() {
            try sendPacketInternal(gatewayRequest, channel: channel)
        }
    }
    
    private func formatIP(_ ip: UInt32) -> String {
        let bytes = withUnsafeBytes(of: ip.bigEndian) { Array($0) }
        return "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"
    }
    
    // MARK: - HTTP Response Handling
    
    private func waitForHTTPResponse() async throws -> HTTPResponse {
        os_log(.default, log: seLog, "waitForHTTPResponse: starting...")
        
        // Simple wait without timeout for now - timeout was causing issues
        // The channel inactive handler will signal error if connection drops
        let response = try await httpResponseReader.waitForResponse()
        os_log(.default, log: seLog, "waitForHTTPResponse: got response")
        return response
    }
    
    fileprivate func handleRawData(_ data: Data) {
        // HTTPResponseReader is now thread-safe (uses locks, not actor)
        // Safe to call directly from NIO handler
        httpResponseReader.receive(data)
    }
    
    // MARK: - Data Handling
    
    fileprivate func handleTunnelData(_ data: Data) {
        // Fast path - minimal checks
        if data.count < 14 { return }
        
        let etherType = UInt16(data[12]) << 8 | UInt16(data[13])
        
        switch etherType {
        case 0x0800: // IPv4 - fast path
            // Check if this is a DHCP response (UDP port 68)
            if data.count >= 42 {
                let ipProtocol = data[23]
                if ipProtocol == 17 { // UDP
                    let dstPort = UInt16(data[36]) << 8 | UInt16(data[37])
                    if dstPort == 68 {
                        handleDHCPResponse(data)
                        return
                    }
                }
            }
            
            onDataReceived?(data)
            delegate?.client(self, didReceivePacket: data)
            
        case 0x0806: // ARP
            handleARP(data)
            
        case 0x8100: // VLAN - skip tag and check inner type
            if data.count >= 18 {
                let innerType = UInt16(data[16]) << 8 | UInt16(data[17])
                if innerType == 0x0800 {
                    onDataReceived?(data)
                    delegate?.client(self, didReceivePacket: data)
                }
            }
            
        default:
            break
        }
    }
    
    private func handleARP(_ data: Data) {
        guard let arpHandler = arpHandler else { return }
        
        if let reply = arpHandler.processARP(data) {
            try? sendPacket(reply)
        }
    }
    
    private func handleDHCPResponse(_ data: Data) {
        guard let dhcpClient = dhcpClient, let channel = self.channel else { 
            os_log(.error, log: seLog, "handleDHCPResponse: no dhcpClient or channel!")
            return 
        }
        
        os_log(.default, log: seLog, "handleDHCPResponse: processing %{public}d bytes, state=%{public}@", 
               data.count, String(describing: dhcpClient.state))
        
        // Pass the full Ethernet frame directly - processResponse expects full frame
        if dhcpClient.processResponse(data) {
            // DHCP completed
            os_log(.default, log: seLog, "DHCP completed! state=%{public}@", String(describing: dhcpClient.state))
        } else if dhcpClient.state == .discoverSent {
            // Got offer, send request - use sendPacketInternal since we're not in .connected state yet
            os_log(.default, log: seLog, "DHCP OFFER received, sending REQUEST...")
            let request = dhcpClient.buildRequest()
            if !request.isEmpty {
                os_log(.default, log: seLog, "Sending DHCP REQUEST (%{public}d bytes)", request.count)
                do {
                    try sendPacketInternal(request, channel: channel)
                    os_log(.default, log: seLog, "DHCP REQUEST sent successfully")
                } catch {
                    os_log(.error, log: seLog, "Failed to send DHCP REQUEST: %{public}@", error.localizedDescription)
                }
            } else {
                os_log(.error, log: seLog, "buildRequest returned empty!")
            }
        } else {
            os_log(.default, log: seLog, "DHCP processResponse returned false, state=%{public}@", String(describing: dhcpClient.state))
        }
    }
}

// MARK: - Supporting Types

struct HelloResponse {
    let random: [UInt8]
    let serverVersion: UInt32
    let serverBuild: UInt32
    let serverString: String
}

struct AuthResult {
    let success: Bool
    let errorCode: UInt32
    let errorMessage: String?
    let sessionKey: Data?
    let redirect: RedirectInfo?
}

/// Redirect information for cluster server setups
struct RedirectInfo {
    let ip: UInt32      // IPv4 address in host byte order
    let port: UInt16
    let ticket: [UInt8] // 20 bytes
}

/// NIO Handler for raw data during handshake
private class RawDataHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    
    private weak var client: SoftEtherClient?
    
    init(client: SoftEtherClient) {
        self.client = client
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            os_log(.default, log: seLog, "Raw data received: %{public}d bytes", bytes.count)
            client?.handleRawData(Data(bytes))
        }
    }
    
    func channelInactive(context: ChannelHandlerContext) {
        os_log(.default, log: seLog, "Channel became inactive")
        // Only propagate error if this is still the active channel
        // During cluster redirect, old channel closes but we've already switched to new one
        if let client = client, context.channel === client.channel {
            client.httpResponseReader.error(SoftEtherError.connectionFailed)
        }
        context.fireChannelInactive()
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        os_log(.error, log: seLog, "Channel error: %{public}s", error.localizedDescription)
        // Only propagate error if this is still the active channel
        if let client = client, context.channel === client.channel {
            client.httpResponseReader.error(error)
        }
        context.close(promise: nil)
    }
}

/// NIO Handler for tunnel data
private final class TunnelDataHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = TunnelFrameType
    
    private weak var client: SoftEtherClient?
    
    init(client: SoftEtherClient) {
        self.client = client
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let frame = unwrapInboundIn(data)
        
        switch frame {
        case .data(let blocks):
            // Fast path - no logging for data packets
            for block in blocks {
                client?.handleTunnelData(block)
            }
        case .keepalive:
            // Keepalives are silent
            break
        }
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        os_log(.error, log: seLog, "TunnelDataHandler error: %{public}s", error.localizedDescription)
        context.close(promise: nil)
    }
}

// MARK: - Errors

public enum SoftEtherError: Error, LocalizedError {
    case alreadyConnected
    case notConnected
    case connectionFailed
    case serverError(Int)
    case invalidResponse
    case authenticationFailed(String)
    case dhcpFailed
    case notImplemented
    
    public var errorDescription: String? {
        switch self {
        case .alreadyConnected: return "Already connected"
        case .notConnected: return "Not connected"
        case .connectionFailed: return "Connection failed"
        case .serverError(let code): return "Server error: HTTP \(code)"
        case .invalidResponse: return "Invalid server response"
        case .authenticationFailed(let msg): return "Authentication failed: \(msg)"
        case .dhcpFailed: return "DHCP configuration failed"
        case .notImplemented: return "Not implemented"
        }
    }
}
