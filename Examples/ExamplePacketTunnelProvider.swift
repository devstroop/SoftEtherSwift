// ExamplePacketTunnelProvider.swift
// Reference implementation showing how to integrate SoftEtherClient with iOS Network Extension
//
// Copy this file to your project's Network Extension target and customize as needed.
// This is NOT compiled as part of the SoftEtherClient library.

#if canImport(NetworkExtension)
import NetworkExtension
import Foundation
import os.log
import SoftEtherClient

/// Example NEPacketTunnelProvider using SoftEtherClient
///
/// To use:
/// 1. Copy this file to your Network Extension target
/// 2. Update bundle identifiers and team IDs in your project
/// 3. Implement `loadConfiguration()` to read from your app's settings
/// 4. Configure the extension's Info.plist with NSExtensionPrincipalClass
///
/// Configuration is passed via `providerConfiguration` dictionary:
/// - server: String (hostname or IP)
/// - port: Int (default 443)
/// - hub: String (virtual hub name)
/// - username: String
/// - passwordHash: String (Base64-encoded SHA0 hash)
class ExamplePacketTunnelProvider: NEPacketTunnelProvider {
    
    // MARK: - Properties
    
    private let logger = Logger(subsystem: "com.example.vpn", category: "PacketTunnel")
    private var client: SoftEtherClient?
    private let queue = DispatchQueue(label: "com.example.vpn.extension", qos: .userInitiated)
    
    // Connection state
    private var isConnecting = false
    private var isStopping = false
    private var pendingCompletion: ((Error?) -> Void)?
    
    // Keepalive
    private var keepaliveTimer: DispatchSourceTimer?
    
    // RX batching for performance
    private var rxPacketBuffer: [Data] = []
    private var rxProtocolBuffer: [NSNumber] = []
    private let rxBufferLock = NSLock()
    private var rxFlushTimer: DispatchSourceTimer?
    
    // MARK: - Lifecycle
    
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("startTunnel called")
        
        guard !isConnecting && client == nil else {
            completionHandler(nil)
            return
        }
        
        isConnecting = true
        isStopping = false
        pendingCompletion = completionHandler
        
        queue.async { [weak self] in
            self?.performConnect()
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("stopTunnel called, reason: \(reason.rawValue)")
        isStopping = true
        
        queue.async { [weak self] in
            self?.performDisconnect()
            completionHandler()
        }
    }
    
    // MARK: - Configuration
    
    private func loadConfiguration() -> VPNConfiguration? {
        guard let tunnelConfig = protocolConfiguration as? NETunnelProviderProtocol,
              let config = tunnelConfig.providerConfiguration else {
            logger.error("No provider configuration")
            return nil
        }
        
        guard let server = config["server"] as? String,
              let username = config["username"] as? String,
              let passwordHash = config["passwordHash"] as? String else {
            logger.error("Missing required configuration fields")
            return nil
        }
        
        return VPNConfiguration(
            host: server,
            port: config["port"] as? Int ?? 443,
            hubName: config["hub"] as? String ?? "VPN",
            username: username,
            passwordHash: passwordHash,
            useTLS: true
        )
    }
    
    // MARK: - Connection
    
    private func performConnect() {
        guard let config = loadConfiguration() else {
            completePending(with: NSError(domain: "VPN", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid configuration"]))
            return
        }
        
        logger.info("Connecting to \(config.host):\(config.port)")
        
        // Create client
        let vpnClient = SoftEtherClient(config: config)
        vpnClient.delegate = self
        vpnClient.onDataReceived = { [weak self] data in
            self?.handleReceivedPacket(data)
        }
        self.client = vpnClient
        
        // Connect
        Task {
            do {
                try await vpnClient.connect()
                // Delegate will be called on success
            } catch {
                logger.error("Connection failed: \(error.localizedDescription)")
                completePending(with: error)
            }
        }
    }
    
    private func performDisconnect() {
        keepaliveTimer?.cancel()
        keepaliveTimer = nil
        rxFlushTimer?.cancel()
        rxFlushTimer = nil
        
        try? client?.disconnect()
        client = nil
        isConnecting = false
    }
    
    // MARK: - Tunnel Settings
    
    private func configureTunnel(with session: SessionInfo) {
        let ip = formatIP(session.assignedIP)
        let mask = formatIP(session.subnetMask)
        let remoteAddress = session.connectedServerIP.isEmpty ? "10.0.0.1" : session.connectedServerIP
        
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        
        // IPv4
        let ipv4 = NEIPv4Settings(addresses: [ip], subnetMasks: [mask])
        ipv4.includedRoutes = [
            NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "128.0.0.0"),
            NEIPv4Route(destinationAddress: "128.0.0.0", subnetMask: "128.0.0.0")
        ]
        if !session.connectedServerIP.isEmpty {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: session.connectedServerIP, subnetMask: "255.255.255.255")]
        }
        settings.ipv4Settings = ipv4
        
        // DNS
        var dnsServers = session.dnsServers.filter { $0 != 0 }.map { formatIP($0) }
        if dnsServers.isEmpty { dnsServers = ["8.8.8.8", "8.8.4.4"] }
        settings.dnsSettings = NEDNSSettings(servers: dnsServers)
        
        settings.mtu = 1400
        
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to apply settings: \(error.localizedDescription)")
                self?.completePending(with: error)
            } else {
                self?.logger.info("Tunnel configured")
                self?.startKeepalive()
                self?.startReadingPackets()
                self?.completePending(with: nil)
            }
        }
    }
    
    // MARK: - Packet Handling
    
    private func handleReceivedPacket(_ data: Data) {
        // L2 → L3: Strip Ethernet header (14 bytes)
        guard data.count > 14 else { return }
        let etherType = UInt16(data[12]) << 8 | UInt16(data[13])
        guard etherType == 0x0800 else { return }  // IPv4 only
        
        let ipPacket = data.dropFirst(14)
        enqueueRxPacket(Data(ipPacket))
    }
    
    private func enqueueRxPacket(_ packet: Data) {
        rxBufferLock.lock()
        rxPacketBuffer.append(packet)
        rxProtocolBuffer.append(NSNumber(value: AF_INET))
        let shouldFlush = rxPacketBuffer.count >= 64
        rxBufferLock.unlock()
        
        if shouldFlush {
            flushRxBuffer()
        } else {
            scheduleRxFlush()
        }
    }
    
    private func scheduleRxFlush() {
        guard rxFlushTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 0.001)
        timer.setEventHandler { [weak self] in self?.flushRxBuffer() }
        timer.resume()
        rxFlushTimer = timer
    }
    
    private func flushRxBuffer() {
        rxFlushTimer?.cancel()
        rxFlushTimer = nil
        
        rxBufferLock.lock()
        let packets = rxPacketBuffer
        let protocols = rxProtocolBuffer
        rxPacketBuffer.removeAll(keepingCapacity: true)
        rxProtocolBuffer.removeAll(keepingCapacity: true)
        rxBufferLock.unlock()
        
        guard !packets.isEmpty else { return }
        packetFlow.writePackets(packets, withProtocols: protocols)
    }
    
    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, !self.isStopping else { return }
            self.sendPacketsToServer(packets)
            self.startReadingPackets()
        }
    }
    
    private func sendPacketsToServer(_ packets: [Data]) {
        guard let client = client else { return }
        
        // Get gateway MAC from ARP handler
        let gatewayMAC = client.gatewayMAC ?? [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        let srcMAC: [UInt8] = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01]  // TODO: Use actual MAC
        
        for packet in packets {
            // L3 → L2: Add Ethernet header
            var frame = Data(capacity: 14 + packet.count)
            frame.append(contentsOf: gatewayMAC)  // Destination MAC
            frame.append(contentsOf: srcMAC)       // Source MAC
            frame.append(contentsOf: [0x08, 0x00]) // EtherType IPv4
            frame.append(packet)
            
            try? client.sendPacket(frame)
        }
    }
    
    // MARK: - Keepalive
    
    private func startKeepalive() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            try? self?.client?.sendKeepalive()
        }
        timer.resume()
        keepaliveTimer = timer
    }
    
    // MARK: - Helpers
    
    private func completePending(with error: Error?) {
        DispatchQueue.main.async { [weak self] in
            self?.pendingCompletion?(error)
            self?.pendingCompletion = nil
            self?.isConnecting = false
        }
    }
    
    private func formatIP(_ ip: UInt32) -> String {
        "\((ip >> 24) & 0xFF).\((ip >> 16) & 0xFF).\((ip >> 8) & 0xFF).\(ip & 0xFF)"
    }
}

// MARK: - SoftEtherClientDelegate

extension ExamplePacketTunnelProvider: SoftEtherClientDelegate {
    func clientDidConnect(_ client: SoftEtherClient, session: SessionInfo) {
        logger.info("Connected! IP: \(formatIP(session.assignedIP))")
        configureTunnel(with: session)
    }
    
    func clientDidDisconnect(_ client: SoftEtherClient, error: Error?) {
        logger.info("Disconnected: \(error?.localizedDescription ?? "clean")")
    }
    
    func client(_ client: SoftEtherClient, didReceivePacket data: Data) {
        // Handled by onDataReceived callback
    }
    
    func client(_ client: SoftEtherClient, stateChanged state: ConnectionState) {
        logger.info("State: \(state.description)")
    }
}
#endif
