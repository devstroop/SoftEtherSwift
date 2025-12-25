// DHCPClient.swift - DHCP protocol implementation for virtual adapter
// Builds and parses DHCP packets for IP address allocation

import Foundation
import os.log

private let dhcpLog = OSLog(subsystem: "com.softether.client", category: "DHCP")

/// DHCP message types
public enum DHCPMessageType: UInt8 {
    case discover = 1
    case offer = 2
    case request = 3
    case decline = 4
    case ack = 5
    case nak = 6
    case release = 7
    case inform = 8
}

/// DHCP option codes
public enum DHCPOption: UInt8 {
    case pad = 0
    case subnetMask = 1
    case router = 3
    case dnsServer = 6
    case hostname = 12
    case domainName = 15
    case requestedIP = 50
    case leaseTime = 51
    case messageType = 53
    case serverIdentifier = 54
    case parameterRequest = 55
    case renewalTime = 58
    case rebindingTime = 59
    case end = 255
}

/// DHCP configuration result
public struct DHCPConfig {
    public var ipAddress: UInt32 = 0
    public var subnetMask: UInt32 = 0
    public var gateway: UInt32 = 0
    public var dns1: UInt32 = 0
    public var dns2: UInt32 = 0
    public var serverID: UInt32 = 0
    public var leaseTime: UInt32 = 0
    public var domainName: String = ""
    
    public var isValid: Bool { ipAddress != 0 }
    
    public var ipAddressString: String {
        return "\(ipAddress >> 24 & 0xFF).\(ipAddress >> 16 & 0xFF).\(ipAddress >> 8 & 0xFF).\(ipAddress & 0xFF)"
    }
    
    public var subnetMaskString: String {
        return "\(subnetMask >> 24 & 0xFF).\(subnetMask >> 16 & 0xFF).\(subnetMask >> 8 & 0xFF).\(subnetMask & 0xFF)"
    }
    
    public var gatewayString: String {
        return "\(gateway >> 24 & 0xFF).\(gateway >> 16 & 0xFF).\(gateway >> 8 & 0xFF).\(gateway & 0xFF)"
    }
}

/// DHCP state machine
public enum DHCPState {
    case idle
    case discoverSent
    case requestSent
    case bound
    case failed
}

/// DHCP magic cookie
private let DHCP_MAGIC: UInt32 = 0x63825363

/// DHCP client for virtual adapter
public class DHCPClient {
    public private(set) var state: DHCPState = .idle
    public private(set) var config = DHCPConfig()
    
    private let mac: [UInt8]
    private let transactionID: UInt32
    private var offeredIP: UInt32 = 0
    private var serverID: UInt32 = 0
    
    public init(mac: [UInt8]) {
        self.mac = mac
        self.transactionID = SoftEtherAuth.generateTransactionId()
    }
    
    /// Build DHCP DISCOVER packet (Ethernet frame)
    public func buildDiscover() -> Data {
        var packet = Data()
        
        // === Ethernet Header (14 bytes) ===
        packet.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) // Destination: broadcast
        packet.append(contentsOf: mac) // Source: our MAC
        packet.append(contentsOf: [0x08, 0x00]) // EtherType: IPv4
        
        // Build DHCP payload first to calculate lengths
        let dhcpPayload = buildDHCPPayload(messageType: .discover, requestedIP: 0, serverID: 0)
        let udpLength = 8 + dhcpPayload.count
        let ipLength = 20 + udpLength
        
        // === IPv4 Header (20 bytes) ===
        packet.append(0x45) // Version 4, IHL 5
        packet.append(0x00) // DSCP/ECN
        packet.append(UInt8((ipLength >> 8) & 0xFF))
        packet.append(UInt8(ipLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // ID, flags, fragment
        packet.append(64) // TTL
        packet.append(17) // Protocol: UDP
        packet.append(contentsOf: [0x00, 0x00]) // Checksum (will calculate)
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Source: 0.0.0.0
        packet.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF]) // Dest: broadcast
        
        // Calculate IP checksum
        let ipStart = 14
        let checksum = calculateIPChecksum(Array(packet[ipStart..<ipStart+20]))
        packet[ipStart + 10] = UInt8((checksum >> 8) & 0xFF)
        packet[ipStart + 11] = UInt8(checksum & 0xFF)
        
        // === UDP Header (8 bytes) ===
        packet.append(contentsOf: [0x00, 68]) // Source port: 68 (DHCP client)
        packet.append(contentsOf: [0x00, 67]) // Dest port: 67 (DHCP server)
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00]) // Checksum (optional for IPv4)
        
        // === DHCP Payload ===
        packet.append(dhcpPayload)
        
        state = .discoverSent
        return packet
    }
    
    /// Build DHCP REQUEST packet (Ethernet frame)
    public func buildRequest() -> Data {
        guard offeredIP != 0 && serverID != 0 else {
            return Data()
        }
        
        var packet = Data()
        
        // === Ethernet Header ===
        packet.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        packet.append(contentsOf: mac)
        packet.append(contentsOf: [0x08, 0x00])
        
        let dhcpPayload = buildDHCPPayload(messageType: .request, requestedIP: offeredIP, serverID: serverID)
        let udpLength = 8 + dhcpPayload.count
        let ipLength = 20 + udpLength
        
        // === IPv4 Header ===
        packet.append(0x45)
        packet.append(0x00)
        packet.append(UInt8((ipLength >> 8) & 0xFF))
        packet.append(UInt8(ipLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        packet.append(64)
        packet.append(17)
        packet.append(contentsOf: [0x00, 0x00])
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        packet.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])
        
        let ipStart = 14
        var data = Array(packet)
        let checksum = calculateIPChecksum(Array(data[ipStart..<ipStart+20]))
        data[ipStart + 10] = UInt8((checksum >> 8) & 0xFF)
        data[ipStart + 11] = UInt8(checksum & 0xFF)
        packet = Data(data)
        
        // === UDP Header ===
        packet.append(contentsOf: [0x00, 68])
        packet.append(contentsOf: [0x00, 67])
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00])
        
        // === DHCP Payload ===
        packet.append(dhcpPayload)
        
        state = .requestSent
        return packet
    }
    
    /// Process incoming DHCP response (Ethernet frame)
    /// Returns true if DHCP is complete
    public func processResponse(_ frame: Data) -> Bool {
        os_log(.default, log: dhcpLog, "processResponse: %{public}d bytes", frame.count)
        
        guard frame.count >= 14 + 20 + 8 + 240 else { 
            os_log(.error, log: dhcpLog, "Frame too small: %{public}d < 282", frame.count)
            return false 
        }
        
        let data = Array(frame)
        
        // Check EtherType (IPv4)
        guard data[12] == 0x08 && data[13] == 0x00 else { 
            os_log(.error, log: dhcpLog, "Bad EtherType: 0x%{public}02x%{public}02x", data[12], data[13])
            return false 
        }
        
        // Check IP protocol (UDP)
        guard data[23] == 17 else { 
            os_log(.error, log: dhcpLog, "Not UDP: protocol=%{public}d", data[23])
            return false 
        }
        
        // Check UDP ports (67 -> 68)
        let srcPort = UInt16(data[34]) << 8 | UInt16(data[35])
        let dstPort = UInt16(data[36]) << 8 | UInt16(data[37])
        guard srcPort == 67 && dstPort == 68 else { 
            os_log(.error, log: dhcpLog, "Wrong ports: %{public}d -> %{public}d", srcPort, dstPort)
            return false 
        }
        
        // Parse DHCP packet (starts at offset 42)
        let dhcpStart = 42
        guard frame.count >= dhcpStart + 240 else { 
            os_log(.error, log: dhcpLog, "Frame too small for DHCP: %{public}d < %{public}d", frame.count, dhcpStart + 240)
            return false 
        }
        
        // Check transaction ID
        let xid = UInt32(data[dhcpStart + 4]) << 24 |
                  UInt32(data[dhcpStart + 5]) << 16 |
                  UInt32(data[dhcpStart + 6]) << 8 |
                  UInt32(data[dhcpStart + 7])
        guard xid == transactionID else { 
            os_log(.error, log: dhcpLog, "XID mismatch: got 0x%{public}08x, expected 0x%{public}08x", xid, transactionID)
            return false 
        }
        
        os_log(.default, log: dhcpLog, "XID matched: 0x%{public}08x", xid)
        
        // Check magic cookie
        let magic = UInt32(data[dhcpStart + 236]) << 24 |
                    UInt32(data[dhcpStart + 237]) << 16 |
                    UInt32(data[dhcpStart + 238]) << 8 |
                    UInt32(data[dhcpStart + 239])
        guard magic == DHCP_MAGIC else { 
            os_log(.error, log: dhcpLog, "Bad magic: 0x%{public}08x != 0x%{public}08x", magic, DHCP_MAGIC)
            return false 
        }
        
        // Parse options
        var optionStart = dhcpStart + 240
        var messageType: DHCPMessageType?
        var newConfig = DHCPConfig()
        
        // Get offered IP from yiaddr field
        let yiaddr = UInt32(data[dhcpStart + 16]) << 24 |
                     UInt32(data[dhcpStart + 17]) << 16 |
                     UInt32(data[dhcpStart + 18]) << 8 |
                     UInt32(data[dhcpStart + 19])
        newConfig.ipAddress = yiaddr
        
        while optionStart < data.count {
            let optCode = data[optionStart]
            
            if optCode == DHCPOption.end.rawValue {
                break
            }
            
            if optCode == DHCPOption.pad.rawValue {
                optionStart += 1
                continue
            }
            
            guard optionStart + 1 < data.count else { break }
            let optLen = Int(data[optionStart + 1])
            guard optionStart + 2 + optLen <= data.count else { break }
            
            let optData = Array(data[(optionStart + 2)..<(optionStart + 2 + optLen)])
            
            switch optCode {
            case DHCPOption.messageType.rawValue:
                if optLen >= 1 {
                    messageType = DHCPMessageType(rawValue: optData[0])
                    os_log(.default, log: dhcpLog, "DHCP option 53 (msgType): raw=%{public}d, parsed=%{public}@", 
                           optData[0], messageType.map { String(describing: $0) } ?? "nil")
                }
                
            case DHCPOption.subnetMask.rawValue:
                if optLen >= 4 {
                    newConfig.subnetMask = UInt32(optData[0]) << 24 |
                                           UInt32(optData[1]) << 16 |
                                           UInt32(optData[2]) << 8 |
                                           UInt32(optData[3])
                }
                
            case DHCPOption.router.rawValue:
                if optLen >= 4 {
                    newConfig.gateway = UInt32(optData[0]) << 24 |
                                        UInt32(optData[1]) << 16 |
                                        UInt32(optData[2]) << 8 |
                                        UInt32(optData[3])
                }
                
            case DHCPOption.dnsServer.rawValue:
                if optLen >= 4 {
                    newConfig.dns1 = UInt32(optData[0]) << 24 |
                                     UInt32(optData[1]) << 16 |
                                     UInt32(optData[2]) << 8 |
                                     UInt32(optData[3])
                }
                if optLen >= 8 {
                    newConfig.dns2 = UInt32(optData[4]) << 24 |
                                     UInt32(optData[5]) << 16 |
                                     UInt32(optData[6]) << 8 |
                                     UInt32(optData[7])
                }
                
            case DHCPOption.serverIdentifier.rawValue:
                if optLen >= 4 {
                    newConfig.serverID = UInt32(optData[0]) << 24 |
                                         UInt32(optData[1]) << 16 |
                                         UInt32(optData[2]) << 8 |
                                         UInt32(optData[3])
                }
                
            case DHCPOption.leaseTime.rawValue:
                if optLen >= 4 {
                    newConfig.leaseTime = UInt32(optData[0]) << 24 |
                                          UInt32(optData[1]) << 16 |
                                          UInt32(optData[2]) << 8 |
                                          UInt32(optData[3])
                }
                
            case DHCPOption.domainName.rawValue:
                newConfig.domainName = String(bytes: optData, encoding: .utf8) ?? ""
                
            default:
                break
            }
            
            optionStart += 2 + optLen
        }
        
        os_log(.default, log: dhcpLog, "Parsed messageType=%{public}@, yiaddr IP=%{public}d.%{public}d.%{public}d.%{public}d", 
               messageType.map { String($0.rawValue) } ?? "nil",
               (newConfig.ipAddress >> 24) & 0xFF, (newConfig.ipAddress >> 16) & 0xFF,
               (newConfig.ipAddress >> 8) & 0xFF, newConfig.ipAddress & 0xFF)
        
        // Handle message type
        switch messageType {
        case .offer:
            offeredIP = newConfig.ipAddress
            serverID = newConfig.serverID
            let ip = newConfig.ipAddress
            os_log(.info, log: dhcpLog, "DHCP OFFER received: IP=%{public}d.%{public}d.%{public}d.%{public}d", 
                   (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF)
            return false // Need to send REQUEST
            
        case .ack:
            config = newConfig
            state = .bound
            let ip = newConfig.ipAddress
            os_log(.info, log: dhcpLog, "DHCP ACK received! IP=%{public}d.%{public}d.%{public}d.%{public}d", 
                   (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF)
            return true // DHCP complete!
            
        case .nak:
            os_log(.error, log: dhcpLog, "DHCP NAK received!")
            state = .failed
            return false
            
        default:
            os_log(.error, log: dhcpLog, "Unknown DHCP message type: %{public}d", messageType?.rawValue ?? 0)
            return false
        }
    }
    
    // MARK: - Private
    
    private func buildDHCPPayload(messageType: DHCPMessageType, requestedIP: UInt32, serverID: UInt32) -> Data {
        var payload = Data()
        
        // DHCP fixed header (236 bytes)
        payload.append(0x01) // op: BOOTREQUEST
        payload.append(0x01) // htype: Ethernet
        payload.append(0x06) // hlen: 6
        payload.append(0x00) // hops: 0
        
        // Transaction ID (4 bytes)
        payload.append(UInt8((transactionID >> 24) & 0xFF))
        payload.append(UInt8((transactionID >> 16) & 0xFF))
        payload.append(UInt8((transactionID >> 8) & 0xFF))
        payload.append(UInt8(transactionID & 0xFF))
        
        // secs, flags (4 bytes)
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        
        // ciaddr (client IP) - 4 bytes of zeros
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        
        // yiaddr (your IP) - 4 bytes of zeros
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        
        // siaddr (server IP) - 4 bytes of zeros
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        
        // giaddr (gateway IP) - 4 bytes of zeros
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        
        // chaddr (client hardware address) - 16 bytes (MAC + padding)
        payload.append(contentsOf: mac)
        payload.append(contentsOf: [UInt8](repeating: 0, count: 10))
        
        // sname (server name) - 64 bytes of zeros
        payload.append(contentsOf: [UInt8](repeating: 0, count: 64))
        
        // file (boot filename) - 128 bytes of zeros
        payload.append(contentsOf: [UInt8](repeating: 0, count: 128))
        
        // Magic cookie
        payload.append(UInt8((DHCP_MAGIC >> 24) & 0xFF))
        payload.append(UInt8((DHCP_MAGIC >> 16) & 0xFF))
        payload.append(UInt8((DHCP_MAGIC >> 8) & 0xFF))
        payload.append(UInt8(DHCP_MAGIC & 0xFF))
        
        // Options
        // Message type
        payload.append(DHCPOption.messageType.rawValue)
        payload.append(1)
        payload.append(messageType.rawValue)
        
        // Requested IP (for REQUEST)
        if requestedIP != 0 {
            payload.append(DHCPOption.requestedIP.rawValue)
            payload.append(4)
            payload.append(UInt8((requestedIP >> 24) & 0xFF))
            payload.append(UInt8((requestedIP >> 16) & 0xFF))
            payload.append(UInt8((requestedIP >> 8) & 0xFF))
            payload.append(UInt8(requestedIP & 0xFF))
        }
        
        // Server ID (for REQUEST)
        if serverID != 0 {
            payload.append(DHCPOption.serverIdentifier.rawValue)
            payload.append(4)
            payload.append(UInt8((serverID >> 24) & 0xFF))
            payload.append(UInt8((serverID >> 16) & 0xFF))
            payload.append(UInt8((serverID >> 8) & 0xFF))
            payload.append(UInt8(serverID & 0xFF))
        }
        
        // Parameter request list
        payload.append(DHCPOption.parameterRequest.rawValue)
        payload.append(4)
        payload.append(DHCPOption.subnetMask.rawValue)
        payload.append(DHCPOption.router.rawValue)
        payload.append(DHCPOption.dnsServer.rawValue)
        payload.append(DHCPOption.domainName.rawValue)
        
        // End option
        payload.append(DHCPOption.end.rawValue)
        
        // Pad to minimum size (300 bytes total for DHCP)
        while payload.count < 300 - 14 - 20 - 8 {
            payload.append(0x00)
        }
        
        return payload
    }
    
    private func calculateIPChecksum(_ header: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        
        for i in stride(from: 0, to: header.count, by: 2) {
            let word = UInt32(header[i]) << 8 | UInt32(header[i + 1])
            sum += word
        }
        
        // Fold 32-bit sum to 16 bits
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        
        return ~UInt16(sum)
    }
}
