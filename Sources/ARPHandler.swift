// ARPHandler.swift - ARP protocol for virtual adapter
// Build and parse ARP packets for gateway MAC discovery

import Foundation
import os.log

private let arpLog = OSLog(subsystem: "com.worxvpn.softether", category: "ARP")

/// ARP operation types
public enum ARPOperation: UInt16 {
    case request = 1
    case reply = 2
}

/// ARP handler for virtual adapter
public class ARPHandler {
    
    private let mac: [UInt8]
    private var gatewayMAC: [UInt8]?
    private var myIP: UInt32 = 0
    private var gatewayIP: UInt32 = 0
    
    public init(mac: [UInt8]) {
        self.mac = mac
    }
    
    /// Configure with our IP and gateway IP
    public func configure(myIP: UInt32, gatewayIP: UInt32) {
        self.myIP = myIP
        self.gatewayIP = gatewayIP
    }
    
    /// Get gateway MAC if discovered
    public var resolvedGatewayMAC: [UInt8]? {
        return gatewayMAC
    }
    
    /// Build Gratuitous ARP (announce our presence)
    public func buildGratuitousARP() -> Data {
        return buildARP(
            operation: .request,
            senderMAC: mac,
            senderIP: myIP,
            targetMAC: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            targetIP: myIP  // Gratuitous: target = sender
        )
    }
    
    /// Build ARP request for gateway
    public func buildGatewayRequest() -> Data {
        return buildARP(
            operation: .request,
            senderMAC: mac,
            senderIP: myIP,
            targetMAC: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            targetIP: gatewayIP
        )
    }
    
    /// Process incoming ARP packet
    /// Returns ARP reply if we need to respond
    public func processARP(_ frame: Data) -> Data? {
        guard frame.count >= 14 + 28 else { return nil }
        
        let data = Array(frame)
        
        // Check EtherType (ARP = 0x0806)
        guard data[12] == 0x08 && data[13] == 0x06 else { return nil }
        
        // Parse ARP header (starts at offset 14)
        let arpStart = 14
        
        // Hardware type (should be Ethernet = 1)
        let hwType = UInt16(data[arpStart]) << 8 | UInt16(data[arpStart + 1])
        guard hwType == 1 else { return nil }
        
        // Protocol type (should be IPv4 = 0x0800)
        let protoType = UInt16(data[arpStart + 2]) << 8 | UInt16(data[arpStart + 3])
        guard protoType == 0x0800 else { return nil }
        
        // Hardware/protocol address lengths
        guard data[arpStart + 4] == 6 && data[arpStart + 5] == 4 else { return nil }
        
        // Operation
        let operation = UInt16(data[arpStart + 6]) << 8 | UInt16(data[arpStart + 7])
        
        // Sender MAC and IP
        let senderMAC = Array(data[(arpStart + 8)..<(arpStart + 14)])
        let senderIP = UInt32(data[arpStart + 14]) << 24 |
                       UInt32(data[arpStart + 15]) << 16 |
                       UInt32(data[arpStart + 16]) << 8 |
                       UInt32(data[arpStart + 17])
        
        // Target MAC and IP
        let targetIP = UInt32(data[arpStart + 24]) << 24 |
                       UInt32(data[arpStart + 25]) << 16 |
                       UInt32(data[arpStart + 26]) << 8 |
                       UInt32(data[arpStart + 27])
        
        // Handle ARP reply - learn gateway MAC
        if operation == ARPOperation.reply.rawValue {
            if senderIP == gatewayIP {
                gatewayMAC = senderMAC
                os_log(.default, log: arpLog, "Learned gateway MAC: %{public}02x:%{public}02x:%{public}02x:%{public}02x:%{public}02x:%{public}02x from IP %{public}@",
                       senderMAC[0], senderMAC[1], senderMAC[2], senderMAC[3], senderMAC[4], senderMAC[5],
                       formatIP(senderIP))
            }
            return nil
        }
        
        // Handle ARP request - respond if it's for us
        if operation == ARPOperation.request.rawValue && targetIP == myIP {
            return buildARP(
                operation: .reply,
                senderMAC: mac,
                senderIP: myIP,
                targetMAC: senderMAC,
                targetIP: senderIP
            )
        }
        
        return nil
    }
    
    // MARK: - Private
    
    private func buildARP(
        operation: ARPOperation,
        senderMAC: [UInt8],
        senderIP: UInt32,
        targetMAC: [UInt8],
        targetIP: UInt32
    ) -> Data {
        var packet = Data()
        
        // Ethernet header
        if operation == .request {
            // Broadcast for request
            packet.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        } else {
            // Unicast for reply
            packet.append(contentsOf: targetMAC)
        }
        packet.append(contentsOf: senderMAC)
        packet.append(contentsOf: [0x08, 0x06]) // EtherType: ARP
        
        // ARP header
        packet.append(contentsOf: [0x00, 0x01]) // Hardware type: Ethernet
        packet.append(contentsOf: [0x08, 0x00]) // Protocol type: IPv4
        packet.append(6) // Hardware address length
        packet.append(4) // Protocol address length
        packet.append(UInt8((operation.rawValue >> 8) & 0xFF))
        packet.append(UInt8(operation.rawValue & 0xFF))
        
        // Sender hardware address
        packet.append(contentsOf: senderMAC)
        
        // Sender protocol address
        packet.append(UInt8((senderIP >> 24) & 0xFF))
        packet.append(UInt8((senderIP >> 16) & 0xFF))
        packet.append(UInt8((senderIP >> 8) & 0xFF))
        packet.append(UInt8(senderIP & 0xFF))
        
        // Target hardware address
        packet.append(contentsOf: targetMAC)
        
        // Target protocol address
        packet.append(UInt8((targetIP >> 24) & 0xFF))
        packet.append(UInt8((targetIP >> 16) & 0xFF))
        packet.append(UInt8((targetIP >> 8) & 0xFF))
        packet.append(UInt8(targetIP & 0xFF))
        
        // Pad to minimum Ethernet frame size (60 bytes without FCS)
        while packet.count < 60 {
            packet.append(0x00)
        }
        
        return packet
    }
    
    private func formatIP(_ ip: UInt32) -> String {
        let a = (ip >> 24) & 0xFF
        let b = (ip >> 16) & 0xFF
        let c = (ip >> 8) & 0xFF
        let d = ip & 0xFF
        return "\(a).\(b).\(c).\(d)"
    }
}
