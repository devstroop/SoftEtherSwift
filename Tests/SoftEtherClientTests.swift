// SoftEtherClientTests.swift

import XCTest
@testable import SoftEtherClient

final class SHA0Tests: XCTestCase {
    
    func testEmptyString() {
        // SHA-0("") = f96cea198ad1dd5617ac084a3d92c6107708c0ef
        let hash = SHA0.hash(Data())
        let expected: [UInt8] = [
            0xf9, 0x6c, 0xea, 0x19, 0x8a, 0xd1, 0xdd, 0x56,
            0x17, 0xac, 0x08, 0x4a, 0x3d, 0x92, 0xc6, 0x10,
            0x77, 0x08, 0xc0, 0xef
        ]
        XCTAssertEqual(Array(hash), expected)
    }
    
    func testABC() {
        // SHA-0("abc") = 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
        let hash = SHA0.hash("abc".data(using: .utf8)!)
        let expected: [UInt8] = [
            0x01, 0x64, 0xb8, 0xa9, 0x14, 0xcd, 0x2a, 0x5e,
            0x74, 0xc4, 0xf7, 0xff, 0x08, 0x2c, 0x4d, 0x97,
            0xf1, 0xed, 0xf8, 0x80
        ]
        XCTAssertEqual(Array(hash), expected)
    }
}

final class PackTests: XCTestCase {
    
    func testBasicTypes() throws {
        let pack = Pack()
        pack.addInt("intVal", 42)
        pack.addStr("strVal", "Hello")
        pack.addBool("boolVal", true)
        
        XCTAssertEqual(pack.getInt("intVal"), 42)
        XCTAssertEqual(pack.getStr("strVal"), "Hello")
        XCTAssertEqual(pack.getBool("boolVal"), true)
    }
    
    func testRoundTrip() throws {
        let pack1 = Pack()
        pack1.addInt("version", 1)
        pack1.addStr("method", "test")
        pack1.addData("data", Data([1, 2, 3, 4]))
        
        let data = pack1.toData()
        let pack2 = try Pack.fromData(data)
        
        XCTAssertEqual(pack2.getInt("version"), 1)
        XCTAssertEqual(pack2.getStr("method"), "test")
        XCTAssertEqual(pack2.getData("data"), Data([1, 2, 3, 4]))
    }
    
    func testCaseInsensitive() {
        let pack = Pack()
        pack.addStr("HubName", "VPN")
        
        XCTAssertEqual(pack.getStr("hubname"), "VPN")
        XCTAssertEqual(pack.getStr("HUBNAME"), "VPN")
    }
}

final class DHCPClientTests: XCTestCase {
    
    func testDiscoverPacket() {
        let mac: [UInt8] = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A]
        let dhcp = DHCPClient(mac: mac)
        
        let discover = dhcp.buildDiscover()
        
        // Check Ethernet header
        XCTAssertEqual(Array(discover.prefix(6)), [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) // Broadcast
        XCTAssertEqual(Array(discover[6..<12]), mac) // Source MAC
        XCTAssertEqual(Array(discover[12..<14]), [0x08, 0x00]) // IPv4
        
        // Check it's large enough for full DHCP packet
        XCTAssertGreaterThan(discover.count, 282) // Ethernet + IP + UDP + DHCP
    }
}

final class ARPHandlerTests: XCTestCase {
    
    func testGratuitousARP() {
        let mac: [UInt8] = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A]
        let arp = ARPHandler(mac: mac)
        arp.configure(myIP: 0x0A000001, gatewayIP: 0x0A0000FE) // 10.0.0.1, 10.0.0.254
        
        let packet = arp.buildGratuitousARP()
        
        // Check broadcast destination
        XCTAssertEqual(Array(packet.prefix(6)), [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        
        // Check source MAC
        XCTAssertEqual(Array(packet[6..<12]), mac)
        
        // Check ARP EtherType
        XCTAssertEqual(Array(packet[12..<14]), [0x08, 0x06])
    }
}

final class SoftEtherAuthTests: XCTestCase {
    
    func testSecurePassword() {
        // Test case: password="test" username="user"
        let securePass = SoftEtherAuth.generateSecurePassword(password: "test", username: "user")
        
        // Should be 20 bytes (SHA-0 output)
        XCTAssertEqual(securePass.count, 20)
    }
    
    func testMACGeneration() {
        let mac = SoftEtherAuth.generateMACAddress()
        
        XCTAssertEqual(mac.count, 6)
        // Check local admin bit is set (5E = 01011110, bit 1 is set)
        XCTAssertTrue((mac[0] & 0x02) != 0)
    }
}

final class WaterMarkTests: XCTestCase {
    
    func testWaterMarkSize() {
        XCTAssertEqual(WaterMark.bytes.count, 1411)
    }
    
    func testGIFHeader() {
        // Should start with GIF89a header
        XCTAssertEqual(WaterMark.bytes[0], 0x47) // 'G'
        XCTAssertEqual(WaterMark.bytes[1], 0x49) // 'I'
        XCTAssertEqual(WaterMark.bytes[2], 0x46) // 'F'
        XCTAssertEqual(WaterMark.bytes[3], 0x38) // '8'
        XCTAssertEqual(WaterMark.bytes[4], 0x39) // '9'
        XCTAssertEqual(WaterMark.bytes[5], 0x61) // 'a'
    }
    
    func testGIFTrailer() {
        // Should end with GIF trailer 0x3B
        XCTAssertEqual(WaterMark.bytes[1410], 0x3B)
    }
}
