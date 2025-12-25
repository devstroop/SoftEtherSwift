# SoftEtherSwift

[![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-iOS%2015%2B%20%7C%20macOS%2012%2B-lightgrey.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure Swift implementation of the SoftEther VPN protocol, using SwiftNIO for event-driven I/O. Designed for iOS Network Extensions and macOS applications.

## Features

- **Pure Swift** - No C code, no FFI, no external frameworks
- **Event-driven** - Uses SwiftNIO with NIOTransportServices (Network.framework)
- **iOS Sandbox Compatible** - Works within iOS Network Extension restrictions
- **Full Protocol Support** - HTTP handshake, Pack serialization, tunnel data channel, DHCP
- **Cluster Redirect** - Automatic redirection to member servers
- **Swift 6 Ready** - Full Sendable conformance

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/devstroop/SoftEtherSwift.git", from: "1.0.0")
]
```

Or in Xcode: File → Add Package Dependencies → Enter the repository URL.

### As Git Submodule

```bash
git submodule add https://github.com/devstroop/SoftEtherSwift.git SoftEtherClient
```

Then add to your project's `Package.swift` or Xcode project.

## Quick Start

### Basic Connection

```swift
import SoftEtherClient

// Create client
let client = SoftEtherClient(
    host: "vpn.example.com",
    port: 443,
    hubName: "VPN",
    username: "user",
    passwordHash: SoftEtherAuth.hashPassword(password: "mypassword", username: "user")
)

// Set packet callback for incoming data
client.setPacketCallback { packets in
    for packet in packets {
        // Handle L3 IP packet from VPN
        print("Received \(packet.count) bytes")
    }
}

// Connect
try await client.connect()

// After connection, start DHCP to get IP
let dhcpResult = try await client.startDHCP()
print("Assigned IP: \(dhcpResult.clientIP)")

// Send packets
client.sendPacket(ipPacketData)
```

### iOS Network Extension

```swift
import NetworkExtension
import SoftEtherClient

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var client: SoftEtherClient?
    
    override func startTunnel(options: [String: NSObject]?, 
                              completionHandler: @escaping (Error?) -> Void) {
        // Create and configure client
        client = SoftEtherClient(
            host: serverHost,
            port: 443,
            hubName: "VPN",
            username: username,
            passwordHash: passwordHash
        )
        
        // Set up packet delivery to iOS
        client?.setPacketCallback { [weak self] packets in
            self?.packetFlow.writePackets(packets, withProtocols: [...])
        }
        
        Task {
            do {
                try await client?.connect()
                let dhcp = try await client?.startDHCP()
                // Apply network settings...
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }
}
```

### Generate Password Hash

SoftEther uses SHA-0 (not SHA-1!) for password hashing:

```swift
import SoftEtherClient

// Generate password hash for storage/transmission
let hashBytes = SoftEtherAuth.hashPassword(password: "mypassword", username: "myuser")
let base64Hash = Data(hashBytes).base64EncodedString()

// Use directly in client
let client = SoftEtherClient(
    host: "vpn.example.com",
    port: 443,
    hubName: "VPN", 
    username: "myuser",
    passwordHash: hashBytes
)
```

## Architecture

```
SoftEtherSwift/
├── Sources/
│   ├── SoftEtherClient.swift   # Main client (connect, auth, tunnel)
│   ├── DHCPClient.swift        # DHCP discovery & IP allocation
│   ├── ARPHandler.swift        # ARP for L2/L3 translation
│   ├── HTTPCodec.swift         # HTTP protocol for handshake
│   ├── Pack.swift              # SoftEther Pack serialization
│   ├── TunnelProtocol.swift    # NIO frame codec for tunnel
│   ├── SoftEtherAuth.swift     # SHA-0 password hashing
│   ├── SHA0.swift              # SHA-0 implementation
│   ├── WaterMark.swift         # Protocol signature GIF
│   └── Exports.swift           # Module exports
├── Tests/
│   └── SoftEtherClientTests.swift
├── Examples/
│   └── ExamplePacketTunnelProvider.swift  # Reference iOS integration
├── Package.swift
├── LICENSE
└── README.md
```

## Protocol Details

### Connection Sequence

1. **TLS Handshake** - Connect to server on port 443 (or configured port)
2. **Upload Signature** - HTTP POST to `/vpnsvc/connect.cgi` with "VPNCONNECT"
3. **Download Hello** - Receive server challenge (20 bytes random)
4. **Upload Auth** - Send Pack with credentials and secure password
5. **Receive Session** - Get session key, connection parameters, or cluster redirect
6. **Tunnel Established** - Begin packet exchange

### Cluster Redirect

SoftEther supports load balancing across server clusters. After initial auth, server may return:
- Direct connection parameters (session key, tunnel key)
- Redirect to member server (IP, port, ticket)

This library handles redirects automatically.

### Tunnel Wire Format

```
[4 bytes] num_blocks (big-endian) or 0xFFFFFFFF for keepalive
For each block:
  [4 bytes] block_size
  [N bytes] Ethernet frame (L2)
```

### L2/L3 Translation

SoftEther operates at Layer 2 (Ethernet). This library handles:
- Adding Ethernet headers for outgoing IP packets
- Stripping Ethernet headers for incoming IP packets
- ARP for gateway MAC resolution
- DHCP for IP address allocation

### Authentication Algorithm

```
1. password_hash = SHA0(password + UPPERCASE(username))
2. secure_password = SHA0(password_hash + server_random)
```

**Important:** SoftEther uses SHA-0 (the original, broken SHA algorithm), NOT SHA-1.

## API Reference

### SoftEtherClient

```swift
// Initialize
init(host: String, port: Int, hubName: String, username: String, passwordHash: [UInt8])

// Connection
func connect() async throws
func disconnect()

// DHCP
func startDHCP() async throws -> DHCPResult

// Packet I/O
func setPacketCallback(_ callback: @escaping ([Data]) -> Void)
func sendPacket(_ data: Data)
func sendPackets(_ packets: [Data])

// Status
var isConnected: Bool { get }
var assignedIP: UInt32 { get }
var gatewayIP: UInt32 { get }
```

### SoftEtherAuth

```swift
// Generate password hash (SHA-0 based)
static func hashPassword(password: String, username: String) -> [UInt8]

// Generate secure password for auth exchange
static func computeSecurePassword(passwordHash: [UInt8], serverRandom: [UInt8]) -> [UInt8]

// Generate random MAC address for virtual adapter
static func generateMACAddress() -> [UInt8]

// Generate random bytes
static func randomBytes(count: Int) -> [UInt8]
```

### DHCPClient

```swift
// Initialize with MAC address
init(mac: [UInt8])

// Build DHCP packets
func buildDiscover() -> Data
func buildRequest(serverIP: UInt32, offeredIP: UInt32) -> Data

// Process responses
func processPacket(_ data: Data) -> DHCPMessage?

// Results
var clientIP: UInt32 { get }
var subnetMask: UInt32 { get }
var gateway: UInt32 { get }
var dns1: UInt32 { get }
var dns2: UInt32 { get }
```

## Requirements

- **iOS 15.0+** or **macOS 12.0+**
- **Swift 5.9+**
- **Xcode 15.0+**

## Dependencies

All dependencies are managed via Swift Package Manager:

- [swift-nio](https://github.com/apple/swift-nio) - Event-driven networking
- [swift-nio-transport-services](https://github.com/apple/swift-nio-transport-services) - Network.framework integration
- [swift-crypto](https://github.com/apple/swift-crypto) - Cryptographic primitives

## Building & Testing

```bash
# Build
swift build

# Run tests
swift test

# Build for release
swift build -c release
```

## License

MIT License - See [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! Please open an issue or pull request.

## Credits

- Protocol reverse-engineered from [SoftEther VPN](https://github.com/SoftEtherVPN/SoftEtherVPN)
- Built with [SwiftNIO](https://github.com/apple/swift-nio)
