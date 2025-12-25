# SoftEtherClient - Pure Swift VPN Client

A pure Swift implementation of the SoftEther VPN protocol, using SwiftNIO for event-driven I/O.

## Features

- **Pure Swift** - No external dependencies except SwiftNIO/SSL/Crypto
- **Event-driven** - Uses SwiftNIO for non-blocking I/O
- **iOS/macOS compatible** - Works on iOS 15+ and macOS 12+
- **Full protocol support** - HTTP handshake, Pack serialization, tunnel data channel

## Components

### Core Protocol

- `SHA0.swift` - SHA-0 hasher (SoftEther uses SHA-0, not SHA-1!)
- `Pack.swift` - Binary serialization format for RPC communication
- `WaterMark.swift` - Protocol signature data
- `TunnelProtocol.swift` - NIO frame codec for tunnel data channel

### Network Layer

- `SoftEtherClient.swift` - Main VPN client using SwiftNIO
- `SoftEtherAuth.swift` - Password hashing and authentication
- `DHCPClient.swift` - DHCP protocol for IP address allocation
- `ARPHandler.swift` - ARP protocol for gateway MAC resolution

### iOS Integration

- `SoftEtherPacketTunnelProvider.swift` - NEPacketTunnelProvider implementation

## Usage

### Basic Connection

```swift
import SoftEtherClient

let config = VPNConfiguration(
    host: "vpn.example.com",
    port: 443,
    hubName: "VPN",
    username: "user",
    passwordHash: "base64_encoded_sha0_hash"
)

let client = SoftEtherClient(config: config)
client.delegate = self

try await client.connect()
```

### Generate Password Hash

```swift
// Generate SHA-0 based secure password hash
let hash = SoftEtherAuth.generateSecurePassword(
    password: "mypassword",
    username: "myuser"
)

// Convert to Base64 for storage
let base64Hash = Data(hash).base64EncodedString()
```

### iOS Network Extension

```swift
// In your PacketTunnelProvider
class PacketTunnelProvider: SoftEtherPacketTunnelProvider {
    // Inherits all functionality
}
```

## Protocol Details

### Handshake Sequence

1. **Upload Signature** - HTTP POST to `/vpnsvc/connect.cgi` with "VPNCONNECT"
2. **Download Hello** - Receive server challenge (20 bytes random)
3. **Upload Auth** - Send Pack with credentials and secure password
4. **Receive Session** - Get session key and connection parameters

### Tunnel Wire Format

```
[4 bytes] num_blocks (big-endian) or 0xFFFFFFFF for keepalive
For each block:
  [4 bytes] block_size
  [N bytes] Ethernet frame
```

### Authentication

SoftEther uses a two-stage hash:
1. `password_hash = SHA0(password)`
2. `secure_password = SHA0(password_hash + UPPERCASE(username))`
3. `response = SHA1(secure_password + server_random)`

**Note:** SoftEther uses SHA-0 (the original, broken SHA algorithm) for password hashing, NOT SHA-1.

## Building

```bash
swift build
swift test
```

## Dependencies

- [swift-nio](https://github.com/apple/swift-nio) - Event-driven I/O
- [swift-nio-ssl](https://github.com/apple/swift-nio-ssl) - TLS support
- [swift-crypto](https://github.com/apple/swift-crypto) - Cryptographic operations

## License

MIT License
