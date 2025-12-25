// SoftEtherAuth.swift - Authentication for SoftEther VPN
// Password hashing, secure password generation

import Foundation
import Crypto

/// SoftEther authentication utilities
public enum SoftEtherAuth {
    
    /// Generate password hash for SoftEther authentication
    /// Uses SHA-0 (not SHA-1!) for legacy compatibility with SoftEther
    ///
    /// The algorithm (from Zig auth.zig):
    /// password_hash = SHA0(password + UPPERCASE(username))
    ///
    public static func hashPassword(password: String, username: String) -> [UInt8] {
        // SHA0(password + UPPERCASE(username))
        let passwordBytes = Array(password.utf8)
        let usernameUpper = username.uppercased()
        let usernameBytes = Array(usernameUpper.utf8)
        
        var combined = passwordBytes
        combined.append(contentsOf: usernameBytes)
        
        return SHA0.hash(combined)
    }
    
    /// Compute secure password from password hash and server random
    /// 
    /// Algorithm (from Zig auth.zig):
    /// secure_password = SHA0(password_hash + server_random)
    ///
    public static func computeSecurePassword(
        passwordHash: [UInt8],
        serverRandom: [UInt8]
    ) -> [UInt8] {
        // SHA0(password_hash + server_random)
        var combined = passwordHash
        combined.append(contentsOf: serverRandom)
        return SHA0.hash(combined)
    }
    
    /// Compute secure password from pre-computed password hash (base64 encoded)
    public static func computeSecurePasswordFromBase64(
        passwordHashBase64: String,
        serverRandom: [UInt8]
    ) -> [UInt8] {
        guard let hashData = Data(base64Encoded: passwordHashBase64) else {
            return [UInt8](repeating: 0, count: 20)
        }
        return computeSecurePassword(passwordHash: Array(hashData), serverRandom: serverRandom)
    }
    
    /// Generate client random for protocol handshake
    public static func generateClientRandom() -> [UInt8] {
        var random = [UInt8](repeating: 0, count: 20)
        for i in 0..<20 {
            random[i] = UInt8.random(in: 0...255)
        }
        return random
    }
    
    /// Generate a unique MAC address for virtual adapter
    /// SoftEther format: 5E:xx:xx:xx:xx:xx (5E is SoftEther prefix)
    public static func generateMACAddress() -> [UInt8] {
        var mac = [UInt8](repeating: 0, count: 6)
        mac[0] = 0x5E  // SoftEther prefix
        for i in 1..<6 {
            mac[i] = UInt8.random(in: 0...255)
        }
        // Ensure locally administered bit is set
        mac[0] |= 0x02
        return mac
    }
    
    /// Generate transaction ID for DHCP
    public static func generateTransactionId() -> UInt32 {
        return UInt32.random(in: 0...UInt32.max)
    }
    
    /// Generate random bytes (for unique_id, pencore, etc.)
    public static func randomBytes(count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            bytes[i] = UInt8.random(in: 0...255)
        }
        return bytes
    }
}
