// SHA0.swift - SHA-0 implementation for SoftEther password hashing
// SoftEther uses SHA-0 (not SHA-1) for legacy compatibility

import Foundation

/// SHA-0 hasher - SoftEther uses this for password hashing
/// The key difference from SHA-1: NO rotation in message schedule
public struct SHA0 {
    public static let digestLength = 20
    public static let blockSize = 64
    
    private var state: (UInt32, UInt32, UInt32, UInt32, UInt32) = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    )
    private var buffer = [UInt8](repeating: 0, count: 64)
    private var bufferLength = 0
    private var totalLength: UInt64 = 0
    
    public init() {}
    
    public mutating func update(_ data: Data) {
        update(Array(data))
    }
    
    public mutating func update(_ data: [UInt8]) {
        var input = data[...]
        totalLength += UInt64(input.count)
        
        // Fill buffer first
        if bufferLength > 0 {
            let space = Self.blockSize - bufferLength
            let toCopy = min(space, input.count)
            for i in 0..<toCopy {
                buffer[bufferLength + i] = input[input.startIndex + i]
            }
            bufferLength += toCopy
            input = input.dropFirst(toCopy)
            
            if bufferLength == Self.blockSize {
                processBlock(buffer)
                bufferLength = 0
            }
        }
        
        // Process full blocks
        while input.count >= Self.blockSize {
            processBlock(Array(input.prefix(Self.blockSize)))
            input = input.dropFirst(Self.blockSize)
        }
        
        // Store remaining
        if !input.isEmpty {
            for (i, byte) in input.enumerated() {
                buffer[i] = byte
            }
            bufferLength = input.count
        }
    }
    
    public mutating func finalize() -> [UInt8] {
        let totalBits = totalLength * 8
        
        // Pad with 0x80
        buffer[bufferLength] = 0x80
        bufferLength += 1
        
        // If not enough space for length, process and start new block
        if bufferLength > 56 {
            for i in bufferLength..<Self.blockSize {
                buffer[i] = 0
            }
            processBlock(buffer)
            bufferLength = 0
        }
        
        // Pad with zeros until length position
        for i in bufferLength..<56 {
            buffer[i] = 0
        }
        
        // Append length in bits (big-endian)
        buffer[56] = UInt8((totalBits >> 56) & 0xFF)
        buffer[57] = UInt8((totalBits >> 48) & 0xFF)
        buffer[58] = UInt8((totalBits >> 40) & 0xFF)
        buffer[59] = UInt8((totalBits >> 32) & 0xFF)
        buffer[60] = UInt8((totalBits >> 24) & 0xFF)
        buffer[61] = UInt8((totalBits >> 16) & 0xFF)
        buffer[62] = UInt8((totalBits >> 8) & 0xFF)
        buffer[63] = UInt8(totalBits & 0xFF)
        
        processBlock(buffer)
        
        // Extract digest (big-endian)
        var digest = [UInt8](repeating: 0, count: Self.digestLength)
        digest[0] = UInt8((state.0 >> 24) & 0xFF)
        digest[1] = UInt8((state.0 >> 16) & 0xFF)
        digest[2] = UInt8((state.0 >> 8) & 0xFF)
        digest[3] = UInt8(state.0 & 0xFF)
        digest[4] = UInt8((state.1 >> 24) & 0xFF)
        digest[5] = UInt8((state.1 >> 16) & 0xFF)
        digest[6] = UInt8((state.1 >> 8) & 0xFF)
        digest[7] = UInt8(state.1 & 0xFF)
        digest[8] = UInt8((state.2 >> 24) & 0xFF)
        digest[9] = UInt8((state.2 >> 16) & 0xFF)
        digest[10] = UInt8((state.2 >> 8) & 0xFF)
        digest[11] = UInt8(state.2 & 0xFF)
        digest[12] = UInt8((state.3 >> 24) & 0xFF)
        digest[13] = UInt8((state.3 >> 16) & 0xFF)
        digest[14] = UInt8((state.3 >> 8) & 0xFF)
        digest[15] = UInt8(state.3 & 0xFF)
        digest[16] = UInt8((state.4 >> 24) & 0xFF)
        digest[17] = UInt8((state.4 >> 16) & 0xFF)
        digest[18] = UInt8((state.4 >> 8) & 0xFF)
        digest[19] = UInt8(state.4 & 0xFF)
        
        return digest
    }
    
    private mutating func processBlock(_ block: [UInt8]) {
        var w = [UInt32](repeating: 0, count: 80)
        
        // Load first 16 words (big-endian)
        for i in 0..<16 {
            let offset = i * 4
            w[i] = UInt32(block[offset]) << 24 |
                   UInt32(block[offset + 1]) << 16 |
                   UInt32(block[offset + 2]) << 8 |
                   UInt32(block[offset + 3])
        }
        
        // SHA-0: NO rotation in message schedule (this is the key difference from SHA-1)
        for i in 16..<80 {
            w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            // SHA-1 would have: w[i] = rotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
        }
        
        var a = state.0
        var b = state.1
        var c = state.2
        var d = state.3
        var e = state.4
        
        for i in 0..<80 {
            var f: UInt32
            var k: UInt32
            
            if i < 20 {
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            } else if i < 40 {
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            } else if i < 60 {
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            } else {
                f = b ^ c ^ d
                k = 0xCA62C1D6
            }
            
            let temp = rotateLeft(a, 5) &+ f &+ e &+ k &+ w[i]
            e = d
            d = c
            c = rotateLeft(b, 30)
            b = a
            a = temp
        }
        
        state.0 = state.0 &+ a
        state.1 = state.1 &+ b
        state.2 = state.2 &+ c
        state.3 = state.3 &+ d
        state.4 = state.4 &+ e
    }
    
    private func rotateLeft(_ value: UInt32, _ bits: Int) -> UInt32 {
        return (value << bits) | (value >> (32 - bits))
    }
    
    /// Convenience function to hash data in one call
    public static func hash(_ data: Data) -> [UInt8] {
        var hasher = SHA0()
        hasher.update(data)
        return hasher.finalize()
    }
    
    public static func hash(_ data: [UInt8]) -> [UInt8] {
        var hasher = SHA0()
        hasher.update(data)
        return hasher.finalize()
    }
}
