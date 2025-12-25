// TunnelProtocol.swift - SoftEther tunnel data channel protocol
// Wire format for data channel after authentication

import Foundation
import NIOCore

/// SoftEther tunnel protocol constants
public enum TunnelConstants {
    /// Magic number indicating keep-alive packet
    public static let keepAliveMagic: UInt32 = 0xFFFFFFFF
    
    /// Maximum Ethernet frame size
    public static let maxPacketSize = 1514
    
    /// Maximum keep-alive data size
    public static let maxKeepaliveSize = 512
    
    /// Maximum blocks to receive at once
    public static let maxRecvBlocks = 512
}

/// Tunnel frame types
public enum TunnelFrameType {
    case data([Data])      // Ethernet frames
    case keepalive(Int)    // Keep-alive with size
}

/// SoftEther tunnel frame decoder
/// Wire format:
/// - [4 bytes] num_blocks (big-endian) or KEEP_ALIVE_MAGIC
/// - For each block:
///   - [4 bytes] block_size (big-endian)
///   - [N bytes] block_data (Ethernet frame)
/// - For keep-alive:
///   - [4 bytes] keep_alive_size
///   - [N bytes] random data
public final class TunnelFrameDecoder: ByteToMessageDecoder {
    public typealias InboundOut = TunnelFrameType
    
    private enum State {
        case readingHeader
        case readingBlocks(count: Int, collected: [Data])
        case readingKeepaliveSize
        case readingKeepaliveData(size: Int)
    }
    
    private var state: State = .readingHeader
    
    public init() {}
    
    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        switch state {
        case .readingHeader:
            guard buffer.readableBytes >= 4 else { return .needMoreData }
            let numBlocks = buffer.readInteger(as: UInt32.self)!
            
            if numBlocks == TunnelConstants.keepAliveMagic {
                state = .readingKeepaliveSize
                return .continue
            }
            
            if numBlocks == 0 {
                context.fireChannelRead(wrapInboundOut(.data([])))
                return .continue
            }
            
            if numBlocks > TunnelConstants.maxRecvBlocks {
                throw TunnelError.tooManyBlocks
            }
            
            state = .readingBlocks(count: Int(numBlocks), collected: [])
            return .continue
            
        case .readingBlocks(let count, var collected):
            guard buffer.readableBytes >= 4 else { return .needMoreData }
            let blockSize = buffer.readInteger(as: UInt32.self)!
            
            if blockSize == 0 {
                // Empty block, skip
                if collected.count + 1 >= count {
                    state = .readingHeader
                    context.fireChannelRead(wrapInboundOut(.data(collected)))
                    return .continue
                } else {
                    state = .readingBlocks(count: count, collected: collected)
                    return .continue
                }
            }
            
            guard blockSize <= TunnelConstants.maxPacketSize * 2 else {
                throw TunnelError.packetTooLarge
            }
            
            guard let blockBytes = buffer.readBytes(length: Int(blockSize)) else {
                // Put the block size back and wait
                buffer.moveReaderIndex(to: buffer.readerIndex - 4)
                return .needMoreData
            }
            
            let blockData = Data(blockBytes)
            collected.append(blockData)
            
            if collected.count >= count {
                state = .readingHeader
                context.fireChannelRead(wrapInboundOut(.data(collected)))
            } else {
                state = .readingBlocks(count: count, collected: collected)
            }
            return .continue
            
        case .readingKeepaliveSize:
            guard buffer.readableBytes >= 4 else { return .needMoreData }
            let kaSize = buffer.readInteger(as: UInt32.self)!
            
            guard kaSize <= TunnelConstants.maxKeepaliveSize else {
                throw TunnelError.invalidKeepalive
            }
            
            if kaSize == 0 {
                state = .readingHeader
                context.fireChannelRead(wrapInboundOut(.keepalive(0)))
                return .continue
            }
            
            state = .readingKeepaliveData(size: Int(kaSize))
            return .continue
            
        case .readingKeepaliveData(let size):
            guard buffer.readableBytes >= size else { return .needMoreData }
            buffer.moveReaderIndex(forwardBy: size) // Discard keep-alive data
            state = .readingHeader
            context.fireChannelRead(wrapInboundOut(.keepalive(size)))
            return .continue
        }
    }
    
    public func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        return .needMoreData
    }
}

/// SoftEther tunnel frame encoder
public final class TunnelFrameEncoder: MessageToByteEncoder {
    public typealias OutboundIn = TunnelFrameType
    
    public init() {}
    
    public func encode(data: TunnelFrameType, out: inout ByteBuffer) throws {
        switch data {
        case .data(let blocks):
            // Write number of blocks
            out.writeInteger(UInt32(blocks.count), endianness: .big)
            
            // Write each block
            for block in blocks {
                out.writeInteger(UInt32(block.count), endianness: .big)
                out.writeBytes(block)
            }
            
        case .keepalive(let size):
            // Write keep-alive magic
            out.writeInteger(TunnelConstants.keepAliveMagic, endianness: .big)
            // Write size
            out.writeInteger(UInt32(size), endianness: .big)
            // Write random padding
            if size > 0 {
                var padding = [UInt8](repeating: 0, count: size)
                for i in 0..<size {
                    padding[i] = UInt8.random(in: 0...255)
                }
                out.writeBytes(padding)
            }
        }
    }
}

/// Tunnel errors
public enum TunnelError: Error {
    case tooManyBlocks
    case packetTooLarge
    case invalidKeepalive
    case connectionClosed
}
