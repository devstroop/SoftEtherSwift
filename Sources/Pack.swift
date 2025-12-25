// Pack.swift - SoftEther Pack Serialization Format
// Binary serialization for RPC communication

import Foundation
import NIOCore
import os.log

private let packLog = OSLog(subsystem: "com.worxvpn.softether", category: "pack")

/// Pack value types matching SoftEther's format
public enum PackValueType: UInt32 {
    case int = 0
    case data = 1
    case str = 2
    case unistr = 3
    case int64 = 4
}

/// A value in a Pack element
public enum PackValue {
    case int(UInt32)
    case data(Data)
    case str(String)
    case unistr(String)
    case int64(UInt64)
    
    var valueType: PackValueType {
        switch self {
        case .int: return .int
        case .data: return .data
        case .str: return .str
        case .unistr: return .unistr
        case .int64: return .int64
        }
    }
}

/// An element in a Pack (named collection of values)
public class PackElement {
    let name: String
    let valueType: PackValueType
    var values: [PackValue]
    
    init(name: String, valueType: PackValueType) {
        self.name = name
        self.valueType = valueType
        self.values = []
    }
}

/// Pack - SoftEther's binary serialization format
/// 
/// Binary Format:
/// - Pack: [num_elements:u32] [element...]
/// - Element: [name:string] [type:u32] [num_values:u32] [value...]
/// - Value types:
///   - INT: [value:u32]
///   - INT64: [value:u64]
///   - DATA: [size:u32] [bytes...]
///   - STR: [len:u32] [utf8_bytes...]
///   - UNISTR: [utf8_size:u32] [utf8_bytes... 0x00]
public class Pack {
    
    private var elements: [PackElement] = []
    
    public init() {}
    
    // MARK: - Add Values
    
    /// Add an integer value
    public func addInt(_ name: String, _ value: UInt32) {
        let elem = getOrCreateElement(name: name, type: .int)
        elem.values.append(.int(value))
    }
    
    /// Add a 64-bit integer value
    public func addInt64(_ name: String, _ value: UInt64) {
        let elem = getOrCreateElement(name: name, type: .int64)
        elem.values.append(.int64(value))
    }
    
    /// Add a string value (ANSI)
    public func addStr(_ name: String, _ value: String) {
        let elem = getOrCreateElement(name: name, type: .str)
        elem.values.append(.str(value))
    }
    
    /// Add a Unicode string value
    public func addUniStr(_ name: String, _ value: String) {
        let elem = getOrCreateElement(name: name, type: .unistr)
        elem.values.append(.unistr(value))
    }
    
    /// Add binary data
    public func addData(_ name: String, _ value: Data) {
        let elem = getOrCreateElement(name: name, type: .data)
        elem.values.append(.data(value))
    }
    
    /// Add a boolean (stored as int)
    public func addBool(_ name: String, _ value: Bool) {
        addInt(name, value ? 1 : 0)
    }
    
    // MARK: - Get Values
    
    /// Get an integer value
    public func getInt(_ name: String) -> UInt32? {
        guard let elem = findElement(name: name),
              elem.valueType == .int,
              let first = elem.values.first,
              case .int(let value) = first else {
            return nil
        }
        return value
    }
    
    /// Get a 64-bit integer value
    public func getInt64(_ name: String) -> UInt64? {
        guard let elem = findElement(name: name),
              elem.valueType == .int64,
              let first = elem.values.first,
              case .int64(let value) = first else {
            return nil
        }
        return value
    }
    
    /// Get a string value
    public func getStr(_ name: String) -> String? {
        guard let elem = findElement(name: name),
              elem.valueType == .str,
              let first = elem.values.first,
              case .str(let value) = first else {
            return nil
        }
        return value
    }
    
    /// Get a Unicode string value
    public func getUniStr(_ name: String) -> String? {
        guard let elem = findElement(name: name),
              elem.valueType == .unistr,
              let first = elem.values.first,
              case .unistr(let value) = first else {
            return nil
        }
        return value
    }
    
    /// Get binary data
    public func getData(_ name: String) -> Data? {
        guard let elem = findElement(name: name),
              elem.valueType == .data,
              let first = elem.values.first,
              case .data(let value) = first else {
            return nil
        }
        return value
    }
    
    /// Get a boolean value
    public func getBool(_ name: String) -> Bool? {
        guard let value = getInt(name) else { return nil }
        return value != 0
    }
    
    /// Check if element exists
    public func contains(_ name: String) -> Bool {
        return findElement(name: name) != nil
    }
    
    // MARK: - Serialization
    
    /// Serialize Pack to binary format
    public func toData() -> Data {
        var buffer = ByteBuffer()
        
        // Write number of elements
        buffer.writeInteger(UInt32(elements.count), endianness: .big)
        
        // Write each element
        for elem in elements {
            writeElement(&buffer, elem)
        }
        
        return Data(buffer.readableBytesView)
    }
    
    /// Serialize to ByteBuffer
    public func toByteBuffer() -> ByteBuffer {
        var buffer = ByteBuffer()
        
        buffer.writeInteger(UInt32(elements.count), endianness: .big)
        
        for elem in elements {
            writeElement(&buffer, elem)
        }
        
        return buffer
    }
    
    /// Deserialize Pack from binary format
    public static func fromData(_ data: Data) throws -> Pack {
        os_log(.default, log: packLog, "fromData: parsing %{public}d bytes", data.count)
        var buffer = ByteBuffer(bytes: data)
        return try fromByteBuffer(&buffer)
    }
    
    /// Deserialize from ByteBuffer
    public static func fromByteBuffer(_ buffer: inout ByteBuffer) throws -> Pack {
        let pack = Pack()
        
        guard let numElements: UInt32 = buffer.readInteger(endianness: .big) else {
            os_log(.error, log: packLog, "ERROR: Cannot read numElements")
            throw PackError.unexpectedEOF
        }
        
        os_log(.default, log: packLog, "numElements = %{public}u", numElements)
        
        // Bounds check
        guard numElements <= PackConstants.maxElements else {
            os_log(.error, log: packLog, "ERROR: Too many elements: %{public}u", numElements)
            throw PackError.tooManyElements
        }
        
        for i in 0..<numElements {
            os_log(.debug, log: packLog, "Reading element %{public}u/%{public}u", i + 1, numElements)
            try pack.readElement(&buffer)
        }
        
        os_log(.default, log: packLog, "Parsing complete")
        return pack
    }
    
    // MARK: - Private
    
    private func findElement(name: String) -> PackElement? {
        // Case-insensitive search to match SoftEther behavior
        return elements.first { $0.name.lowercased() == name.lowercased() }
    }
    
    private func getOrCreateElement(name: String, type: PackValueType) -> PackElement {
        if let existing = findElement(name: name) {
            return existing
        }
        let elem = PackElement(name: name, valueType: type)
        elements.append(elem)
        return elem
    }
    
    private func writeElement(_ buffer: inout ByteBuffer, _ elem: PackElement) {
        // Write name (length-prefixed with null terminator counted but not written)
        let nameBytes = elem.name.utf8
        buffer.writeInteger(UInt32(nameBytes.count + 1), endianness: .big) // +1 for null
        buffer.writeBytes(nameBytes)
        
        // Write type
        buffer.writeInteger(elem.valueType.rawValue, endianness: .big)
        
        // Write number of values
        buffer.writeInteger(UInt32(elem.values.count), endianness: .big)
        
        // Write each value
        for value in elem.values {
            writeValue(&buffer, value)
        }
    }
    
    private func writeValue(_ buffer: inout ByteBuffer, _ value: PackValue) {
        switch value {
        case .int(let v):
            buffer.writeInteger(v, endianness: .big)
            
        case .int64(let v):
            buffer.writeInteger(v, endianness: .big)
            
        case .data(let d):
            buffer.writeInteger(UInt32(d.count), endianness: .big)
            buffer.writeBytes(d)
            
        case .str(let s):
            let bytes = s.utf8
            buffer.writeInteger(UInt32(bytes.count), endianness: .big)
            buffer.writeBytes(bytes)
            
        case .unistr(let s):
            let bytes = s.utf8
            buffer.writeInteger(UInt32(bytes.count + 1), endianness: .big) // +1 for null
            buffer.writeBytes(bytes)
            buffer.writeInteger(UInt8(0)) // null terminator
        }
    }
    
    private func readElement(_ buffer: inout ByteBuffer) throws {
        // Read name length
        guard let nameLen: UInt32 = buffer.readInteger(endianness: .big) else {
            throw PackError.unexpectedEOF
        }
        
        // Bounds check: name length must include null terminator (so at least 1)
        // Also limit to reasonable size
        guard nameLen >= 1 && nameLen <= 4096 else {
            throw PackError.stringTooLong
        }
        
        // Name length includes null terminator which isn't written
        let actualNameLen = Int(nameLen) - 1
        let name: String
        if actualNameLen == 0 {
            name = ""
        } else {
            guard let nameBytes = buffer.readBytes(length: actualNameLen) else {
                throw PackError.unexpectedEOF
            }
            name = String(decoding: nameBytes, as: UTF8.self)
        }
        
        // Read type
        guard let typeInt: UInt32 = buffer.readInteger(endianness: .big) else {
            throw PackError.unexpectedEOF
        }
        guard let valueType = PackValueType(rawValue: typeInt) else {
            throw PackError.invalidElementType
        }
        
        // Read number of values
        guard let numValues: UInt32 = buffer.readInteger(endianness: .big) else {
            throw PackError.unexpectedEOF
        }
        
        // Bounds check
        guard numValues <= PackConstants.maxValueNum else {
            throw PackError.tooManyValues
        }
        
        // Read each value
        for _ in 0..<numValues {
            try readValue(name: name, type: valueType, &buffer)
        }
    }
    
    private func readValue(name: String, type: PackValueType, _ buffer: inout ByteBuffer) throws {
        switch type {
        case .int:
            guard let value: UInt32 = buffer.readInteger(endianness: .big) else {
                throw PackError.unexpectedEOF
            }
            addInt(name, value)
            
        case .int64:
            guard let value: UInt64 = buffer.readInteger(endianness: .big) else {
                throw PackError.unexpectedEOF
            }
            addInt64(name, value)
            
        case .data:
            guard let size: UInt32 = buffer.readInteger(endianness: .big) else {
                throw PackError.unexpectedEOF
            }
            guard size <= PackConstants.maxValueSize else {
                throw PackError.dataTooLarge
            }
            guard let bytes = buffer.readBytes(length: Int(size)) else {
                throw PackError.unexpectedEOF
            }
            addData(name, Data(bytes))
            
        case .str:
            guard let len: UInt32 = buffer.readInteger(endianness: .big) else {
                throw PackError.unexpectedEOF
            }
            guard len <= PackConstants.maxValueSize else {
                throw PackError.stringTooLong
            }
            guard let bytes = buffer.readBytes(length: Int(len)) else {
                throw PackError.unexpectedEOF
            }
            addStr(name, String(decoding: bytes, as: UTF8.self))
            
        case .unistr:
            guard let size: UInt32 = buffer.readInteger(endianness: .big) else {
                throw PackError.unexpectedEOF
            }
            if size == 0 {
                addUniStr(name, "")
                return
            }
            guard size <= PackConstants.maxValueSize else {
                throw PackError.stringTooLong
            }
            guard let bytes = buffer.readBytes(length: Int(size)) else {
                throw PackError.unexpectedEOF
            }
            // Remove null terminator if present
            let actualLen = bytes.last == 0 ? bytes.count - 1 : bytes.count
            addUniStr(name, String(decoding: bytes[0..<actualLen], as: UTF8.self))
        }
    }
}

/// Pack serialization errors
public enum PackError: Error, LocalizedError {
    case unexpectedEOF
    case invalidElementType
    case dataTooLarge
    case stringTooLong
    case tooManyValues
    case tooManyElements
    
    public var errorDescription: String? {
        switch self {
        case .unexpectedEOF: return "Unexpected end of Pack data"
        case .invalidElementType: return "Invalid Pack element type"
        case .dataTooLarge: return "Pack data too large"
        case .stringTooLong: return "Pack string too long"
        case .tooManyValues: return "Too many values in Pack element"
        case .tooManyElements: return "Too many elements in Pack"
        }
    }
}

/// Pack constants (matching SoftEther/Zig implementation)
public enum PackConstants {
    public static let maxValueSize = 96 * 1024 * 1024  // 96 MB
    public static let maxValueNum = 65536
    public static let maxElements = 65536
}

// MARK: - ByteBuffer Extensions

extension ByteBuffer {
    mutating func writeBytes(_ data: Data) {
        self.writeBytes([UInt8](data))
    }
    
    mutating func writeBytes(_ string: String.UTF8View) {
        self.writeBytes(Array(string))
    }
}
