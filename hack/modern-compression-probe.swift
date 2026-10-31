// macOS 27+ experiment: exercise the new Compression.framework buffer codecs.
//
// This deliberately does NOT write com.apple.decmpfs or change file flags.
// A working buffer codec does not imply that the APFS kernel supports the
// corresponding transparent filesystem compression format.

import Compression
import Foundation

struct Codec {
    let name: String
    let algorithm: compression_algorithm
}

@available(macOS 27, *)
func modernCodecs() -> [Codec] {
    [
        Codec(name: "LZFSE", algorithm: COMPRESSION_LZFSE),
        Codec(name: "LZMESH", algorithm: COMPRESSION_LZMESH),
        Codec(name: "LZRAVEN", algorithm: COMPRESSION_LZRAVEN),
    ]
}

func sampleChatLog() -> [UInt8] {
    var text = ""
    for n in 0..<1024 {
        text += "{\"role\":\"user\",\"session\":42,\"index\":\(n),\"message\":\"Explain transparent APFS compression for text-heavy chat logs.\"}\n"
        text += "{\"role\":\"assistant\",\"session\":42,\"index\":\(n),\"message\":\"Files stay readable while macOS decompresses them on demand.\"}\n"
    }
    return Array(text.utf8)
}

func sampleHighEntropy() -> [UInt8] {
    // Deterministic xorshift stream, to exercise raw-block/fallback behaviour.
    var state: UInt32 = 0xD15EA5E
    var bytes = [UInt8]()
    bytes.reserveCapacity(128 * 1024)
    for _ in 0..<(128 * 1024) {
        state ^= state << 13
        state ^= state >> 17
        state ^= state << 5
        bytes.append(UInt8(truncatingIfNeeded: state))
    }
    return bytes
}

func run(_ codec: Codec, input: [UInt8]) throws {
    // Include overhead for formats that emit raw blocks for incompressible data.
    let capacity = input.count * 2 + 65_536
    var compressed = [UInt8](repeating: 0, count: capacity)
    var decoded = [UInt8](repeating: 0, count: input.count)

    let encodeScratchSize = max(1, compression_encode_scratch_buffer_size(codec.algorithm))
    let decodeScratchSize = max(1, compression_decode_scratch_buffer_size(codec.algorithm))
    let encodeScratch = UnsafeMutableRawPointer.allocate(byteCount: encodeScratchSize, alignment: 64)
    let decodeScratch = UnsafeMutableRawPointer.allocate(byteCount: decodeScratchSize, alignment: 64)
    defer {
        encodeScratch.deallocate()
        decodeScratch.deallocate()
    }

    let startEncode = DispatchTime.now().uptimeNanoseconds
    let compressedCount = input.withUnsafeBufferPointer { src in
        compressed.withUnsafeMutableBufferPointer { dst in
            compression_encode_buffer(
                dst.baseAddress!, dst.count,
                src.baseAddress!, src.count,
                encodeScratch, codec.algorithm
            )
        }
    }
    let endEncode = DispatchTime.now().uptimeNanoseconds
    guard compressedCount > 0 else {
        throw ProbeError.failed("\(codec.name) encoding returned zero bytes")
    }

    let startDecode = DispatchTime.now().uptimeNanoseconds
    let decodedCount = compressed.withUnsafeBufferPointer { src in
        decoded.withUnsafeMutableBufferPointer { dst in
            compression_decode_buffer(
                dst.baseAddress!, dst.count,
                src.baseAddress!, compressedCount,
                decodeScratch, codec.algorithm
            )
        }
    }
    let endDecode = DispatchTime.now().uptimeNanoseconds
    guard decodedCount == input.count, decoded == input else {
        throw ProbeError.failed("\(codec.name) round-trip mismatch: decoded \(decodedCount) of \(input.count) bytes")
    }

    let percent = 100.0 * Double(compressedCount) / Double(input.count)
    let encodeMs = Double(endEncode - startEncode) / 1_000_000
    let decodeMs = Double(endDecode - startDecode) / 1_000_000
    let paddedName = codec.name.padding(toLength: 8, withPad: " ", startingAt: 0)
    print(String(format: "%@  %10d  %10d  %6.1f%%  %9.2f  %9.2f  OK",
                 paddedName as NSString, input.count, compressedCount,
                 percent, encodeMs, decodeMs))
}

enum ProbeError: Error, CustomStringConvertible {
    case failed(String)

    var description: String {
        switch self {
        case .failed(let detail): return detail
        }
    }
}

do {
    guard #available(macOS 27, *) else {
        throw ProbeError.failed("LZMESH and LZRAVEN require macOS 27 or newer")
    }
    let args = Array(CommandLine.arguments.dropFirst())
    let inputs: [(name: String, bytes: [UInt8])]
    if args.isEmpty {
        inputs = [
            ("generated JSONL-style chat log", sampleChatLog()),
            ("generated high-entropy bytes", sampleHighEntropy()),
        ]
    } else if args.count == 2, args[0] == "--file" {
        // Local-only optional input, NEVER used by CI or uploaded to artifacts.
        let fileURL = URL(fileURLWithPath: args[1])
        let attrs = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        if let byteCount = attrs[.size] as? NSNumber, byteCount.uint64Value > 64 * 1024 * 1024 {
            throw ProbeError.failed("Limit input to 64 MiB to bound temporary memory usage")
        }
        inputs = [("local file (read-only)", Array(try Data(contentsOf: fileURL)))]
    } else {
        throw ProbeError.failed("Usage: swift hack/modern-compression-probe.swift [--file /path/to/log.jsonl]")
    }
    for (name, input) in inputs {
        guard !input.isEmpty else { throw ProbeError.failed("Input is empty") }
        guard input.count <= 64 * 1024 * 1024 else {
            throw ProbeError.failed("Limit input to 64 MiB to bound temporary memory usage")
        }
        print("Input: \(name)")
        print("Codec       Input (B)  Output (B)    Size    Encode ms  Decode ms  Verified")
        if #available(macOS 27, *) {
            for codec in modernCodecs() {
                try run(codec, input: input)
            }
        }
    }
    print("Buffer round-trips passed. No APFS/decmpfs filesystem support is implied or tested.")
} catch {
    fputs("Probe failed: \(error)\n", stderr)
    exit(EXIT_FAILURE)
}
