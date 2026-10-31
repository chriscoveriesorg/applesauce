// macOS 27+ experiment: exercise the new Compression.framework buffer codecs.
//
// This deliberately does NOT write com.apple.decmpfs or change file flags.
// A working buffer codec does not imply that the APFS kernel supports the
// corresponding transparent filesystem compression format.

import Compression
import Darwin
import Dispatch
import Foundation

let maximumInputBytes = 64 * 1024 * 1024

struct Codec {
    let name: String
    let algorithm: compression_algorithm
}

struct CodecResult: Encodable {
    let input: String
    let codec: String
    let inputBytes: Int
    let compressedBytes: Int
    let encodeNanoseconds: UInt64
    let decodeNanoseconds: UInt64
    let verified: Bool
}

struct ProbeReport: Encodable {
    let schemaVersion = 1
    let kind = "compression-buffer-probe"
    let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
    let architecture: String
    let kernelSupportTested = false
    let timingMethod = "single-run smoke test; not a performance benchmark"
    let results: [CodecResult]
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

func run(_ codec: Codec, inputName: String, input: [UInt8]) throws -> CodecResult {
    // Include overhead for formats that emit raw blocks for incompressible data.
    let capacity = input.count * 2 + 65_536
    var compressed = [UInt8](repeating: 0, count: capacity)
    // An extra output byte detects a decoder that would otherwise silently
    // fill the destination with the correct prefix of an overlong result.
    var decoded = [UInt8](repeating: 0, count: input.count + 1)

    let encodeScratchSize = compression_encode_scratch_buffer_size(codec.algorithm)
    let decodeScratchSize = compression_decode_scratch_buffer_size(codec.algorithm)
    // Zero scratch is valid for some implementations; it is not evidence
    // that a codec is unavailable. Only an actual round-trip can establish it.
    let encodeScratch: UnsafeMutableRawPointer? = encodeScratchSize == 0 ? nil :
        UnsafeMutableRawPointer.allocate(byteCount: encodeScratchSize, alignment: 64)
    let decodeScratch: UnsafeMutableRawPointer? = decodeScratchSize == 0 ? nil :
        UnsafeMutableRawPointer.allocate(byteCount: decodeScratchSize, alignment: 64)
    defer {
        encodeScratch?.deallocate()
        decodeScratch?.deallocate()
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
    guard decodedCount == input.count, decoded.prefix(input.count).elementsEqual(input) else {
        throw ProbeError.failed("\(codec.name) round-trip mismatch: decoded \(decodedCount) of \(input.count) bytes")
    }

    return CodecResult(
        input: inputName, codec: codec.name,
        inputBytes: input.count, compressedBytes: compressedCount,
        encodeNanoseconds: endEncode - startEncode,
        decodeNanoseconds: endDecode - startDecode, verified: true
    )
}

func printResult(_ result: CodecResult) {
    let percent = 100.0 * Double(result.compressedBytes) / Double(result.inputBytes)
    let encodeMs = Double(result.encodeNanoseconds) / 1_000_000
    let decodeMs = Double(result.decodeNanoseconds) / 1_000_000
    let paddedName = result.codec.padding(toLength: 8, withPad: " ", startingAt: 0)
    print(String(format: "%@  %10lld  %10lld  %6.1f%%  %9.2f  %9.2f  OK",
                 paddedName as NSString, Int64(result.inputBytes), Int64(result.compressedBytes),
                 percent, encodeMs, decodeMs))
}

func readBoundedFile(_ path: String) throws -> [UInt8] {
    // O_NONBLOCK lets us reject pipes/devices after open without hanging.
    // fstat checks the opened descriptor, not a racy pre-open path snapshot.
    let fd = path.withCString { open($0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC) }
    guard fd >= 0 else {
        throw ProbeError.failed("Cannot open local input: \(String(cString: strerror(errno)))")
    }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
        throw ProbeError.failed("Local input must be a regular file")
    }
    guard info.st_size <= Int64(maximumInputBytes) else {
        throw ProbeError.failed("Limit input to 64 MiB to bound temporary memory usage")
    }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
    var data = Data()
    // Read at most the limit plus one byte, even if a live log grows after
    // fstat. The local contents and the source path are never emitted.
    while data.count <= maximumInputBytes {
        let wanted = min(64 * 1024, maximumInputBytes + 1 - data.count)
        guard let chunk = try handle.read(upToCount: wanted), !chunk.isEmpty else { break }
        data.append(chunk)
    }
    guard data.count <= maximumInputBytes else {
        throw ProbeError.failed("Limit input to 64 MiB to bound temporary memory usage")
    }
    var after = stat()
    guard fstat(fd, &after) == 0, after.st_size == info.st_size,
          Int64(data.count) == info.st_size,
          after.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec,
          after.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec else {
        throw ProbeError.failed("Local input changed while being read; use a stable copy")
    }
    return Array(data)
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
    let usage = "Usage: swift hack/modern-compression-probe.swift [--json] [--file /path/to/log.jsonl]"
    var args = ArraySlice(CommandLine.arguments.dropFirst())
    var jsonOutput = false
    var localFile: String?
    while let argument = args.popFirst() {
        switch argument {
        case "--json" where !jsonOutput:
            jsonOutput = true
        case "--file" where localFile == nil:
            guard let path = args.popFirst() else { throw ProbeError.failed(usage) }
            localFile = path
        case "--help", "-h":
            print(usage)
            exit(EXIT_SUCCESS)
        default:
            throw ProbeError.failed(usage)
        }
    }
    let inputs: [(name: String, bytes: [UInt8])]
    if let path = localFile {
        // Local-only optional input, NEVER used by CI or uploaded to artifacts.
        inputs = [("local file (read-only)", try readBoundedFile(path))]
    } else {
        let chatLog = sampleChatLog()
        inputs = [
            ("generated JSONL-style chat log", chatLog),
            ("generated high-entropy bytes", sampleHighEntropy()),
            ("one-byte input", [0x61]),
            ("64 KiB + 1 byte input", Array(chatLog.prefix(65_537))),
        ]
    }
    var results = [CodecResult]()
    for (name, input) in inputs {
        guard !input.isEmpty else { throw ProbeError.failed("Input is empty") }
        guard input.count <= maximumInputBytes else {
            throw ProbeError.failed("Limit input to 64 MiB to bound temporary memory usage")
        }
        if !jsonOutput {
            print("Input: \(name)")
            print("Codec       Input (B)  Output (B)    Size    Encode ms  Decode ms  Verified")
        }
        if #available(macOS 27, *) {
            for codec in modernCodecs() {
                let result = try run(codec, inputName: name, input: input)
                results.append(result)
                if !jsonOutput { printResult(result) }
            }
        }
    }
    if jsonOutput {
        #if arch(arm64)
        let architecture = "arm64"
        #elseif arch(x86_64)
        let architecture = "x86_64"
        #else
        let architecture = "unknown"
        #endif
        let report = ProbeReport(architecture: architecture, results: results)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        print(String(decoding: try encoder.encode(report), as: UTF8.self))
    } else {
        print("Buffer round-trips passed. No APFS/decmpfs filesystem support is implied or tested.")
        print("Timings are single-run smoke measurements, not a performance benchmark.")
    }
} catch {
    fputs("Probe failed: \(error)\n", stderr)
    exit(EXIT_FAILURE)
}
