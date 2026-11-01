//! Read-only codec diagnostics. The native writer allowlist is independent
//! from public buffer availability, including when used by companion tools.
use applesauce::apple_buffer::{self, Codec, MAX_BUFFER_BYTES};
use applesauce::compressor::Kind;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CodecName {
    Zlib,
    Lzvn,
    Lzfse,
    Lzbitmap,
    Lzmesh,
    Lzraven,
}

impl CodecName {
    const ALL: [Self; 6] = [
        Self::Zlib,
        Self::Lzvn,
        Self::Lzfse,
        Self::Lzbitmap,
        Self::Lzmesh,
        Self::Lzraven,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Lzvn => "lzvn",
            Self::Lzfse => "lzfse",
            Self::Lzbitmap => "lzbitmap",
            Self::Lzmesh => "lzmesh",
            Self::Lzraven => "lzraven",
        }
    }

    fn buffer(self) -> Option<Codec> {
        Some(match self {
            Self::Zlib => Codec::Zlib,
            Self::Lzfse => Codec::Lzfse,
            Self::Lzbitmap => Codec::Lzbitmap,
            Self::Lzmesh => Codec::Lzmesh,
            Self::Lzraven => Codec::Lzraven,
            Self::Lzvn => return None,
        })
    }

    fn native_kind(self) -> Option<Kind> {
        Some(match self {
            Self::Zlib => Kind::Zlib,
            Self::Lzvn => Kind::Lzvn,
            Self::Lzfse => Kind::Lzfse,
            Self::Lzbitmap => Kind::Lzbitmap,
            Self::Lzmesh | Self::Lzraven => return None,
        })
    }

    fn native_cli_enabled(self) -> bool {
        // Cargo can unify a dependency's codec feature without enabling the
        // corresponding CLI value. Attestation must match this binary's
        // selectable `compress -c` variants, not just its linked core library.
        match self {
            Self::Zlib => cfg!(feature = "zlib"),
            Self::Lzvn => cfg!(feature = "lzvn"),
            Self::Lzfse => cfg!(feature = "lzfse"),
            Self::Lzbitmap => cfg!(all(feature = "lzbitmap", target_os = "macos")),
            Self::Lzmesh | Self::Lzraven => false,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Capabilities {
    /// Emit the versioned machine-readable integration contract
    #[arg(long)]
    json: bool,

    /// Exit nonzero unless this exact codec has an enabled native writer
    #[arg(long, value_enum)]
    require_native: Option<CodecName>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Benchmark {
    /// Read one regular file (max 64 MiB); never modify or upload it
    #[arg(long)]
    file: Option<PathBuf>,

    /// Select buffer codecs (default: all public buffer codecs)
    #[arg(long, value_enum, value_delimiter = ',')]
    codec: Vec<CodecName>,

    /// Repeat each trial and report mean encode/decode time
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=10))]
    iterations: u8,

    /// Emit JSON without including source paths or source text
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Host {
    os: &'static str,
    arch: &'static str,
    macos_version: Option<String>,
    macos_build: Option<String>,
}

impl Host {
    fn current() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            macos_version: apple_buffer::macos_version().map(|v| v.to_string()),
            macos_build: apple_buffer::macos_build(),
        }
    }
}

#[derive(Serialize)]
struct BufferCapability {
    available: bool,
    verified_roundtrip: bool,
    reason: String,
}

#[derive(Serialize)]
struct NativeCapability {
    writable: bool,
    decmpfs_types: Vec<u32>,
    experimental: bool,
    reason: String,
}

#[derive(Serialize)]
struct CodecCapability {
    name: CodecName,
    apple_buffer: BufferCapability,
    native_decmpfs: NativeCapability,
}

#[derive(Serialize)]
struct CapabilityReport {
    schema_version: u32,
    applesauce_version: &'static str,
    host: Host,
    codecs: Vec<CodecCapability>,
}

fn buffer_capability(name: CodecName) -> BufferCapability {
    let result = name.buffer().map_or_else(
        || {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no public Apple buffer selector for LZVN; native implementation is separate",
            ))
        },
        Codec::verify_roundtrip,
    );
    match result {
        Ok(()) => BufferCapability { available: true, verified_roundtrip: true,
            reason: "generated buffer round trip passed; this does not establish native filesystem support".into() },
        Err(error) => BufferCapability { available: false, verified_roundtrip: false, reason: error.to_string() },
    }
}

fn native_capability(name: CodecName) -> NativeCapability {
    let Some(kind) = name.native_kind() else {
        return NativeCapability { writable: false, decmpfs_types: Vec::new(), experimental: true,
            reason: "no verified native decmpfs type/framing mapping; buffer support does not authorize file compression".into() };
    };
    let types = match kind {
        Kind::Zlib => vec![3, 4],
        Kind::Lzvn => vec![7, 8],
        Kind::Lzfse => vec![11, 12],
        Kind::Lzbitmap => vec![13, 14],
    };
    let writable = name.native_cli_enabled() && kind.supported();
    let experimental = kind == Kind::Lzbitmap;
    let reason = if !writable {
        "native writer disabled in this build or unavailable on this host"
    } else if experimental {
        "opt-in experimental LZBitmap writer; requires a compatible target volume and backup; readback verification is forced by the CLI"
    } else {
        "native writer enabled; target volume and per-file eligibility are checked when compressing"
    };
    NativeCapability {
        writable,
        decmpfs_types: types,
        experimental,
        reason: reason.into(),
    }
}

pub(crate) fn capabilities(args: &Capabilities) -> io::Result<()> {
    let report = CapabilityReport {
        schema_version: 1,
        applesauce_version: env!("CARGO_PKG_VERSION"),
        host: Host::current(),
        codecs: CodecName::ALL
            .into_iter()
            .map(|name| CodecCapability {
                name,
                apple_buffer: buffer_capability(name),
                native_decmpfs: native_capability(name),
            })
            .collect(),
    };
    if args.json {
        print_json(&report)?;
    } else {
        println!("Codec       Apple buffer round trip   Native transparent writer");
        for codec in &report.codecs {
            println!(
                "{:<11} {:<25} {}",
                codec.name.name(),
                if codec.apple_buffer.available {
                    "passed"
                } else {
                    "unavailable"
                },
                if codec.native_decmpfs.writable {
                    "enabled"
                } else {
                    "unavailable"
                }
            );
            if !codec.apple_buffer.available {
                println!("  buffer: {}", codec.apple_buffer.reason);
            }
            println!("  native: {}", codec.native_decmpfs.reason);
        }
    }
    if let Some(required) = args.require_native {
        let codec = report
            .codecs
            .iter()
            .find(|c| c.name == required)
            .expect("all codec names are reported");
        if !codec.native_decmpfs.writable || codec.native_decmpfs.decmpfs_types.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{} cannot be used for transparent file compression: {}",
                    required.name(),
                    codec.native_decmpfs.reason
                ),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Layout {
    WholeBuffer,
    #[serde(rename = "independent-64k")]
    Independent64k,
}

impl Layout {
    fn name(self) -> &'static str {
        match self {
            Self::WholeBuffer => "whole-buffer",
            Self::Independent64k => "independent-64k",
        }
    }
}

#[derive(Serialize)]
struct BenchmarkResult {
    codec: CodecName,
    input: &'static str,
    layout: Layout,
    status: &'static str,
    input_bytes: usize,
    encoded_bytes: Option<usize>,
    encoded_ratio: Option<f64>,
    encode_ms: Option<f64>,
    decode_ms: Option<f64>,
    verified_roundtrip: bool,
    reason: Option<String>,
}

#[derive(Serialize)]
struct BenchmarkReport {
    schema_version: u32,
    applesauce_version: &'static str,
    host: Host,
    iterations: u8,
    note: &'static str,
    results: Vec<BenchmarkResult>,
}

fn measure(
    codec: Codec,
    input: &[u8],
    layout: Layout,
    iterations: u8,
) -> io::Result<(usize, f64, f64)> {
    let block_size = match layout {
        Layout::WholeBuffer => input.len(),
        Layout::Independent64k => 65536,
    };
    let mut encode_time = std::time::Duration::ZERO;
    let mut decode_time = std::time::Duration::ZERO;
    let mut encoded_size = 0;
    for iteration in 0..iterations {
        let mut total = 0;
        for block in input.chunks(block_size) {
            let started = Instant::now();
            let encoded = codec.encode(block)?;
            encode_time += started.elapsed();
            let started = Instant::now();
            let decoded = codec.decode_exact(&encoded, block.len())?;
            decode_time += started.elapsed();
            if decoded != block {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "round-trip byte mismatch",
                ));
            }
            total += encoded.len();
        }
        if iteration == 0 {
            encoded_size = total;
        } else if total != encoded_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded size changed across identical trials",
            ));
        }
    }
    let scale = 1000.0 / f64::from(iterations);
    Ok((
        encoded_size,
        encode_time.as_secs_f64() * scale,
        decode_time.as_secs_f64() * scale,
    ))
}

pub(crate) fn benchmark(args: &Benchmark) -> io::Result<()> {
    let inputs = match &args.file {
        Some(path) => vec![("file", read_bounded_file(path)?)],
        None => generated_inputs(),
    };
    let selected = if args.codec.is_empty() {
        CodecName::ALL
            .into_iter()
            .filter(|c| c.buffer().is_some())
            .collect()
    } else {
        args.codec.clone()
    };
    let mut results = Vec::new();
    let mut failed = false;
    for name in selected {
        let capability = buffer_capability(name);
        for (label, input) in &inputs {
            for layout in [Layout::WholeBuffer, Layout::Independent64k] {
                let mut result = BenchmarkResult {
                    codec: name,
                    input: label,
                    layout,
                    status: "unavailable",
                    input_bytes: input.len(),
                    encoded_bytes: None,
                    encoded_ratio: None,
                    encode_ms: None,
                    decode_ms: None,
                    verified_roundtrip: false,
                    reason: None,
                };
                if !capability.available {
                    result.reason = Some(capability.reason.clone());
                    // New APIs may be absent on an older host. Explicit selections,
                    // and failures on an advertised API, fail the command.
                    failed |=
                        !args.codec.is_empty() || name.buffer().is_some_and(Codec::is_supported);
                } else {
                    match measure(
                        name.buffer().expect("available buffer has a selector"),
                        input,
                        layout,
                        args.iterations,
                    ) {
                        Ok((size, encode_ms, decode_ms)) => {
                            result.status = "ok";
                            result.encoded_bytes = Some(size);
                            result.encoded_ratio = Some(size as f64 / input.len() as f64);
                            result.encode_ms = Some(encode_ms);
                            result.decode_ms = Some(decode_ms);
                            result.verified_roundtrip = true;
                        }
                        Err(error) => {
                            failed = true;
                            result.status = "error";
                            result.reason = Some(error.to_string());
                        }
                    }
                }
                results.push(result);
            }
        }
    }
    let report = BenchmarkReport { schema_version: 1, applesauce_version: env!("CARGO_PKG_VERSION"),
        host: Host::current(), iterations: args.iterations,
        note: "Read-only raw buffer benchmark, not APFS disk savings. Independent 64 KiB buffers model dictionary resets only; no decmpfs framing or raw-block fallback. Times include buffer allocation and API-managed scratch. Source paths/text are omitted.", results };
    if args.json {
        print_json(&report)?;
    } else {
        println!("{}", report.note);
        println!("Codec      Input                    Layout            Encoded/input  Encode ms  Decode ms");
        for result in &report.results {
            if let (Some(ratio), Some(encode), Some(decode)) =
                (result.encoded_ratio, result.encode_ms, result.decode_ms)
            {
                println!(
                    "{:<10} {:<24} {:<17} {:>12.3} {:>10.2} {:>10.2}",
                    result.codec.name(),
                    result.input,
                    result.layout.name(),
                    ratio,
                    encode,
                    decode
                );
            } else {
                println!(
                    "{} / {} / {}: {}",
                    result.codec.name(),
                    result.input,
                    result.layout.name(),
                    result.reason.as_deref().unwrap_or("failed")
                );
            }
        }
    }
    if failed {
        Err(io::Error::other(
            "one or more requested buffer trials failed; see the report",
        ))
    } else {
        Ok(())
    }
}

fn print_json(value: &impl Serialize) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value).map_err(io::Error::other)?;
    writeln!(out)
}

fn read_bounded(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "benchmark input must be 1 byte through 64 MiB",
        ));
    }
    Ok(bytes)
}

// A same-size in-place rewrite can restore its mtime. Unix ctime (inode
// status-change time, not creation time) gives us an additional read-only
// check before trusting benchmark data from a supposedly stable copy.
fn metadata_stable(before: &std::fs::Metadata, after: &std::fs::Metadata) -> io::Result<bool> {
    Ok(before.len() == after.len()
        && before.modified()? == after.modified()?
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec())
}

fn read_bounded_file(path: &Path) -> io::Result<Vec<u8>> {
    // O_NONBLOCK prevents a raced-in FIFO from hanging before fstat. O_NOFOLLOW
    // refuses a final-component symlink. No write mode is ever requested.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_BUFFER_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--file requires a nonempty regular file of at most 64 MiB",
        ));
    }
    let bytes = read_bounded(&mut file, MAX_BUFFER_BYTES)?;
    let after = file.metadata()?;
    if !metadata_stable(&before, &after)? || bytes.len() as u64 != before.len() {
        return Err(io::Error::other(
            "input changed while being read; benchmark a stable copy",
        ));
    }
    Ok(bytes)
}

fn generated_inputs() -> Vec<(&'static str, Vec<u8>)> {
    let mut jsonl = Vec::with_capacity(1024 * 1024);
    for index in 0..8192 {
        writeln!(jsonl, "{{\"session\":{},\"role\":\"assistant\",\"event\":{},\"message\":\"Generated agent log for codec benchmarking; no private conversation data.\"}}", index / 64, index).expect("Vec write");
    }
    let mut state = 0x9a3c_115e_b2d7_648fu64;
    let noise = (0..256 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    vec![
        ("synthetic-jsonl", jsonl),
        ("synthetic-high-entropy", noise),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_buffer_support_never_grants_native_writes() {
        for name in [CodecName::Lzraven, CodecName::Lzmesh] {
            let native = native_capability(name);
            assert!(!native.writable);
            assert!(native.decmpfs_types.is_empty());
        }
    }

    #[test]
    fn integration_schema_separates_capabilities() {
        let item = CodecCapability {
            name: CodecName::Lzraven,
            apple_buffer: BufferCapability {
                available: true,
                verified_roundtrip: true,
                reason: "test".into(),
            },
            native_decmpfs: native_capability(CodecName::Lzraven),
        };
        let json = serde_json::to_value(item).unwrap();
        assert_eq!(json["name"], "lzraven");
        assert_eq!(json["apple_buffer"]["available"], true);
        assert_eq!(json["native_decmpfs"]["writable"], false);
        assert_eq!(
            json["native_decmpfs"]["decmpfs_types"],
            serde_json::json!([])
        );
    }

    #[test]
    fn unavailable_cli_variants_cannot_attest_native_support() {
        for name in CodecName::ALL {
            if !name.native_cli_enabled() {
                assert!(!native_capability(name).writable);
            }
        }
    }

    #[test]
    fn benchmark_layout_labels_are_stable() {
        assert_eq!(
            serde_json::to_value(Layout::WholeBuffer).unwrap(),
            "whole-buffer"
        );
        assert_eq!(
            serde_json::to_value(Layout::Independent64k).unwrap(),
            "independent-64k"
        );
    }

    #[test]
    fn bounded_reader_rejects_empty_and_growing_input() {
        assert!(read_bounded(&b""[..], 4).is_err());
        assert_eq!(read_bounded(&b"abcd"[..], 4).unwrap(), b"abcd");
        assert!(read_bounded(&b"abcde-more-data"[..], 4).is_err());
    }

    #[test]
    fn benchmark_metadata_detects_rewrite_with_restored_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stable.jsonl");
        std::fs::write(&path, b"modified test data").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let original_mtime = before.modified().unwrap();

        // Keep file length and mtime unchanged, like a writer that attempts
        // to replace data while a benchmark reads an existing file.
        std::thread::sleep(std::time::Duration::from_millis(25));
        std::fs::write(&path, b"replaced test data").unwrap();
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();
        let after = std::fs::metadata(&path).unwrap();

        assert_eq!(before.len(), after.len());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        assert!(!metadata_stable(&before, &after).unwrap());
    }

    #[test]
    fn benchmark_only_reads_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.jsonl");
        std::fs::write(&path, b"generated test data").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(read_bounded_file(&path).unwrap(), before);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(read_bounded_file(dir.path()).is_err());
        let link = dir.path().join("symlink");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_bounded_file(&link).is_err());
    }
}
