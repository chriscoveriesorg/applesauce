//! Criterion speed/ratio benchmarks for Apple's public in-memory codecs.
//! Never writes `decmpfs` attributes or touches a user's filesystem data.
// The runner is macOS-only. Linux can still compile/check the harness without
// triggering dozens of unused warnings from deliberately inactive cases.
#![cfg_attr(not(target_os = "macos"), allow(unused))]

mod fixtures;

use applesauce_core::apple_buffer::{Codec, Scratch};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fixtures::{generate, Workload};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};

const CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Suite {
    Smoke,
    Standard,
    Extended,
}

impl Suite {
    fn from_env() -> Self {
        match std::env::var("APPLESAUCE_BENCH_SUITE").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("standard") => Self::Standard,
            Ok("smoke") => Self::Smoke,
            Ok("extended") => Self::Extended,
            other => panic!(
                "unknown APPLESAUCE_BENCH_SUITE {other:?}; expected smoke, standard or extended"
            ),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Standard => "standard",
            Self::Extended => "extended",
        }
    }

    fn workloads(self) -> &'static [Workload] {
        match self {
            Self::Smoke => &[Workload::ChatJsonl, Workload::Entropy],
            Self::Standard | Self::Extended => &Workload::ALL,
        }
    }

    fn sizes(self) -> &'static [usize] {
        match self {
            Self::Smoke => &[65_536],
            Self::Standard => &[4_096, 65_536, 1_048_576, 8_388_608],
            Self::Extended => &[4_096, 65_536, 1_048_576, 8_388_608],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    Whole,
    Independent64k,
}

impl Layout {
    const fn name(self) -> &'static str {
        match self {
            Self::Whole => "whole",
            Self::Independent64k => "independent-64k",
        }
    }

    const fn chunk_bytes(self, size: usize) -> usize {
        match self {
            Self::Whole => size,
            Self::Independent64k => CHUNK_BYTES,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    ApiManaged,
    ReusedScratch,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::ApiManaged => "api-managed",
            Self::ReusedScratch => "reused-scratch",
        }
    }

    fn scratch(self, codec: Codec) -> Option<Scratch> {
        match self {
            Self::ApiManaged => None,
            Self::ReusedScratch => Some(codec.reusable_scratch().expect("Apple scratch query")),
        }
    }
}

fn modes(suite: Suite, workload: Workload, size: usize, layout: Layout) -> &'static [Mode] {
    // Standard uses scratch reuse throughout. API-owned scratch is compared on
    // representative workloads; Extended compares both modes on every case.
    if suite == Suite::Smoke
        || suite == Suite::Extended
        || (layout == Layout::Whole
            && (size == 65_536 || size == 1_048_576)
            && matches!(workload, Workload::ChatJsonl | Workload::Entropy))
    {
        &[Mode::ApiManaged, Mode::ReusedScratch]
    } else {
        &[Mode::ReusedScratch]
    }
}

fn encode(codec: Codec, scratch: &mut Option<Scratch>, dst: &mut [u8], src: &[u8]) -> usize {
    match scratch {
        Some(scratch) => scratch.encode_into(dst, src).expect("reusable encode"),
        None => codec.encode_into(dst, src).expect("API-managed encode"),
    }
}

fn decode(codec: Codec, scratch: &mut Option<Scratch>, dst: &mut [u8], src: &[u8]) -> usize {
    match scratch {
        Some(scratch) => scratch.decode_into(dst, src).expect("reusable decode"),
        None => codec.decode_into(dst, src).expect("API-managed decode"),
    }
}

struct Prepared {
    encoded: Vec<Vec<u8>>,
    encoded_bytes: usize,
    scratch_sizes: Option<(usize, usize)>,
}

fn prepare(codec: Codec, mode: Mode, pieces: &[&[u8]]) -> Prepared {
    let mut scratch = mode.scratch(codec);
    let sizes = scratch.as_ref().map(Scratch::sizes);
    let mut encoded = Vec::with_capacity(pieces.len());
    let mut encoded_bytes = 0;
    for piece in pieces {
        let mut buffer = vec![0; piece.len() * 2 + 65_536];
        let count = encode(codec, &mut scratch, &mut buffer, piece);
        buffer.truncate(count);
        // The overflow guard matters: compression_decode_buffer can return
        // exactly the destination length even if it truncated the output.
        let mut decoded = vec![0; piece.len() + 1];
        let decoded_len = decode(codec, &mut scratch, &mut decoded, &buffer);
        assert_eq!(
            decoded_len,
            piece.len(),
            "{} truncated output",
            codec.name()
        );
        assert_eq!(&decoded[..decoded_len], *piece, "{} mismatch", codec.name());
        encoded_bytes += count;
        encoded.push(buffer);
    }
    Prepared {
        encoded,
        encoded_bytes,
        scratch_sizes: sizes,
    }
}

fn manifest_writer() -> Option<BufWriter<File>> {
    let path = std::env::var_os("APPLESAUCE_BENCH_MANIFEST")?;
    let mut writer = BufWriter::new(File::create(path).expect("create benchmark manifest"));
    writeln!(
        writer,
        "schema_version,fixture_version,suite,workload,input_bytes,input_sha256,layout,chunk_bytes,codec,scratch_mode,encode_scratch_bytes,decode_scratch_bytes,encoded_bytes,encoded_over_input_ratio,verified_roundtrip"
    )
    .expect("write manifest header");
    Some(writer)
}

fn benchmark(c: &mut Criterion) {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = c;
        eprintln!("modern_buffer requires Apple's macOS Compression.framework");
    }

    #[cfg(target_os = "macos")]
    benchmark_macos(c);
}

#[cfg(target_os = "macos")]
fn benchmark_macos(c: &mut Criterion) {
    let suite = Suite::from_env();
    let mut manifest = manifest_writer();
    for &workload in suite.workloads() {
        for &size in suite.sizes() {
            let input = generate(workload, size);
            let mut hash = String::with_capacity(64);
            for byte in Sha256::digest(&input).iter() {
                write!(&mut hash, "{byte:02x}").expect("format SHA-256");
            }
            let layouts: &[Layout] = if size >= 1_048_576 {
                &[Layout::Whole, Layout::Independent64k]
            } else {
                &[Layout::Whole]
            };
            for &layout in layouts {
                let pieces: Vec<&[u8]> = input.chunks(layout.chunk_bytes(size)).collect();
                let group_name = format!(
                    "apple-buffer/{}/{}/{}/{}",
                    suite.name(),
                    size,
                    workload.name(),
                    layout.name()
                );
                let mut group = c.benchmark_group(group_name);
                group.throughput(Throughput::Bytes(input.len() as u64));
                for codec in Codec::ALL {
                    if !codec.is_supported() {
                        eprintln!("skip {}: unavailable on this OS", codec.name());
                        continue;
                    }
                    for &mode in modes(suite, workload, size, layout) {
                        let prepared = prepare(codec, mode, &pieces);
                        if let Some(writer) = manifest.as_mut() {
                            let (encode_scratch, decode_scratch) = prepared
                                .scratch_sizes
                                .map_or(("n/a".to_owned(), "n/a".to_owned()), |(e, d)| {
                                    (e.to_string(), d.to_string())
                                });
                            writeln!(
                                writer,
                                "1,{},{},{},{},{},{},{},{},{},{},{},{},{:.9},true",
                                fixtures::VERSION,
                                suite.name(),
                                workload.name(),
                                input.len(),
                                hash,
                                layout.name(),
                                layout.chunk_bytes(size),
                                codec.name(),
                                mode.name(),
                                encode_scratch,
                                decode_scratch,
                                prepared.encoded_bytes,
                                prepared.encoded_bytes as f64 / input.len() as f64,
                            )
                            .expect("write benchmark manifest");
                            writer.flush().expect("flush benchmark manifest");
                        }

                        let bench_name = format!("{}-{}", codec.name(), mode.name());
                        let mut encoded_outputs: Vec<Vec<u8>> = pieces
                            .iter()
                            .map(|piece| vec![0; piece.len() * 2 + 65_536])
                            .collect();
                        let mut encode_scratch = mode.scratch(codec);
                        group.bench_function(BenchmarkId::new(&bench_name, "encode"), |b| {
                            b.iter(|| {
                                let mut bytes = 0;
                                for (&src, dst) in pieces.iter().zip(encoded_outputs.iter_mut()) {
                                    bytes += encode(
                                        codec,
                                        &mut encode_scratch,
                                        black_box(dst.as_mut_slice()),
                                        black_box(src),
                                    );
                                }
                                black_box(bytes)
                            });
                        });

                        let mut decoded_outputs: Vec<Vec<u8>> = pieces
                            .iter()
                            .map(|piece| vec![0; piece.len() + 1])
                            .collect();
                        let mut decode_scratch = mode.scratch(codec);
                        group.bench_function(BenchmarkId::new(&bench_name, "decode"), |b| {
                            b.iter(|| {
                                let mut bytes = 0;
                                for (src, dst) in
                                    prepared.encoded.iter().zip(decoded_outputs.iter_mut())
                                {
                                    bytes += decode(
                                        codec,
                                        &mut decode_scratch,
                                        black_box(dst.as_mut_slice()),
                                        black_box(src.as_slice()),
                                    );
                                }
                                black_box(bytes)
                            });
                        });
                    }
                }
                group.finish();
            }
        }
    }
}

criterion_group!(modern_codecs, benchmark);
criterion_main!(modern_codecs);
