use crate::progress::{ProgressBarWriter, ProgressBars, Verbosity};
use applesauce::compressor::Kind;
use applesauce::Stats;
use cfg_if::cfg_if;
use clap::Parser;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufWriter, LineWriter, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::{fmt, io};
use tracing::metadata::LevelFilter;
use tracing_chrome::ChromeLayerBuilder;
use tracing_subscriber::fmt::time;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

mod archive;
mod codecs;
mod progress;
mod size_report;

#[derive(Debug, clap::Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output chrome tracing format to a file
    ///
    /// The passed file can be passed to chrome at chrome://tracing
    #[arg(long, global(true))]
    chrome_tracing: Option<PathBuf>,

    #[arg(short, long, global(true), action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, global(true), action = clap::ArgAction::Count, conflicts_with = "verbose")]
    quiet: u8,
}

impl Cli {
    fn verbosity(&self) -> Verbosity {
        let verbosity = self.verbose as i8 - self.quiet as i8;
        match verbosity {
            ..=-1 => Verbosity::Quiet,
            0 => Verbosity::Normal,
            1.. => Verbosity::Verbose,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    /// Compress files
    Compress(Compress),

    /// Decompress files
    Decompress(Decompress),

    /// Get info about compression for file(s)
    Info(Info),

    /// Report buffer codecs and native filesystem writers separately (read-only)
    Capabilities(codecs::Capabilities),

    /// Compare Apple buffer codecs on generated data or one file (read-only)
    BenchmarkCodecs(codecs::Benchmark),

    /// Encode, verify, or restore separate Raven/Mesh cold-file archives (not native APFS)
    Archive(archive::Args),
}

#[derive(Debug, clap::Args)]
struct Decompress {
    /// Paths to recursively decompress
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Decompress manually, rather than allowing the OS to do decompression
    ///
    /// This may be useful to do decompression from an older OS version which can't
    /// natively read the compressed file
    #[arg(long)]
    manual: bool,

    /// Verify restored bytes against the compressed source's logical contents before replacing it
    ///
    /// Requires the OS to read the compressed source, including with --manual.
    /// If kernel decoding is unavailable, verification fails without replacing the source.
    #[arg(long)]
    verify: bool,
}

#[derive(Debug, clap::Args)]
struct Compress {
    /// Paths to recursively compress
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// The compression level to use
    #[arg(
        short, long,
        default_value_t = 5,
        value_parser = clap::value_parser!(u32).range(1..=12)
    )]
    level: u32,

    /// The minimum compression ratio
    ///
    /// Files will be skipped if they compress to a larger size than this ratio
    /// of the original size
    ///
    /// A value of 0.0 (or less) will skip all files
    /// A value of 1.0 will only skip files which cannot be compressed at all
    /// Values greater than 1.0 are valid, and will allow forcing compression to
    /// be used even if it results in a larger file
    #[arg(
        short = 'r',
        long,
        default_value_t = 0.95,
        value_parser = parse_finite_ratio
    )]
    minimum_compression_ratio: f64,

    /// The type of compression to use
    #[arg(short, long, value_enum, default_value_t = Compression::default())]
    compression: Compression,

    /// Verify that the compressed file has the same contents as the original before replacing it
    ///
    /// This is an extra safety check to ensure that the compressed file is exactly the same as the
    /// original file.
    #[arg(long)]
    verify: bool,

    /// Fully encode input without modifying it and report projected native allocation
    ///
    /// Dry-run never creates compression temp files, attributes, flags, trace files,
    /// or timestamp resetters. Every eligible regular file is encoded in full.
    #[arg(long, conflicts_with = "verify")]
    dry_run: bool,

    /// Emit JSON: the versioned dry-run projection with --dry-run, otherwise the
    /// actual-storage report after compression
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct Info {
    /// Paths to inspect
    ///
    /// Info will be reported for each path
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Emit the versioned actual-storage JSON report
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Copy, Clone, clap::ValueEnum, PartialEq, Eq)]
enum Compression {
    /// Measure bounded per-file native samples and select a stable codec.
    Auto,
    #[cfg(all(feature = "lzbitmap", target_os = "macos"))]
    Lzbitmap,
    #[cfg(feature = "lzfse")]
    Lzfse,
    #[cfg(feature = "zlib")]
    Zlib,
    #[cfg(feature = "lzvn")]
    Lzvn,
}

impl From<Compression> for Kind {
    fn from(c: Compression) -> Self {
        match c {
            Compression::Auto => unreachable!("auto codec is selected per input file"),
            #[cfg(all(feature = "lzbitmap", target_os = "macos"))]
            Compression::Lzbitmap => Kind::Lzbitmap,
            #[cfg(feature = "zlib")]
            Compression::Zlib => Kind::Zlib,
            #[cfg(feature = "lzfse")]
            Compression::Lzfse => Kind::Lzfse,
            #[cfg(feature = "lzvn")]
            Compression::Lzvn => Kind::Lzvn,
        }
    }
}

// Using cfg_if is much easier than using drive and specifying the default as an attribute on a derive
#[allow(clippy::derivable_impls)]
impl Default for Compression {
    fn default() -> Self {
        cfg_if! {
            if #[cfg(feature = "lzfse")] {
                Self::Lzfse
            } else if #[cfg(feature = "zlib")] {
                Self::Zlib
            } else if #[cfg(feature = "lzvn")] {
                Self::Lzvn
            } else {
                compile_error!("At least one compression type must be configured")
            }
        }
    }
}

fn chrome_tracing_file(path: Option<&Path>) -> Option<impl io::Write> {
    let path = path?;

    let file = match File::create(path) {
        Ok(file) => file,
        Err(e) => {
            // Tracing isn't set up yet, log the old-fashioned way
            eprintln!("Unable to open chrome layer: {e}");
            return None;
        }
    };

    Some(BufWriter::new(file))
}

fn parse_finite_ratio(value: &str) -> Result<f64, String> {
    let ratio = value
        .parse::<f64>()
        .map_err(|error| format!("invalid compression ratio: {error}"))?;
    if ratio.is_finite() {
        Ok(ratio)
    } else {
        Err("compression ratio must be finite".to_owned())
    }
}

fn main() {
    let cli = Cli::parse();

    if let Commands::Compress(args) = &cli.command {
        if args.dry_run {
            if args.compression == Compression::Auto {
                eprintln!(
                    "applesauce: --compression auto is not yet supported by the full-encoding dry-run projection"
                );
                std::process::exit(1);
            }
            if cli.chrome_tracing.is_some() {
                eprintln!("applesauce: --chrome-tracing is not supported with --dry-run");
                std::process::exit(1);
            }
            let kind: Kind = args.compression.into();
            if !kind.supported() {
                eprintln!("applesauce: {kind} is unavailable in this build or on this host");
                std::process::exit(1);
            }
            let report = applesauce::dry_run::analyze(
                &args.paths,
                kind,
                args.minimum_compression_ratio,
                args.level,
            );
            if args.json {
                let stdout = io::stdout();
                let mut output = stdout.lock();
                if let Err(error) = serde_json::to_writer_pretty(&mut output, &report)
                    .map_err(io::Error::other)
                    .and_then(|()| writeln!(output))
                {
                    eprintln!("applesauce: unable to write dry-run report: {error}");
                    std::process::exit(1);
                }
            } else {
                display_dry_run(&report);
            }
            if !report.complete {
                std::process::exit(1);
            }
            return;
        }
    }

    // Info is read-only, including when tracing was requested globally.
    if let Commands::Info(args) = &cli.command {
        if cli.chrome_tracing.is_some() {
            eprintln!("applesauce: --chrome-tracing is not supported with info");
            std::process::exit(1);
        }
        let report = size_report::analyze(&args.paths);
        if let Err(error) = size_report::display(&report, args.json) {
            eprintln!("applesauce: unable to write size report: {error}");
            std::process::exit(1);
        }
        if !report.complete {
            std::process::exit(1);
        }
        return;
    }

    // Diagnostics never start the file-mutating pipeline or create trace files.
    let diagnostic = match &cli.command {
        Commands::Capabilities(_) | Commands::BenchmarkCodecs(_) | Commands::Archive(_)
            if cli.chrome_tracing.is_some() =>
        {
            Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--chrome-tracing is not supported for codec and archive commands",
            )))
        }
        Commands::Capabilities(args) => Some(codecs::capabilities(args)),
        Commands::BenchmarkCodecs(args) => Some(codecs::benchmark(args)),
        Commands::Archive(args) => Some(archive::run(args)),
        _ => None,
    };
    if let Some(result) = diagnostic {
        if let Err(error) = result {
            eprintln!("applesauce: {error}");
            std::process::exit(1);
        }
        return;
    }
    let verbosity = cli.verbosity();

    let mut _chrome_guard = None;
    let chrome_file = chrome_tracing_file(cli.chrome_tracing.as_deref());
    let chrome_layer: Option<_> = chrome_file.map(|f| {
        let (layer, guard) = ChromeLayerBuilder::new()
            .writer(f)
            .include_args(true)
            .build();
        _chrome_guard = Some(guard);
        layer
    });

    let progress_bars = ProgressBars::new(cli.verbosity());
    let fmt_writer = Mutex::new(LineWriter::new(ProgressBarWriter::new(
        progress_bars.multi_progress().clone(),
        io::stderr(),
    )));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_timer(time::uptime())
        .with_writer(fmt_writer)
        .with_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::OFF.into())
                .from_env_lossy(),
        );

    tracing_subscriber::registry()
        .with(chrome_layer)
        .with(fmt_layer)
        .init();

    match cli.command {
        Commands::Capabilities(_) | Commands::BenchmarkCodecs(_) | Commands::Archive(_) => {
            unreachable!("handled before tracing")
        }
        Commands::Compress(Compress {
            paths,
            compression,
            minimum_compression_ratio,
            level,
            verify,
            dry_run: false,
            json,
        }) => {
            let kind = (compression != Compression::Auto).then(|| Kind::from(compression));
            if let Some(kind) = kind {
                if !kind.supported() {
                    eprintln!("applesauce: {kind} is unavailable in this build or on this host");
                    std::process::exit(1);
                }
            }
            // Experimental native encoders must verify before atomic replacement.
            let verify = verify || kind == Some(Kind::Lzbitmap);

            if kind.is_some_and(|kind| kind != Kind::Zlib) && level != 5 {
                tracing::warn!("Compression level is ignored for non-zlib compression");
            }

            let mut compressor = applesauce::FileCompressor::new();
            let _stats = if let Some(kind) = kind {
                compressor.recursive_compress(
                    paths.iter().map(Path::new),
                    kind,
                    minimum_compression_ratio,
                    level,
                    &progress_bars,
                    verify,
                )
            } else {
                compressor.recursive_compress_auto(
                    paths.iter().map(Path::new),
                    minimum_compression_ratio,
                    level,
                    &progress_bars,
                    verify,
                )
            };
            progress_bars.finish();
            let mut report = size_report::analyze(&paths);
            report.operation_errors(progress_bars.errors());
            if json || verbosity >= Verbosity::Normal {
                if let Err(error) = size_report::display(&report, json) {
                    eprintln!("applesauce: unable to write size report: {error}");
                    std::process::exit(1);
                }
            }
            if !report.complete {
                std::process::exit(1);
            }
        }
        Commands::Compress(Compress { dry_run: true, .. }) => {
            unreachable!("dry-run handled before tracing")
        }
        Commands::Decompress(Decompress {
            paths,
            manual,
            verify,
        }) => {
            let mut compressor = applesauce::FileCompressor::new();
            let stats = compressor.recursive_decompress(
                paths.iter().map(Path::new),
                manual,
                &progress_bars,
                verify,
            );
            progress_bars.finish();
            tracing::info!("Finished decompressing");
            if verbosity >= Verbosity::Normal {
                display_stats(&stats, false);
            }
        }
        Commands::Info(_) => unreachable!("info handled before tracing"),
    }
}

fn display_dry_run(report: &applesauce::dry_run::Report) {
    for path in &report.paths {
        let logical = optional_bytes(path.logical_size_bytes);
        let current = optional_bytes(path.current_allocation_bytes);
        let projected = optional_bytes(path.projected_native_allocation_bytes);
        let upper = optional_bytes(path.projected_native_allocation_upper_bound_bytes);
        let raw = optional_bytes(path.raw_compressed_bytes);
        let decmpfs = optional_bytes(path.decmpfs_xattr_bytes);
        let resource_fork = optional_bytes(path.resource_fork_bytes);
        let allocation_block = optional_bytes(path.allocation_block_bytes);
        let storage = path.storage.unwrap_or("none");
        let savings = path
            .savings_bytes
            .map_or_else(|| "unknown".to_owned(), |value| format!("{value:+}"));
        println!(
            "{}: codec={} would_compress={} reason={} logical={} current_allocation={} allocation_block={} raw_compressed={} decmpfs_xattr={} resource_fork={} storage={} projected_native_allocation={} conservative_bound={} savings_bytes={}",
            path.path.display,
            path.codec,
            path.would_compress,
            path.reason,
            logical,
            current,
            allocation_block,
            raw,
            decmpfs,
            resource_fork,
            storage,
            projected,
            upper,
            savings,
        );
        if let Some(error) = &path.error {
            println!("  error[{}]: {}", error.kind, error.message);
        }
    }
    for directory in &report.directories {
        println!(
            "{}: directory logical={} current_allocation={} projected_native_allocation={} conservative_bound={} savings_bytes={} files={} would_compress={} skipped={} hard_links_excluded={} complete={}",
            directory.path.display,
            optional_bytes(directory.totals.logical_size_bytes),
            optional_bytes(directory.totals.current_allocation_bytes),
            optional_bytes(directory.totals.projected_native_allocation_bytes),
            optional_bytes(directory.totals.projected_native_allocation_upper_bound_bytes),
            directory
                .totals
                .savings_bytes
                .map_or_else(|| "unknown".to_owned(), |value| format!("{value:+}")),
            directory.totals.files_included,
            directory.totals.files_would_compress,
            directory.totals.files_skipped,
            directory.totals.hard_links_excluded,
            directory.totals.complete,
        );
        if let Some(error) = &directory.error {
            println!("  error[{}]: {}", error.kind, error.message);
        }
    }
    println!(
        "TOTAL: logical={} current_allocation={} projected_native_allocation={} conservative_bound={} savings_bytes={} files={} would_compress={} skipped={} hard_links_excluded={} complete={}",
        optional_bytes(report.totals.logical_size_bytes),
        optional_bytes(report.totals.current_allocation_bytes),
        optional_bytes(report.totals.projected_native_allocation_bytes),
        optional_bytes(report.totals.projected_native_allocation_upper_bound_bytes),
        report
            .totals
            .savings_bytes
            .map_or_else(|| "unknown".to_owned(), |value| format!("{value:+}")),
        report.totals.files_included,
        report.totals.files_would_compress,
        report.totals.files_skipped,
        report.totals.hard_links_excluded,
        report.complete,
    );
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |bytes| bytes.to_string())
}

pub fn display_stats(stats: &Stats, compress_mode: bool) {
    println!("Total Files: {}", stats.files.load(Ordering::Relaxed));
    let total_file_sizes = stats.total_file_sizes.load(Ordering::Relaxed);

    let compressed_count_start = stats.compressed_file_count_start.load(Ordering::Relaxed);
    let compressed_count_final = stats.compressed_file_count_final.load(Ordering::Relaxed);
    if compress_mode {
        println!(
            "New Files Compressed: {} ({} total compressed)",
            compressed_count_final.saturating_sub(compressed_count_start),
            compressed_count_final,
        );
    } else {
        print!(
            "Files Decompressed: {}",
            compressed_count_start.saturating_sub(compressed_count_final),
        );
        if compressed_count_final != 0 {
            println!(" ({compressed_count_final} remaining compressed)");
        } else {
            println!();
        }
    }

    let compressed_size_start = stats.compressed_size_start.load(Ordering::Relaxed);
    let compressed_size_final = stats.compressed_size_final.load(Ordering::Relaxed);
    println!(
        "Starting Size (total filesize): {} ({})",
        format_bytes(total_file_sizes),
        total_file_sizes,
    );
    println!(
        "Starting Size (on disk):        {} ({})",
        format_bytes(compressed_size_start),
        compressed_size_start,
    );
    println!(
        "Final Size (on disk):           {} ({})",
        format_bytes(compressed_size_final),
        compressed_size_final,
    );
    println!(
        "Savings:                        {:.1}%",
        stats.compression_change_portion() * 100.0
    );
}

#[must_use]
pub fn truncate_path(path: &Path, width: usize) -> PathBuf {
    let mut segments: Vec<_> = path.components().collect();
    let mut total_len = path.as_os_str().len();

    if total_len <= width || segments.len() <= 1 {
        return path.to_owned();
    }

    let mut first = true;
    while total_len > width && segments.len() > 1 {
        // Bias toward the beginning for even counts
        let mid = (segments.len() - 1) / 2;
        let segment = segments[mid];
        if matches!(segment, Component::RootDir | Component::Prefix(_)) {
            break;
        }

        total_len -= segment.as_os_str().len();

        if first {
            // First time, we're just replacing the segment with an ellipsis
            // like `aa/bb/cc/dd` -> `aa/…/cc/dd`, so we remove the
            // segment, and add an ellipsis char
            total_len += 1;
            first = false;
        } else {
            // Other times, we're removing the segment, and a slash
            // `aa/…/cc/dd` -> `aa/…/dd`
            total_len -= 1;
        }
        segments.remove(mid);
    }
    segments.insert(segments.len() / 2, Component::Normal(OsStr::new("…")));
    let mut path = PathBuf::with_capacity(total_len);
    for segment in segments {
        path.push(segment);
    }

    path
}

fn format_bytes(byte_size: u64) -> impl fmt::Display {
    humansize::SizeFormatter::new(byte_size, humansize::BINARY)
}

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[test]
fn minimal_truncate() {
    let orig_path = Path::new("abcd");
    // Trying to truncate smaller than a single segment does nothing
    assert_eq!(truncate_path(orig_path, 1), PathBuf::from("abcd"));

    let orig_path = Path::new("1234/5678");
    // Trying to truncate removes the first element
    assert_eq!(truncate_path(orig_path, 1), PathBuf::from("…/5678"));
    let orig_path = Path::new("/1234/5678");
    // Never truncate the leading /
    assert_eq!(truncate_path(orig_path, 1), PathBuf::from("/…/5678"));

    let orig_path = Path::new("/1234/5678");
    assert_eq!(truncate_path(orig_path, 1), PathBuf::from("/…/5678"));

    let orig_path = Path::new("/1234/5678/90123/4567");
    assert_eq!(truncate_path(orig_path, 1), PathBuf::from("/…/4567"));
}

#[test]
fn no_truncation() {
    let orig_path = Path::new("abcd");
    assert_eq!(truncate_path(orig_path, 4), PathBuf::from(orig_path));

    let orig_path = Path::new("a/b/c/d");
    assert_eq!(truncate_path(orig_path, 7), PathBuf::from(orig_path));
    let orig_path = Path::new("/a/b/c/d");
    assert_eq!(truncate_path(orig_path, 8), PathBuf::from(orig_path));
}

#[test]
fn truncate_single_segment() {
    let orig_path = Path::new("a/bbbbbbbbbb/c");
    assert_eq!(truncate_path(orig_path, 5), PathBuf::from("a/…/c"));
}

#[test]
fn command_check() {
    use clap::CommandFactory;
    Cli::command().debug_assert()
}

#[test]
fn native_auto_codec_is_explicit_and_does_not_change_defaults() {
    let parsed =
        Cli::try_parse_from(["applesauce", "compress", "--compression", "auto", "fixture"])
            .unwrap();
    let Commands::Compress(compress) = parsed.command else {
        panic!("expected compress");
    };
    assert_eq!(compress.compression, Compression::Auto);
    let parsed = Cli::try_parse_from(["applesauce", "compress", "fixture"]).unwrap();
    let Commands::Compress(compress) = parsed.command else {
        panic!("expected compress");
    };
    assert_ne!(compress.compression, Compression::Auto);
}

#[test]
fn compression_ratio_parser_accepts_only_finite_values() {
    assert_eq!(parse_finite_ratio("-1").unwrap(), -1.0);
    assert_eq!(parse_finite_ratio("0").unwrap(), 0.0);
    assert_eq!(parse_finite_ratio("1.5").unwrap(), 1.5);
    for value in ["NaN", "nan", "inf", "+inf", "-inf"] {
        assert!(parse_finite_ratio(value).is_err(), "accepted {value}");
    }
}
