//! Explicit cold-file archive operations for Apple's public Raven/Mesh buffers.
//! These commands create *separate files*. They never write decmpfs metadata,
//! replace a source log, or claim transparent native APFS compression.

use applesauce_core::apple_buffer::Codec;
use applesauce_core::cold_archive::{write_archive, ArchiveReader, MAX_READ_BYTES};
use clap::{Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

const DEFAULT_CHUNK_BYTES: usize = 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 128 * 1024;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Create a verified Raven/Mesh archive alongside the unchanged source
    Create {
        source: PathBuf,
        output: PathBuf,
        #[arg(long, value_enum, default_value = "lzraven")]
        codec: ArchiveCodec,
        /// Power-of-two chunk size, from 65536 to 8388608 bytes
        #[arg(long, default_value_t = DEFAULT_CHUNK_BYTES)]
        chunk_bytes: usize,
        /// Permit an archive that consumes at least as many bytes as the source
        #[arg(long)]
        allow_expansion: bool,
    },
    /// Inspect ASCF metadata without decoding or modifying files
    Info { archive: PathBuf },
    /// Verify every chunk and the whole-file digest without changing files
    Verify { archive: PathBuf },
    /// Restore logical bytes into a new file, keeping the archive intact
    Extract {
        archive: PathBuf,
        output: PathBuf,
        /// Decode only the verified logical byte range OFFSET:LENGTH
        #[arg(long, value_parser = parse_logical_range)]
        range: Option<(u64, u64)>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ArchiveCodec {
    Lzraven,
    Lzmesh,
}

impl From<ArchiveCodec> for Codec {
    fn from(value: ArchiveCodec) -> Self {
        match value {
            ArchiveCodec::Lzraven => Self::Lzraven,
            ArchiveCodec::Lzmesh => Self::Lzmesh,
        }
    }
}

pub fn run(args: &Args) -> io::Result<()> {
    match &args.action {
        Action::Create {
            source,
            output,
            codec,
            chunk_bytes,
            allow_expansion,
        } => create(
            source,
            output,
            (*codec).into(),
            *chunk_bytes,
            *allow_expansion,
        ),
        Action::Info { archive } => info(archive),
        Action::Verify { archive } => verify(archive),
        Action::Extract { archive, output, range } => match range {
            Some(range) => extract_range(archive, output, *range),
            None => extract(archive, output),
        },
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse_logical_range(input: &str) -> Result<(u64, u64), String> {
    let (offset, length) = input
        .split_once(':')
        .ok_or_else(|| "expected OFFSET:LENGTH in decimal bytes".to_string())?;
    let offset = offset
        .parse::<u64>()
        .map_err(|_| "range OFFSET must be an unsigned decimal integer".to_string())?;
    let length = length
        .parse::<u64>()
        .map_err(|_| "range LENGTH must be an unsigned decimal integer".to_string())?;
    offset
        .checked_add(length)
        .ok_or_else(|| "logical range overflows u64".to_string())?;
    Ok((offset, length))
}

fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("archive input must be a regular file"));
    }
    Ok(file)
}

fn unused_output(output: &Path) -> io::Result<()> {
    match fs::symlink_metadata(output) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "output exists; select a new filename",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn staging(output: &Path) -> io::Result<NamedTempFile> {
    unused_output(output)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    NamedTempFile::new_in(parent)
}

fn hash_reader(source: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; HASH_BUFFER_BYTES];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

fn create(
    source_path: &Path,
    output: &Path,
    codec: Codec,
    chunk_bytes: usize,
    allow_expansion: bool,
) -> io::Result<()> {
    let mut source = open_regular(source_path)?;
    let before = source.metadata()?;
    if before.len() == 0 {
        return Err(invalid("archive source must be nonempty"));
    }
    if !codec.is_supported() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{} buffer API is unavailable on this host", codec.name()),
        ));
    }
    let mut temporary = staging(output)?;
    let stats = write_archive(
        &mut source,
        temporary.as_file_mut(),
        before.len(),
        codec,
        chunk_bytes,
    )?;
    if !allow_expansion && stats.archive_bytes >= stats.logical_size {
        return Err(invalid(
            "archive would not save space; use --allow-expansion to keep it",
        ));
    }

    // Re-read the same opened source to reject in-place changes while encoding.
    source.rewind()?;
    if hash_reader(&mut source)? != stats.logical_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source changed while building the archive",
        ));
    }
    let after = source.metadata()?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source metadata changed while building the archive",
        ));
    }

    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    {
        let mut reader = ArchiveReader::open(temporary.as_file_mut())?;
        reader.verify_all()?;
        if reader.logical_sha256() != stats.logical_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staged archive digest differs from source",
            ));
        }
    }
    if temporary.as_file().metadata()?.len() != stats.archive_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged archive size changed after verification",
        ));
    }
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    println!(
        "{} archive: {} -> {} bytes ({:.1}% saved); original unchanged",
        codec.name(),
        stats.logical_size,
        stats.archive_bytes,
        100.0 * (1.0 - stats.archive_bytes as f64 / stats.logical_size as f64)
    );
    Ok(())
}

fn info(path: &Path) -> io::Result<()> {
    let source = open_regular(path)?;
    let archive_bytes = source.metadata()?.len();
    // Header/index validation is portable and does not initialize decoder scratch.
    let reader = ArchiveReader::open(source)?;
    println!(
        "ASCF {}: {} logical bytes, {} archive bytes, {} chunks of {} bytes, SHA-256 {} (metadata only)",
        reader.codec().name(),
        reader.logical_size(),
        archive_bytes,
        reader.chunk_count(),
        reader.chunk_size(),
        hex_digest(reader.logical_sha256())
    );
    Ok(())
}

fn verify(path: &Path) -> io::Result<()> {
    let source = open_regular(path)?;
    let mut reader = ArchiveReader::open(source)?;
    reader.verify_all()?;
    println!(
        "Verified {} archive; {} logical bytes, SHA-256 {}",
        reader.codec().name(),
        reader.logical_size(),
        hex_digest(reader.logical_sha256())
    );
    Ok(())
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn extract(archive_path: &Path, output: &Path) -> io::Result<()> {
    unused_output(output)?;
    let mut source = open_regular(archive_path)?;
    let before = source.metadata()?;
    let mut reader = ArchiveReader::open(&mut source)?;
    // A corrupt archive should not even create a staging destination.
    reader.verify_all()?;
    let logical_size = reader.logical_size();
    let digest = reader.logical_sha256();
    let mut temporary = staging(output)?;
    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    while offset < logical_size {
        let bytes_to_read = (logical_size - offset).min(MAX_READ_BYTES as u64) as usize;
        let bytes = reader.read_range(offset, bytes_to_read)?;
        hash.update(&bytes);
        temporary.write_all(&bytes)?;
        offset += bytes.len() as u64;
    }
    let written_digest: [u8; 32] = hash.finalize().into();
    if written_digest != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "restored bytes do not match archive SHA-256",
        ));
    }
    drop(reader);
    let after = source.metadata()?;
    if after.len() != before.len() || after.modified().ok() != before.modified().ok() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive source changed during extraction",
        ));
    }
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary.as_file_mut().rewind()?;
    if hash_reader(temporary.as_file_mut())? != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged restore failed read-back verification",
        ));
    }
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    println!("Restored {} verified bytes into a new file", logical_size);
    Ok(())
}

/// Restore a slice without decoding unrelated chunks. The header/index
/// is validated on open, and each touched chunk gets its own SHA-256 check.
/// Publication is atomic and the output is verified through a second read.
/// This does not claim whole-file verification of untouched logical chunks.
fn extract_range(archive_path: &Path, output: &Path, range: (u64, u64)) -> io::Result<()> {
    unused_output(output)?;
    let mut source = open_regular(archive_path)?;
    let before = source.metadata()?;
    let mut reader = ArchiveReader::open(&mut source)?;
    let (start, length) = range;
    let end = start.checked_add(length).ok_or_else(|| invalid("logical range overflows u64"))?;
    if start > reader.logical_size() || end > reader.logical_size() {
        return Err(invalid("logical range exceeds archive size"));
    }
    let mut temporary = staging(output)?;
    let mut digest = Sha256::new();
    let mut offset = start;
    while offset < end {
        let count = (end - offset).min(MAX_READ_BYTES as u64) as usize;
        let bytes = reader.read_range(offset, count)?;
        digest.update(&bytes);
        temporary.write_all(&bytes)?;
        offset += bytes.len() as u64;
    }
    drop(reader);
    let after = source.metadata()?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive source changed during range extraction",
        ));
    }
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary.as_file_mut().rewind()?;
    let output_digest = hash_reader(temporary.as_file_mut())?;
    let range_digest: [u8; 32] = digest.finalize().into();
    if output_digest != range_digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged logical range failed read-back verification",
        ));
    }
    temporary.persist_noclobber(output).map_err(|error| error.error)?;
    println!(
        "Restored verified logical range {}:{} into a new file; range SHA-256 {}",
        start, length, hex_digest(range_digest)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn archive_cli_accepts_only_explicit_buffer_codecs() {
        assert!(crate::Cli::try_parse_from([
            "applesauce",
            "archive",
            "create",
            "input",
            "output",
            "--codec",
            "lzraven",
        ])
        .is_ok());
        assert!(crate::Cli::try_parse_from([
            "applesauce",
            "archive",
            "create",
            "input",
            "output",
            "--codec",
            "lzmesh",
        ])
        .is_ok());
        assert!(crate::Cli::try_parse_from([
            "applesauce",
            "archive",
            "create",
            "input",
            "output",
            "--codec",
            "lzvn",
        ])
        .is_err());
    }

    #[test]
    fn range_parser_enforces_unsigned_bounds_and_explicit_syntax() {
        for bad in ["", "1", "-1:2", "1:-2", "1:2:3", "1:", ":2", "1.0:2", "18446744073709551615:1"] {
            assert!(parse_logical_range(bad).is_err(), "accepted {bad:?}");
            assert!(crate::Cli::try_parse_from([
                "applesauce", "archive", "extract", "src.ascf", "slice", "--range", bad
            ]).is_err());
        }
        assert_eq!(parse_logical_range("0:0").unwrap(), (0, 0));
        assert_eq!(parse_logical_range("65535:131073").unwrap(), (65535, 131073));
        assert!(crate::Cli::try_parse_from(["applesauce", "archive", "info", "source.ascf"]).is_ok());
        assert!(crate::Cli::try_parse_from([
            "applesauce", "archive", "extract", "source.ascf", "slice", "--range", "65535:131073"
        ]).is_ok());
    }

    #[test]
    fn existing_targets_and_symlink_sources_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input.jsonl");
        fs::write(&source, b"hello").unwrap();
        let output = dir.path().join("output.ascf");
        fs::write(&output, b"KEEP").unwrap();
        assert_eq!(
            unused_output(&output).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(output).unwrap(), b"KEEP");
        #[cfg(unix)]
        {
            let symlink = dir.path().join("input-link");
            std::os::unix::fs::symlink(source, &symlink).unwrap();
            assert!(open_regular(&symlink).is_err());
        }
    }

    #[test]
    fn generated_raven_mesh_create_verify_extract_roundtrip() {
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            if !codec.is_supported() {
                // Portable CI tests the interface; macOS 27 CI exercises both.
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("input.jsonl");
            let archive = dir.path().join("cold.ascf");
            let restored = dir.path().join("restored.jsonl");
            let payload =
                b"{\"role\":\"user\",\"content\":\"repeatable generated archive test\"}\n"
                    .repeat(4500);
            fs::write(&source, &payload).unwrap();
            create(&source, &archive, codec, 64 * 1024, false).unwrap();
            verify(&archive).unwrap();
            extract(&archive, &restored).unwrap();
            assert_eq!(fs::read(&source).unwrap(), payload);
            assert_eq!(fs::read(&restored).unwrap(), payload);
            info(&archive).unwrap();
            let part = dir.path().join("partial.jsonl");
            extract_range(&archive, &part, (65_535, 131_073)).unwrap();
            assert_eq!(fs::read(&part).unwrap(), payload[65_535..196_608]);
            let empty = dir.path().join("empty-range");
            extract_range(&archive, &empty, (payload.len() as u64, 0)).unwrap();
            assert_eq!(fs::read(&empty).unwrap(), b"");
            let past_end = dir.path().join("outside-range");
            assert!(extract_range(&archive, &past_end, (payload.len() as u64, 1)).is_err());
            assert!(!past_end.exists());
            // A broken tail chunk must not produce any output.
            let mut corrupt = fs::read(&archive).unwrap();
            *corrupt.last_mut().unwrap() ^= 1;
            fs::write(&archive, corrupt).unwrap();
            // Header/index remains parseable although payload authentication fails.
            info(&archive).unwrap();
            let refused = dir.path().join("refused.jsonl");
            assert!(extract(&archive, &refused).is_err());
            assert!(!refused.exists());
            let bad_slice = dir.path().join("corrupt-range");
            assert!(extract_range(&archive, &bad_slice, (payload.len() as u64 - 5, 5)).is_err());
            assert!(!bad_slice.exists());
        }
    }

    #[test]
    fn verify_rejects_non_archive_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let text = dir.path().join("notes.txt");
        fs::write(&text, b"plain text, not an archive").unwrap();
        assert_eq!(
            verify(&text).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(info(&text).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let no_output = dir.path().join("bad-range");
        assert!(extract_range(&text, &no_output, (0, 1)).is_err());
        assert!(!no_output.exists());
        // A magic-correct but truncated prefix is also refused.
        let short = dir.path().join("short.ascf");
        fs::write(&short, b"ASCF0001").unwrap();
        assert!(verify(&short).is_err());
        assert!(extract(&short, &dir.path().join("out")).is_err());
    }

    #[test]
    fn create_rejects_empty_and_directory_sources_without_output() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        fs::write(&empty, b"").unwrap();
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            let output = dir.path().join(format!("empty-{}.ascf", codec.name()));
            assert!(create(&empty, &output, codec, 64 * 1024, false).is_err());
            assert!(!output.exists());
            let output = dir.path().join(format!("dir-{}.ascf", codec.name()));
            assert!(create(dir.path(), &output, codec, 64 * 1024, false).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn create_rejects_out_of_range_chunk_sizes() {
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            if !codec.is_supported() {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("input");
            fs::write(&source, b"chunk-size guard input").unwrap();
            for bad in [32 * 1024usize, 100_000, 96 * 1024, 16 * 1024 * 1024] {
                let output = dir.path().join(format!("bad-{bad}.ascf"));
                assert!(
                    create(&source, &output, codec, bad, false).is_err(),
                    "chunk size {bad} must be refused"
                );
                assert!(!output.exists());
            }
        }
    }

    #[test]
    fn incompressible_source_needs_allow_expansion_flag() {
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            if !codec.is_supported() {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("noise");
            let mut state = 0x243f_6a88_85a3_08d3u64;
            let noise: Vec<u8> = (0..80_000)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            fs::write(&source, &noise).unwrap();
            let output = dir.path().join("noise.ascf");
            // An archive that cannot shrink the data is refused by default.
            assert!(create(&source, &output, codec, 64 * 1024, false).is_err());
            assert!(!output.exists());
            // The explicit opt-in flag keeps it.
            create(&source, &output, codec, 64 * 1024, true).unwrap();
            assert!(output.exists());
        }
    }
}
