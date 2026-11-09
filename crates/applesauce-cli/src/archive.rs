//! Explicit cold-file archive operations for Apple's public Raven/Mesh buffers.
//! These commands create *separate files*. They never write decmpfs metadata,
//! replace a source log, or claim transparent native APFS compression.

use applesauce_core::apple_buffer::Codec;
use applesauce_core::cold_archive::{
    validate_archive_geometry, write_archive, ArchiveReader, MAX_READ_BYTES,
};
use clap::{Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

const DEFAULT_CHUNK_BYTES: usize = 1024 * 1024;
const AUTO_SAMPLE_BYTES: usize = 64 * 1024;
const AUTO_SAMPLE_WINDOWS: usize = 3;
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
        /// Choose Raven, Mesh or explicitly sample both (--codec auto).
        /// Auto prefers Mesh unless Raven saves at least 20% of sample bytes.
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
    Auto,
}

impl ArchiveCodec {
    fn selected(self) -> Option<Codec> {
        match self {
            Self::Lzraven => Some(Codec::Lzraven),
            Self::Lzmesh => Some(Codec::Lzmesh),
            Self::Auto => None,
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
            codec.selected(),
            *chunk_bytes,
            *allow_expansion,
        ),
        Action::Info { archive } => info(archive),
        Action::Verify { archive } => verify(archive),
        Action::Extract {
            archive,
            output,
            range,
        } => match range {
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
    // Reject obvious devices, FIFOs, sockets and links before opening them.
    // This reduces unwanted device-side effects and lets callers fail early.
    // The O_NOFOLLOW/O_NONBLOCK flags and descriptor metadata check below
    // remain mandatory: the pathname can change after this preflight.
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(invalid("archive input must be a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK is required before checking metadata: opening an input
        // FIFO for reading would otherwise wait indefinitely for a writer.
        // Ordinary regular-file reads remain blocking as usual.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("archive input must be a regular file"));
    }
    Ok(file)
}

// Check that the pathname still identifies the opened input before publishing
// a separate archive or restoration. A replaced path may have identical size
// and timestamps while the held descriptor still reads the old inode.
// Snapshot captured at open is the trust anchor. Comparing two live fstat
// results misses in-place rewrites when the writer restores the original mtime.
fn same_archive_source_snapshot(before: &fs::Metadata, now: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    now.file_type().is_file()
        && before.dev() == now.dev()
        && before.ino() == now.ino()
        && before.nlink() == now.nlink()
        && before.len() == now.len()
        && before.mtime() == now.mtime()
        && before.mtime_nsec() == now.mtime_nsec()
        && before.ctime() == now.ctime()
        && before.ctime_nsec() == now.ctime_nsec()
}

fn ensure_open_path_identity(path: &Path, opened: &File, before: &fs::Metadata) -> io::Result<()> {
    // Nonblocking opens prevent a substituted FIFO from stalling publication.
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive source pathname is no longer a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let current = options.open(path)?;
    if !same_archive_source_snapshot(before, &opened.metadata()?)
        || !same_archive_source_snapshot(before, &current.metadata()?)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive input changed since open; refusing publication",
        ));
    }
    Ok(())
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

/// Explicit opt-in: inspect at most 64 KiB total across the beginning,
/// middle and end of large files. A first-block-only trial can misclassify
/// a heterogeneous JSONL log. These are independently encoded windows,
/// so account for each window's actual codec overhead in the comparison.
/// No sample implies native APFS decoder support.
fn prefer_auto_codec(raven_bytes: usize, mesh_bytes: usize) -> Codec {
    // Compare exact cross-products: saturating usize multiplication makes
    // two very large lengths both equal usize::MAX and may select Raven even
    // when it saves no bytes. u128 handles every possible usize input.
    if (raven_bytes as u128) * 100 <= (mesh_bytes as u128) * 80 {
        Codec::Lzraven
    } else {
        Codec::Lzmesh
    }
}

fn auto_sample_windows(source_len: u64) -> Vec<(u64, usize)> {
    let total = source_len.min(AUTO_SAMPLE_BYTES as u64) as usize;
    // For small files preserve the original contiguous trial. On large files,
    // divide the same bounded budget into three nonoverlapping windows.
    if source_len < (AUTO_SAMPLE_BYTES * AUTO_SAMPLE_WINDOWS) as u64 {
        return vec![(0, total)];
    }
    let first = total / AUTO_SAMPLE_WINDOWS;
    let middle = first;
    let last = total - first - middle;
    vec![
        (0, first),
        ((source_len - middle as u64) / 2, middle),
        (source_len - last as u64, last),
    ]
}

fn read_auto_samples(source: &mut File, source_len: u64) -> io::Result<Vec<Vec<u8>>> {
    let mut samples = Vec::new();
    for (offset, length) in auto_sample_windows(source_len) {
        source.seek(SeekFrom::Start(offset))?;
        let mut sample = vec![0_u8; length];
        source.read_exact(&mut sample)?;
        samples.push(sample);
    }
    // The normal writer must always begin at logical byte zero.
    source.rewind()?;
    Ok(samples)
}

/// Use one Apple scratch allocation per codec, plus one bounded pair of
/// encoded/decoded buffers for all windows. Raven's scratch request can be
/// much larger than a 21 KiB window, so allocating on every trial is wasteful.
/// The identical byte lengths and guarded round-trip preserve the selection
/// policy independently of Apple's API-managed scratch path.
fn auto_encoded_lengths(samples: &[Vec<u8>]) -> io::Result<[usize; 2]> {
    let max_len = samples
        .iter()
        .map(Vec::len)
        .max()
        .filter(|length| *length > 0)
        .ok_or_else(|| invalid("auto codec samples must be nonempty"))?;
    let capacity = max_len
        .checked_mul(2)
        .and_then(|size| size.checked_add(64 * 1024))
        .ok_or_else(|| invalid("auto codec sample capacity overflow"))?;
    let mut encoded = vec![0_u8; capacity];
    let mut decoded = vec![0_u8; max_len + 1];
    let mut encoded_lengths = [0_usize; 2];

    for (index, codec) in [Codec::Lzraven, Codec::Lzmesh].into_iter().enumerate() {
        let mut scratch = codec.reusable_scratch()?;
        for sample in samples {
            if sample.is_empty() {
                return Err(invalid("auto codec samples must be nonempty"));
            }
            let encoded_limit = sample.len() * 2 + 64 * 1024;
            let count = scratch.encode_into(&mut encoded[..encoded_limit], sample)?;
            let decoded_len =
                scratch.decode_into(&mut decoded[..sample.len() + 1], &encoded[..count])?;
            if decoded_len != sample.len() || decoded[..decoded_len] != sample[..] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auto codec sample failed exact-byte round-trip",
                ));
            }
            encoded_lengths[index] = encoded_lengths[index]
                .checked_add(count)
                .ok_or_else(|| invalid("auto codec sample length overflow"))?;
        }
    }
    Ok(encoded_lengths)
}

fn sample_auto_codec(source: &mut File, source_len: u64) -> io::Result<Codec> {
    for codec in [Codec::Lzraven, Codec::Lzmesh] {
        if !codec.is_supported() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "auto requires both lzraven and lzmesh buffer APIs",
            ));
        }
    }
    let samples = read_auto_samples(source, source_len)?;
    let encoded_lengths = auto_encoded_lengths(&samples)?;
    let selected = prefer_auto_codec(encoded_lengths[0], encoded_lengths[1]);
    eprintln!(
        "archive --codec auto: {} sampled bytes across {} window(s), raven {} bytes, mesh {} bytes; selected {}",
        samples.iter().map(Vec::len).sum::<usize>(),
        samples.len(),
        encoded_lengths[0],
        encoded_lengths[1],
        selected.name()
    );
    Ok(selected)
}

fn create(
    source_path: &Path,
    output: &Path,
    requested_codec: Option<Codec>,
    chunk_bytes: usize,
    allow_expansion: bool,
) -> io::Result<()> {
    let mut source = open_regular(source_path)?;
    let before = source.metadata()?;
    if before.len() == 0 {
        return Err(invalid("archive source must be nonempty"));
    }
    // Validate the entire archive geometry before auto sampling invokes either
    // expensive Apple codec. The writer uses this exact core policy again.
    validate_archive_geometry(before.len(), chunk_bytes)?;
    // Refuse an occupied output before codec initialization or sampling; the
    // later staging check still protects against a pathname race.
    unused_output(output)?;
    let codec = match requested_codec {
        Some(codec) => codec,
        None => sample_auto_codec(&mut source, before.len())?,
    };
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
    ensure_open_path_identity(source_path, &source, &before)?;
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
    ensure_open_path_identity(archive_path, &source, &before)?;
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
    let end = start
        .checked_add(length)
        .ok_or_else(|| invalid("logical range overflows u64"))?;
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
    ensure_open_path_identity(archive_path, &source, &before)?;
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    println!(
        "Restored verified logical range {}:{} into a new file; range SHA-256 {}",
        start,
        length,
        hex_digest(range_digest)
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

    #[cfg(unix)]
    #[test]
    fn archive_source_path_replacement_refused_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("held-original");
        let replacement = dir.path().join("replacement");
        fs::write(&source, b"AAAA").unwrap();
        fs::write(&replacement, b"BBBB").unwrap();
        let mut held = open_regular(&source).unwrap();
        let scanned = held.metadata().unwrap();
        ensure_open_path_identity(&source, &held, &scanned).unwrap();
        let original_modified = held.metadata().unwrap().modified().unwrap();
        OpenOptions::new()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(original_modified))
            .unwrap();
        assert_eq!(
            held.metadata().unwrap().modified().unwrap(),
            fs::metadata(&replacement).unwrap().modified().unwrap()
        );

        // Matching length and modified time, but a distinct inode: the
        // original metadata-only check would accept this swapped pathname.
        fs::rename(&replacement, &source).unwrap();
        assert_eq!(
            ensure_open_path_identity(&source, &held, &scanned)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut bytes = [0_u8; 4];
        held.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"AAAA");

        // A removed or symlink-substituted pathname must also fail closed.
        fs::remove_file(&source).unwrap();
        assert_eq!(
            ensure_open_path_identity(&source, &held, &scanned)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        std::os::unix::fs::symlink(dir.path().join("held-original"), &source).unwrap();
        assert!(ensure_open_path_identity(&source, &held, &scanned).is_err());
        fs::remove_file(&source).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let fifo_path = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_path is a live, NUL-terminated CString in an isolated
        // temporary test directory, and mkfifo only reads its pathname bytes.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        // O_NONBLOCK is necessary even after the symlink_metadata precheck:
        // the pathname could change to a FIFO between preflight and open.
        assert!(ensure_open_path_identity(&source, &held, &scanned).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn archive_publication_guard_refuses_same_inode_rewrite_with_restored_mtime() {
        use std::os::unix::fs::MetadataExt;
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive-source");
        fs::write(&path, b"AAAA").unwrap();
        let held = open_regular(&path).unwrap();
        let before = held.metadata().unwrap();
        ensure_open_path_identity(&path, &held, &before).unwrap();

        // A same-length, same-inode rewrite followed by resetting mtime
        // previously passed the two-live-metadata publication check.
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&path, b"BBBB").unwrap();
        File::open(&path)
            .unwrap()
            .set_modified(before.modified().unwrap())
            .unwrap();
        let changed = held.metadata().unwrap();
        assert_eq!(before.dev(), changed.dev());
        assert_eq!(before.ino(), changed.ino());
        assert_eq!(before.len(), changed.len());
        assert_eq!(before.modified().unwrap(), changed.modified().unwrap());
        assert!(
            before.ctime() != changed.ctime() || before.ctime_nsec() != changed.ctime_nsec(),
            "test filesystem failed to record changed inode ctime"
        );
        assert_eq!(
            ensure_open_path_identity(&path, &held, &before)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fs::read(&path).unwrap(), b"BBBB");

        // Hardlink changes are rejected even when the data is untouched.
        let baseline = held.metadata().unwrap();
        fs::hard_link(&path, dir.path().join("second-name")).unwrap();
        assert_ne!(baseline.nlink(), held.metadata().unwrap().nlink());
        assert_eq!(
            ensure_open_path_identity(&path, &held, &baseline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn auto_choice_is_explicit_and_uses_a_deterministic_threshold() {
        assert!(crate::Cli::try_parse_from([
            "applesauce",
            "archive",
            "create",
            "input",
            "output",
            "--codec",
            "auto",
        ])
        .is_ok());
        assert_eq!(ArchiveCodec::Lzraven.selected(), Some(Codec::Lzraven));
        assert_eq!(ArchiveCodec::Lzmesh.selected(), Some(Codec::Lzmesh));
        assert_eq!(ArchiveCodec::Auto.selected(), None);
        assert_eq!(prefer_auto_codec(80, 100), Codec::Lzraven);
        assert_eq!(prefer_auto_codec(81, 100), Codec::Lzmesh);
        assert_eq!(prefer_auto_codec(100, 80), Codec::Lzmesh);
        assert_eq!(prefer_auto_codec(usize::MAX, 1), Codec::Lzmesh);
        assert_eq!(prefer_auto_codec(usize::MAX, usize::MAX), Codec::Lzmesh);
        assert_eq!(prefer_auto_codec(usize::MAX - 1, usize::MAX), Codec::Lzmesh);
        assert_eq!(
            prefer_auto_codec(usize::MAX / 2, usize::MAX),
            Codec::Lzraven
        );
        // Round exactly at the threshold, including the largest usize values.
        let multiple = usize::MAX / 100;
        assert_eq!(
            prefer_auto_codec(multiple * 80, multiple * 100),
            Codec::Lzraven
        );
        assert_eq!(
            prefer_auto_codec(multiple * 80 + 1, multiple * 100),
            Codec::Lzmesh
        );
    }

    #[test]
    fn auto_sampling_is_bounded_and_covers_heterogeneous_large_files() {
        assert_eq!(auto_sample_windows(1), vec![(0, 1)]);
        assert_eq!(
            auto_sample_windows((AUTO_SAMPLE_BYTES * AUTO_SAMPLE_WINDOWS - 1) as u64),
            vec![(0, AUTO_SAMPLE_BYTES)]
        );
        let windows = auto_sample_windows((AUTO_SAMPLE_BYTES * 4) as u64);
        assert_eq!(windows.len(), AUTO_SAMPLE_WINDOWS);
        assert_eq!(
            windows.iter().map(|(_, length)| length).sum::<usize>(),
            AUTO_SAMPLE_BYTES
        );
        assert_eq!(windows[0].0, 0);
        assert_eq!(
            windows[2].0 + windows[2].1 as u64,
            (AUTO_SAMPLE_BYTES * 4) as u64
        );
        assert!(windows.windows(2).all(|w| w[0].0 + w[0].1 as u64 <= w[1].0));

        // Pure file-read regression: works even when Apple codecs are absent.
        // A first-window-only sampler would never see the B/C sections.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic-strata");
        let mut bytes = vec![b'A'; AUTO_SAMPLE_BYTES * 4];
        bytes[AUTO_SAMPLE_BYTES..AUTO_SAMPLE_BYTES * 3].fill(b'B');
        bytes[AUTO_SAMPLE_BYTES * 3..].fill(b'C');
        fs::write(&path, &bytes).unwrap();
        let mut source = open_regular(&path).unwrap();
        let samples = read_auto_samples(&mut source, bytes.len() as u64).unwrap();
        assert!(samples[0].iter().all(|b| *b == b'A'));
        assert!(samples[1].iter().all(|b| *b == b'B'));
        assert!(samples[2].iter().all(|b| *b == b'C'));
        assert_eq!(source.stream_position().unwrap(), 0);
        assert_eq!(
            auto_sample_windows(u64::MAX)
                .iter()
                .map(|(_, length)| length)
                .sum::<usize>(),
            AUTO_SAMPLE_BYTES
        );
    }

    #[test]
    fn auto_reused_scratch_matches_api_managed_sample_lengths() {
        if !Codec::Lzraven.is_supported() || !Codec::Lzmesh.is_supported() {
            return;
        }
        // Three heterogeneous, independently encoded windows on a generated
        // source. The sample's exact payload lengths must be identical with
        // API-owned and reused scratch for both Apple codecs.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("generated-auto-scratch");
        let mut bytes = vec![b'A'; AUTO_SAMPLE_BYTES * 4];
        bytes[AUTO_SAMPLE_BYTES..AUTO_SAMPLE_BYTES * 3].fill(b'B');
        bytes[AUTO_SAMPLE_BYTES * 3..].fill(b'C');
        fs::write(&path, &bytes).unwrap();
        let mut source = open_regular(&path).unwrap();
        let samples = read_auto_samples(&mut source, bytes.len() as u64).unwrap();
        assert_eq!(source.stream_position().unwrap(), 0);
        let reference: Vec<usize> = [Codec::Lzraven, Codec::Lzmesh]
            .into_iter()
            .map(|codec| {
                samples
                    .iter()
                    .map(|sample| {
                        let encoded = codec.encode(sample).unwrap();
                        assert_eq!(codec.decode_exact(&encoded, sample.len()).unwrap(), *sample);
                        encoded.len()
                    })
                    .sum::<usize>()
            })
            .collect();
        let reused = auto_encoded_lengths(&samples).unwrap();
        assert_eq!(reused.as_slice(), reference.as_slice());
        assert_eq!(
            prefer_auto_codec(reused[0], reused[1]),
            prefer_auto_codec(reference[0], reference[1])
        );
        assert_eq!(
            auto_encoded_lengths(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            auto_encoded_lengths(&[Vec::new()]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn auto_preflight_refuses_occupied_output_and_invalid_geometry_before_codec_work() {
        use applesauce_core::cold_archive::{MAX_CHUNKS, MIN_CHUNK_BYTES};

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("synthetic-input");
        fs::write(&source, b"generated data for a bounded archive").unwrap();
        let occupied = dir.path().join("occupied.ascf");
        fs::write(&occupied, b"preserve existing output").unwrap();
        // Must report the occupied output even on hosts where the two Apple
        // codecs are unsupported; sampling need not be attempted at all.
        assert_eq!(
            create(&source, &occupied, None, MIN_CHUNK_BYTES, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&occupied).unwrap(), b"preserve existing output");

        let output = dir.path().join("must-not-be-created.ascf");
        for invalid_chunk_bytes in [0, MIN_CHUNK_BYTES / 2, 100_000, 16 * 1024 * 1024] {
            assert_eq!(
                create(&source, &output, None, invalid_chunk_bytes, true)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "invalid chunk bytes: {invalid_chunk_bytes}"
            );
            assert!(!output.exists());
        }

        // A sparse synthetic file tests the maximum archive geometry without
        // reading or allocating 4 GiB. Validation must finish before samples.
        let oversized = dir.path().join("sparse-too-many-chunks");
        let handle = File::create(&oversized).unwrap();
        handle
            .set_len(MAX_CHUNKS as u64 * MIN_CHUNK_BYTES as u64 + 1)
            .unwrap();
        drop(handle);
        assert_eq!(
            create(&oversized, &output, None, MIN_CHUNK_BYTES, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!output.exists());
    }

    #[test]
    fn auto_archive_roundtrips_without_touching_source() {
        if !Codec::Lzraven.is_supported() || !Codec::Lzmesh.is_supported() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("auto-source.jsonl");
        let archive_path = dir.path().join("auto.ascf");
        let restore_path = dir.path().join("auto-restored");
        let data = b"{\"role\":\"user\",\"content\":\"generated fixture\"}\n".repeat(4096);
        fs::write(&source_path, &data).unwrap();
        let expected = {
            let mut source = open_regular(&source_path).unwrap();
            sample_auto_codec(&mut source, data.len() as u64).unwrap()
        };
        create(&source_path, &archive_path, None, 64 * 1024, false).unwrap();
        let archive = open_regular(&archive_path).unwrap();
        let reader = ArchiveReader::open(archive).unwrap();
        assert_eq!(reader.codec(), expected);
        verify(&archive_path).unwrap();
        extract(&archive_path, &restore_path).unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), data);
        assert_eq!(fs::read(&restore_path).unwrap(), data);
    }

    #[test]
    fn range_parser_enforces_unsigned_bounds_and_explicit_syntax() {
        for bad in [
            "",
            "1",
            "-1:2",
            "1:-2",
            "1:2:3",
            "1:",
            ":2",
            "1.0:2",
            "18446744073709551615:1",
        ] {
            assert!(parse_logical_range(bad).is_err(), "accepted {bad:?}");
            assert!(crate::Cli::try_parse_from([
                "applesauce",
                "archive",
                "extract",
                "src.ascf",
                "slice",
                "--range",
                bad
            ])
            .is_err());
        }
        assert_eq!(parse_logical_range("0:0").unwrap(), (0, 0));
        assert_eq!(
            parse_logical_range("65535:131073").unwrap(),
            (65535, 131073)
        );
        assert!(
            crate::Cli::try_parse_from(["applesauce", "archive", "info", "source.ascf"]).is_ok()
        );
        assert!(crate::Cli::try_parse_from([
            "applesauce",
            "archive",
            "extract",
            "source.ascf",
            "slice",
            "--range",
            "65535:131073"
        ])
        .is_ok());
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

    #[cfg(unix)]
    #[test]
    fn fifo_inputs_are_rejected_without_opening_a_blocking_reader() {
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("untrusted-input-fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the pathname points into an isolated temporary test directory.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        // All archive entrypoints open the same untrusted pathname. With
        // O_NONBLOCK missing from open_regular, the first assertion hangs.
        assert_eq!(
            open_regular(&fifo).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let archive_output = dir.path().join("output.ascf");
        let restored_output = dir.path().join("restored.jsonl");
        assert!(create(
            &fifo,
            &archive_output,
            Some(Codec::Lzraven),
            64 * 1024,
            false
        )
        .is_err());
        assert!(info(&fifo).is_err());
        assert!(verify(&fifo).is_err());
        assert!(extract(&fifo, &restored_output).is_err());
        assert!(extract_range(&fifo, &restored_output, (0, 1)).is_err());
        assert!(!archive_output.exists());
        assert!(!restored_output.exists());
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
            create(&source, &archive, Some(codec), 64 * 1024, false).unwrap();
            verify(&archive).unwrap();
            extract(&archive, &restored).unwrap();
            assert_eq!(fs::read(&source).unwrap(), payload);
            assert_eq!(fs::read(&restored).unwrap(), payload);
            info(&archive).unwrap();
            let report = crate::size_report::analyze(std::slice::from_ref(&archive));
            assert!(report.complete);
            let report = serde_json::to_value(report).unwrap();
            let entry = &report["paths"][0];
            assert_eq!(entry["source"], "ascf");
            assert_eq!(entry["logical_size_bytes"], payload.len() as u64);
            assert_eq!(
                entry["archive_bytes"],
                fs::metadata(&archive).unwrap().len()
            );
            assert_eq!(entry["codec"], codec.name());
            assert_eq!(
                entry["entry_count"],
                (payload.len() as u64).div_ceil(64 * 1024)
            );
            assert_eq!(
                entry["raw_compressed_bytes"].as_u64().unwrap()
                    + 64
                    + 48 * entry["entry_count"].as_u64().unwrap(),
                entry["archive_bytes"]
            );
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
            // Size inspection validates metadata only and never decodes payloads.
            assert!(crate::size_report::analyze(std::slice::from_ref(&archive)).complete);
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
            assert!(create(&empty, &output, Some(codec), 64 * 1024, false).is_err());
            assert!(!output.exists());
            let output = dir.path().join(format!("dir-{}.ascf", codec.name()));
            assert!(create(dir.path(), &output, Some(codec), 64 * 1024, false).is_err());
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
                    create(&source, &output, Some(codec), bad, false).is_err(),
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
            assert!(create(&source, &output, Some(codec), 64 * 1024, false).is_err());
            assert!(!output.exists());
            // The explicit opt-in flag keeps it.
            create(&source, &output, Some(codec), 64 * 1024, true).unwrap();
            assert!(output.exists());
        }
    }
}
