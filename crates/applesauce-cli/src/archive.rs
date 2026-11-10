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
    // Reject devices, sockets and FIFOs before open() can interact with them.
    // Descriptor validation below remains essential if a path is swapped.
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(invalid("archive input must be a regular file"));
    }
    open_checked_regular(path, &before)
}

// Kept separate so tests can reproduce a pathname swap AFTER the first
// metadata check. All callers must still use open_regular for preflight.
fn open_checked_regular(path: &Path, before: &fs::Metadata) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW rejects symlink inputs. O_NONBLOCK keeps a swapped-in
        // FIFO from hanging before metadata() can reject non-regular files.
        // Regular-file reads retain their normal blocking semantics.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(invalid("archive input must be a regular file"));
    }
    // In-place edits are also substitutions, even if device and inode match.
    if !same_regular_snapshot(before, &opened) {
        return Err(invalid("archive input changed between preflight and open"));
    }
    Ok(file)
}

// Compare identity and change times in addition to size. In particular,
// matching device/inode alone does not catch a writer modifying the same file.
// A same-size rewrite with a restored mtime still advances ctime on Unix.
fn same_regular_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        before.len() == after.len() && before.modified().ok() == after.modified().ok()
    }
}

// Recheck both the pinned descriptor and the selected path before publishing
// output. A rename can replace the pathname while the original descriptor
// continues yielding valid bytes. Neither case may publish under that identity.
fn ensure_unchanged_regular_input(
    path: &Path,
    file: &File,
    expected: &fs::Metadata,
) -> io::Result<()> {
    let opened = file.metadata()?;
    let selected = fs::symlink_metadata(path)?;
    if !selected.file_type().is_file()
        || !same_regular_snapshot(expected, &opened)
        || !same_regular_snapshot(expected, &selected)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive source changed during operation",
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
    ensure_unchanged_regular_input(source_path, &source, &before)?;

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
    ensure_unchanged_regular_input(archive_path, &source, &before)?;
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
    ensure_unchanged_regular_input(archive_path, &source, &before)?;
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

    // Run potentially blocking FIFO opens in a separate thread with a deadline.
    // A regression that drops O_NONBLOCK must fail quickly instead of hanging
    // the entire CI job until the runner's global timeout expires.
    #[cfg(unix)]
    fn assert_rejected_without_blocking<T, F>(action: F)
    where
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let outcome = action().map(|_| ()).map_err(|error| error.kind());
            let _ = sender.send(outcome);
        });
        let outcome = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("archive operation blocked while opening a FIFO");
        assert_eq!(outcome, Err(io::ErrorKind::InvalidInput));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_input_is_rejected_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("unopened-archive-pipe");
        let raw = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: raw is NUL terminated, and the path belongs to this tempdir.
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        let output = dir.path().join("must-not-exist");

        // A FIFO opened with O_RDONLY alone would wait indefinitely for a
        // writer. All archive entry points must reject it before reading.
        // Each operation has its own bound. A single blocking entry point
        // cannot prevent the remaining cases from being diagnosed.
        assert_rejected_without_blocking({
            let path = fifo.clone();
            move || open_regular(&path)
        });
        assert_rejected_without_blocking({
            let path = fifo.clone();
            move || info(&path)
        });
        assert_rejected_without_blocking({
            let path = fifo.clone();
            move || verify(&path)
        });
        assert_rejected_without_blocking({
            let path = fifo.clone();
            let destination = output.clone();
            move || extract(&path, &destination)
        });
        assert_rejected_without_blocking({
            let path = fifo.clone();
            let destination = output.clone();
            move || extract_range(&path, &destination, (0, 1))
        });
        assert_rejected_without_blocking({
            let path = fifo.clone();
            let destination = output.clone();
            move || create(&path, &destination, Codec::Lzraven, 64 * 1024, true)
        });
        assert!(!output.exists());

        // The nonblocking flag must not stop an ordinary file being read.
        let regular = dir.path().join("regular");
        fs::write(&regular, b"ordinary archive input").unwrap();
        let mut file = open_regular(&regular).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"ordinary archive input");
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_and_directory_inputs_are_rejected_before_open() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("archive-socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        for path in [&socket, dir.path()] {
            assert_eq!(
                open_regular(path).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "accepted non-regular archive input: {path:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn swapped_fifo_is_rejected_after_a_successful_regular_file_preflight() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("formerly-regular");
        let replacement = dir.path().join("replacement-fifo");
        fs::write(&source, b"original").unwrap();
        let before = fs::symlink_metadata(&source).unwrap();
        assert!(before.file_type().is_file());

        let raw = CString::new(replacement.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-terminated path is owned by this disposable tempdir.
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        // Simulate replacement between the metadata preflight and open().
        // No writer exists for this FIFO. An O_RDONLY open without O_NONBLOCK
        // would hang here; descriptor validation must reject the substituted
        // object without returning a File.
        fs::rename(&replacement, &source).unwrap();
        assert_rejected_without_blocking(move || open_checked_regular(&source, &before));
    }

    #[cfg(unix)]
    #[test]
    fn swapped_symlink_is_rejected_after_regular_file_preflight() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("selected-archive");
        let target = dir.path().join("other-archive");
        fs::write(&source, b"selected bytes").unwrap();
        fs::write(&target, b"other bytes").unwrap();
        let before = fs::symlink_metadata(&source).unwrap();
        assert!(before.file_type().is_file());

        // A pathname may become a symlink after the initial regular-file
        // check. O_NOFOLLOW must still refuse it without reading its target.
        fs::remove_file(&source).unwrap();
        symlink(&target, &source).unwrap();
        let error = open_checked_regular(&source, &before).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
        assert_eq!(fs::read(&target).unwrap(), b"other bytes");
    }

    #[cfg(unix)]
    #[test]
    fn in_place_growth_is_rejected_after_regular_file_preflight() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("selected-input");
        fs::write(&source, b"original").unwrap();
        let before = fs::symlink_metadata(&source).unwrap();
        let opened = open_regular(&source).unwrap();
        ensure_unchanged_regular_input(&source, &opened, &before).unwrap();

        // Preserve the inode while mutating the file between metadata checks.
        OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(b" changed")
            .unwrap();
        let after = fs::symlink_metadata(&source).unwrap();
        assert_eq!(before.dev(), after.dev());
        assert_eq!(before.ino(), after.ino());

        let error = open_checked_regular(&source, &before).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            ensure_unchanged_regular_input(&source, &opened, &before)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_archive_path_replacement_is_rejected_before_publication() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("selected.ascf");
        let replacement = dir.path().join("replacement.ascf");
        fs::write(&selected, b"original archived bytes").unwrap();
        fs::write(&replacement, b"other archived bytes").unwrap();
        let opened = open_regular(&selected).unwrap();
        let before = opened.metadata().unwrap();

        // The pinned descriptor remains readable after its path is replaced.
        // A successful content check alone must not publish from this input.
        fs::rename(&replacement, &selected).unwrap();
        assert_eq!(
            ensure_unchanged_regular_input(&selected, &opened, &before)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fs::read(&selected).unwrap(), b"other archived bytes");
    }

    #[cfg(unix)]
    #[test]
    fn swapped_regular_file_is_rejected_after_metadata_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("selected-input");
        let replacement = dir.path().join("different-regular-input");
        fs::write(&source, b"authorized archive input").unwrap();
        fs::write(&replacement, b"unexpected replacement bytes").unwrap();
        let before = fs::symlink_metadata(&source).unwrap();
        assert!(before.file_type().is_file());

        // Identical path and file type are insufficient after a rename race.
        fs::rename(&replacement, &source).unwrap();
        let error = open_checked_regular(&source, &before).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error
            .to_string()
            .contains("changed between preflight and open"));

        // A subsequent explicit operation is free to select the new file.
        let mut opened = open_regular(&source).unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"unexpected replacement bytes");
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
