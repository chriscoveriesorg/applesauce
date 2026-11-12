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
#[cfg(not(unix))]
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
            && before.nlink() == after.nlink()
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

// A verified staging descriptor is not enough for safe publication: the
// temporary pathname can be renamed or replaced while decoding and hashing
// run. Revalidate its identity and change timestamps immediately before the
// NamedTempFile publication call. Like the source guard, this is a best-effort
// check; it cannot make pathname validation and rename a single operation.
fn ensure_unchanged_staging_output(
    temporary: &PinnedTempFile,
    verified: &fs::Metadata,
) -> io::Result<()> {
    let opened = temporary.as_file().metadata()?;
    let selected = fs::symlink_metadata(temporary.path())?;
    if !selected.file_type().is_file()
        || !same_regular_snapshot(verified, &opened)
        || !same_regular_snapshot(verified, &selected)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "verified archive staging file changed before publication",
        ));
    }
    Ok(())
}

// Read-only operations must validate the same opened inode and selected path
// after parsing or decoding. Report success only after that final validation.
fn read_unchanged_regular<T>(
    path: &Path,
    action: impl FnOnce(&mut File) -> io::Result<T>,
) -> io::Result<T> {
    let mut source = open_regular(path)?;
    let before = source.metadata()?;
    let result = action(&mut source)?;
    ensure_unchanged_regular_input(path, &source, &before)?;
    Ok(result)
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

/// Retain the staged inode and its directory descriptor throughout the
/// operation. A NamedTempFile path destructor could remove an unrelated file
/// if a directory is swapped, or a staging name is replaced, on an error path.
/// This wrapper never delegates cleanup to a saved pathname.
#[cfg(unix)]
struct PinnedTempFile {
    file: File,
    directory: File,
    path: PathBuf,
    name: std::ffi::CString,
    cleaned: bool,
}

#[cfg(unix)]
impl PinnedTempFile {
    fn new(file: File, directory: File, path: PathBuf, name: std::ffi::CString) -> Self {
        Self {
            file,
            directory,
            path,
            name,
            cleaned: false,
        }
    }

    fn as_file(&self) -> &File {
        &self.file
    }

    fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn cleanup(&mut self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        if self.cleaned {
            return Ok(());
        }
        // Mark cleanup attempted before any fallible operation. Even a failed
        // fstat cannot trigger an implicit pathname-based unlink on Drop.
        self.cleaned = true;
        let original = self.file.metadata()?;
        let mut selected = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: directory descriptor and filename are owned by self, and the
        // selected buffer is valid writable storage for a libc::stat.
        let status = unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
                selected.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status != 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            };
        }
        // SAFETY: successful fstatat initialized selected.
        let selected = unsafe { selected.assume_init() };
        if selected.st_dev as u64 != original.dev() || selected.st_ino != original.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive staging name was replaced before pinned cleanup",
            ));
        }
        // SAFETY: directory descriptor and name remain valid for unlinkat.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(unix)]
impl std::ops::Deref for PinnedTempFile {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

#[cfg(unix)]
impl std::ops::DerefMut for PinnedTempFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

#[cfg(unix)]
impl Drop for PinnedTempFile {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(not(unix))]
type PinnedTempFile = NamedTempFile;

/// Pin the directory in which the private staged file was created. A rename
/// or symlink retarget of the parent while encoding/decoding runs must not
/// redirect the final publication to a different directory. Directory mtime
/// and ctime are deliberately excluded: creating the staged file changes them.
struct OutputDirectoryGuard {
    path: PathBuf,
    opened: File,
    original: fs::Metadata,
}

fn same_directory_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    if !left.is_dir() || !right.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        // The CLI's archive publication protocol needs stable inode identity.
        false
    }
}

// On failed publication, unlink only if the target still names the staged
// inode. A competing writer can replace the target between linkat and the
// post-publication identity check; unconditional unlink would delete that
// unrelated replacement. This remains a best-effort guard in a directory
// writable by an adversary because fstatat/unlinkat are separate operations.
#[cfg(unix)]
fn rollback_published_link_if_ours(
    directory: &File,
    name: &std::ffi::CStr,
    expected: &fs::Metadata,
) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let mut selected = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory stays open, name is NUL-terminated, and stat is writable.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            selected.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }
    // SAFETY: successful fstatat initialized selected.
    let selected = unsafe { selected.assume_init() };
    if selected.st_dev as u64 != expected.dev() || selected.st_ino != expected.ino() {
        return Ok(false);
    }
    // SAFETY: directory and name are valid for unlinkat.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

impl OutputDirectoryGuard {
    fn open(path: &Path) -> io::Result<Self> {
        let original = fs::metadata(path)?;
        Self::open_checked(path, original)
    }

    // Separate the pathname preflight from open so tests can force a swap.
    // O_DIRECTORY prevents a replaced FIFO from blocking in open(2), while
    // the inode check below catches a replaced directory. Allow a symlink
    // parent when its resolved directory identity remains unchanged.
    fn open_checked(path: &Path, original: fs::Metadata) -> io::Result<Self> {
        if !original.is_dir() {
            return Err(invalid("archive output parent must be a directory"));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK);
        }
        let opened = options.open(path)?;
        let guard = Self {
            path: path.to_owned(),
            opened,
            original,
        };
        guard.ensure_unchanged()?;
        Ok(guard)
    }

    fn ensure_unchanged(&self) -> io::Result<()> {
        if !same_directory_identity(&self.original, &self.opened.metadata()?)
            || !same_directory_identity(&self.original, &fs::metadata(&self.path)?)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive output parent changed during operation",
            ));
        }
        Ok(())
    }

    /// Atomically publish through the *opened directory*, not a pathname which
    /// can resolve to a different directory between validation and publication.
    /// linkat rejects existing files, including symlinks, without clobbering.
    fn publish_verified(
        &self,
        mut temporary: PinnedTempFile,
        output: &Path,
        verified: &fs::Metadata,
    ) -> io::Result<()> {
        let selected_parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if selected_parent != self.path.as_path() {
            return Err(invalid(
                "archive output parent differs from pinned directory",
            ));
        }
        self.ensure_unchanged()?;
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::MetadataExt;

            let source_name = temporary
                .path()
                .file_name()
                .ok_or_else(|| invalid("archive staging filename is missing"))?;
            let target_name = output
                .file_name()
                .ok_or_else(|| invalid("archive output filename is missing"))?;
            let source_name = CString::new(source_name.as_bytes())
                .map_err(|_| invalid("archive staging filename contains NUL"))?;
            let target_name = CString::new(target_name.as_bytes())
                .map_err(|_| invalid("archive output filename contains NUL"))?;

            // Reuse the caller's verified snapshot. Recapturing metadata here
            // would trust an in-place rewrite between final hash verification
            // and publication as though it were the original staged content.
            ensure_unchanged_staging_output(&temporary, verified)?;
            let opened = temporary.as_file().metadata()?;
            let directory_fd = self.opened.as_raw_fd();
            // SAFETY: directory_fd is an open directory descriptor; both CStrings
            // are NUL-terminated names without interior NUL bytes.
            let linked = unsafe {
                libc::linkat(
                    directory_fd,
                    source_name.as_ptr(),
                    directory_fd,
                    target_name.as_ptr(),
                    0,
                )
            };
            if linked != 0 {
                return Err(io::Error::last_os_error());
            }

            // An attacker may replace the staged pathname between its last
            // identity check and linkat. Check the published hardlink against
            // the descriptor, then recheck that the requested parent still
            // resolves to this directory.
            let mut published = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: directory_fd is valid, target_name is NUL-terminated,
            // and published points to writable storage for a libc::stat.
            let stat_result = unsafe {
                libc::fstatat(
                    directory_fd,
                    target_name.as_ptr(),
                    published.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            let identity_ok = if stat_result == 0 {
                // SAFETY: successful fstatat initialized the entire stat value.
                let published = unsafe { published.assume_init() };
                opened.dev() == published.st_dev as u64
                    && opened.ino() == published.st_ino
                    && opened.len() == published.st_size as u64
            } else {
                false
            };
            let parent_ok = self.ensure_unchanged();
            if !identity_ok || parent_ok.is_err() {
                // Only remove our own published link. A competing writer may
                // have replaced the final name after linkat; deleting that
                // replacement would violate no-clobber publication.
                if let Err(error) =
                    rollback_published_link_if_ours(&self.opened, &target_name, &opened)
                {
                    eprintln!("warning: archive publication rollback failed: {error}");
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "archive publication lost staging or destination identity",
                ));
            }

            // Publication has succeeded; a cleanup failure is reported as a
            // warning rather than a false "publication failed" result. Drop
            // also uses the pinned descriptor for early-return cleanup.
            if let Err(error) = temporary.cleanup() {
                eprintln!(
                    "warning: verified archive published but staging cleanup failed: {error}"
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (temporary, output, verified);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned archive publication requires Unix directory descriptors",
            ))
        }
    }
}

// Allocate staging names from OS entropy and create through the pinned
// dirfd. No NamedTempFile or pathname-based destructor exists, including on
// an early error before publication. O_EXCL rejects a guessed/colliding name.
#[cfg(unix)]
fn create_pinned_staging(
    parent: &Path,
    guard: &OutputDirectoryGuard,
) -> io::Result<PinnedTempFile> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let mut entropy = File::open("/dev/urandom")?;
    let directory = guard.opened.try_clone()?;
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        entropy.read_exact(&mut random)?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let basename = format!(".applesauce-{suffix}");
        let name = CString::new(basename.as_bytes())
            .map_err(|_| invalid("archive staging filename contains NUL"))?;
        // SAFETY: the directory descriptor is open, name has no separators
        // or interior NUL bytes, and O_EXCL prevents an occupied name.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: openat returned a uniquely owned descriptor.
            let file = unsafe { File::from_raw_fd(fd) };
            return Ok(PinnedTempFile::new(
                file,
                directory,
                parent.join(basename),
                name,
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique archive staging filename",
    ))
}

fn staging(output: &Path) -> io::Result<(PinnedTempFile, OutputDirectoryGuard)> {
    unused_output(output)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let guard = OutputDirectoryGuard::open(parent)?;
    #[cfg(unix)]
    let temporary = create_pinned_staging(parent, &guard)?;
    #[cfg(not(unix))]
    let temporary = NamedTempFile::new_in(parent)?;
    guard.ensure_unchanged()?;
    Ok((temporary, guard))
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
    let (mut temporary, output_parent) = staging(output)?;
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
    let verified_staging = temporary.as_file().metadata()?;
    if verified_staging.len() != stats.archive_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged archive size changed after verification",
        ));
    }
    // Encoding, re-hashing and staged verification can take substantial time.
    // Recheck immediately before publishing in case the source changed after
    // the earlier source hash check.
    ensure_unchanged_regular_input(source_path, &source, &before)?;
    ensure_unchanged_staging_output(&temporary, &verified_staging)?;
    output_parent.publish_verified(temporary, output, &verified_staging)?;
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
    // Header/index validation is portable and does not initialize decoder scratch.
    let message = read_unchanged_regular(path, |source| {
        let archive_bytes = source.metadata()?.len();
        let reader = ArchiveReader::open(source)?;
        Ok(format!(
            "ASCF {}: {} logical bytes, {} archive bytes, {} chunks of {} bytes, SHA-256 {} (metadata only)",
            reader.codec().name(),
            reader.logical_size(),
            archive_bytes,
            reader.chunk_count(),
            reader.chunk_size(),
            hex_digest(reader.logical_sha256())
        ))
    })?;
    println!("{message}");
    Ok(())
}

fn verify(path: &Path) -> io::Result<()> {
    let message = read_unchanged_regular(path, |source| {
        let mut reader = ArchiveReader::open(source)?;
        reader.verify_all()?;
        Ok(format!(
            "Verified {} archive; {} logical bytes, SHA-256 {}",
            reader.codec().name(),
            reader.logical_size(),
            hex_digest(reader.logical_sha256())
        ))
    })?;
    println!("{message}");
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
    let (mut temporary, output_parent) = staging(output)?;
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
    let verified_staging = temporary.as_file().metadata()?;
    temporary.as_file_mut().rewind()?;
    if hash_reader(temporary.as_file_mut())? != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged restore failed read-back verification",
        ));
    }
    ensure_unchanged_regular_input(archive_path, &source, &before)?;
    ensure_unchanged_staging_output(&temporary, &verified_staging)?;
    output_parent.publish_verified(temporary, output, &verified_staging)?;
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
    let (mut temporary, output_parent) = staging(output)?;
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
    let verified_staging = temporary.as_file().metadata()?;
    temporary.as_file_mut().rewind()?;
    let output_digest = hash_reader(temporary.as_file_mut())?;
    let range_digest: [u8; 32] = digest.finalize().into();
    if output_digest != range_digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged logical range failed read-back verification",
        ));
    }
    ensure_unchanged_regular_input(archive_path, &source, &before)?;
    ensure_unchanged_staging_output(&temporary, &verified_staging)?;
    output_parent.publish_verified(temporary, output, &verified_staging)?;
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

    #[cfg(unix)]
    #[test]
    fn staging_creation_stays_in_pinned_directory_after_parent_swap() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("selected");
        let moved = root.path().join("original");
        fs::create_dir(&parent).unwrap();
        let guard = OutputDirectoryGuard::open(&parent).unwrap();

        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        let mut temporary = create_pinned_staging(&parent, &guard).unwrap();
        temporary.write_all(b"private staged contents").unwrap();
        let name = temporary.path().file_name().unwrap().to_os_string();

        assert!(moved.join(&name).exists());
        assert!(!parent.join(&name).exists());
        assert!(guard.ensure_unchanged().is_err());
        drop(temporary);
        assert!(!moved.join(&name).exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_staging_drop_preserves_retargeted_parent_files() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("selected");
        let moved = root.path().join("old-selected");
        fs::create_dir(&parent).unwrap();
        let (mut temporary, guard) = staging(&parent.join("output.ascf")).unwrap();
        temporary.write_all(b"private staged contents").unwrap();
        let stage_name = temporary.path().file_name().unwrap().to_os_string();

        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(parent.join(&stage_name), b"unrelated replacement").unwrap();

        // The old pathname now points to an unrelated file. Early-return
        // cleanup must remove only the original staged inode through dirfd.
        assert!(guard.ensure_unchanged().is_err());
        drop(temporary);
        assert_eq!(
            fs::read(parent.join(&stage_name)).unwrap(),
            b"unrelated replacement"
        );
        assert!(!moved.join(&stage_name).exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_staging_replacement_does_not_trigger_pathname_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("target.ascf");
        let (mut temporary, _guard) = staging(&output).unwrap();
        temporary.write_all(b"original private staging").unwrap();
        let stage_path = temporary.path().to_owned();
        let displaced = dir.path().join("displaced-staging");
        fs::rename(&stage_path, &displaced).unwrap();
        fs::write(&stage_path, b"unrelated replacement").unwrap();

        assert_eq!(
            temporary.cleanup().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(temporary);
        assert_eq!(fs::read(&stage_path).unwrap(), b"unrelated replacement");
        assert_eq!(fs::read(&displaced).unwrap(), b"original private staging");
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_staging_cleanup_is_idempotent_after_reuse_of_name() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("target.ascf");
        let (mut temporary, _guard) = staging(&output).unwrap();
        temporary.write_all(b"original private staging").unwrap();
        let stage_path = temporary.path().to_owned();
        temporary.cleanup().unwrap();
        assert!(!stage_path.exists());
        fs::write(&stage_path, b"new unrelated entry").unwrap();

        temporary.cleanup().unwrap();
        drop(temporary);
        assert_eq!(fs::read(&stage_path).unwrap(), b"new unrelated entry");
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn output_parent_fifo_swap_after_preflight_cannot_block() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("selected-output");
        let moved = root.path().join("original-output");
        fs::create_dir(&parent).unwrap();
        let original = fs::metadata(&parent).unwrap();
        fs::rename(&parent, &moved).unwrap();
        let name = CString::new(parent.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is NUL-terminated and refers to an isolated tempdir.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let outcome = OutputDirectoryGuard::open_checked(&parent, original).map(|_| ());
            let _ = sender.send(outcome);
        });
        assert!(receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("archive output parent blocked while opening a swapped FIFO")
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn output_parent_guard_accepts_new_siblings_but_rejects_directory_swap() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("destination");
        let moved = root.path().join("moved-destination");
        fs::create_dir(&parent).unwrap();
        let output = parent.join("restored.bin");
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"staged synthetic bytes").unwrap();
        guard.ensure_unchanged().unwrap();

        // Staging changes directory mtime/ctime; unrelated siblings do too.
        // Neither should be mistaken for a destination replacement.
        fs::write(parent.join("another-file"), b"other").unwrap();
        guard.ensure_unchanged().unwrap();

        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        assert_eq!(
            guard.ensure_unchanged().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!output.exists());
        assert!(moved.join("another-file").exists());
    }

    #[cfg(unix)]
    #[test]
    fn output_parent_guard_detects_retargeted_symlink_ancestor() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        let alias = root.path().join("alias");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        symlink(&first, &alias).unwrap();
        let output = alias.join("restore.bin");
        let (_temporary, guard) = staging(&output).unwrap();
        guard.ensure_unchanged().unwrap();

        fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        assert_eq!(
            guard.ensure_unchanged().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_rollback_preserves_replaced_target_and_symlink() {
        use std::ffi::CString;
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("target");
        let protected = root.path().join("protected");
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"verified archive").unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        let target_name = CString::new("target").unwrap();

        fs::hard_link(temporary.path(), &output).unwrap();
        fs::remove_file(&output).unwrap();
        fs::write(&output, b"unrelated replacement").unwrap();
        assert!(!rollback_published_link_if_ours(&guard.opened, &target_name, &verified).unwrap());
        assert_eq!(fs::read(&output).unwrap(), b"unrelated replacement");

        fs::write(&protected, b"protected contents").unwrap();
        fs::remove_file(&output).unwrap();
        symlink(&protected, &output).unwrap();
        assert!(!rollback_published_link_if_ours(&guard.opened, &target_name, &verified).unwrap());
        assert!(fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&protected).unwrap(), b"protected contents");
    }

    #[cfg(unix)]
    #[test]
    fn pinned_rollback_removes_our_link_after_parent_rename() {
        use std::ffi::CString;

        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("selected");
        let moved = root.path().join("moved");
        fs::create_dir(&parent).unwrap();
        let output = parent.join("target");
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"verified archive").unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        fs::hard_link(temporary.path(), &output).unwrap();

        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(&output, b"unrelated name in replacement parent").unwrap();

        let target_name = CString::new("target").unwrap();
        assert!(rollback_published_link_if_ours(&guard.opened, &target_name, &verified).unwrap());
        assert!(!moved.join("target").exists());
        assert_eq!(
            fs::read(&output).unwrap(),
            b"unrelated name in replacement parent"
        );
        assert!(!rollback_published_link_if_ours(&guard.opened, &target_name, &verified).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_publish_creates_only_verified_output_and_cleans_stage() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("destination");
        fs::create_dir(&parent).unwrap();
        let output = parent.join("résumé restored.bin");
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"verified synthetic content").unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        guard
            .publish_verified(temporary, &output, &verified)
            .unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"verified synthetic content");
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn pinned_publish_rejects_a_different_requested_parent() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let other = root.path().join("other");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&other).unwrap();
        let original_target = original.join("restored.bin");
        let other_target = other.join("restored.bin");
        let (mut temporary, guard) = staging(&original_target).unwrap();
        temporary.write_all(b"verified bytes").unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        assert_eq!(
            guard
                .publish_verified(temporary, &other_target, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!original_target.exists());
        assert!(!other_target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_publish_refuses_existing_target_including_symlink() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let parent = root.path();
        let output = parent.join("target");
        let protected = parent.join("protected");
        fs::write(&protected, b"do not overwrite").unwrap();
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"verified bytes").unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        symlink(&protected, &output).unwrap();
        assert_eq!(
            guard
                .publish_verified(temporary, &output, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&protected).unwrap(), b"do not overwrite");
        assert!(fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_publish_refuses_changed_staging_inode() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("verified");
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"verified bytes").unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        let moved = root.path().join("moved-stage");
        fs::rename(temporary.path(), &moved).unwrap();
        fs::write(temporary.path(), b"attacker bytes").unwrap();
        assert_eq!(
            guard
                .publish_verified(temporary, &output, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_publish_refuses_rewrite_since_verified_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("verified");
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"verified bytes").unwrap();
        let verified = temporary.as_file().metadata().unwrap();

        // A competing writer retains the same inode and byte count after
        // verification. A fresh snapshot taken inside publish would accept it.
        fs::write(temporary.path(), b"tampered bytes").unwrap();
        temporary
            .as_file()
            .set_modified(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345),
            )
            .unwrap();
        assert_eq!(
            verified.len(),
            temporary.as_file().metadata().unwrap().len()
        );
        assert_eq!(
            guard
                .publish_verified(temporary, &output, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_publish_refuses_replaced_parent_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("output");
        let moved = root.path().join("moved");
        fs::create_dir(&parent).unwrap();
        let output = parent.join("restored.bin");
        let (mut temporary, guard) = staging(&output).unwrap();
        temporary.write_all(b"verified bytes").unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        assert_eq!(
            guard
                .publish_verified(temporary, &output, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!output.exists());
        assert!(!moved.join("restored.bin").exists());
    }

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
        ensure_unchanged_regular_input(&source, &held, &scanned).unwrap();
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
            ensure_unchanged_regular_input(&source, &held, &scanned)
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
            ensure_unchanged_regular_input(&source, &held, &scanned)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        std::os::unix::fs::symlink(dir.path().join("held-original"), &source).unwrap();
        assert!(ensure_unchanged_regular_input(&source, &held, &scanned).is_err());
        fs::remove_file(&source).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let fifo_path = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_path is a live, NUL-terminated CString in an isolated
        // temporary test directory, and mkfifo only reads its pathname bytes.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        // O_NONBLOCK is necessary even after the symlink_metadata precheck:
        // the pathname could change to a FIFO between preflight and open.
        assert!(ensure_unchanged_regular_input(&source, &held, &scanned).is_err());
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
        ensure_unchanged_regular_input(&path, &held, &before).unwrap();

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
            ensure_unchanged_regular_input(&path, &held, &before)
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
            ensure_unchanged_regular_input(&path, &held, &baseline)
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
            move || create(&path, &destination, Some(Codec::Lzraven), 64 * 1024, true)
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

    // The same post-read validation guards `archive info` and `archive
    // verify` before their success messages. Mutations are deterministic
    // and happen while the read-only operation still owns its descriptor.
    #[test]
    fn read_only_operations_reject_path_replacement_after_successful_read() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("selected.ascf");
        let replacement = dir.path().join("replacement.ascf");
        fs::write(&selected, b"original bytes").unwrap();
        fs::write(&replacement, b"replacement bytes").unwrap();

        let error = read_unchanged_regular(&selected, |source| {
            let mut observed = Vec::new();
            source.read_to_end(&mut observed)?;
            assert_eq!(observed, b"original bytes");
            fs::rename(&replacement, &selected)?;
            Ok(observed)
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&selected).unwrap(), b"replacement bytes");
    }

    #[test]
    fn read_only_operations_reject_in_place_growth_after_successful_read() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("growing.ascf");
        fs::write(&selected, b"original bytes").unwrap();

        let error = read_unchanged_regular(&selected, |source| {
            let mut observed = Vec::new();
            source.read_to_end(&mut observed)?;
            assert_eq!(observed, b"original bytes");
            OpenOptions::new()
                .append(true)
                .open(&selected)?
                .write_all(b" changed")?;
            Ok(observed)
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&selected).unwrap(), b"original bytes changed");
    }

    #[test]
    fn read_only_operations_accept_stable_regular_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("stable.ascf");
        fs::write(&selected, b"stable input").unwrap();
        let observed = read_unchanged_regular(&selected, |source| {
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes)?;
            Ok(bytes)
        })
        .unwrap();
        assert_eq!(observed, b"stable input");
    }

    #[test]
    fn verified_staging_rejects_replaced_regular_file_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let (mut temporary, _guard) = staging(&dir.path().join("test-out.ascf")).unwrap();
        temporary
            .write_all(b"generated verified staging bytes")
            .unwrap();
        temporary.flush().unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        ensure_unchanged_staging_output(&temporary, &verified).unwrap();

        let selected = temporary.path().to_owned();
        let moved = dir.path().join("original-staged-inode");
        fs::rename(&selected, &moved).unwrap();
        fs::write(&selected, b"generated verified staging bytes").unwrap();
        // Matching bytes and length must not allow a substituted inode.
        assert_eq!(
            ensure_unchanged_staging_output(&temporary, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        fs::remove_file(&selected).unwrap();
        std::os::unix::fs::symlink(&moved, &selected).unwrap();
        assert_eq!(
            ensure_unchanged_staging_output(&temporary, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn verified_staging_rejects_in_place_same_length_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let (mut temporary, _guard) = staging(&dir.path().join("test-out.ascf")).unwrap();
        temporary.write_all(b"generated verified bytes").unwrap();
        temporary.flush().unwrap();
        let verified = temporary.as_file().metadata().unwrap();
        ensure_unchanged_staging_output(&temporary, &verified).unwrap();

        // Retain the inode and length, then force a different timestamp so
        // the test is deterministic even on coarse timestamp filesystems.
        fs::write(temporary.path(), b"generated changed! bytes").unwrap();
        temporary
            .as_file()
            .set_modified(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345),
            )
            .unwrap();
        assert_eq!(
            temporary.as_file().metadata().unwrap().len(),
            verified.len()
        );
        assert_eq!(
            ensure_unchanged_staging_output(&temporary, &verified)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
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
