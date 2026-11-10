#![warn(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::cast_lossless)]
#![warn(clippy::cast_ptr_alignment)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cloned_instead_of_copied)]
#![warn(clippy::debug_assert_with_mut_call)]
#![warn(clippy::filetype_is_file)]
#![warn(clippy::match_same_arms)]
extern crate core;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
compile_error!("applesauce only works on macos/ios");

pub mod dry_run;
pub mod info;
pub mod progress;
pub use applesauce_core::apple_buffer;
pub use applesauce_core::compressor;

mod rfork_storage;
mod scan;
mod seq_queue;
mod threads;
mod times;
mod volumes;
mod xattr;

use libc::c_char;
use std::ffi::CStr;
use std::fs::{File, Metadata};
use std::io::prelude::*;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::{io, mem, ptr};
use tracing::warn;

/// Apply the same compressed-payload ratio gate used by the mutating writer.
///
/// The ratio is deliberately based on the sum of encoded block payloads. Native
/// decmpfs framing and filesystem allocation are reported separately by dry-run.
#[must_use]
pub fn compressed_payload_is_allowed(
    compressed_payload_bytes: u64,
    logical_size_bytes: u64,
    minimum_compression_ratio: f64,
) -> bool {
    // Library callers can bypass the CLI's argument validation. Never let
    // NaN, infinity or a negative ratio become a permissive native-write threshold.
    if !minimum_compression_ratio.is_finite() || minimum_compression_ratio < 0.0 {
        return false;
    }
    // Converting u64 sizes above 2^53 to f64 loses integer precision.
    // A ratio of exactly one must compare byte counts without rounding.
    if minimum_compression_ratio == 1.0 {
        return compressed_payload_bytes <= logical_size_bytes;
    }
    let maximum = (logical_size_bytes as f64 * minimum_compression_ratio) as u64;
    compressed_payload_bytes <= maximum
}

#[cfg(test)]
mod compression_ratio_tests {
    use super::compressed_payload_is_allowed;

    #[test]
    fn payload_ratio_gate_includes_equality_and_preserves_finite_edges() {
        assert!(compressed_payload_is_allowed(50, 100, 0.5));
        assert!(!compressed_payload_is_allowed(51, 100, 0.5));
        assert!(compressed_payload_is_allowed(0, 100, 0.0));
        assert!(!compressed_payload_is_allowed(1, 100, 0.0));
        assert!(compressed_payload_is_allowed(101, 100, 1.01));
        // 2^53 + 1 cannot be represented exactly by f64. At ratio 1,
        // equality must still pass and one extra byte must fail.
        let large = (1_u64 << 53) + 1;
        assert!(compressed_payload_is_allowed(large, large, 1.0));
        assert!(!compressed_payload_is_allowed(large + 1, large, 1.0));
        assert!(compressed_payload_is_allowed(u64::MAX, u64::MAX, 1.0));
        // Negative ratios must not saturate to zero and allow empty payloads.
        for ratio in [-0.1, -1.0, f64::MIN] {
            assert!(!compressed_payload_is_allowed(0, 100, ratio));
            assert!(!compressed_payload_is_allowed(1, 100, ratio));
        }
        // Fail closed even when invoked through the public library API.
        for ratio in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(!compressed_payload_is_allowed(0, 100, ratio));
            assert!(!compressed_payload_is_allowed(50, 100, ratio));
        }
    }
}

use crate::info::{FileCompressionState, FileInfo};
use crate::progress::Progress;
use crate::threads::{BackgroundThreads, Mode};
use applesauce_core::compressor::Kind;

const fn c_char_bytes(chars: &[c_char]) -> &[u8] {
    assert!(size_of::<c_char>() == size_of::<u8>());
    assert!(align_of::<c_char>() == align_of::<u8>());
    // SAFETY: c_char is the same layout as u8
    unsafe { mem::transmute(chars) }
}

fn cstr_from_bytes_until_null(bytes: &[c_char]) -> Option<&CStr> {
    let bytes = c_char_bytes(bytes);
    let pos = memchr::memchr(0, bytes)?;
    CStr::from_bytes_with_nul(&bytes[..=pos]).ok()
}

fn vol_supports_compression_cap(mnt_root: &CStr) -> io::Result<bool> {
    #[repr(C)]
    struct VolAttrs {
        length: u32,
        vol_attrs: libc::vol_capabilities_attr_t,
    }
    const IDX: usize = libc::VOL_CAPABILITIES_FORMAT;
    const MASK: libc::attrgroup_t = libc::VOL_CAP_FMT_DECMPFS_COMPRESSION;

    // SAFETY: All fields are simple integers which can be zero-initialized
    let mut attrs = unsafe { MaybeUninit::<libc::attrlist>::zeroed().assume_init() };
    attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    attrs.volattr = libc::ATTR_VOL_CAPABILITIES;

    let mut vol_attrs = MaybeUninit::<VolAttrs>::uninit();
    // SAFETY:
    // `mnt_root` is a valid pointer, and is null terminated
    // attrs is a valid pointer to initialized memory of the correct type
    // vol_attrs is a valid pointer, and its size is passed as the size of the buffer
    let rc = unsafe {
        libc::getattrlist(
            mnt_root.as_ptr(),
            ptr::addr_of_mut!(attrs).cast(),
            vol_attrs.as_mut_ptr().cast(),
            size_of_val(&vol_attrs),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getattrlist returned success
    let vol_attrs = unsafe { vol_attrs.assume_init_ref() };
    if vol_attrs.length != u32::try_from(size_of::<VolAttrs>()).unwrap() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "getattrlist returned bad size",
        ));
    }

    Ok(vol_attrs.vol_attrs.valid[IDX] & vol_attrs.vol_attrs.capabilities[IDX] & MASK != 0)
}

#[tracing::instrument(level = "trace", skip_all, fields(flags), err)]
fn set_flags(file: &File, flags: libc::c_uint) -> io::Result<()> {
    let rc =
        // SAFETY: fd is valid
        unsafe { libc::fchflags(file.as_raw_fd(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    /// Total number of files scanned
    pub files: AtomicU64,
    /// Total of all file sizes (uncompressed)
    pub total_file_sizes: AtomicU64,

    pub compressed_size_start: AtomicU64,
    /// Total of all file sizes (after compression) after performing this operation
    pub compressed_size_final: AtomicU64,
    /// Number of files that were compressed before performing this operation
    pub compressed_file_count_start: AtomicU64,
    /// Number of files that were compressed after performing this operation
    pub compressed_file_count_final: AtomicU64,

    /// Number of files that were incompressible (only present when compressing)
    pub incompressible_file_count: AtomicU64,
}

impl Stats {
    fn add_start_file(&self, metadata: &Metadata, file_info: &FileInfo) {
        self.files
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_file_sizes
            .fetch_add(metadata.len(), std::sync::atomic::Ordering::Relaxed);
        self.compressed_size_start
            .fetch_add(file_info.on_disk_size, std::sync::atomic::Ordering::Relaxed);
        match file_info.compression_state {
            FileCompressionState::Compressed => {
                self.compressed_file_count_start
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            FileCompressionState::Compressible => {}
            FileCompressionState::Incompressible(_) => {
                self.incompressible_file_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn add_end_file(&self, _metadata: &Metadata, file_info: &FileInfo) {
        self.compressed_size_final
            .fetch_add(file_info.on_disk_size, std::sync::atomic::Ordering::Relaxed);
        if let FileCompressionState::Compressed = file_info.compression_state {
            self.compressed_file_count_final
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn compression_savings(&self) -> f64 {
        let total_file_sizes = self
            .total_file_sizes
            .load(std::sync::atomic::Ordering::Relaxed);
        let compressed_size = self
            .compressed_size_final
            .load(std::sync::atomic::Ordering::Relaxed);
        if total_file_sizes == 0 {
            0.0
        } else {
            1.0 - (compressed_size as f64 / total_file_sizes as f64)
        }
    }

    #[must_use]
    pub fn compression_change_portion(&self) -> f64 {
        let compressed_size_start = self
            .compressed_size_start
            .load(std::sync::atomic::Ordering::Relaxed);
        let compressed_size_final = self
            .compressed_size_final
            .load(std::sync::atomic::Ordering::Relaxed);
        // This is reversed because we're looking at the change in compression:
        // we want a smaller final size to be a positive change in compression
        if compressed_size_start == 0 {
            0.0
        } else {
            (compressed_size_start as f64 - compressed_size_final as f64)
                / compressed_size_start as f64
        }
    }
}

#[derive(Default)]
pub struct FileCompressor {
    bg_threads: BackgroundThreads,
}

impl FileCompressor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[tracing::instrument(skip_all)]
    pub fn recursive_compress<'a, P>(
        &mut self,
        paths: impl IntoIterator<Item = &'a Path>,
        kind: Kind,
        minimum_compression_ratio: f64,
        level: u32,
        progress: &P,
        verify: bool,
    ) -> Stats
    where
        P: Progress + Send + Sync,
        P::Task: Send + Sync + 'static,
    {
        // Opt-in native backends must verify before publishing the staged file,
        // including callers using the library rather than our CLI.
        let verify = verify || kind == Kind::Lzbitmap;
        self.bg_threads.scan(
            Mode::Compress {
                kind,
                level,
                minimum_compression_ratio,
            },
            paths,
            progress,
            verify,
        )
    }

    #[tracing::instrument(skip_all)]
    pub fn recursive_decompress<'a, P>(
        &mut self,
        paths: impl IntoIterator<Item = &'a Path>,
        manual: bool,
        progress: &P,
        verify: bool,
    ) -> Stats
    where
        P: Progress + Send + Sync,
        P::Task: Send + Sync + 'static,
    {
        let mode = if manual {
            Mode::DecompressManually
        } else {
            Mode::DecompressByReading
        };
        self.bg_threads.scan(mode, paths, progress, verify)
    }
}

fn try_read_all<R: Read>(mut r: R, buf: &mut [u8]) -> io::Result<usize> {
    let bulk_read_span = tracing::trace_span!(
        "try_read_all",
        len = buf.len(),
        read_len = tracing::field::Empty,
    );
    let full_len = buf.len();
    let mut remaining = buf;
    loop {
        let _enter = bulk_read_span.enter();
        let n = match r.read(remaining) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        remaining = &mut remaining[n..];
        if remaining.is_empty() {
            return Ok(full_len);
        }
    }
    let read_len = full_len - remaining.len();

    bulk_read_span.record("read_len", read_len);
    Ok(read_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::{SkipReason, Task};
    use crate::volumes::Volumes;
    use std::collections::HashMap;
    use std::os::unix::fs::{symlink, FileTypeExt};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::time::SystemTime;
    use std::{fs, iter};
    use tempfile::TempDir;
    use walkdir::WalkDir;

    #[test]
    fn empty_scan_statistics_are_finite() {
        let stats = Stats::default();
        assert_eq!(stats.compression_savings(), 0.0);
        assert_eq!(stats.compression_change_portion(), 0.0);

        // A scan can account for physical metadata blocks without logical
        // bytes; this must not produce NaN or infinite savings.
        stats.compressed_size_final.store(4096, Ordering::Relaxed);
        assert_eq!(stats.compression_savings(), 0.0);
        assert_eq!(stats.compression_change_portion(), 0.0);
    }

    #[test]
    fn nonempty_scan_statistics_preserve_existing_ratios() {
        let stats = Stats::default();
        stats.total_file_sizes.store(1000, Ordering::Relaxed);
        stats.compressed_size_start.store(800, Ordering::Relaxed);
        stats.compressed_size_final.store(200, Ordering::Relaxed);
        assert_eq!(stats.compression_savings(), 0.8);
        assert_eq!(stats.compression_change_portion(), 0.75);
    }

    struct NoProgress;
    impl Task for NoProgress {
        fn increment(&self, _amt: u64) {}
        fn error(&self, _message: &str) {}
    }
    impl Progress for NoProgress {
        type Task = NoProgress;

        fn error(&self, path: &Path, message: &str) {
            panic!("Expected no errors, got {message} for {path:?}");
        }

        fn file_task(&self, _path: &Path, _size: u64) -> Self::Task {
            NoProgress
        }
    }

    struct MockProgress {
        skip_reasons: Mutex<HashMap<PathBuf, SkipReason>>,
    }
    impl Progress for MockProgress {
        type Task = NoProgress;

        fn error(&self, path: &Path, message: &str) {
            panic!("Expected no errors, got {message} for {path:?}");
        }

        fn file_skipped(&self, path: &Path, why: SkipReason) {
            self.skip_reasons
                .lock()
                .unwrap()
                .insert(path.to_owned(), why);
        }

        fn file_task(&self, _path: &Path, _size: u64) -> Self::Task {
            NoProgress
        }
    }

    #[derive(Default)]
    struct RootErrorProgress {
        errors: Mutex<Vec<(PathBuf, String)>>,
    }

    impl Progress for RootErrorProgress {
        type Task = NoProgress;

        fn error(&self, path: &Path, message: &str) {
            self.errors
                .lock()
                .unwrap()
                .push((path.to_owned(), message.to_owned()));
        }

        fn file_task(&self, _path: &Path, _size: u64) -> Self::Task {
            NoProgress
        }
    }

    #[test]
    fn explicit_missing_root_is_reported_as_an_operation_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.ascf");
        let reporter = RootErrorProgress::default();
        let mut compressor = FileCompressor::new();

        // Decompression of a nonexistent root must fail through Progress::error
        // rather than silently returning zero work and successful statistics.
        compressor.recursive_decompress(iter::once(missing.as_path()), true, &reporter, true);

        let errors = reporter.errors.lock().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, missing);
        assert!(errors[0].1.contains("unable to inspect input root"));
        assert!(!missing.exists());
    }

    #[test]
    fn explicit_link_roots_refuse_restoration_without_touching_targets() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original.txt");
        let symlink_root = dir.path().join("shortcut.txt");
        let hardlink_root = dir.path().join("other-name.txt");
        let directory = dir.path().join("directory");
        let directory_link = dir.path().join("shortcut-dir");
        fs::write(&original, b"unchanged generated test data").unwrap();
        symlink(&original, &symlink_root).unwrap();
        fs::hard_link(&original, &hardlink_root).unwrap();
        fs::create_dir(&directory).unwrap();
        symlink(&directory, &directory_link).unwrap();

        let mut compressor = FileCompressor::new();
        for manual in [false, true] {
            for root in [&symlink_root, &directory_link, &hardlink_root] {
                let reporter = RootErrorProgress::default();
                compressor.recursive_decompress(
                    iter::once(root.as_path()),
                    manual,
                    &reporter,
                    true,
                );
                let errors = reporter.errors.lock().unwrap();
                assert_eq!(errors.len(), 1, "missing error for {}", root.display());
                assert_eq!(&errors[0].0, root);
                assert!(
                    errors[0].1.contains("refusing to restore"),
                    "wrong error for {}: {}",
                    root.display(),
                    errors[0].1
                );
            }
        }
        assert_eq!(
            fs::read(&original).unwrap(),
            b"unchanged generated test data"
        );
        assert!(symlink_root
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(directory_link
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(&hardlink_root).unwrap(),
            fs::read(&original).unwrap()
        );
    }

    #[test]
    fn compression_refuses_explicit_symlink_roots_without_changing_targets() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("outside-file.txt");
        let directory = dir.path().join("outside-directory");
        let nested_file = directory.join("untouched.txt");
        let file_link = dir.path().join("selected-file-link.txt");
        let directory_link = dir.path().join("selected-directory-link");
        let original = vec![b'Q'; 3 * 65_536 + 19];

        fs::create_dir(&directory).unwrap();
        fs::write(&file, &original).unwrap();
        fs::write(&nested_file, &original).unwrap();
        symlink(&file, &file_link).unwrap();
        symlink(&directory, &directory_link).unwrap();

        let mut compressor = FileCompressor::new();
        for root in [&file_link, &directory_link] {
            let reporter = RootErrorProgress::default();
            compressor.recursive_compress(
                iter::once(root.as_path()),
                Kind::default(),
                1.0,
                2,
                &reporter,
                true,
            );
            let errors = reporter.errors.lock().unwrap();
            assert_eq!(errors.len(), 1, "missing compression error for {}", root.display());
            assert_eq!(&errors[0].0, root);
            assert!(
                errors[0].1.contains("refusing to compress a symlink input root"),
                "wrong error for {}: {}",
                root.display(),
                errors[0].1
            );
        }
        for path in [&file, &nested_file] {
            assert_eq!(fs::read(path).unwrap(), original);
            assert!(!info::get(path).unwrap().is_compressed);
        }
        for root in [&file_link, &directory_link] {
            assert!(root.symlink_metadata().unwrap().file_type().is_symlink());
        }
    }

    #[test]
    fn explicit_special_file_roots_refuse_restoration_without_opening_them() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("never-open-this-fifo");
        let socket = dir.path().join("never-open-this-socket");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: this is an isolated temporary directory and the C string is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let _socket_listener = UnixListener::bind(&socket).unwrap();

        let mut compressor = FileCompressor::new();
        for manual in [false, true] {
            for root in [&fifo, &socket] {
                let reporter = RootErrorProgress::default();
                compressor.recursive_decompress(
                    iter::once(root.as_path()),
                    manual,
                    &reporter,
                    true,
                );
                let errors = reporter.errors.lock().unwrap();
                assert_eq!(errors.len(), 1, "missing error for {}", root.display());
                assert_eq!(&errors[0].0, root);
                assert!(
                    errors[0].1.contains("non-regular input root"),
                    "{:?}",
                    errors[0]
                );
            }
        }
        for root in [&fifo, &socket] {
            let reporter = RootErrorProgress::default();
            compressor.recursive_compress(
                iter::once(root.as_path()),
                Kind::default(),
                1.0,
                2,
                &reporter,
                true,
            );
            let errors = reporter.errors.lock().unwrap();
            assert_eq!(errors.len(), 1, "missing compression refusal for {}", root.display());
            assert_eq!(&errors[0].0, root);
            assert!(
                errors[0].1.contains("refusing to compress a non-regular input root"),
                "wrong compression error for {}: {}",
                root.display(),
                errors[0].1
            );
        }
        assert!(fifo.symlink_metadata().unwrap().file_type().is_fifo());
        assert!(socket.exists());
    }

    #[test]
    fn compressed_hardlinks_nested_under_a_directory_cause_restore_failure() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("selected-directory");
        fs::create_dir(&root).unwrap();
        let primary = root.join("compressed.txt");
        let alias = root.join("hardlink.txt");
        let source = vec![b'Z'; 256 * 1024];
        fs::write(&primary, &source).unwrap();

        let mut compressor = FileCompressor::new();
        compressor.recursive_compress(
            iter::once(primary.as_path()),
            Kind::default(),
            1.0,
            2,
            &NoProgress,
            true,
        );
        assert!(info::get(&primary).unwrap().is_compressed);
        fs::hard_link(&primary, &alias).unwrap();

        for manual in [false, true] {
            let reporter = RootErrorProgress::default();
            compressor.recursive_decompress(iter::once(root.as_path()), manual, &reporter, true);
            let errors = reporter.errors.lock().unwrap();
            assert_eq!(
                errors.len(),
                2,
                "hardlinks were silently skipped: {errors:?}"
            );
            for path in [&primary, &alias] {
                assert!(
                    errors.iter().any(|(found, message)| found == path
                        && message.contains("hard-linked compressed file")),
                    "missing refusal for {}: {errors:?}",
                    path.display()
                );
                assert_eq!(fs::read(path).unwrap(), source);
                assert!(info::get(path).unwrap().is_compressed);
            }
        }
    }

    #[test]
    fn uncompressed_nested_hardlinks_remain_safe_skips() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("uncompressed");
        let alias = dir.path().join("uncompressed-link");
        fs::write(&primary, b"unchanged uncompressed hard-linked bytes").unwrap();
        fs::hard_link(&primary, &alias).unwrap();

        let mut compressor = FileCompressor::new();
        let reporter = RootErrorProgress::default();
        compressor.recursive_decompress(iter::once(dir.path()), true, &reporter, true);
        assert!(reporter.errors.lock().unwrap().is_empty());
        assert_eq!(fs::read(&primary).unwrap(), fs::read(&alias).unwrap());
    }

    #[derive(Debug)]
    struct EntryInfo {
        path: PathBuf,
        modified_time: SystemTime,
        content: Option<Vec<u8>>,
    }

    fn assert_entries_equal(old: &[EntryInfo], new: &[EntryInfo]) {
        assert_eq!(old.len(), new.len());
        for (old, new) in old.iter().zip(new.iter()) {
            assert_eq!(old.path, new.path);
            assert_eq!(
                old.modified_time,
                new.modified_time,
                "modified time mismatch at {}",
                old.path.display()
            );
            assert_eq!(
                old.content,
                new.content,
                "content mismatch at {}",
                old.path.display()
            );
        }
    }

    fn recursive_read(dir: &Path) -> Vec<EntryInfo> {
        let mut result = Vec::new();
        for item in WalkDir::new(dir).sort_by_file_name() {
            let item = item.unwrap();
            let metadata = item.metadata().unwrap();
            let modified_time = metadata.modified().unwrap();
            let content = if !item.file_type().is_dir() {
                Some(fs::read(item.path()).unwrap())
            } else {
                None
            };

            result.push(EntryInfo {
                path: item.into_path(),
                modified_time,
                content,
            });
        }
        result
    }

    fn populate_dir(dir: &Path) {
        // Empty file
        fs::write(dir.join("EMPTY"), b"").unwrap();

        // Medium files
        for i in 0u8..=0xFF {
            let p = dir.join(format!("{i}"));
            fs::write(p, vec![i; usize::from(i) * 1024]).unwrap();
        }

        let subdir = dir.join("subdir");
        fs::create_dir(&subdir).unwrap();
        // Tiny Files
        for i in 0u8..=0xFF {
            let p = subdir.join(format!("{i}"));
            fs::write(p, vec![i; usize::from(i)]).unwrap();
        }

        let big_file = dir.join("BIG");
        let mut big_content = Vec::new();
        for i in 0u8..=0xFF {
            big_content.extend_from_slice(&[i; 1234]);
        }
        fs::write(big_file, big_content).unwrap();
    }

    fn compress_folder(compressor_kind: Kind, dir: &Path) {
        let mut uncompressed_file = tempfile::NamedTempFile::new().unwrap();
        uncompressed_file.write_all(&[0; 8 * 1024]).unwrap();
        uncompressed_file.flush().unwrap();
        populate_dir(dir);
        symlink(uncompressed_file.path(), dir.join("symlink")).unwrap();

        let old_contents = recursive_read(dir);

        let mut fc = FileCompressor::new();
        fc.recursive_compress(iter::once(dir), compressor_kind, 1.0, 2, &NoProgress, true);
        std::thread::sleep(std::time::Duration::from_millis(10));

        let new_contents = recursive_read(dir);
        assert_entries_equal(&old_contents, &new_contents);

        let info = info::get_recursive(dir).unwrap();
        // These are very compressible files
        assert!(info.compression_savings_fraction() > 0.5);

        // Expect symlinked file to not be compressed
        assert!(matches!(
            info::get_file_info(
                uncompressed_file.path(),
                &uncompressed_file.as_file().metadata().unwrap(),
                &Volumes::new(),
            )
            .compression_state,
            FileCompressionState::Compressible,
        ));
        assert!(dir.join("symlink").is_symlink());

        // Now Decompress
        let mut fc = FileCompressor::new();
        fc.recursive_decompress(iter::once(dir), true, &NoProgress, true);

        let new_contents = recursive_read(dir);
        assert_entries_equal(&old_contents, &new_contents);
    }

    #[test]
    fn compress_single_file() {
        let mut compressible_file = tempfile::NamedTempFile::new().unwrap();
        compressible_file.write_all(&[0; 16 * 1024]).unwrap();
        compressible_file.flush().unwrap();
        let contents = recursive_read(compressible_file.path());

        let mut fc = FileCompressor::new();
        fc.recursive_compress(
            iter::once(compressible_file.path()),
            Kind::default(),
            1.0,
            2,
            &NoProgress,
            true,
        );

        let new_contents = recursive_read(compressible_file.path());
        assert_entries_equal(&contents, &new_contents);

        let info = info::get_recursive(compressible_file.path()).unwrap();
        // These are very compressible files
        assert!(info.compression_savings_fraction() > 0.5);
    }

    #[test]
    fn compress_dir_and_file() {
        let outer_dir = TempDir::new().unwrap();
        let inner_dir = outer_dir.path().join("inner");
        fs::create_dir(&inner_dir).unwrap();
        populate_dir(&inner_dir);

        let inner_file_path = outer_dir.path().join("file");
        let mut inner_file = File::create(&inner_file_path).unwrap();
        inner_file.write_all(&[0; 16 * 1024]).unwrap();
        inner_file.flush().unwrap();

        let contents = recursive_read(outer_dir.path());

        let mut fc = FileCompressor::new();
        fc.recursive_compress(
            [inner_dir.as_path(), inner_file_path.as_path()],
            Kind::default(),
            1.0,
            2,
            &NoProgress,
            false,
        );

        let new_contents = recursive_read(outer_dir.path());
        assert_entries_equal(&contents, &new_contents);

        let info = info::get_recursive(outer_dir.path()).unwrap();
        // These are very compressible files
        assert!(info.compression_savings_fraction() > 0.5);
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn compress_zlib() {
        let dir = TempDir::new().unwrap();
        compress_folder(Kind::Zlib, dir.path());
    }

    #[cfg(feature = "lzvn")]
    #[test]
    fn compress_lzvn() {
        let dir = TempDir::new().unwrap();
        compress_folder(Kind::Lzvn, dir.path());
    }

    #[cfg(feature = "lzfse")]
    #[test]
    fn compress_lzfse() {
        let dir = TempDir::new().unwrap();
        compress_folder(Kind::Lzfse, dir.path());
    }

    #[test]
    fn compress_with_hardlinks() {
        let dir = TempDir::new().unwrap();
        let orig_file = dir.path().join("test1.txt");
        fs::write(&orig_file, b"fooooooobaaaaar").unwrap();
        let second_file = dir.path().join("test2.txt");
        fs::hard_link(&orig_file, &second_file).unwrap();

        let progress = MockProgress {
            skip_reasons: Mutex::new(HashMap::new()),
        };

        let orig_contents = recursive_read(dir.path());
        let mut fc = FileCompressor::new();
        fc.recursive_compress([dir.path()], Kind::default(), 2.0, 2, &progress, false);
        let next_contents = recursive_read(dir.path());
        assert_entries_equal(&orig_contents, &next_contents);

        let skip_reasons = progress.skip_reasons.into_inner().unwrap();
        assert_eq!(skip_reasons.len(), 2);
        assert!(matches!(skip_reasons[&orig_file], SkipReason::HardLink));
        assert!(matches!(skip_reasons[&second_file], SkipReason::HardLink));

        assert!(!info::get(&orig_file).unwrap().is_compressed);
        assert!(!info::get(&second_file).unwrap().is_compressed);
    }
}
