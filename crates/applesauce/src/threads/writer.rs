use crate::threads::{BgWork, Context, Mode, WorkHandler};
use crate::{compressed_payload_is_allowed, seq_queue, set_flags, times, xattr};
use applesauce_core::compressor::Kind;
use applesauce_core::decmpfs;
use resource_fork::ResourceFork;
use std::fs::{File, Metadata};
use std::io::{BufRead, BufReader, BufWriter, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::macos::fs::MetadataExt;
use std::os::unix::fs::MetadataExt as UnixMetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::{cmp, fmt, io, ptr};
use tempfile::NamedTempFile;

/// Compression ratio rejection is an expected skip, not a failed filesystem write.
/// Preserve its identity through io::Error so other writer failures remain visible.
#[derive(Debug)]
struct BelowMinimumRatio(f64);

impl fmt::Display for BelowMinimumRatio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "did not compress to at least {}% of original size",
            self.0 * 100.0
        )
    }
}

impl std::error::Error for BelowMinimumRatio {}

fn record_write_result(progress: &dyn crate::progress::Task, path: &Path, result: &io::Result<()>) {
    match result {
        Ok(()) => {}
        Err(error)
            if error
                .get_ref()
                .is_some_and(|source| source.is::<BelowMinimumRatio>()) => {}
        Err(error) => {
            progress.error(&format!("Error writing {}: {error}", path.display()));
        }
    }
}

// A decmpfs resource-fork payload is compressed storage, not a user-visible
// resource fork to copy to the restored file. Inline compression may coexist
// with a legitimate resource fork, which must survive the restoration.
fn remove_consumed_compression_metadata(
    staged: &File,
    compression_type: decmpfs::CompressionType,
) -> io::Result<()> {
    xattr::remove_if_present(staged, decmpfs::XATTR_NAME)?;
    if matches!(
        compression_type.compression_storage(),
        Some((_, decmpfs::Storage::ResourceFork))
    ) {
        xattr::remove_if_present(staged, resource_fork::XATTR_NAME)?;
    }
    Ok(())
}

// Restoring an APFS-compressed source expands its logical bytes into a
// temporary file on the same volume. Check available blocks before copying
// payloads so a clearly impossible restore fails while the source is intact.
// This is an advisory snapshot: other writers can consume space afterwards,
// and write_all/sync_all must still propagate ENOSPC.
fn require_restore_capacity(
    logical_size: u64,
    blocks_available: u64,
    block_size: u64,
) -> io::Result<()> {
    let bytes_available = u128::from(blocks_available) * u128::from(block_size);
    if u128::from(logical_size) > bytes_available {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "insufficient free space for restoration: need {logical_size} bytes, have {bytes_available} bytes"
            ),
        ));
    }
    Ok(())
}

fn preflight_restore_capacity(stage: &File, logical_size: u64) -> io::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: stage is an open descriptor and stat points to writable storage
    // for the complete statfs structure. Its contents are read only on success.
    if unsafe { libc::fstatfs(stage.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded and initialized the entire result structure.
    let stat = unsafe { stat.assume_init() };
    require_restore_capacity(logical_size, stat.f_bavail, u64::from(stat.f_bsize))
}

pub(super) type Sender = crossbeam_channel::Sender<WorkItem>;

pub(super) struct Chunk {
    pub block: Vec<u8>,
    pub orig_size: u64,
}

pub(super) struct WorkItem {
    pub context: Arc<Context>,
    pub file: Arc<File>,
    pub blocks: seq_queue::Receiver<Chunk, io::Error>,
}

pub(super) struct Work;

impl BgWork for Work {
    type Item = WorkItem;
    type Handler = Handler;
    const NAME: &'static str = "writer";

    fn make_handler(&self) -> Handler {
        Handler::new()
    }

    fn queue_capacity(&self) -> usize {
        4
    }
}

pub(super) struct Handler {
    decomp_xattr_val_buf: Vec<u8>,
}

impl Handler {
    fn new() -> Self {
        Self {
            decomp_xattr_val_buf: Vec::with_capacity(decmpfs::MAX_XATTR_SIZE),
        }
    }

    #[tracing::instrument(level = "debug", skip_all, err)]
    fn write_blocks(
        &mut self,
        context: &Context,
        writer: &mut applesauce_core::writer::Writer<impl applesauce_core::writer::Open>,
        chunks: seq_queue::Receiver<Chunk, io::Error>,
    ) -> io::Result<()> {
        let block_span = tracing::debug_span!("write block");

        let mut total_compressed_size = 0;
        let minimum_compression_ratio = match context.operation.mode {
            Mode::Compress {
                minimum_compression_ratio,
                ..
            } => minimum_compression_ratio,
            _ => unreachable!("write_blocks called in non-compress mode"),
        };
        chunks.try_for_each(|chunk| {
            total_compressed_size += u64::try_from(chunk.block.len()).unwrap();
            if !compressed_payload_is_allowed(
                total_compressed_size,
                context.orig_metadata.len(),
                minimum_compression_ratio,
            ) {
                context.progress.not_compressible_enough(&context.path);
                return Err(io::Error::other(BelowMinimumRatio(
                    minimum_compression_ratio,
                )));
            }

            let Chunk { block, orig_size } = chunk;
            let _enter = block_span.enter();

            writer.add_block(&block)?;
            context.progress.increment(orig_size);
            Ok(())
        })?;
        Ok(())
    }

    fn write_compressed_file(
        &mut self,
        mut item: WorkItem,
        compressor_kind: Kind,
    ) -> io::Result<()> {
        let uncompressed_file_size = item.context.orig_metadata.len();

        let mut tmp_file = tmp_file_for(&item)?;
        copy_xattrs(&item.file, tmp_file.as_file())?;

        let mut writer =
            applesauce_core::writer::Writer::new(compressor_kind, uncompressed_file_size, || {
                BufWriter::new(ResourceFork::new(tmp_file.as_file()))
            })?;

        self.write_blocks(&item.context, &mut writer, item.blocks)?;

        self.decomp_xattr_val_buf.clear();
        writer.finish_decmpfs_data(&mut self.decomp_xattr_val_buf)?;
        {
            let _entered = tracing::debug_span!("set decmpfs xattr").entered();
            xattr::set(
                tmp_file.as_file(),
                decmpfs::XATTR_NAME,
                &self.decomp_xattr_val_buf,
                0,
            )?;
        }

        copy_metadata(&item.file, tmp_file.as_file())?;
        set_flags(
            tmp_file.as_file(),
            item.context.orig_metadata.st_flags() | libc::UF_COMPRESSED,
        )?;

        if item.context.operation.verify {
            let _entered = tracing::info_span!("verify").entered();

            let orig_file = Arc::get_mut(&mut item.file)
                .expect("Reader should drop file before finishing writing blocks, writer should have the only reference");
            let mut orig_file = BufReader::new(orig_file);
            let mut new_file = BufReader::new(tmp_file.as_file_mut());

            orig_file.rewind()?;
            new_file.rewind()?;

            ensure_identical_files(orig_file, new_file).map_err(|e| {
                io::Error::other(format!(
                    "verification failed: {e}, {} unchanged",
                    item.context.path.display()
                ))
            })?;
        }

        let new_file = {
            let _entered = tracing::debug_span!("rename tmp file").entered();
            ensure_source_path_matches_open_file(
                &item.file,
                &item.context.path,
                &item.context.orig_metadata,
            )?;
            tmp_file.persist(&item.context.path)?
        };
        if let Some(resetter) = &item.context.parent_resetter {
            resetter.activate();
        }
        if let Err(e) = times::reset_times(&new_file, &item.context.orig_times) {
            tracing::error!("Unable to reset times: {e}");
        }
        Ok(())
    }

    fn write_uncompressed_file(&mut self, item: WorkItem) -> io::Result<()> {
        let mut tmp_file = tmp_file_for(&item)?;
        copy_xattrs(&item.file, tmp_file.as_file())?;
        let decmpfs_data = xattr::read(
            item.file.as_ref(),
            decmpfs::XATTR_NAME,
            decmpfs::MAX_XATTR_SIZE,
        )?
        .ok_or_else(|| io::Error::other("file is not compressed"))?;
        let header = decmpfs::Value::from_data(&decmpfs_data)?;

        // COPYFILE_XATTR can copy both the decmpfs descriptor and the
        // compressed payload's resource fork. Neither belongs in a restored
        // plain file. Preserve an unrelated resource fork for inline-xattr
        // compression: only resource-fork-backed types consume that fork.
        // Fail before publication when clearing either attribute is denied.
        remove_consumed_compression_metadata(tmp_file.as_file(), header.compression_type)?;
        let expected_size = header.uncompressed_size;
        // Refuse a clearly over-capacity restore before writing staged bytes.
        // The staged destination is on the same volume as the source.
        preflight_restore_capacity(tmp_file.as_file(), expected_size)?;
        let mut written_size = 0u64;

        item.blocks.try_for_each(|chunk| {
            written_size = written_size
                .checked_add(chunk.block.len() as u64)
                .ok_or(io::ErrorKind::InvalidData)?;
            if written_size > expected_size {
                return Err(io::ErrorKind::InvalidData.into());
            }
            tmp_file.write_all(&chunk.block)?;
            // Increment progress by the uncompressed size of the block,
            // not the "original" (compressed) size
            item.context.progress.increment(chunk.block.len() as u64);
            Ok(())
        })?;

        if written_size != expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed size does not match decmpfs metadata",
            ));
        }

        // The --verify flag must also guard decompression publication.
        // Compare the staged plaintext with the kernel-visible logical bytes
        // of the original compressed file before replacing anything. Manual
        // restore can work on older hosts without kernel decoding, but asking
        // for this independent comparison must fail closed on such a host.
        if item.context.operation.verify {
            let _entered = tracing::info_span!("verify restored file").entered();
            let mut original = BufReader::new(item.file.as_ref());
            let mut restored = BufReader::new(tmp_file.as_file_mut());
            original.rewind()?;
            restored.rewind()?;
            ensure_identical_files(original, restored).map_err(|e| {
                io::Error::other(format!(
                    "restored file verification failed: {e}; {} unchanged",
                    item.context.path.display()
                ))
            })?;
        }

        copy_metadata(&item.file, tmp_file.as_file())?;
        set_flags(
            tmp_file.as_file(),
            item.context.orig_metadata.st_flags() & !libc::UF_COMPRESSED,
        )?;

        // Restore the scanned timestamps on staging, before touching the
        // original pathname. A denied metadata update must fail the restore
        // while the original compressed inode is still intact. Resetting
        // timestamps after persist could instead report success with a
        // partially restored metadata state.
        times::reset_times(tmp_file.as_file(), &item.context.orig_times)?;

        // Commit only a fully written, verified and durable staging file,
        // including its restored timestamps.
        tmp_file.as_file().sync_all()?;

        ensure_source_path_matches_open_file(
            &item.file,
            &item.context.path,
            &item.context.orig_metadata,
        )?;
        tmp_file.persist(&item.context.path)?;
        if let Some(resetter) = &item.context.parent_resetter {
            resetter.activate();
        }
        Ok(())
    }
}

impl WorkHandler<WorkItem> for Handler {
    fn handle_item(&mut self, item: WorkItem) {
        let context = Arc::clone(&item.context);
        let _entered = tracing::info_span!("writing file", path=%context.path.display()).entered();

        let res = match context.operation.mode {
            Mode::Compress { kind, .. } => self.write_compressed_file(item, kind),
            Mode::DecompressManually | Mode::DecompressByReading => {
                self.write_uncompressed_file(item)
            }
        };

        // Errors from verification, temporary-file publication, metadata and
        // block decoding must reach CLI progress reporting. The ratio gate
        // is a deliberate non-error skip.
        record_write_result(context.progress.as_ref(), &context.path, &res);
        if res.is_ok() {
            context.report_new_stats();
            let compressing = context.operation.mode.is_compressing();
            let prefix = if compressing { "" } else { "de" };
            tracing::info!("Successfully {prefix}compressed {}", context.path.display());
        }
    }
}

#[tracing::instrument(level="debug", skip_all, err, fields(path=%item.context.path.display()))]
fn tmp_file_for(item: &WorkItem) -> io::Result<NamedTempFile> {
    item.context
        .operation
        .volumes
        .tempfile_for(&item.context.path, &item.context.orig_metadata)
}

#[tracing::instrument(level = "debug", skip_all, err)]
fn copy_xattrs(src: &File, dst: &File) -> io::Result<()> {
    // SAFETY:
    //   src and dst fds are valid
    //   passing null state is allowed
    //   flags are valid
    let rc = unsafe {
        libc::fcopyfile(
            src.as_raw_fd(),
            dst.as_raw_fd(),
            ptr::null_mut(),
            libc::COPYFILE_XATTR,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[tracing::instrument(level = "debug", skip_all, err)]
fn copy_metadata(src: &File, dst: &File) -> io::Result<()> {
    // SAFETY:
    //   src and dst fds are valid
    //   passing null state is allowed
    //   flags are valid
    let rc = unsafe {
        libc::fcopyfile(
            src.as_raw_fd(),
            dst.as_raw_fd(),
            ptr::null_mut(),
            libc::COPYFILE_SECURITY,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// Compare the original scan's source snapshot with both the open descriptor
// and the pathname about to be replaced. Inode identity alone misses edits to
// the same inode (including same-length rewrites) and replacement between scan
// and open. ctime catches ordinary edits even if mtime is restored; atime is
// deliberately excluded because reading the source may update it.
// This is a best-effort race guard, NOT an atomic conditional rename or a
// checksum. An edit after the final stat can still race with publication.
// We intentionally require a regular file, not merely a non-directory.
#[allow(clippy::filetype_is_file)]
fn same_source_snapshot(expected: &Metadata, actual: &Metadata) -> bool {
    actual.file_type().is_file()
        && UnixMetadataExt::dev(expected) == UnixMetadataExt::dev(actual)
        && UnixMetadataExt::ino(expected) == UnixMetadataExt::ino(actual)
        && UnixMetadataExt::nlink(expected) == UnixMetadataExt::nlink(actual)
        && expected.len() == actual.len()
        && UnixMetadataExt::mtime(expected) == UnixMetadataExt::mtime(actual)
        && UnixMetadataExt::mtime_nsec(expected) == UnixMetadataExt::mtime_nsec(actual)
        && UnixMetadataExt::ctime(expected) == UnixMetadataExt::ctime(actual)
        && UnixMetadataExt::ctime_nsec(expected) == UnixMetadataExt::ctime_nsec(actual)
}

pub(super) fn ensure_source_path_matches_open_file(
    source: &File,
    path: &Path,
    scanned: &Metadata,
) -> io::Result<()> {
    let opened = source.metadata()?;
    let current = path.symlink_metadata()?;
    if !same_source_snapshot(scanned, &opened) || !same_source_snapshot(scanned, &current) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source changed during processing; refusing to replace it",
        ));
    }
    Ok(())
}

fn ensure_identical_files<R1: BufRead, R2: BufRead>(mut lhs: R1, mut rhs: R2) -> io::Result<()> {
    loop {
        let l = lhs.fill_buf()?;
        let r = rhs.fill_buf()?;

        if l.is_empty() && r.is_empty() {
            return Ok(());
        }
        if l.is_empty() || r.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Files are not the same size",
            ));
        }

        let min_len = cmp::min(l.len(), r.len());
        let l = &l[..min_len];
        let r = &r[..min_len];

        if l != r {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Files are not identical",
            ));
        }

        lhs.consume(min_len);
        rhs.consume(min_len)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_identical_files, ensure_source_path_matches_open_file, record_write_result,
        require_restore_capacity, BelowMinimumRatio,
    };
    use crate::progress::Task;
    use std::fs::{self, File};
    use std::io::{self, BufReader, Cursor, ErrorKind};
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    #[test]
    fn restore_metadata_cleanup_drops_only_consumed_resource_forks() {
        use applesauce_core::compressor::Kind;
        use applesauce_core::decmpfs::{self, CompressionType, Storage};
        use resource_fork::{ResourceFork, XATTR_NAME};
        use std::io::Write;

        for storage in [Storage::ResourceFork, Storage::Xattr] {
            let staged = tempfile::NamedTempFile::new().unwrap();
            let file = staged.as_file();
            ResourceFork::new(file).write_all(b"generated fork bytes").unwrap();
            assert!(crate::xattr::is_present(file, XATTR_NAME).unwrap());

            super::remove_consumed_compression_metadata(
                file,
                CompressionType::new(Kind::Zlib, storage),
            )
            .unwrap();

            assert_eq!(
                crate::xattr::is_present(file, XATTR_NAME).unwrap(),
                storage == Storage::Xattr,
                "inline compression must preserve an unrelated resource fork"
            );
            assert!(!crate::xattr::is_present(file, decmpfs::XATTR_NAME).unwrap());
        }
    }

    #[test]
    fn publication_guard_rejects_replaced_path_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let moved = dir.path().join("moved");
        fs::write(&path, b"generated original bytes").unwrap();
        let scanned = fs::metadata(&path).unwrap();
        let source = File::open(&path).unwrap();
        ensure_source_path_matches_open_file(&source, &path, &scanned).unwrap();

        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"unrelated replacement").unwrap();
        assert_eq!(
            ensure_source_path_matches_open_file(&source, &path, &scanned)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        fs::remove_file(&path).unwrap();
        symlink(&moved, &path).unwrap();
        assert_eq!(
            ensure_source_path_matches_open_file(&source, &path, &scanned)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn publication_guard_rejects_missing_source_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        fs::write(&path, b"generated original bytes").unwrap();
        let scanned = fs::metadata(&path).unwrap();
        let source = File::open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(
            ensure_source_path_matches_open_file(&source, &path, &scanned)
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn publication_guard_rejects_same_length_source_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let original = b"generated original bytes";
        fs::write(&path, original).unwrap();
        let scanned = fs::metadata(&path).unwrap();
        let source = File::open(&path).unwrap();

        // The pathname and inode remain identical, and the logical size is
        // unchanged. Force a distinct mtime so the test is deterministic on
        // filesystems with coarse timestamp granularity.
        fs::write(&path, vec![b'Z'; original.len()]).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(12_345))
            .unwrap();
        assert_eq!(source.metadata().unwrap().len(), scanned.len());
        assert_eq!(
            ensure_source_path_matches_open_file(&source, &path, &scanned)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn publication_guard_rejects_replacement_between_scan_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let moved = dir.path().join("moved");
        fs::write(&path, b"generated original bytes").unwrap();
        let scanned = fs::metadata(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"generated replacement bytes").unwrap();
        let replacement = File::open(&path).unwrap();
        assert_eq!(
            ensure_source_path_matches_open_file(&replacement, &path, &scanned)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn publication_guard_rejects_new_hard_link_after_scan() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let other = dir.path().join("new-hard-link");
        fs::write(&path, b"generated original bytes").unwrap();
        let scanned = fs::metadata(&path).unwrap();
        let source = File::open(&path).unwrap();
        fs::hard_link(&path, &other).unwrap();
        assert_eq!(
            ensure_source_path_matches_open_file(&source, &path, &scanned)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    fn generated_bytes() -> Vec<u8> {
        (0..(2 * 65536 + 13))
            .map(|index| (index % 251) as u8)
            .collect()
    }

    #[test]
    fn staged_restore_verification_accepts_exact_bytes_with_different_read_buffers() {
        let expected = generated_bytes();
        let original = BufReader::with_capacity(7, Cursor::new(expected.as_slice()));
        let restored = BufReader::with_capacity(4096, Cursor::new(expected.as_slice()));
        ensure_identical_files(original, restored).unwrap();
    }

    #[test]
    fn staged_restore_verification_rejects_corruption_and_length_changes() {
        let expected = generated_bytes();
        let mut corrupted = expected.clone();
        corrupted[65536] ^= 0xff;
        let mut longer = expected.clone();
        longer.push(0x42);

        for (actual, error_kind) in [
            (corrupted.as_slice(), ErrorKind::InvalidData),
            (&expected[..expected.len() - 1], ErrorKind::UnexpectedEof),
            (longer.as_slice(), ErrorKind::UnexpectedEof),
        ] {
            let original = BufReader::with_capacity(7, Cursor::new(expected.as_slice()));
            let restored = BufReader::with_capacity(4096, Cursor::new(actual));
            assert_eq!(
                ensure_identical_files(original, restored)
                    .unwrap_err()
                    .kind(),
                error_kind
            );
        }
    }

    #[test]
    fn restoration_space_preflight_rejects_overcommit_without_overflow() {
        // Exact fit succeeds, but even a one-byte deficit must refuse.
        assert!(require_restore_capacity(8192, 2, 4096).is_ok());
        let err = require_restore_capacity(8193, 2, 4096).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::StorageFull);
        assert!(err.to_string().contains("need 8193 bytes"));
        assert!(require_restore_capacity(1, 0, 4096).is_err());
        assert!(require_restore_capacity(0, 0, 4096).is_ok());

        // Multiply in u128, allowing realistic large logical files and free
        // block counts without an overflowing u64 intermediate.
        assert!(require_restore_capacity(u64::MAX, u64::MAX, 4096).is_ok());
        assert!(require_restore_capacity(u64::MAX, 1, 4096).is_err());
    }

    #[derive(Default)]
    struct RecordingTask(Mutex<Vec<String>>);

    impl Task for RecordingTask {
        fn increment(&self, _amount: u64) {}

        fn error(&self, message: &str) {
            self.0.lock().unwrap().push(message.to_owned());
        }
    }

    #[test]
    fn writer_failures_are_reported_but_expected_ratio_skips_are_not() {
        let progress = RecordingTask::default();
        let file = Path::new("generated-file");

        record_write_result(&progress, file, &Ok(()));
        record_write_result(
            &progress,
            file,
            &Err(io::Error::other(BelowMinimumRatio(0.95))),
        );
        assert!(progress.0.lock().unwrap().is_empty());

        record_write_result(
            &progress,
            file,
            &Err(io::Error::new(
                ErrorKind::InvalidData,
                "restored file verification failed",
            )),
        );
        record_write_result(
            &progress,
            file,
            &Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "temporary file publication denied",
            )),
        );
        let errors = progress.0.lock().unwrap();
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("generated-file"));
        assert!(errors[0].contains("restored file verification failed"));
        assert!(errors[1].contains("temporary file publication denied"));
    }
}
