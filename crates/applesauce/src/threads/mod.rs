use crate::info::{FileCompressionState, FileInfo, IncompressibleReason};
use crate::progress::{self, Progress, SkipReason};
use crate::volumes::Volumes;
use crate::{info, scan, times, Stats};
use applesauce_core::compressor;
use std::collections::HashSet;
use std::fs::Metadata;
use std::io;
use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::{fmt, mem};

pub mod compressing;
pub mod reader;
pub mod writer;

struct ThreadJoiner {
    threads: Vec<JoinHandle<()>>,
}

impl ThreadJoiner {
    fn new(threads: Vec<JoinHandle<()>>) -> Self {
        Self { threads }
    }
}

impl Drop for ThreadJoiner {
    fn drop(&mut self) {
        for handle in self.threads.drain(..) {
            handle.join().unwrap();
        }
    }
}

pub struct BackgroundThreads {
    reader: BgWorker<reader::Work>,
    _compressor: BgWorker<compressing::Work>,
    _writer: BgWorker<writer::Work>,
}

#[derive(Debug)]
pub struct OperationContext {
    mode: Mode,
    stats: Stats,
    finished_stats: crossbeam_channel::Sender<Stats>,
    volumes: Volumes,
    verify: bool,
    pub(crate) directory_timestamp_errors: times::ResetFailureLog,
}

impl OperationContext {
    fn new(
        mode: Mode,
        finished_stats: crossbeam_channel::Sender<Stats>,
        volumes: Volumes,
        verify: bool,
    ) -> Self {
        let directory_timestamp_errors = volumes.timestamp_errors();
        Self {
            mode,
            stats: Stats::default(),
            finished_stats,
            volumes,
            verify,
            directory_timestamp_errors,
        }
    }

    pub fn is_temp_dir(&self, path: &Path) -> bool {
        self.volumes.is_temp_dir(path)
    }
}

impl Drop for OperationContext {
    fn drop(&mut self) {
        // Last file context has completed its parent reset before releasing
        // the operation Arc. Remove all on-volume scratch directories, then
        // restore their parent timestamps and record cleanup failures before
        // waking the caller to drain the shared error ledger.
        self.volumes.finish();
        let stats = mem::take(&mut self.stats);
        let _ = self.finished_stats.send(stats);
    }
}

pub struct Context {
    // Fields are dropped in top-down order, so ensure we update the parent's times before
    // dropping the operation (which will notify that the operation is done if this is the last
    // file).
    parent_resetter: Option<Arc<times::Resetter>>,
    operation: Arc<OperationContext>,
    path: PathBuf,
    progress: Box<dyn progress::Task + Send + Sync>,
    orig_metadata: Metadata,
    orig_compression_info: FileInfo,
    orig_times: times::Saved,
    stats_reported: AtomicBool,
}

impl Context {
    pub fn report_new_stats(&self) {
        let Ok(metadata) = self.path.symlink_metadata() else {
            return;
        };
        let already_reported = self
            .stats_reported
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!already_reported, "stats already reported");

        let file_info = info::get_file_info(&self.path, &metadata, &self.operation.volumes);
        self.operation.stats.add_end_file(&metadata, &file_info);
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self
            .stats_reported
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        self.operation
            .stats
            .add_end_file(&self.orig_metadata, &self.orig_compression_info);
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Mode {
    Compress {
        kind: compressor::Kind,
        minimum_compression_ratio: f64,
        level: u32,
    },
    DecompressManually,
    DecompressByReading,
}

impl Mode {
    pub fn is_compressing(self) -> bool {
        matches!(self, Self::Compress { .. })
    }
}

impl BackgroundThreads {
    #[must_use]
    pub fn new() -> Self {
        let compressor_threads = thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);

        let compressor = BgWorker::new(compressor_threads, &compressing::Work);
        let writer = BgWorker::new(16, &writer::Work);
        let reader = BgWorker::new(
            8,
            &reader::Work {
                compressor: compressor.chan().clone(),
                writer: writer.chan().clone(),
            },
        );
        Self {
            reader,
            _compressor: compressor,
            _writer: writer,
        }
    }

    pub fn scan<'a, P>(
        &self,
        mode: Mode,
        paths: impl IntoIterator<Item = &'a Path>,
        progress: &P,
        verify: bool,
    ) -> Stats
    where
        P: Progress + Send + Sync,
        P::Task: Send + Sync + 'static,
    {
        let (finished_stats, finished_stats_rx) = crossbeam_channel::bounded(1);
        let volumes = Volumes::new();
        let mut walker = scan::Walker::new(progress);
        for path in paths {
            // Never follow an explicitly selected symlink root in either
            // direction. In particular, following a symlink to a directory
            // during compression could walk and replace files outside the
            // tree the caller intended to select.
            let metadata = match path.symlink_metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    // Silently dropping an explicit input can make a partial
                    // compression or restoration appear successful.
                    progress.error(path, &format!("unable to inspect input root: {error}"));
                    continue;
                }
            };
            let action = if mode.is_compressing() {
                "compress"
            } else {
                "restore"
            };
            if metadata.file_type().is_symlink() {
                progress.error(path, &format!("refusing to {action} a symlink input root"));
                continue;
            }
            if !metadata.is_file() && !metadata.is_dir() {
                // A FIFO, device or socket is not a legitimate input root.
                // Reject it before the walker can silently skip or open it.
                progress.error(
                    path,
                    &format!("refusing to {action} a non-regular input root"),
                );
                continue;
            }
            if metadata.is_file() && metadata.nlink() > 1 {
                // Replacing one name of a shared inode would break the link
                // relationship. A directory walk can skip these files, but
                // an explicitly selected hard-linked file must fail visibly
                // instead of letting the CLI report a successful no-op.
                progress.error(
                    path,
                    &format!("refusing to {action} a hard-linked input root"),
                );
                continue;
            }
            // No staging directory means this root cannot be restored safely.
            // Report the preflight failure through Progress so CLI invocations
            // exit nonzero even when scanning would otherwise skip every file.
            if !prepare_root_volume(path, progress, volumes.add_root_dir(path, &metadata)) {
                continue;
            }
            walker.add_path(path);
        }
        let operation = Arc::new(OperationContext::new(mode, finished_stats, volumes, verify));
        let timestamp_errors = Arc::clone(&operation.directory_timestamp_errors);
        let stats = &operation.stats;
        let chan = self.reader.chan();
        // Overlapping directory and explicit-file roots can select the same
        // inode for both compression and restoration. Claim it before queueing
        // either kind of writer to avoid competing atomic replacements.
        let input_claims = Mutex::new(HashSet::new());

        walker.run(&operation, |file_type, path, dir_reset| {
            // We really only want to deal with files, not symlinks to files, or fifos, etc.
            #[allow(clippy::filetype_is_file)]
            if !file_type.is_file() {
                progress.file_skipped(&path, SkipReason::NotFile);
                return;
            }
            let metadata = match path.symlink_metadata() {
                Ok(metadata) => metadata,
                Err(e) => {
                    report_scan_read_error(progress, mode, &path, e);
                    return;
                }
            };
            let link_count = metadata.nlink();
            if link_count > 1 {
                // An uncompressed shared inode can remain an ordinary skip.
                // A compressed inode under a requested directory is work the
                // caller asked us to restore. Refuse it visibly so the CLI
                // cannot exit successfully with compressed data left behind.
                if !mode.is_compressing()
                    && matches!(
                        info::get_compression_state(&path, &metadata, &operation.volumes),
                        FileCompressionState::Compressed
                    )
                {
                    progress.error(&path, "refusing to restore a hard-linked compressed file");
                } else {
                    progress.file_skipped(&path, SkipReason::HardLink);
                }
                return;
            }
            let mut file_info = info::get_file_info(&path, &metadata, &operation.volumes);
            stats.add_start_file(&metadata, &file_info);

            let skip_reason: Option<SkipReason> = match &mut file_info.compression_state {
                FileCompressionState::Compressed => {
                    if mode.is_compressing() {
                        Some(SkipReason::AlreadyCompressed)
                    } else {
                        None
                    }
                }
                FileCompressionState::Compressible => {
                    if mode.is_compressing() {
                        None
                    } else {
                        Some(SkipReason::NotCompressed)
                    }
                }
                FileCompressionState::Incompressible(reason) => {
                    if mode.is_compressing() {
                        // We don't actually need the real reason, so we'll steal the reason here
                        Some(SkipReason::from(mem::replace(
                            reason,
                            IncompressibleReason::Empty,
                        )))
                    } else {
                        // Incompressible describes an uncompressed file that is
                        // ineligible for *compression*, not a file needing
                        // restoration. This includes empty, oversized, and
                        // resource-fork-bearing files in ordinary mixed trees.
                        Some(SkipReason::NotCompressed)
                    }
                }
            };
            if let Some(skip_reason) = skip_reason {
                progress.file_skipped(&path, skip_reason);
                stats.add_end_file(&metadata, &file_info);
                return;
            }
            // A file may appear under multiple requested roots. Only one
            // writer may compress or restore an eligible source inode. Without
            // this guard, two compressors can both stage from the same source
            // and race the final replacement (or report a spurious failure).
            if !claim_input_inode(&input_claims, &metadata) {
                progress.file_skipped(&path, SkipReason::DuplicateInput);
                stats.add_end_file(&metadata, &file_info);
                return;
            }

            let saved_times = match times::save_times(path.as_path()) {
                Ok(saved_times) => saved_times,
                Err(e) => {
                    report_scan_read_error(progress, mode, &path, e);
                    stats.add_end_file(&metadata, &file_info);
                    return;
                }
            };

            let inner_progress = Box::new(progress.file_task(&path, metadata.len()));
            chan.send(reader::WorkItem {
                context: Arc::new(Context {
                    operation: Arc::clone(&operation),
                    path,
                    progress: inner_progress,
                    orig_metadata: metadata,
                    parent_resetter: dir_reset,
                    orig_times: saved_times,
                    orig_compression_info: file_info,
                    stats_reported: AtomicBool::new(false),
                }),
            })
            .unwrap();
        });
        drop(operation);

        // Each file Context drops its parent resetter before releasing the
        // operation reference. By the time the stats sender is dropped, every
        // activated directory reset has completed and any failures are ready.
        let stats = finished_stats_rx
            .recv()
            .expect("OperationContext will send stats on drop of all arcs");
        for (directory, message) in timestamp_errors.lock().unwrap().drain(..) {
            progress.error(&directory, &message);
        }
        stats
    }
}

// Fail closed before queueing work if the selected volume cannot provide a
// staging directory. A warning-only preflight could make a whole restore look
// successful when compression-state discovery later skips its entries.
fn prepare_root_volume<P: Progress>(
    path: &Path,
    progress: &P,
    registration: io::Result<()>,
) -> bool {
    match registration {
        Ok(()) => true,
        Err(error) => {
            progress.error(path, &format!("unable to prepare staging volume: {error}"));
            false
        }
    }
}

// Claim each eligible source inode once across all requested paths, including
// overlapping directory and explicit-file roots, in either operation mode.
fn claim_input_inode(seen: &Mutex<HashSet<(u64, u64)>>, metadata: &Metadata) -> bool {
    seen.lock()
        .unwrap()
        .insert((metadata.dev(), metadata.ino()))
}

// A failed metadata or timestamp read while scanning an input for restoration
// must propagate to the caller. Reporting it only as a skip would allow
// decompress to exit successfully even though a requested file was untouched.
fn report_scan_read_error<P: Progress>(progress: &P, mode: Mode, path: &Path, error: io::Error) {
    if mode.is_compressing() {
        progress.file_skipped(path, SkipReason::ReadError(error));
    } else {
        progress.error(path, &format!("decompression scan failed: {error}"));
    }
}

impl Default for BackgroundThreads {
    fn default() -> Self {
        Self::new()
    }
}

trait WorkHandler<WorkItem> {
    fn handle_item(&mut self, item: WorkItem);
}

trait BgWork {
    type Item: Send + 'static;
    type Handler: WorkHandler<Self::Item> + Send + 'static;

    const NAME: &'static str;

    fn make_handler(&self) -> Self::Handler;
    fn queue_capacity(&self) -> usize {
        1
    }
}

struct BgWorker<Work: BgWork> {
    tx: crossbeam_channel::Sender<Work::Item>,
    _joiner: ThreadJoiner,
}

impl<Work: BgWork> BgWorker<Work> {
    pub fn new(thread_count: usize, work: &Work) -> Self {
        assert!(thread_count > 0);

        let (tx, rx) = crossbeam_channel::bounded(work.queue_capacity());
        let threads: Vec<_> = (0..thread_count)
            .map(|i| {
                let rx = rx.clone();
                let handler = work.make_handler();

                thread::Builder::new()
                    .name(format!("{} {i}", Work::NAME))
                    .spawn(move || handle_fn(rx, handler))
                    .unwrap()
            })
            .collect();

        Self {
            tx,
            _joiner: ThreadJoiner::new(threads),
        }
    }

    pub fn chan(&self) -> &crossbeam_channel::Sender<Work::Item> {
        &self.tx
    }
}

fn handle_fn<WorkItem, Handler: WorkHandler<WorkItem>>(
    rx: crossbeam_channel::Receiver<WorkItem>,
    mut handler: Handler,
) {
    for item in rx {
        handler.handle_item(item);
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("path", &self.path)
            .field("orig_size", &self.orig_metadata.len())
            .field("operation", &self.operation)
            .finish()
    }
}

#[cfg(test)]
mod scan_failure_tests {
    use super::{claim_input_inode, prepare_root_volume, report_scan_read_error, Mode};
    use crate::progress::{Progress, SkipReason, Task};
    use std::collections::HashSet;
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingProgress {
        errors: Mutex<Vec<String>>,
        skips: Mutex<Vec<String>>,
    }

    struct NoTask;

    impl Task for NoTask {
        fn increment(&self, _amount: u64) {}
        fn error(&self, _message: &str) {}
    }

    impl Progress for RecordingProgress {
        type Task = NoTask;

        fn error(&self, _path: &Path, message: &str) {
            self.errors.lock().unwrap().push(message.to_owned());
        }

        fn file_skipped(&self, _path: &Path, reason: SkipReason) {
            self.skips.lock().unwrap().push(reason.to_string());
        }

        fn file_task(&self, _path: &Path, _size: u64) -> Self::Task {
            NoTask
        }
    }

    #[test]
    fn staging_volume_preflight_errors_are_reported_and_reject_roots() {
        let path = Path::new("unavailable-volume");
        let recorder = RecordingProgress::default();
        assert!(!prepare_root_volume(
            path,
            &recorder,
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "temp directory cannot be created",
            )),
        ));
        let errors = recorder.errors.lock().unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("unable to prepare staging volume"));
        assert!(errors[0].contains("temp directory cannot be created"));
        drop(errors);
        assert!(recorder.skips.lock().unwrap().is_empty());

        // Successful volume preparation may proceed to scanning.
        assert!(prepare_root_volume(path, &recorder, Ok(())));
        assert_eq!(recorder.errors.lock().unwrap().len(), 1);
    }

    #[test]
    fn input_claims_are_unique_for_paths_with_the_same_inode() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let alias = dir.path().join("hard-link-alias");
        let separate = dir.path().join("separate");
        fs::write(&source, b"generated input").unwrap();
        fs::hard_link(&source, &alias).unwrap();
        fs::write(&separate, b"generated input").unwrap();
        let seen = Mutex::new(HashSet::new());

        assert!(claim_input_inode(&seen, &fs::metadata(&source).unwrap()));
        assert!(!claim_input_inode(&seen, &fs::metadata(&source).unwrap()));
        assert!(!claim_input_inode(&seen, &fs::metadata(&alias).unwrap()));
        assert!(claim_input_inode(&seen, &fs::metadata(&separate).unwrap()));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn decompression_scan_read_errors_fail_instead_of_succeeding_as_skips() {
        let path = Path::new("disappeared-during-scan");
        let recorder = RecordingProgress::default();
        for mode in [Mode::DecompressManually, Mode::DecompressByReading] {
            report_scan_read_error(
                &recorder,
                mode,
                path,
                io::Error::new(io::ErrorKind::NotFound, "file vanished"),
            );
        }
        assert_eq!(recorder.errors.lock().unwrap().len(), 2);
        assert!(recorder
            .errors
            .lock()
            .unwrap()
            .iter()
            .all(|message| message.contains("file vanished")));
        assert!(recorder.skips.lock().unwrap().is_empty());

        report_scan_read_error(
            &recorder,
            Mode::Compress {
                kind: applesauce_core::compressor::Kind::default(),
                minimum_compression_ratio: 0.95,
                level: 5,
            },
            path,
            io::Error::new(io::ErrorKind::NotFound, "file vanished"),
        );
        assert_eq!(recorder.errors.lock().unwrap().len(), 2);
        assert_eq!(recorder.skips.lock().unwrap().len(), 1);
    }
}
