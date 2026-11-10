use crate::progress::Progress;
use crate::threads::OperationContext;
use crate::times;
use std::fs::FileType;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// jwalk invokes the directory callback concurrently. Keep any failed parent
// timestamp capture in a shared ledger and report it after the walk. Without
// this, an `.ok()` in the callback silently drops the resetter and a successful
// file replacement can change the containing directory's timestamps.
type ResetFailures = Arc<Mutex<Vec<(PathBuf, String)>>>;

fn checked_resetter(
    directory: &Path,
    setup: io::Result<times::Resetter>,
    failures: &Mutex<Vec<(PathBuf, String)>>,
) -> State {
    match setup {
        Ok(resetter) => Some(Arc::new(resetter)),
        Err(error) => {
            failures.lock().unwrap().push((
                directory.to_path_buf(),
                format!("unable to preserve directory timestamps: {error}"),
            ));
            None
        }
    }
}

fn walk_dir_over(
    path: &Path,
    context: Arc<OperationContext>,
    failures: ResetFailures,
) -> jwalk::WalkDirGeneric<((), State)> {
    let walker = jwalk::WalkDirGeneric::new(path);
    walker.process_read_dir(
        move |_depth,
              path: &Path,
              _state,
              entries: &mut Vec<jwalk::Result<jwalk::DirEntry<((), State)>>>| {
            let mut reset_times: Option<State> = None;
            // Remove ignored directories from the list of entries.
            // Also, add the client state to the entry.
            entries.retain_mut(|entry| {
                if let Ok(entry) = entry {
                    if entry.file_type().is_dir() && context.is_temp_dir(&entry.path()) {
                        return false;
                    }
                    #[allow(clippy::filetype_is_file)]
                    if entry.file_type().is_file() {
                        // One failed setup invalidates every regular-file entry
                        // in this directory. Never publish a replacement when
                        // its parent timestamps could not be captured.
                        let reset_times = reset_times.get_or_insert_with(|| {
                            let setup = times::Resetter::capture_with_failure_log(
                                path,
                                Arc::clone(&context.directory_timestamp_errors),
                            );
                            checked_resetter(path, setup, &failures)
                        });
                        if reset_times.is_none() {
                            return false;
                        }
                        entry.client_state.clone_from(reset_times);
                    }
                }
                true
            });
        },
    )
}

type State = Option<Arc<times::Resetter>>;

pub struct Walker<'a, P> {
    paths: Vec<&'a Path>,
    progress: &'a P,
}

impl<'a, P: Progress + Send + Sync> Walker<'a, P> {
    pub fn new(progress: &'a P) -> Self {
        Self {
            paths: Vec::new(),
            progress,
        }
    }

    pub fn add_path(&mut self, path: &'a Path) {
        self.paths.push(path);
    }

    pub fn run(
        self,
        context: &Arc<OperationContext>,
        f: impl Fn(FileType, PathBuf, Option<Arc<times::Resetter>>) + Send + Sync,
    ) {
        for path in self.paths {
            let failures: ResetFailures = Arc::new(Mutex::new(Vec::new()));
            let walker = walk_dir_over(path, Arc::clone(context), Arc::clone(&failures));
            for entry in walker {
                let mut entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        self.progress
                            .error(Path::new("?"), &format!("error scanning: {e}"));
                        continue;
                    }
                };
                let path = entry.path();
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        self.progress
                            .error(&path, &format!("error getting metadata: {e}"));
                        continue;
                    }
                };
                if metadata.is_dir() {
                    continue;
                }
                f(metadata.file_type(), path, entry.client_state.take())
            }
            // A callback failure can occur on another jwalk worker. Make the
            // operation report it even if every affected file was filtered.
            for (directory, message) in failures.lock().unwrap().drain(..) {
                self.progress.error(&directory, &message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::checked_resetter;
    use std::io;
    use std::path::Path;
    use std::sync::Mutex;

    #[test]
    fn failed_parent_timestamp_capture_is_a_visible_error_and_has_no_resetter() {
        let failures = Mutex::new(Vec::new());
        let path = Path::new("/synthetic/protected-directory");
        let resetter = checked_resetter(
            path,
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "timestamp denied")),
            &failures,
        );
        assert!(resetter.is_none());
        let errors = failures.lock().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, path);
        assert!(errors[0].1.contains("timestamp denied"));
    }

    #[test]
    fn accessible_parent_timestamp_capture_retains_resetter() {
        let dir = tempfile::tempdir().unwrap();
        let saved = crate::times::save_times(dir.path()).unwrap();
        let resetter = crate::times::Resetter::new(dir.path(), saved).unwrap();
        let failures = Mutex::new(Vec::new());
        assert!(checked_resetter(dir.path(), Ok(resetter), &failures).is_some());
        assert!(failures.lock().unwrap().is_empty());
    }
}
