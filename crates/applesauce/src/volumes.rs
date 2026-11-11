//! Per-volume information

use crate::cstr_from_bytes_until_null;
use crate::times;
use dashmap::{DashMap, DashSet};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{fs, io};
use tempfile::{NamedTempFile, TempDir};

const TEMPDIR_PREFIX: &str = "applesauce_tmp";
const TEMPFILE_PREFIX: &str = "applesauce_tmp";
const ZFS_SUBTYPE: u32 = u32::from_be_bytes(*b"ZFS\0");

// A bare relative file path has an empty parent, which cannot be opened.
// Map it to the current directory when selecting the on-volume scratch area.
fn staging_parent_for_file(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

// A non-system-volume scratch directory lives inside a user-selected tree.
// Creating and deleting it changes the containing directory's timestamps.
// Capture those *before* creation and restore them only after the scratch
// directory has been removed. Any failure must reach CLI progress.
#[derive(Debug)]
struct StagingDirectory {
    temp_dir: Option<TempDir>,
    parent_resetter: Option<times::Resetter>,
    errors: times::ResetFailureLog,
}

impl StagingDirectory {
    fn system(temp_dir: TempDir, errors: times::ResetFailureLog) -> Self {
        Self {
            temp_dir: Some(temp_dir),
            parent_resetter: None,
            errors,
        }
    }

    fn on_volume(parent: &Path, errors: times::ResetFailureLog) -> io::Result<Self> {
        let parent_resetter =
            times::Resetter::capture_with_failure_log(parent, Arc::clone(&errors))?;
        // Even a failed scratch creation may have modified the parent.
        parent_resetter.activate();
        let temp_dir = TempDir::with_prefix_in(TEMPDIR_PREFIX, parent)?;
        Ok(Self {
            temp_dir: Some(temp_dir),
            parent_resetter: Some(parent_resetter),
            errors,
        })
    }

    fn path(&self) -> &Path {
        self.temp_dir.as_ref().expect("staging directory exists").path()
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        // TempDir::drop swallows removal errors; close explicitly so incomplete
        // cleanup cannot be reported to callers as a successful operation.
        if let Some(temp_dir) = self.temp_dir.take() {
            let path = temp_dir.path().to_path_buf();
            if let Err(error) = temp_dir.close() {
                self.errors.lock().unwrap().push((
                    path,
                    format!("unable to remove staging directory: {error}"),
                ));
            }
        }
        // The resetter must run after removal, including on cleanup failures.
        drop(self.parent_resetter.take());
    }
}

#[derive(Debug)]
enum VolumeInfo {
    NoCompression,
    SupportsCompression {
        temp_dir: Option<StagingDirectory>,
    },
}

#[derive(Debug)]
pub struct Volumes {
    infos: DashMap<u64, VolumeInfo>,
    tmp_dirs: DashSet<Box<Path>>,
    directory_timestamp_errors: times::ResetFailureLog,
}

impl Default for Volumes {
    fn default() -> Self {
        Self::new()
    }
}

fn vol_with_file_supports_compression(path: &Path) -> io::Result<bool> {
    let path_cstr = CString::new(path.as_os_str().as_bytes())?;
    let mut statfs_buf = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: path is a valid pointer, and null terminated, statfs_buf is a valid ptr, and is used as an out ptr
    let rc = unsafe { libc::statfs(path_cstr.as_ptr(), statfs_buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: if statfs returned non-zero, we returned already, it should have filled in statfs_buf
    let statfs_buf = unsafe { statfs_buf.assume_init_ref() };
    // TODO: let is_apfs = statfs_buf.f_fstypename.starts_with(APFS_CHARS);
    if statfs_buf.f_fssubtype == ZFS_SUBTYPE {
        return Ok(false);
    }
    let root_path = cstr_from_bytes_until_null(&statfs_buf.f_mntonname)
        .ok_or_else(|| io::Error::other("failed to get root path from statfs"))?;
    crate::vol_supports_compression_cap(root_path)
}

fn system_volinfo(errors: times::ResetFailureLog) -> Option<(u64, VolumeInfo)> {
    let system = match TempDir::with_prefix(TEMPDIR_PREFIX) {
        Ok(system) => system,
        Err(e) => {
            tracing::warn!("failed to create temp dir in system temp dir: {e}");
            return None;
        }
    };
    let system_metadata = match system.path().metadata() {
        Ok(system_metadata) => system_metadata,
        Err(e) => {
            tracing::warn!("failed to get metadata for system temp dir: {e}");
            return None;
        }
    };
    let compression_support = vol_with_file_supports_compression(system.path()).unwrap_or(false);
    let volume_info = if compression_support {
        VolumeInfo::SupportsCompression {
            temp_dir: Some(StagingDirectory::system(system, errors)),
        }
    } else {
        VolumeInfo::NoCompression
    };
    Some((system_metadata.dev(), volume_info))
}

impl Volumes {
    pub fn new() -> Self {
        let infos = DashMap::new();
        let tmp_dirs = DashSet::new();
        let directory_timestamp_errors = Arc::new(Mutex::new(Vec::new()));
        if let Some((dev, vol_info)) = system_volinfo(Arc::clone(&directory_timestamp_errors)) {
            if let VolumeInfo::SupportsCompression {
                temp_dir: Some(dir),
            } = &vol_info
            {
                tmp_dirs.insert(dir.path().into());
            }
            infos.insert(dev, vol_info);
        }
        Self {
            infos,
            tmp_dirs,
            directory_timestamp_errors,
        }
    }

    pub(crate) fn timestamp_errors(&self) -> times::ResetFailureLog {
        Arc::clone(&self.directory_timestamp_errors)
    }

    // Called when all writers have released their OperationContext references.
    // Drop scratch directories and their parent resetters before the completion
    // signal, so subsequent error draining observes any cleanup failure.
    pub(crate) fn finish(&mut self) {
        self.infos.clear();
        self.tmp_dirs.clear();
    }

    fn get_or_insert(
        &self,
        path: &Path,
        metadata: &fs::Metadata,
    ) -> io::Result<dashmap::mapref::one::Ref<'_, u64, VolumeInfo>> {
        let device = metadata.dev();
        // Double lookup, we don't need a write lock if the item is already present
        if let Some(vol_info) = self.infos.get(&device) {
            return Ok(vol_info);
        }
        self.infos
            .entry(device)
            .or_try_insert_with(|| {
                let tempdir_parent = if metadata.is_dir() {
                    path
                } else {
                    let parent = staging_parent_for_file(path);

                    if parent.metadata()?.dev() != device {
                        return Err(io::Error::other(
                            "file on volume has different device than parent",
                        ));
                    }

                    parent
                };
                let compression_support = vol_with_file_supports_compression(path)?;
                let volume_info = if compression_support {
                    let temp_dir = StagingDirectory::on_volume(
                        tempdir_parent,
                        self.timestamp_errors(),
                    )?;
                    self.tmp_dirs.insert(temp_dir.path().into());
                    VolumeInfo::SupportsCompression {
                        temp_dir: Some(temp_dir),
                    }
                } else {
                    VolumeInfo::NoCompression
                };
                Ok(volume_info)
            })
            .map(|ref_mut| ref_mut.downgrade())
    }

    pub fn supports_compression(&self, path: &Path, metadata: &fs::Metadata) -> io::Result<bool> {
        let current = self.get_or_insert(path, metadata)?;
        Ok(matches!(
            current.value(),
            VolumeInfo::SupportsCompression { .. }
        ))
    }

    pub fn add_root_dir(&self, path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
        self.get_or_insert(path, metadata)?;
        Ok(())
    }

    pub fn is_temp_dir(&self, path: &Path) -> bool {
        self.tmp_dirs.contains(path)
    }

    pub fn tempfile_for(&self, path: &Path, metadata: &fs::Metadata) -> io::Result<NamedTempFile> {
        let current = self.get_or_insert(path, metadata)?;
        match current.value() {
            VolumeInfo::NoCompression => {
                Err(io::Error::other("volume does not support compression"))
            }
            VolumeInfo::SupportsCompression { temp_dir } => {
                let dir = match temp_dir {
                    Some(dir) => dir.path(),
                    None => return Err(io::Error::other("no temp dir for volume")),
                };
                let mut builder = tempfile::Builder::new();
                builder.prefix(TEMPFILE_PREFIX);
                if let Some(file_name) = path.file_name() {
                    builder.suffix(file_name);
                }
                builder.tempfile_in(dir)
            }
        }
    }
}

#[cfg(test)]
mod staging_parent_tests {
    use super::staging_parent_for_file;
    use std::path::Path;


    #[test]
    fn external_volume_scratch_restores_parent_after_cleanup() {
        use super::StagingDirectory;
        use std::fs;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, SystemTime};

        let root = tempfile::tempdir().unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_690_000_000);
        fs::File::open(root.path()).unwrap().set_modified(old).unwrap();
        let expected = fs::metadata(root.path()).unwrap().modified().unwrap();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let scratch = StagingDirectory::on_volume(root.path(), Arc::clone(&errors)).unwrap();
        assert!(scratch.path().is_dir());
        let generated = scratch.path().join("payload");
        fs::write(&generated, b"temporary generated content").unwrap();
        drop(scratch);
        assert!(!generated.exists());
        assert_eq!(fs::metadata(root.path()).unwrap().modified().unwrap(), expected);
        assert!(errors.lock().unwrap().is_empty());
    }

    #[test]
    fn scratch_parent_replacement_records_error_without_touching_new_directory() {
        use super::StagingDirectory;
        use std::fs;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, SystemTime};

        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        let moved = root.path().join("moved");
        fs::create_dir(&parent).unwrap();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let scratch = StagingDirectory::on_volume(&parent, Arc::clone(&errors)).unwrap();
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        let marker = SystemTime::UNIX_EPOCH + Duration::from_secs(1_690_100_000);
        fs::File::open(&parent).unwrap().set_modified(marker).unwrap();
        let expected = fs::metadata(&parent).unwrap().modified().unwrap();
        drop(scratch);
        assert_eq!(fs::metadata(&parent).unwrap().modified().unwrap(), expected);
        let errors = errors.lock().unwrap();
        assert_eq!(errors.len(), 2);
        assert!(errors.iter().any(|(_, message)| message.contains("unable to remove staging directory")));
        assert!(errors.iter().any(|(_, message)| message.contains("parent directory changed")));
    }

    #[test]
    fn relative_file_uses_current_directory_for_scratch_parent() {
        assert_eq!(staging_parent_for_file(Path::new("source.txt")), Path::new("."));
        assert_eq!(
            staging_parent_for_file(Path::new("nested/source.txt")),
            Path::new("nested")
        );
        assert_eq!(
            staging_parent_for_file(Path::new("/tmp/source.txt")),
            Path::new("/tmp")
        );
    }
}
