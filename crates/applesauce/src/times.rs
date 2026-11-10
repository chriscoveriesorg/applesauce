use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::{io, mem, ptr};

#[derive(Copy, Clone)]
pub struct Saved {
    create_time: libc::timespec,
    mod_time: libc::timespec,
    access_time: libc::timespec,
    add_time: libc::timespec,
}

impl Saved {
    fn from_attr_buf(attr_buf: &AttrGetBuf) -> Self {
        assert_eq!(attr_buf.len as usize, size_of_val(attr_buf));
        Self {
            create_time: attr_buf.create_time,
            mod_time: attr_buf.mod_time,
            access_time: attr_buf.access_time,
            add_time: attr_buf.add_time,
        }
    }
}

impl fmt::Debug for Saved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time_debug = |time: &libc::timespec| format!("@{}.{:09}", time.tv_sec, time.tv_nsec);
        f.debug_struct("Saved")
            .field("create_time", &time_debug(&self.create_time))
            .field("mod_time", &time_debug(&self.mod_time))
            .field("access_time", &time_debug(&self.access_time))
            .field("add_time", &time_debug(&self.add_time))
            .finish()
    }
}

#[repr(C, packed(4))]
struct AttrGetBuf {
    len: u32,
    returned_attrs: libc::attribute_set_t,
    create_time: libc::timespec,
    mod_time: libc::timespec,
    access_time: libc::timespec,
    add_time: libc::timespec,
}

#[repr(C, packed(4))]
struct AttrSetBuf {
    create_time: libc::timespec,
    mod_time: libc::timespec,
    access_time: libc::timespec,
    add_time: libc::timespec,
}

pub trait GetSet {
    fn get_times(&self) -> io::Result<Saved>;

    fn reset_times(&self, saved: &Saved) -> io::Result<()>;
}

fn attrlist_get() -> libc::attrlist {
    // SAFETY: libc::attrlist is a POD c struct, zero is a valid value for all fields.
    let mut attrlist: libc::attrlist = unsafe { mem::zeroed() };
    attrlist.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    attrlist.commonattr = libc::ATTR_CMN_RETURNED_ATTRS
        | libc::ATTR_CMN_CRTIME
        | libc::ATTR_CMN_MODTIME
        | libc::ATTR_CMN_ACCTIME
        | libc::ATTR_CMN_ADDEDTIME;
    attrlist
}

fn attrlist_set() -> libc::attrlist {
    // SAFETY: libc::attrlist is a POD c struct, zero is a valid value for all fields.
    let mut attrlist: libc::attrlist = unsafe { mem::zeroed() };
    attrlist.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    attrlist.commonattr = libc::ATTR_CMN_CRTIME
        | libc::ATTR_CMN_MODTIME
        | libc::ATTR_CMN_ACCTIME
        | libc::ATTR_CMN_ADDEDTIME;
    attrlist
}

impl GetSet for File {
    fn get_times(&self) -> io::Result<Saved> {
        let mut attrlist = attrlist_get();

        let mut attr_buf: MaybeUninit<AttrGetBuf> = MaybeUninit::uninit();

        // SAFETY: attr_buf is filled by a successful call
        unsafe {
            let rc = libc::fgetattrlist(
                self.as_raw_fd(),
                ptr::addr_of_mut!(attrlist).cast::<c_void>(),
                attr_buf.as_mut_ptr().cast::<c_void>(),
                size_of::<AttrGetBuf>(),
                libc::FSOPT_PACK_INVAL_ATTRS,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            let attr_buf = attr_buf.assume_init_ref();
            Ok(Saved::from_attr_buf(attr_buf))
        }
    }

    fn reset_times(&self, saved: &Saved) -> io::Result<()> {
        let mut attrlist = attrlist_set();

        let mut attr_buf = AttrSetBuf {
            create_time: saved.create_time,
            mod_time: saved.mod_time,
            access_time: saved.access_time,
            add_time: saved.add_time,
        };

        // Safety: attr_buf is filled by a successful call, the fd is valid
        unsafe {
            let rc = libc::fsetattrlist(
                self.as_raw_fd(),
                ptr::addr_of_mut!(attrlist).cast::<c_void>(),
                ptr::addr_of_mut!(attr_buf).cast::<c_void>(),
                size_of::<AttrSetBuf>(),
                0,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }
}

impl GetSet for CStr {
    fn get_times(&self) -> io::Result<Saved> {
        let mut attrlist = attrlist_get();

        let mut attr_buf: MaybeUninit<AttrGetBuf> = MaybeUninit::uninit();

        // Safety: attr_buf is filled by a successful call
        unsafe {
            let rc = libc::getattrlist(
                self.as_ptr(),
                ptr::addr_of_mut!(attrlist).cast::<c_void>(),
                attr_buf.as_mut_ptr().cast::<c_void>(),
                size_of::<AttrGetBuf>(),
                libc::FSOPT_PACK_INVAL_ATTRS,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            let attr_buf = attr_buf.assume_init_ref();
            Ok(Saved::from_attr_buf(attr_buf))
        }
    }

    fn reset_times(&self, saved: &Saved) -> io::Result<()> {
        let mut attrlist = attrlist_set();

        let mut attr_buf = AttrSetBuf {
            create_time: saved.create_time,
            mod_time: saved.mod_time,
            access_time: saved.access_time,
            add_time: saved.add_time,
        };

        // Safety: attr_buf is filled by a successful call
        unsafe {
            let rc = libc::setattrlist(
                self.as_ptr(),
                ptr::addr_of_mut!(attrlist).cast::<c_void>(),
                ptr::addr_of_mut!(attr_buf).cast::<c_void>(),
                size_of::<AttrSetBuf>(),
                0,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }
}

impl GetSet for Path {
    fn get_times(&self) -> io::Result<Saved> {
        let cstr = CString::new(self.as_os_str().as_bytes())?;
        <CStr as GetSet>::get_times(&cstr)
    }

    fn reset_times(&self, saved: &Saved) -> io::Result<()> {
        let cstr = CString::new(self.as_os_str().as_bytes())?;
        <CStr as GetSet>::reset_times(&cstr, saved)
    }
}

#[tracing::instrument(level = "debug")]
#[inline]
pub fn save_times<F: GetSet + fmt::Debug + ?Sized>(f: &F) -> io::Result<Saved> {
    f.get_times()
}

#[tracing::instrument(level = "debug")]
#[inline]
pub fn reset_times<F: GetSet + fmt::Debug + ?Sized>(f: &F, saved: &Saved) -> io::Result<()> {
    f.reset_times(saved)
}

/// Failures which happen after an atomic file replacement must remain visible to
/// the caller, even though the directory resetter runs in Drop on a worker.
pub(crate) type ResetFailureLog = Arc<Mutex<Vec<(PathBuf, String)>>>;

/// Restore the original directory timestamps when the last writer finishes.
/// Open a no-follow directory descriptor for both capture and restoration.
/// Bound open descriptors by closing each immediately after its operation.
#[derive(Debug)]
pub struct Resetter {
    dir_path: PathBuf,
    dir_dev: u64,
    dir_ino: u64,
    saved_times: Saved,
    activated: AtomicBool,
    failures: Option<ResetFailureLog>,
}

impl Resetter {
    fn open_directory(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    pub fn new(path: &Path, saved_times: Saved) -> io::Result<Self> {
        let dir_file = Self::open_directory(path)?;
        let metadata = dir_file.metadata()?;
        Ok(Self {
            dir_path: path.to_path_buf(),
            dir_dev: metadata.dev(),
            dir_ino: metadata.ino(),
            saved_times,
            activated: AtomicBool::new(false),
            failures: None,
        })
    }

    /// Capture timestamps and inode identity from one descriptor. Restore
    /// opens the path again with O_NOFOLLOW and checks the same inode before
    /// applying the saved times, without retaining thousands of open handles.
    pub(crate) fn capture_with_failure_log(
        path: &Path,
        failures: ResetFailureLog,
    ) -> io::Result<Self> {
        let dir_file = Self::open_directory(path)?;
        let saved_times = save_times(&dir_file)?;
        let metadata = dir_file.metadata()?;
        Ok(Self {
            dir_path: path.to_path_buf(),
            dir_dev: metadata.dev(),
            dir_ino: metadata.ino(),
            saved_times,
            activated: AtomicBool::new(false),
            failures: Some(failures),
        })
    }

    pub fn activate(&self) {
        self.activated
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn reset_if_same_directory(&self) -> io::Result<()> {
        let dir_file = Self::open_directory(&self.dir_path)?;
        let metadata = dir_file.metadata()?;
        if metadata.dev() != self.dir_dev || metadata.ino() != self.dir_ino {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "parent directory changed before timestamp restoration",
            ));
        }
        reset_times(&dir_file, &self.saved_times)
    }

    fn record_reset_result(&self, result: io::Result<()>) {
        if let Err(error) = result {
            let message = format!(
                "unable to restore directory timestamps after publication: {error}"
            );
            if let Some(failures) = &self.failures {
                failures.lock().unwrap().push((self.dir_path.clone(), message));
            } else {
                tracing::error!(path = %self.dir_path.display(), "{message}");
            }
        }
    }
}

impl Drop for Resetter {
    fn drop(&mut self) {
        if self.activated.load(std::sync::atomic::Ordering::Relaxed) {
            self.record_reset_result(self.reset_if_same_directory());
        }
    }
}

#[cfg(test)]
mod resetter_tests {
    use super::{ResetFailureLog, Resetter};
    use std::fs;
    use std::io;
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::sync::{Arc, Mutex};

    #[test]
    fn post_publication_directory_reset_failure_reaches_error_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let failures: ResetFailureLog = Arc::new(Mutex::new(Vec::new()));
        let resetter = Resetter::capture_with_failure_log(dir.path(), Arc::clone(&failures))
            .unwrap();
        resetter.record_reset_result(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic timestamp refusal",
        )));
        let recorded = failures.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, dir.path());
        assert!(recorded[0].1.contains("synthetic timestamp refusal"));
    }

    #[test]
    fn directory_reset_succeeds_on_unchanged_parent() {
        let dir = tempfile::tempdir().unwrap();
        let failures: ResetFailureLog = Arc::new(Mutex::new(Vec::new()));
        let resetter = Resetter::capture_with_failure_log(dir.path(), Arc::clone(&failures))
            .unwrap();
        resetter.activate();
        drop(resetter);
        assert!(failures.lock().unwrap().is_empty());
    }

    #[test]
    fn directory_capture_rejects_symlink_and_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        symlink(dir.path(), &link).unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"generated").unwrap();
        let failures: ResetFailureLog = Arc::new(Mutex::new(Vec::new()));
        assert!(Resetter::capture_with_failure_log(&link, Arc::clone(&failures)).is_err());
        assert!(Resetter::capture_with_failure_log(&file, failures).is_err());
    }

    #[test]
    fn directory_reset_refuses_replaced_parent_path() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("selected");
        let moved = dir.path().join("moved");
        fs::create_dir(&selected).unwrap();
        let failures: ResetFailureLog = Arc::new(Mutex::new(Vec::new()));
        let resetter = Resetter::capture_with_failure_log(&selected, Arc::clone(&failures))
            .unwrap();
        let selected_ino = fs::metadata(&selected).unwrap().ino();
        fs::rename(&selected, &moved).unwrap();
        fs::create_dir(&selected).unwrap();
        assert_ne!(fs::metadata(&selected).unwrap().ino(), selected_ino);
        resetter.activate();
        drop(resetter);
        let errors = failures.lock().unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].1.contains("parent directory changed"));
    }
}
