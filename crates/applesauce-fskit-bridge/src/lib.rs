//! Read-only C ABI to back a separately mounted FSKit file with ASCF bytes.
//! This library does not mount anything or implement APFS decmpfs. Calls do
//! not write, manipulate attributes, or run unknown kernel decoder probes.
#![cfg(unix)]

use applesauce_core::cold_archive::{ArchiveReader, MAX_READ_BYTES};
use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::fd::{FromRawFd, RawFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Mutex;

/// Opaque handle, serialising reads so decoder scratch remains reusable.
pub struct AscfReader {
    inner: Mutex<ArchiveReader<File>>,
}

/// Metadata describes the uncompressed logical file.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AscfInfo {
    pub logical_size: u64,
    pub codec_selector: u32,
    pub reserved: u32,
    pub logical_sha256: [u8; 32],
}

fn posix(code: libc::c_int) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn errno(error: io::Error) -> libc::c_int {
    match error.kind() {
        ErrorKind::InvalidData | ErrorKind::UnexpectedEof => libc::EIO,
        ErrorKind::InvalidInput => libc::EINVAL,
        ErrorKind::PermissionDenied => libc::EACCES,
        ErrorKind::Unsupported => libc::ENOTSUP,
        _ => error.raw_os_error().unwrap_or(libc::EIO),
    }
}

fn guarded(f: impl FnOnce() -> io::Result<()>) -> libc::c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => errno(error),
        Err(_) => libc::EIO,
    }
}

fn open_readonly_fd(fd: RawFd) -> io::Result<File> {
    if fd < 0 {
        return Err(posix(libc::EINVAL));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(posix(libc::EACCES));
    }
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned an owned duplicate. Drop closes it,
    // never the original descriptor supplied by FSKit.
    let file = unsafe { File::from_raw_fd(duplicated) };
    if !file.metadata()?.is_file() {
        return Err(posix(libc::EINVAL));
    }
    Ok(file)
}

/// Open a previously published archive from a dedicated O_RDONLY regular FD.
/// The duplicate retains a shared file offset; reserve the FD for this handle.
/// Returns zero on success, or a positive POSIX errno.
///
/// # Safety
/// out must be writable. Close the returned handle once after readers finish.
#[no_mangle]
pub unsafe extern "C" fn ascf_open_fd(fd: libc::c_int, out: *mut *mut AscfReader) -> libc::c_int {
    if out.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: the caller owns a writable out pointer.
    unsafe { *out = ptr::null_mut() };
    guarded(|| {
        let reader = ArchiveReader::open(open_readonly_fd(fd)?)?;
        let handle = Box::into_raw(Box::new(AscfReader {
            inner: Mutex::new(reader),
        }));
        // SAFETY: out was checked nonnull and remains writable during call.
        unsafe { *out = handle };
        Ok(())
    })
}

/// Fetch logical size, codec selector and whole-file hash without decoding.
///
/// # Safety
/// handle must be live and out must be writable; neither may be freed concurrently.
#[no_mangle]
pub unsafe extern "C" fn ascf_info(handle: *mut AscfReader, out: *mut AscfInfo) -> libc::c_int {
    if handle.is_null() || out.is_null() {
        return libc::EINVAL;
    }
    guarded(|| {
        // SAFETY: live opaque handle is required by the API.
        let reader = unsafe { &*handle }.inner.lock().map_err(|_| posix(libc::EIO))?;
        let info = AscfInfo {
            logical_size: reader.logical_size(),
            codec_selector: reader.codec() as u32,
            reserved: 0,
            logical_sha256: reader.logical_sha256(),
        };
        // SAFETY: caller supplied writable metadata storage.
        unsafe { *out = info };
        Ok(())
    })
}

/// Bounded, authenticated logical pread suitable for FSKit's read handler.
/// Zero bytes at or beyond EOF succeeds. Errors never change caller bytes.
/// Each call is limited to MAX_READ_BYTES; returned errno is always positive.
///
/// # Safety
/// handle must remain live, out_read writable, and destination valid for
/// capacity bytes unless capacity is zero (when null is permitted).
#[no_mangle]
pub unsafe extern "C" fn ascf_pread(
    handle: *mut AscfReader,
    offset: u64,
    destination: *mut u8,
    capacity: usize,
    out_read: *mut usize,
) -> libc::c_int {
    if out_read.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: caller guarantees writable count storage.
    unsafe { *out_read = 0 };
    if handle.is_null() || (destination.is_null() && capacity != 0) || capacity > MAX_READ_BYTES {
        return libc::EINVAL;
    }
    guarded(|| {
        // SAFETY: live opaque handle is required by the API.
        let mut reader = unsafe { &*handle }.inner.lock().map_err(|_| posix(libc::EIO))?;
        let count = reader.logical_size().saturating_sub(offset).min(capacity as u64) as usize;
        if count == 0 {
            return Ok(());
        }
        // SAFETY: non-null and writable destination; count <= capacity. The
        // archive reader decodes into staging memory and copies on success.
        let bytes = unsafe { std::slice::from_raw_parts_mut(destination, count) };
        reader.read_exact_at(offset, bytes)?;
        // SAFETY: caller supplied a writable count pointer.
        unsafe { *out_read = count };
        Ok(())
    })
}

/// Verify every chunk and the total logical SHA-256 before mount publication.
/// This does not guarantee that another process cannot modify the source later.
///
/// # Safety
/// handle must remain live until verification returns.
#[no_mangle]
pub unsafe extern "C" fn ascf_verify_all(handle: *mut AscfReader) -> libc::c_int {
    if handle.is_null() {
        return libc::EINVAL;
    }
    guarded(|| {
        // SAFETY: live opaque handle is required by the API.
        unsafe { &*handle }
            .inner
            .lock()
            .map_err(|_| posix(libc::EIO))?
            .verify_all()
    })
}

/// Release the duplicated FD and reader scratch.
///
/// # Safety
/// Close a live handle once after every concurrent read has finished.
#[no_mangle]
pub unsafe extern "C" fn ascf_close(handle: *mut AscfReader) {
    if !handle.is_null() {
        // SAFETY: caller transfers ownership exactly once.
        drop(unsafe { Box::from_raw(handle) });
    }
}
