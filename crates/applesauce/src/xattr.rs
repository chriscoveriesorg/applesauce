use libc::ssize_t;
use memchr::memchr;
use std::ffi::{c_int, CStr, CString};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::{io, ptr};

const FLAGS: c_int = libc::XATTR_SHOWCOMPRESSION;
// A concurrently changing attribute must not keep a caller spinning forever.
const MAX_XATTR_READ_ATTEMPTS: usize = 8;
// Refuse implausibly large, untrusted listxattr size probes before allocating.
// A 1 MiB budget accommodates many normal attributes and bounds memory use.
const MAX_XATTR_NAMES_BYTES: usize = 1024 * 1024;

pub trait XattrSource {
    unsafe fn get_xattr(&self, xattr_name: &CStr, value: *mut u8, size: usize) -> ssize_t;
    unsafe fn set_xattr(
        &self,
        xattr_name: &CStr,
        value: *const u8,
        size: usize,
        offset: u32,
    ) -> c_int;
    #[allow(unused)]
    unsafe fn remove_xattr(&self, xattr_name: &CStr) -> c_int;
    unsafe fn list_xattr(&self, name_buf: *mut u8, size: usize) -> ssize_t;
}

impl XattrSource for CStr {
    unsafe fn get_xattr(&self, xattr_name: &CStr, value: *mut u8, size: usize) -> ssize_t {
        // SAFETY: self and xattr_name are valid, null terminated strings.
        //         caller must ensure value/size safety
        unsafe {
            libc::getxattr(
                self.as_ptr(),
                xattr_name.as_ptr(),
                value.cast(),
                size,
                0,
                FLAGS,
            )
        }
    }

    unsafe fn set_xattr(
        &self,
        xattr_name: &CStr,
        value: *const u8,
        size: usize,
        offset: u32,
    ) -> c_int {
        // SAFETY: self and xattr_name are valid, null terminated strings.
        //         caller must ensure value/size safety
        unsafe {
            libc::setxattr(
                self.as_ptr(),
                xattr_name.as_ptr(),
                value.cast(),
                size,
                offset,
                FLAGS,
            )
        }
    }

    unsafe fn remove_xattr(&self, xattr_name: &CStr) -> c_int {
        // SAFETY: self and xattr_name are valid, null terminated strings
        unsafe { libc::removexattr(self.as_ptr(), xattr_name.as_ptr(), FLAGS) }
    }

    unsafe fn list_xattr(&self, name_buf: *mut u8, size: usize) -> ssize_t {
        // SAFETY: self and xattr_name are valid, null terminated strings
        //         caller must ensure buf/size safety
        unsafe { libc::listxattr(self.as_ptr(), name_buf.cast(), size, FLAGS) }
    }
}

impl XattrSource for CString {
    unsafe fn get_xattr(&self, xattr_name: &CStr, value: *mut u8, size: usize) -> ssize_t {
        // SAFETY: Defer to cstr impl
        unsafe { self.as_c_str().get_xattr(xattr_name, value, size) }
    }

    unsafe fn set_xattr(
        &self,
        xattr_name: &CStr,
        value: *const u8,
        size: usize,
        offset: u32,
    ) -> c_int {
        // SAFETY: Defer to cstr impl
        unsafe { self.as_c_str().set_xattr(xattr_name, value, size, offset) }
    }

    unsafe fn remove_xattr(&self, xattr_name: &CStr) -> c_int {
        // SAFETY: Defer to cstr impl
        unsafe { self.as_c_str().remove_xattr(xattr_name) }
    }

    unsafe fn list_xattr(&self, name_buf: *mut u8, size: usize) -> ssize_t {
        // SAFETY: Defer to cstr impl
        unsafe { self.as_c_str().list_xattr(name_buf, size) }
    }
}

impl XattrSource for File {
    unsafe fn get_xattr(&self, xattr_name: &CStr, value: *mut u8, size: usize) -> ssize_t {
        // SAFETY:
        //   self.as_raw_fd is a valid fd
        //   xattr_name is valid, null terminated string
        //   caller must ensure value/size safety
        unsafe {
            libc::fgetxattr(
                self.as_raw_fd(),
                xattr_name.as_ptr(),
                value.cast(),
                size,
                0,
                FLAGS,
            )
        }
    }

    unsafe fn set_xattr(
        &self,
        xattr_name: &CStr,
        value: *const u8,
        size: usize,
        offset: u32,
    ) -> c_int {
        // SAFETY:
        //   self.as_raw_fd is a valid fd
        //   xattr_name is valid, null terminated string
        //   caller must ensure value/size safety
        unsafe {
            libc::fsetxattr(
                self.as_raw_fd(),
                xattr_name.as_ptr(),
                value.cast(),
                size,
                offset,
                FLAGS,
            )
        }
    }

    unsafe fn remove_xattr(&self, xattr_name: &CStr) -> c_int {
        // SAFETY:
        //   self.as_raw_fd is a valid fd
        //   xattr_name is valid, null terminated string
        unsafe { libc::fremovexattr(self.as_raw_fd(), xattr_name.as_ptr(), FLAGS) }
    }

    unsafe fn list_xattr(&self, name_buf: *mut u8, size: usize) -> ssize_t {
        // SAFETY:
        //   self.as_raw_fd is a valid fd
        //   xattr_name is valid, null terminated string
        //   caller must ensure buf/size safety
        unsafe { libc::flistxattr(self.as_raw_fd(), name_buf.cast(), size, FLAGS) }
    }
}

pub fn len<F: XattrSource + ?Sized>(f: &F, xattr_name: &CStr) -> io::Result<Option<usize>> {
    // SAFETY:
    // f is valid, xattr_name is a valid pointer and is null terminated
    // value == NULL, size == 0 is allowed to just return the size
    let rc = unsafe { f.get_xattr(xattr_name, ptr::null_mut(), 0) };
    if rc == -1 {
        let last_error = io::Error::last_os_error();
        return if last_error.raw_os_error() == Some(libc::ENOATTR) {
            Ok(None)
        } else {
            Err(last_error)
        };
    }
    Ok(Some(rc as usize))
}

pub fn is_present<F: XattrSource + ?Sized>(f: &F, xattr_name: &CStr) -> io::Result<bool> {
    len(f, xattr_name).map(|len| len.is_some())
}

pub fn set<F: XattrSource + ?Sized>(
    f: &F,
    xattr_name: &CStr,
    data: &[u8],
    offset: u32,
) -> io::Result<()> {
    // SAFETY:
    // f is valid
    // xattr name is valid and null terminated
    // value is valid, writable, and initialized up to `.len()` bytes
    let rc = unsafe { f.set_xattr(xattr_name, data.as_ptr(), data.len(), offset) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Remove an attribute if it exists. Missing attributes are already clean;
/// permission or I/O failures must not be mistaken for successful removal.
pub fn remove_if_present<F: XattrSource + ?Sized>(f: &F, xattr_name: &CStr) -> io::Result<()> {
    // SAFETY: f is a valid xattr source and xattr_name is NUL terminated.
    let rc = unsafe { f.remove_xattr(xattr_name) };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOATTR) {
        Ok(())
    } else {
        Err(error)
    }
}

/// Read an xattr without allocating more than the caller's format permits.
/// A size probe can report untrusted metadata, so enforce the limit before
/// allocating and again after fetching the value.
pub fn read<F: XattrSource + ?Sized>(
    f: &F,
    xattr_name: &CStr,
    max_len: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();

    for _ in 0..MAX_XATTR_READ_ATTEMPTS {
        let len = match len(f, xattr_name)? {
            Some(len) => len,
            None => return Ok(None),
        };
        if len > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xattr exceeds maximum allowed size",
            ));
        }
        if len > buf.len() {
            buf.resize(len, 0);
        }

        // SAFETY:
        // path/xattr_name are valid pointers and are null terminated
        // value == NULL, size == 0 is allowed to just return the size
        let rc = unsafe { f.get_xattr(xattr_name, buf.as_mut_ptr(), buf.len()) };
        if rc < 0 {
            let last_error = io::Error::last_os_error();
            return match last_error.raw_os_error() {
                Some(libc::ERANGE) => continue,
                Some(libc::ENOATTR) => Ok(None),
                _ => Err(last_error),
            };
        }
        let new_len = rc as usize;
        if new_len > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xattr exceeds maximum allowed size",
            ));
        }
        // A prior ERANGE retry may have left a larger buffer. Always
        // return precisely the bytes fetched on this successful attempt.
        if new_len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xattr reader reported more bytes than the destination can hold",
            ));
        }
        buf.truncate(new_len);
        return Ok(Some(buf));
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "xattr kept changing during repeated reads",
    ))
}

fn raw_names<F: XattrSource + ?Sized>(f: &F) -> io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..MAX_XATTR_READ_ATTEMPTS {
        // Safety:
        // it is safe to pass list=null,size=0
        let rc = unsafe { f.list_xattr(ptr::null_mut(), 0) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENOTSUP | libc::EPERM) => Ok(Vec::new()),
                _ => Err(e),
            };
        }
        let size = rc as usize;
        if size > MAX_XATTR_NAMES_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xattr name list exceeds maximum allowed size",
            ));
        }
        if size > buf.len() {
            // Size probes come from the filesystem. Allocate fallibly so an
            // enormous or changing list cannot panic or exhaust memory.
            buf.try_reserve_exact(size - buf.len())
                .map_err(io::Error::other)?;
            buf.resize(size, 0);
        }

        // Safety:
        // buf is valid, and writable for len bytes
        let rc = unsafe { f.list_xattr(buf.as_mut_ptr(), buf.len()) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ERANGE) => continue,
                _ => Err(e),
            };
        }
        let size = rc as usize;
        if size > MAX_XATTR_NAMES_BYTES || size > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xattr name reader returned an invalid length",
            ));
        }
        buf.truncate(size);
        return Ok(buf);
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "xattr names kept changing during repeated reads",
    ))
}

pub fn with_names<T: XattrSource + ?Sized, F: FnMut(&CStr) -> io::Result<()>>(
    file: &T,
    mut f: F,
) -> io::Result<()> {
    let raw_buf = raw_names(file)?;
    let mut raw_buf = &raw_buf[..];

    while !raw_buf.is_empty() {
        let next_end = memchr(b'\0', raw_buf)
            .ok_or_else(|| io::Error::other("expected null terminator in xattr names"))?;
        let end_including_term = next_end + 1;
        let name = CStr::from_bytes_with_nul(&raw_buf[..end_including_term])
            .expect("Found the first null, cannot be interior or missing null char");
        f(name)?;
        raw_buf = &raw_buf[end_including_term..];
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use applesauce_core::decmpfs;
    use std::cell::Cell;

    struct MockXattr {
        data: Vec<u8>,
        reads: Cell<usize>,
    }

    impl XattrSource for MockXattr {
        unsafe fn get_xattr(&self, _: &CStr, value: *mut u8, size: usize) -> ssize_t {
            self.reads.set(self.reads.get() + 1);
            if value.is_null() {
                return self.data.len() as ssize_t;
            }
            if size < self.data.len() {
                return -1;
            }
            // SAFETY: the caller supplied a writable buffer of at least
            // data.len() bytes, checked immediately above.
            unsafe { ptr::copy_nonoverlapping(self.data.as_ptr(), value, self.data.len()) };
            self.data.len() as ssize_t
        }

        unsafe fn set_xattr(&self, _: &CStr, _: *const u8, _: usize, _: u32) -> c_int {
            -1
        }

        unsafe fn remove_xattr(&self, _: &CStr) -> c_int {
            -1
        }

        unsafe fn list_xattr(&self, _: *mut u8, _: usize) -> ssize_t {
            -1
        }
    }

    // Simulate the kernel reporting ERANGE while another writer changes an
    // attribute. These tests use only in-memory generated bytes.
    struct RacingXattr {
        probes: Cell<usize>,
        reads: Cell<usize>,
        lists: Cell<usize>,
        read_failures: usize,
        list_failures: usize,
        shrink_after_first_probe: bool,
    }

    impl RacingXattr {
        fn new(read_failures: usize, list_failures: usize, shrink: bool) -> Self {
            Self {
                probes: Cell::new(0),
                reads: Cell::new(0),
                lists: Cell::new(0),
                read_failures,
                list_failures,
                shrink_after_first_probe: shrink,
            }
        }
    }

    impl XattrSource for RacingXattr {
        unsafe fn get_xattr(&self, _: &CStr, value: *mut u8, size: usize) -> ssize_t {
            if value.is_null() {
                let count = self.probes.get();
                self.probes.set(count + 1);
                return if self.shrink_after_first_probe && count == 0 {
                    4
                } else {
                    2
                };
            }
            let count = self.reads.get();
            self.reads.set(count + 1);
            if count < self.read_failures || size < 2 {
                // SAFETY: macOS's errno accessor returns a valid thread-local pointer.
                unsafe { *libc::__error() = libc::ERANGE };
                return -1;
            }
            // SAFETY: the caller provided at least two writable bytes.
            unsafe { ptr::copy_nonoverlapping(b"ok".as_ptr(), value, 2) };
            2
        }

        unsafe fn set_xattr(&self, _: &CStr, _: *const u8, _: usize, _: u32) -> c_int {
            -1
        }

        unsafe fn remove_xattr(&self, _: &CStr) -> c_int {
            -1
        }

        unsafe fn list_xattr(&self, value: *mut u8, size: usize) -> ssize_t {
            if value.is_null() {
                return 2;
            }
            let count = self.lists.get();
            self.lists.set(count + 1);
            if count < self.list_failures || size < 2 {
                // SAFETY: macOS's errno accessor returns a valid thread-local pointer.
                unsafe { *libc::__error() = libc::ERANGE };
                return -1;
            }
            // SAFETY: the caller provided at least two writable bytes.
            unsafe { ptr::copy_nonoverlapping(c"x".as_ptr().cast(), value, 2) };
            2
        }
    }

    #[test]
    fn shrinking_xattr_after_erange_returns_exact_fetched_bytes() {
        let xattr = RacingXattr::new(1, 0, true);
        let value = read(&xattr, decmpfs::XATTR_NAME, decmpfs::MAX_XATTR_SIZE)
            .unwrap()
            .unwrap();
        assert_eq!(value, b"ok");
        assert_eq!(xattr.probes.get(), 2);
        assert_eq!(xattr.reads.get(), 2);
    }

    #[test]
    fn continuously_changing_xattr_read_has_a_finite_retry_budget() {
        let xattr = RacingXattr::new(usize::MAX, 0, false);
        let error = read(&xattr, decmpfs::XATTR_NAME, decmpfs::MAX_XATTR_SIZE).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(xattr.probes.get(), MAX_XATTR_READ_ATTEMPTS);
        assert_eq!(xattr.reads.get(), MAX_XATTR_READ_ATTEMPTS);
    }

    #[test]
    fn oversized_xattr_name_list_is_rejected_before_fetching() {
        // A forged listxattr size probe must never allocate its claimed
        // storage or invoke the read side of the API.
        struct OversizedNames;
        impl XattrSource for OversizedNames {
            unsafe fn get_xattr(&self, _: &CStr, _: *mut u8, _: usize) -> ssize_t {
                panic!("unrelated xattr lookup")
            }
            unsafe fn set_xattr(&self, _: &CStr, _: *const u8, _: usize, _: u32) -> c_int {
                panic!("unrelated xattr mutation")
            }
            unsafe fn remove_xattr(&self, _: &CStr) -> c_int {
                panic!("unrelated xattr mutation")
            }
            unsafe fn list_xattr(&self, names: *mut u8, _: usize) -> ssize_t {
                assert!(names.is_null(), "oversized name list must not be fetched");
                (MAX_XATTR_NAMES_BYTES + 1) as ssize_t
            }
        }

        let err = raw_names(&OversizedNames).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn continuously_changing_xattr_names_have_a_finite_retry_budget() {
        let xattr = RacingXattr::new(0, usize::MAX, false);
        let error = with_names(&xattr, |_| Ok(())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(xattr.lists.get(), MAX_XATTR_READ_ATTEMPTS);
    }

    #[test]
    fn xattr_name_list_recovers_after_a_single_size_race() {
        let xattr = RacingXattr::new(0, 1, false);
        let mut names = Vec::new();
        with_names(&xattr, |name| {
            names.push(name.to_bytes().to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(names, [b"x".to_vec()]);
        assert_eq!(xattr.lists.get(), 2);
    }

    #[test]
    fn remove_if_present_ignores_missing_xattrs_but_propagates_real_failures() {
        struct RemovalMock {
            errno: Option<c_int>,
            calls: Cell<usize>,
        }

        impl XattrSource for RemovalMock {
            unsafe fn get_xattr(&self, _: &CStr, _: *mut u8, _: usize) -> ssize_t {
                panic!("removal must not probe the attribute")
            }
            unsafe fn set_xattr(&self, _: &CStr, _: *const u8, _: usize, _: u32) -> c_int {
                panic!("removal must not set an attribute")
            }
            unsafe fn remove_xattr(&self, name: &CStr) -> c_int {
                assert_eq!(name, decmpfs::XATTR_NAME);
                self.calls.set(self.calls.get() + 1);
                if let Some(errno) = self.errno {
                    // SAFETY: macOS provides a valid thread-local errno pointer.
                    unsafe { *libc::__error() = errno };
                    -1
                } else {
                    0
                }
            }
            unsafe fn list_xattr(&self, _: *mut u8, _: usize) -> ssize_t {
                panic!("removal must not list attributes")
            }
        }

        for (errno, expected_kind) in [
            (None, None),
            (Some(libc::ENOATTR), None),
            (Some(libc::EPERM), Some(io::ErrorKind::PermissionDenied)),
        ] {
            let source = RemovalMock {
                errno,
                calls: Cell::new(0),
            };
            let result = remove_if_present(&source, decmpfs::XATTR_NAME);
            match expected_kind {
                None => assert!(result.is_ok()),
                Some(kind) => assert_eq!(result.unwrap_err().kind(), kind),
            }
            assert_eq!(source.calls.get(), 1);
        }
    }

    #[test]
    fn oversized_decmpfs_xattr_is_rejected_before_allocation_or_read() {
        let xattr = MockXattr {
            data: vec![0xa5; decmpfs::MAX_XATTR_SIZE + 1],
            reads: Cell::new(0),
        };
        let error = read(&xattr, decmpfs::XATTR_NAME, decmpfs::MAX_XATTR_SIZE).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(xattr.reads.get(), 1, "oversized value must not be fetched");
    }

    #[test]
    fn decmpfs_xattr_at_size_limit_is_read_exactly() {
        let xattr = MockXattr {
            data: vec![0x5a; decmpfs::MAX_XATTR_SIZE],
            reads: Cell::new(0),
        };
        let value = read(&xattr, decmpfs::XATTR_NAME, decmpfs::MAX_XATTR_SIZE)
            .unwrap()
            .unwrap();
        assert_eq!(value, xattr.data);
        assert_eq!(xattr.reads.get(), 2);
    }
}
