#![cfg(unix)]

#[cfg(target_os = "macos")]
use applesauce_core::apple_buffer::Codec;
#[cfg(target_os = "macos")]
use applesauce_core::cold_archive::write_archive;
use applesauce_core::cold_archive::MIN_CHUNK_BYTES;
use applesauce_fskit_bridge::*;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::fs::FileExt;
use std::ptr;
use tempfile::NamedTempFile;

fn synthetic_header() -> Vec<u8> {
    // Valid versioned index; deliberately invalid Raven payload. Metadata
    // parsing works portably, while a logical read must fail closed.
    let mut b = vec![0u8; 112];
    b[0..8].copy_from_slice(b"ASCF0001");
    b[8..12].copy_from_slice(&0xD05u32.to_le_bytes());
    b[12..16].copy_from_slice(&(MIN_CHUNK_BYTES as u32).to_le_bytes());
    b[16..24].copy_from_slice(&1u64.to_le_bytes());
    b[24..28].copy_from_slice(&1u32.to_le_bytes());
    b[32..64].fill(0x5a);
    b[64..72].copy_from_slice(&112u64.to_le_bytes());
    b[72..76].copy_from_slice(&1u32.to_le_bytes());
    b[76..80].copy_from_slice(&1u32.to_le_bytes());
    b[80..112].fill(0x5a);
    b.push(0x40);
    b
}

fn file_for(data: &[u8]) -> NamedTempFile {
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(data).unwrap();
    temp.as_file_mut().sync_all().unwrap();
    temp
}

fn open_from(temp: &NamedTempFile) -> *mut AscfReader {
    let source = File::open(temp.path()).unwrap();
    let mut handle = ptr::null_mut();
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    assert_eq!(unsafe { ascf_open_fd(source.as_raw_fd(), &mut handle) }, 0);
    assert!(!handle.is_null());
    handle
}

#[test]
fn metadata_and_eof_work_without_decoder() {
    let temp = file_for(&synthetic_header());
    let handle = open_from(&temp);
    let mut info = AscfInfo {
        logical_size: 0,
        codec_selector: 0,
        reserved: 1,
        logical_sha256: [0; 32],
    };
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    assert_eq!(unsafe { ascf_info(handle, &mut info) }, 0);
    assert_eq!(info.logical_size, 1);
    assert_eq!(info.codec_selector, 0xD05);
    assert_eq!(info.reserved, 0);
    assert_eq!(info.logical_sha256, [0x5a; 32]);
    // A parseable header with invalid compressed data must never pass the
    // full verification gate used by FSKit probe and mount.
    // SAFETY: handle was opened above, remains live, and is closed once below.
    assert_ne!(unsafe { ascf_verify_all(handle) }, 0);
    assert_eq!(size_of::<AscfInfo>(), 48);
    let mut bytes = [0xa5u8; 8];
    let mut count = 55;
    for offset in [1, 2, u64::MAX] {
        assert_eq!(
            // SAFETY: test uses live handles and valid output storage; all closes are single-use.
            unsafe { ascf_pread(handle, offset, bytes.as_mut_ptr(), 8, &mut count) },
            0
        );
        assert_eq!(count, 0);
        assert_eq!(bytes, [0xa5; 8]);
    }
    assert_eq!(
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_pread(handle, 0, ptr::null_mut(), 0, &mut count) },
        0
    );
    assert_eq!(count, 0);
    assert_ne!(
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_pread(handle, 0, bytes.as_mut_ptr(), 8, &mut count) },
        0
    );
    assert_eq!(count, 0);
    assert_eq!(bytes, [0xa5; 8]);
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    unsafe { ascf_close(handle) };
}

#[test]
fn refuses_writable_and_nonregular_fd_and_bad_buffers() {
    let temp = file_for(&synthetic_header());
    let mut handle = ptr::NonNull::<AscfReader>::dangling().as_ptr();
    assert_eq!(
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_open_fd(temp.as_file().as_raw_fd(), &mut handle) },
        libc::EACCES
    );
    assert!(handle.is_null());
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    assert_eq!(unsafe { ascf_open_fd(-1, &mut handle) }, libc::EINVAL);
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    assert_eq!(unsafe { ascf_open_fd(-1, ptr::null_mut()) }, libc::EINVAL);
    let mut pipes = [-1; 2];
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    assert_eq!(unsafe { libc::pipe(pipes.as_mut_ptr()) }, 0);
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    assert_eq!(unsafe { ascf_open_fd(pipes[0], &mut handle) }, libc::EINVAL);
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    unsafe {
        libc::close(pipes[0]);
        libc::close(pipes[1]);
    }
    let h = open_from(&temp);
    let mut count = 9usize;
    assert_eq!(
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_pread(h, 0, ptr::null_mut(), 1, &mut count) },
        libc::EINVAL
    );
    assert_eq!(count, 0);
    let mut sentinel = [0xa5; 1];
    assert_eq!(
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_pread(h, 0, sentinel.as_mut_ptr(), 8 * 1024 * 1024 + 1, &mut count) },
        libc::EINVAL
    );
    assert_eq!(count, 0);
    assert_eq!(sentinel, [0xa5]);
    assert_eq!(
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_info(ptr::null_mut(), ptr::null_mut()) },
        libc::EINVAL
    );
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    assert_eq!(unsafe { ascf_verify_all(ptr::null_mut()) }, libc::EINVAL);
    // SAFETY: test uses live handles and valid output storage; all closes are single-use.
    unsafe {
        ascf_close(h);
        ascf_close(ptr::null_mut());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos27_real_codecs_preserve_random_reads_and_reject_late_corruption() {
    for codec in [Codec::Lzraven, Codec::Lzmesh] {
        if !codec.is_supported() {
            continue;
        }
        let mut logical = vec![0u8; MIN_CHUNK_BYTES * 2 + 17];
        for (i, b) in logical.iter_mut().enumerate() {
            *b = if i % 37 < 30 { b'Q' } else { (i % 251) as u8 };
        }
        let mut temp = NamedTempFile::new().unwrap();
        let stats = write_archive(
            logical.as_slice(),
            temp.as_file_mut(),
            logical.len() as u64,
            codec,
            MIN_CHUNK_BYTES,
        )
        .unwrap();
        temp.as_file_mut().sync_all().unwrap();
        let handle = open_from(&temp);
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        assert_eq!(unsafe { ascf_verify_all(handle) }, 0);
        let mut info = AscfInfo {
            logical_size: 0,
            codec_selector: 0,
            reserved: 0,
            logical_sha256: [0; 32],
        };
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        assert_eq!(unsafe { ascf_info(handle, &mut info) }, 0);
        assert_eq!(info.logical_size, logical.len() as u64);
        assert_eq!(info.logical_sha256, stats.logical_sha256);
        let mut observed = [0xa5u8; 40];
        let mut got = 123usize;
        assert_eq!(
            // SAFETY: test uses live handles and valid output storage; all closes are single-use.
            unsafe {
                ascf_pread(
                    handle,
                    (MIN_CHUNK_BYTES - 16) as u64,
                    observed.as_mut_ptr(),
                    40,
                    &mut got,
                )
            },
            0
        );
        assert_eq!(got, 40);
        assert_eq!(
            &observed[..],
            &logical[MIN_CHUNK_BYTES - 16..MIN_CHUNK_BYTES + 24]
        );
        assert_eq!(
            // SAFETY: test uses live handles and valid output storage; all closes are single-use.
            unsafe {
                ascf_pread(
                    handle,
                    (logical.len() - 4) as u64,
                    observed.as_mut_ptr(),
                    40,
                    &mut got,
                )
            },
            0
        );
        assert_eq!(got, 4);
        assert_eq!(&observed[..4], &logical[logical.len() - 4..]);
        // Regression: another process can mutate an ASCF source after the
        // full pre-mount verification. Each subsequent read must authenticate
        // its chunk again and leave caller memory unchanged on corruption.
        let before = std::fs::read(temp.path()).unwrap();
        let second_offset = u64::from_le_bytes(before[112..120].try_into().unwrap());
        assert_eq!(
            temp.as_file()
                .write_at(&[before[second_offset as usize] ^ 0xff], second_offset)
                .unwrap(),
            1
        );
        temp.as_file().sync_all().unwrap();
        let mut late_sentinel = [0xa5u8; 32];
        got = 999;
        assert_ne!(
            // SAFETY: test uses live handles and valid output storage; all closes are single-use.
            unsafe {
                ascf_pread(
                    handle,
                    MIN_CHUNK_BYTES as u64,
                    late_sentinel.as_mut_ptr(),
                    late_sentinel.len(),
                    &mut got,
                )
            },
            0
        );
        assert_eq!(got, 0);
        assert_eq!(late_sentinel, [0xa5; 32]);
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_close(handle) };

        // Start from the valid pre-mutation snapshot so both corruption
        // checks exercise the decoder against independently damaged sources.
        let mut damaged = before;
        let second = u64::from_le_bytes(damaged[112..120].try_into().unwrap()) as usize;
        damaged[second] ^= 0xff;
        let damaged_file = file_for(&damaged);
        let handle = open_from(&damaged_file);
        let mut sentinel = [0xa5u8; 32];
        got = 999;
        assert_ne!(
            // SAFETY: test uses live handles and valid output storage; all closes are single-use.
            unsafe {
                ascf_pread(
                    handle,
                    (MIN_CHUNK_BYTES - 16) as u64,
                    sentinel.as_mut_ptr(),
                    32,
                    &mut got,
                )
            },
            0
        );
        assert_eq!(got, 0);
        assert_eq!(sentinel, [0xa5; 32]);
        // SAFETY: test uses live handles and valid output storage; all closes are single-use.
        unsafe { ascf_close(handle) };
    }
}
