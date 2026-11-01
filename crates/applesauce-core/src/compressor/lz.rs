use crate::compressor::{lz_table, CompressorImpl};
use crate::decmpfs::BlockInfo;
use std::alloc;
use std::io;
use std::marker::PhantomData;
use std::ptr::NonNull;

macro_rules! cached_size {
    ($size:expr) => {{
        static CACHED_SIZE: ::std::sync::atomic::AtomicUsize =
            ::std::sync::atomic::AtomicUsize::new(0);
        let size = CACHED_SIZE.load(std::sync::atomic::Ordering::Relaxed);
        if size != 0 {
            size
        } else {
            let size = $size;
            debug_assert_ne!(size, 0);
            CACHED_SIZE.store(size, std::sync::atomic::Ordering::Relaxed);
            size
        }
    }};
}
pub(super) use cached_size;

/// An implementation of the LZ compression algorithm.
///
/// # Safety
///
/// Implementations of this trait must
/// - Always return the same size for `scratch_size()`
/// - Only access the up to `scratch_size()` bytes of the `scratch` buffer
pub unsafe trait Impl {
    const UNCOMPRESSED_PREFIX: Option<u8> = None;

    fn scratch_size() -> usize;

    unsafe fn encode(dst: &mut [u8], src: &[u8], scratch: NonNull<u8>) -> usize;
    unsafe fn decode(dst: &mut [u8], src: &[u8], scratch: NonNull<u8>) -> usize;
}

pub struct Lz<I: Impl> {
    buf: NonNull<u8>,
    _impl: PhantomData<I>,
}

// SAFETY: No interior mutability
unsafe impl<I: Impl> Send for Lz<I> {}
// SAFETY: No interior mutability
unsafe impl<I: Impl> Sync for Lz<I> {}

impl<I: Impl> Lz<I> {
    pub fn new() -> Self {
        let layout = Self::layout();
        assert!(layout.size() > 0);

        // SAFETY: layout is non-zero sized
        let buf = unsafe { alloc::alloc(layout) };
        let buf = NonNull::new(buf).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        Self {
            buf,
            _impl: PhantomData,
        }
    }

    fn layout() -> alloc::Layout {
        // Ensure at least one byte: not allowed to allocate a zero sized layout
        let size = I::scratch_size().max(1);
        alloc::Layout::from_size_align(size, align_of::<*mut u8>()).unwrap()
    }
}

impl<I: Impl> Drop for Lz<I> {
    fn drop(&mut self) {
        // SAFETY: `self.buf` was allocated with `alloc::alloc`, and `layout` must be constant
        //         because the implementor promised to return a constant scratch size
        unsafe {
            alloc::dealloc(self.buf.as_ptr(), Self::layout());
        }
    }
}

impl<I: Impl> CompressorImpl for Lz<I> {
    fn header_size(block_count: u64) -> u64 {
        lz_table::header_size(block_count)
    }

    fn compress(&mut self, dst: &mut [u8], src: &[u8], _level: u32) -> io::Result<usize> {
        if dst.len() <= src.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "destination must be larger than the uncompressed block",
            ));
        }

        let max_compress_size = if I::UNCOMPRESSED_PREFIX.is_some() {
            src.len()
        } else {
            dst.len()
        };
        // SAFETY:
        // dst is valid to write up to len bytes
        // len is either dst.len() or src.len(), and dst.len() > src.len()
        // src is initialised for len bytes
        // buf is valid to write up to scratch size bytes
        let len = unsafe { I::encode(&mut dst[..max_compress_size], src, self.buf) };
        // A faulty codec must not report bytes beyond the output slice.
        // A debug assertion would panic in development but allow invalid
        // compressed block lengths to reach the writer in release builds.
        if len > max_compress_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ encoder returned more bytes than its destination capacity",
            ));
        }

        if len == 0 {
            let uncompressed_prefix = I::UNCOMPRESSED_PREFIX.ok_or(io::ErrorKind::WriteZero)?;
            tracing::trace!("storing uncompressed data");
            dst[0] = uncompressed_prefix;
            dst[1..][..src.len()].copy_from_slice(src);
            Ok(src.len() + 1)
        } else {
            Ok(len)
        }
    }

    fn decompress(&mut self, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        if src.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        // check if the data was stored uncompressed
        if let Some(uncompressed_prefix) = I::UNCOMPRESSED_PREFIX {
            if src[0] == uncompressed_prefix {
                let src = &src[1..];
                if src.is_empty() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if dst.len() < src.len() {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                dst[..src.len()].copy_from_slice(src);
                return Ok(src.len());
            }
        }
        // SAFETY:
        // dst is valid to write up to len bytes
        // src is initialised for len bytes
        // buf is valid to write up to scratch size bytes
        let len = unsafe { I::decode(dst, src, self.buf) };
        // A full destination may mean truncated decoding. Reject it before
        // returning bytes, including unexpected oversized decoder results.
        // A one-byte destination is therefore insufficient for one byte of
        // compressed output; callers must provide an overflow guard.
        if len == 0 || len >= dst.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(len)
    }

    fn read_block_info<R: io::Read + io::Seek>(
        reader: R,
        orig_file_size: u64,
    ) -> io::Result<Vec<BlockInfo>> {
        lz_table::read_block_info(reader, orig_file_size)
    }

    fn finish<W: io::Write + io::Seek>(writer: W, block_sizes: &[u32]) -> io::Result<()> {
        lz_table::finish(writer, block_sizes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A bounded decoder can legitimately fill the caller's output exactly.
    // The LZ wrapper must report ambiguous truncation without a debug panic.
    struct OneByteDecoder;

    // SAFETY: This test implementation uses no scratch storage and only
    // accesses initialized, in-bounds elements of the caller's buffers.
    unsafe impl Impl for OneByteDecoder {
        fn scratch_size() -> usize {
            0
        }

        unsafe fn encode(_: &mut [u8], _: &[u8], _: NonNull<u8>) -> usize {
            0
        }

        unsafe fn decode(dst: &mut [u8], src: &[u8], _: NonNull<u8>) -> usize {
            if dst.is_empty() || src.is_empty() {
                return 0;
            }
            dst[0] = src[0];
            1
        }
    }

    // Deliberately violate the encoder's output-length contract. Both the
    // stored-marker and direct-encoding paths must fail closed in release
    // builds instead of returning a length outside the provided buffer.
    struct OversizedEncoder<const STORED: bool>;

    // SAFETY: This test implementation does not access scratch or write
    // outside any slice; it only reports a deliberately invalid length.
    unsafe impl<const STORED: bool> Impl for OversizedEncoder<STORED> {
        const UNCOMPRESSED_PREFIX: Option<u8> = if STORED { Some(0x06) } else { None };

        fn scratch_size() -> usize {
            0
        }

        unsafe fn encode(dst: &mut [u8], _: &[u8], _: NonNull<u8>) -> usize {
            dst.len() + 1
        }

        unsafe fn decode(_: &mut [u8], _: &[u8], _: NonNull<u8>) -> usize {
            0
        }
    }

    #[test]
    fn oversized_encoder_result_is_rejected_with_and_without_stored_marker() {
        let input = [0xa5; 8];
        let mut output = [0x5a; 16];

        let error = Lz::<OversizedEncoder<true>>::new()
            .compress(&mut output, &input, 0)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(output, [0x5a; 16]);

        let error = Lz::<OversizedEncoder<false>>::new()
            .compress(&mut output, &input, 0)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(output, [0x5a; 16]);
    }

    #[test]
    fn marker_only_stored_block_is_invalid() {
        let mut compressor = Lz::<OversizedEncoder<true>>::new();
        let mut output = [0xa5; 2];
        let error = compressor.decompress(&mut output, &[0x06]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(output, [0xa5; 2]);

        let size = compressor.decompress(&mut output, &[0x06, 0x41]).unwrap();
        assert_eq!(size, 1);
        assert_eq!(output[0], 0x41);
    }

    #[test]
    fn exact_destination_capacity_reports_error_and_guarded_retry_succeeds() {
        let mut compressor = Lz::<OneByteDecoder>::new();
        let mut exact = [0u8; 1];
        assert_eq!(
            compressor
                .decompress(&mut exact, &[0x41])
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero,
        );

        // The error leaves the scratch allocation usable, and the extra
        // output byte makes the decoded length unambiguous.
        let mut guarded = [0u8; 2];
        assert_eq!(compressor.decompress(&mut guarded, &[0x41]).unwrap(), 1);
        assert_eq!(guarded[0], 0x41);
    }
}
