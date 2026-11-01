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
        debug_assert!(len <= max_compress_size);

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
        debug_assert!(len < dst.len());
        if len == 0 || len == dst.len() {
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
