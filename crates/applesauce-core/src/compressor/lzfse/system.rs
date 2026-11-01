use crate::compressor::lz;
use std::cmp;
use std::ptr::NonNull;

pub enum Impl {}

const ALGORITHM: u32 = crate::apple_buffer::Codec::Lzfse as u32;

// SAFETY: The system reports a stable scratch size for this fixed algorithm;
// encode/decode access only that scratch allocation and the supplied slices.
unsafe impl lz::Impl for Impl {
    fn scratch_size() -> usize {
        // SAFETY: Both of these functions are always safe to call
        lz::cached_size!(unsafe {
            cmp::max(
                bindings::compression_encode_scratch_buffer_size(ALGORITHM),
                bindings::compression_decode_scratch_buffer_size(ALGORITHM),
            )
        })
    }

    unsafe fn encode(dst: &mut [u8], src: &[u8], scratch: NonNull<u8>) -> usize {
        // SAFETY: Buffers are valid for the specified lengths, and caller must ensure scratch is large enough
        let res = unsafe {
            bindings::compression_encode_buffer(
                dst.as_mut_ptr().cast(),
                dst.len(),
                src.as_ptr().cast(),
                src.len(),
                scratch.as_ptr().cast(),
                ALGORITHM,
            )
        };
        debug_assert!(res <= dst.len());
        res
    }

    unsafe fn decode(dst: &mut [u8], src: &[u8], scratch: NonNull<u8>) -> usize {
        // SAFETY: Buffers are valid for the specified lengths, and caller must ensure scratch is large enough
        let res = unsafe {
            bindings::compression_decode_buffer(
                dst.as_mut_ptr().cast(),
                dst.len(),
                src.as_ptr().cast(),
                src.len(),
                scratch.as_ptr().cast(),
                ALGORITHM,
            )
        };
        debug_assert!(res <= dst.len());
        res
    }
}

mod bindings {
    // Keep the C enum's u32 ABI identical to apple_buffer's declarations.
    // Distinct Rust enum declarations for the same symbols clash when both
    // the system-lzfse and modern buffer modules are built together.

    #[link(name = "compression")]
    extern "C" {
        pub fn compression_encode_scratch_buffer_size(algorithm: u32) -> usize;

        pub fn compression_encode_buffer(
            dst_buffer: *mut u8,
            dst_size: usize,
            src_buffer: *const u8,
            src_size: usize,
            scratch_buffer: *mut ::std::os::raw::c_void,
            algorithm: u32,
        ) -> usize;

        pub fn compression_decode_scratch_buffer_size(algorithm: u32) -> usize;

        pub fn compression_decode_buffer(
            dst_buffer: *mut u8,
            dst_size: usize,
            src_buffer: *const u8,
            src_size: usize,
            scratch_buffer: *mut ::std::os::raw::c_void,
            algorithm: u32,
        ) -> usize;
    }
}
