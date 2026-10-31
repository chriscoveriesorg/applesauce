//! Native LZBitmap blocks for decmpfs types 13 (inline) and 14 (resource fork).
//!
//! The public buffer selector is `COMPRESSION_LZBITMAP = 0x702`; it is not a
//! decmpfs type number. Resource-fork chunks use the shared LZ offset table.
//! An incompressible chunk is stored as `0xff` followed by its logical bytes.
//!
//! Format evidence: Siguza/fscmp's AppleFSCompression.h and the independent
//! native type-13/14 captures in deploymenttheory/go-apfs-v2's
//! docs/compression-writer.md. Native kernel-readback tests remain required
//! before promoting this opt-in backend to a default.

use super::{lz_table, CompressorImpl};
use crate::apple_buffer::Codec;
use crate::decmpfs::BlockInfo;
use std::io;
use std::sync::OnceLock;

const STORED_MARKER: u8 = 0xff;

pub(super) struct Lzbitmap;

impl Lzbitmap {
    pub(super) fn supported() -> bool {
        static SUPPORTED: OnceLock<bool> = OnceLock::new();
        *SUPPORTED.get_or_init(|| {
            Codec::Lzbitmap.is_supported() && Codec::Lzbitmap.verify_roundtrip().is_ok()
        })
    }

    pub(super) fn new() -> Option<Self> {
        Self::supported().then_some(Self)
    }
}

impl CompressorImpl for Lzbitmap {
    fn header_size(block_count: u64) -> u64 {
        lz_table::header_size(block_count)
    }

    fn compress(&mut self, dst: &mut [u8], src: &[u8], _level: u32) -> io::Result<usize> {
        // Reserve space for the stored marker if the bounded native encoder
        // declines compression. Do not treat Unsupported or other failures as
        // a successfully available codec.
        if dst.len() <= src.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        match Codec::Lzbitmap.encode_into(&mut dst[..src.len()], src) {
            Ok(size) => Ok(size),
            Err(error) if error.kind() == io::ErrorKind::WriteZero => {
                dst[0] = STORED_MARKER;
                dst[1..][..src.len()].copy_from_slice(src);
                Ok(src.len() + 1)
            }
            Err(error) => Err(error),
        }
    }

    fn decompress(&mut self, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        let Some((&first, rest)) = src.split_first() else {
            return Err(io::ErrorKind::UnexpectedEof.into());
        };
        if first == STORED_MARKER {
            if dst.len() < rest.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            dst[..rest.len()].copy_from_slice(rest);
            return Ok(rest.len());
        }

        // Apple's decoder returns a full destination even when output was
        // truncated. Like the other LZ backends, require one spare output byte
        // so callers cannot mistake a successfully decoded prefix for a block.
        let size = Codec::Lzbitmap.decode_into(dst, src)?;
        if size == dst.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(size)
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

    fn native_compressor() -> Lzbitmap {
        Lzbitmap::new().expect("native LZBitmap tests require macOS 12+ and a working buffer codec")
    }

    #[test]
    fn round_trip() {
        super::super::tests::compressor_round_trip(&mut native_compressor());
    }

    #[test]
    fn native_bounded_encoding_falls_back_to_the_stored_marker() {
        let mut compressor = native_compressor();
        let mut encoded = [0; 2];
        let size = compressor.compress(&mut encoded, b"x", 0).unwrap();
        assert_eq!(&encoded[..size], &[0xff, b'x']);
        let mut decoded = [0; 1];
        assert_eq!(compressor.decompress(&mut decoded, &encoded).unwrap(), 1);
        assert_eq!(&decoded, b"x");
    }

    #[test]
    fn small_destination_cannot_hide_truncated_decoding() {
        let mut compressor = native_compressor();
        let input = vec![b'a'; crate::BLOCK_SIZE];
        let mut encoded = vec![0; input.len() + 1];
        let size = compressor.compress(&mut encoded, &input, 0).unwrap();
        assert!(size < input.len());
        encoded.truncate(size);
        for capacity in [1, input.len() - 1, input.len()] {
            assert!(compressor
                .decompress(&mut vec![0; capacity], &encoded)
                .is_err());
        }
        let mut decoded = vec![0; input.len() + 1];
        let size = compressor.decompress(&mut decoded, &encoded).unwrap();
        assert_eq!(&decoded[..size], input);
    }

    #[test]
    fn invalid_or_empty_blocks_are_rejected() {
        let mut compressor = native_compressor();
        assert!(compressor.decompress(&mut [0; 8], &[]).is_err());
        assert!(compressor.decompress(&mut [0; 8], &[0, 1, 2, 3]).is_err());
        assert!(compressor.decompress(&mut [0; 1], &[0xff, 1, 2]).is_err());
        assert!(compressor.compress(&mut [0; 1], &[1], 0).is_err());
    }
}
