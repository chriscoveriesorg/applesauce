use crate::decmpfs::{BlockInfo, ZLIB_BLOCK_TABLE_START, ZLIB_TRAILER};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};

pub struct Zlib {
    compressor_level: u32,
    compressor: libdeflater::Compressor,
    decompressor: libdeflater::Decompressor,
}

impl Zlib {
    pub fn new() -> Self {
        let lvl = libdeflater::CompressionLvl::new(12).unwrap();
        Self {
            compressor_level: 12,
            compressor: libdeflater::Compressor::new(lvl),
            decompressor: libdeflater::Decompressor::new(),
        }
    }
}

impl super::CompressorImpl for Zlib {
    fn header_size(block_count: u64) -> u64 {
        ZLIB_BLOCK_TABLE_START + size_of::<u32>() as u64 + block_count * BlockInfo::SIZE as u64
    }

    fn trailer_size() -> u64 {
        u64::try_from(ZLIB_TRAILER.len()).unwrap()
    }

    fn compress(&mut self, dst: &mut [u8], src: &[u8], level: u32) -> io::Result<usize> {
        if dst.len() <= src.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "destination must be larger than the uncompressed block",
            ));
        }

        // The CLI and public API both accept levels 1..=12. Some libdeflate
        // versions accept level 0, so check the contract explicitly.
        if !(1..=12).contains(&level) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zlib compression level must be 1..=12",
            ));
        }

        if self.compressor_level != level {
            let invalid_level = || {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "zlib compression level must be 1..=12",
                )
            };
            let level_i32 = i32::try_from(level).map_err(|_| invalid_level())?;
            let validated_level =
                libdeflater::CompressionLvl::new(level_i32).map_err(|_| invalid_level())?;
            self.compressor = libdeflater::Compressor::new(validated_level);
            self.compressor_level = level;
        }

        let len = match self.compressor.zlib_compress(src, &mut dst[..src.len()]) {
            Ok(len) => len,
            Err(libdeflater::CompressionError::InsufficientSpace) => {
                tracing::trace!("writing uncompressed data");
                dst[0] = 0xff;
                dst[1..][..src.len()].copy_from_slice(src);
                src.len() + 1
            }
        };
        Ok(len)
    }

    fn decompress(&mut self, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        if src.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if src[0] == 0xff {
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
        self.decompressor
            .zlib_decompress(src, dst)
            .map_err(io::Error::other)
    }

    fn read_block_info<R: Read + Seek>(
        mut reader: R,
        orig_file_size: u64,
    ) -> io::Result<Vec<BlockInfo>> {
        let block_count = u32::try_from(crate::num_blocks(orig_file_size)).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "unrepresentable block count")
        })?;

        let total_size = u32::try_from(reader.seek(SeekFrom::End(0))?).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource fork exceeds u32 range",
            )
        })?;
        let data_end = total_size
            .checked_sub(u32::try_from(ZLIB_TRAILER.len()).unwrap())
            .filter(|&end| end >= 0x108)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "resource fork too short"))?;

        // Each block needs a table entry and at least one payload byte.
        // Reject impossible untrusted sizes before reading or allocating.
        let table_end = Self::header_size(u64::from(block_count));
        if table_end
            .checked_add(u64::from(block_count))
            .is_none_or(|min_end| min_end > u64::from(data_end))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "block table and minimum payload extend past compressed data",
            ));
        }

        reader.rewind()?;
        let mut header_buf = [0; HEADER_LEN];
        reader.read_exact(&mut header_buf)?;
        if header_buf != header(data_end) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zlib header does not match expectation",
            ));
        }

        let mut buf = [0; 0x100 - HEADER_LEN];
        reader.read_exact(&mut buf)?;
        if buf.iter().any(|&b| b != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected zeros between header and 0x100",
            ));
        }

        let mut buf = [0; size_of::<u32>()];
        reader.read_exact(&mut buf)?;
        if buf != u32::to_be_bytes(data_end - 0x104) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected data at 0x100",
            ));
        }

        reader.read_exact(&mut buf)?;
        if buf != block_count.to_le_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "block count does not match computed value",
            ));
        }

        // A sparse or forged fork can claim millions of blocks while holding
        // only a short readable prefix. Grow metadata after checking each
        // entry, and report allocation failures instead of panicking.
        let mut result = Vec::new();
        let mut previous_end = table_end as u32;
        let mut buf = [0; BlockInfo::SIZE];
        for _ in 0..block_count {
            reader.read_exact(&mut buf)?;
            let mut block_info = BlockInfo::from_bytes(buf);
            block_info.offset = block_info
                .offset
                .checked_add(ZLIB_BLOCK_TABLE_START as u32)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "block offset overflow")
                })?;
            let block_end = block_info
                .offset
                .checked_add(block_info.compressed_size)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "block end overflow"))?;
            if block_info.compressed_size == 0 || block_info.offset < previous_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty, overlapping, or header-overlapping compressed block",
                ));
            }
            if block_end > data_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "block extends past compressed data",
                ));
            }
            previous_end = block_end;
            result.try_reserve(1).map_err(io::Error::other)?;
            result.push(block_info);
        }

        reader.seek(SeekFrom::Start(data_end.into()))?;
        let mut trailer_buf = [0; ZLIB_TRAILER.len()];
        reader.read_exact(&mut trailer_buf)?;
        if trailer_buf != ZLIB_TRAILER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailer does not match",
            ));
        }

        Ok(result)
    }

    fn finish<W: Write + Seek>(mut writer: W, block_sizes: &[u32]) -> io::Result<()> {
        let block_count =
            u32::try_from(block_sizes.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let data_end =
            u32::try_from(writer.stream_position()?).map_err(|_| io::ErrorKind::InvalidInput)?;

        // Preflight the complete resource-fork layout before writing the
        // trailer or header. The block table must describe exactly the
        // payload written so far, and the trailer must fit 32-bit offsets.
        let block_start = Self::header_size(u64::from(block_count));
        let max_data_end = u64::from(u32::MAX) - Self::trailer_size();
        if block_start > max_data_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zlib resource-fork block table exceeds 32-bit offsets",
            ));
        }
        let expected_data_end = block_sizes.iter().try_fold(block_start, |offset, &size| {
            if size == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "zlib resource-fork blocks must be nonempty",
                ));
            }
            offset
                .checked_add(u64::from(size))
                .filter(|&end| end <= max_data_end)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "zlib resource-fork offsets exceed 32 bits",
                    )
                })
        })?;
        if u64::from(data_end) != expected_data_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zlib resource-fork block lengths do not match written data",
            ));
        }
        let table_start = u32::try_from(block_start - ZLIB_BLOCK_TABLE_START)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        writer.write_all(&ZLIB_TRAILER)?;

        // This is logically a non-modifying operation, even if it takes &mut self, and can fail
        #[allow(clippy::debug_assert_with_mut_call)]
        {
            debug_assert_eq!(
                writer.stream_position()?,
                u64::from(data_end) + Self::trailer_size()
            );
        }

        writer.rewind()?;
        writer.write_all(&header(data_end))?;

        writer.seek(SeekFrom::Start(0x100))?;
        writer.write_all(&u32::to_be_bytes(data_end - 0x104))?;

        writer.write_all(&u32::to_le_bytes(block_count))?;
        let mut current_offset = table_start;
        for &size in block_sizes {
            let block_info = BlockInfo {
                offset: current_offset,
                compressed_size: size,
            };
            writer.write_all(&block_info.to_bytes())?;

            current_offset = current_offset
                .checked_add(size)
                .ok_or_else(|| io::Error::other("offset too large for 32 bytes"))?;
        }

        writer.flush()?;

        // This is logically a non-modifying operation, even if it takes &mut self, and can fail
        #[allow(clippy::debug_assert_with_mut_call)]
        {
            debug_assert_eq!(
                writer.stream_position()?,
                Self::header_size(block_count.into())
            );
        }
        Ok(())
    }
}

const HEADER_LEN: usize = 4 * size_of::<u32>();
fn header(data_end: u32) -> [u8; HEADER_LEN] {
    let mut result = [0; HEADER_LEN];

    let mut writer = &mut result[..];
    writer.write_all(&u32::to_be_bytes(0x100)).unwrap();
    writer.write_all(&u32::to_be_bytes(data_end)).unwrap();
    writer
        .write_all(&u32::to_be_bytes(data_end - 0x100))
        .unwrap();
    writer.write_all(&u32::to_be_bytes(0x32)).unwrap();
    assert!(writer.is_empty());

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compressor::tests::compressor_round_trip;
    use crate::compressor::CompressorImpl;
    use crate::BLOCK_SIZE;
    use std::io::Cursor;

    #[test]
    fn marker_only_stored_block_is_invalid() {
        let mut compressor = Zlib::new();
        let mut output = [0xa5; 2];
        let error = compressor.decompress(&mut output, &[0xff]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(output, [0xa5; 2]);

        let size = compressor.decompress(&mut output, &[0xff, 0x41]).unwrap();
        assert_eq!(size, 1);
        assert_eq!(output[0], 0x41);
    }

    #[test]
    fn invalid_level_fails_without_panic_or_state_change() {
        let mut compressor = Zlib::new();
        let input = [0x41; 256];
        let mut output = vec![0xa5; 512];
        for level in [0, 13, u32::MAX] {
            let error = compressor.compress(&mut output, &input, level).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(output.iter().all(|&byte| byte == 0xa5));
        }

        // A rejected level must leave the compressor usable.
        let size = compressor.compress(&mut output, &input, 6).unwrap();
        let mut recovered = [0; 257];
        let decoded = compressor
            .decompress(&mut recovered, &output[..size])
            .unwrap();
        assert_eq!(&recovered[..decoded], &input);
    }

    #[test]
    fn round_trip() {
        let mut compressor = Zlib::new();
        compressor_round_trip(&mut compressor);
    }

    #[test]
    fn extra_size() {
        assert_eq!(Zlib::header_size(0) + Zlib::trailer_size(), 0x13A);
    }

    #[test]
    fn finish() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let block_sizes = &[10, 20, 30, 40, 10];
        let blocks_start = Zlib::header_size(block_sizes.len() as u64);
        let data_end = 110 + blocks_start as u32;
        cursor.set_position(data_end.into());
        // Ensure file is extended to size
        let _ = cursor.write(&[]).unwrap();

        Zlib::finish(&mut cursor, block_sizes).unwrap();
        let len = cursor.get_ref().len() as u64;
        assert_eq!(
            len,
            110 + Zlib::header_size(block_sizes.len() as u64) + Zlib::trailer_size()
        );

        let result = cursor.get_ref();
        assert_eq!(result[..16], header(data_end));
        assert!(result[16..0x100].iter().all(|&b| b == 0));
        assert_eq!(result[0x100..0x104], u32::to_be_bytes(data_end - 0x104));
        assert_eq!(
            result[0x104..0x108],
            u32::to_le_bytes(block_sizes.len() as _)
        );

        cursor.set_position(0);
        let block_info =
            Zlib::read_block_info(&mut cursor, (block_sizes.len() * BLOCK_SIZE) as u64).unwrap();
        let expected_block_info: Vec<BlockInfo> = block_sizes
            .iter()
            .scan(blocks_start as u32, |acc, &size| {
                let offset = *acc;
                *acc += size;
                Some(BlockInfo {
                    offset,
                    compressed_size: size,
                })
            })
            .collect();
        assert_eq!(block_info, expected_block_info);
    }

    #[test]
    fn rejects_short_resource_fork() {
        let mut cursor = Cursor::new(vec![0; ZLIB_TRAILER.len() - 1]);
        assert!(Zlib::read_block_info(&mut cursor, 0).is_err());
    }

    #[test]
    fn rejects_unrepresentable_block_count_without_panicking() {
        let error = Zlib::read_block_info(Cursor::new(Vec::<u8>::new()), u64::MAX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_block_table_without_minimum_payload_before_reading() {
        // A block must occupy at least one byte beyond its table entry.
        // Reject the forged length without reading any filesystem bytes.
        struct SeekOnly(u64);

        impl io::Read for SeekOnly {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("invalid layout must be rejected before reading");
            }
        }

        impl io::Seek for SeekOnly {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                match pos {
                    SeekFrom::End(0) => Ok(self.0),
                    _ => panic!("invalid layout must be rejected before seeking the table"),
                }
            }
        }

        let data_end = u32::try_from(Zlib::header_size(2) + 1).unwrap();
        let reported_len = u64::from(data_end) + Zlib::trailer_size();
        let error =
            Zlib::read_block_info(SeekOnly(reported_len), 2 * BLOCK_SIZE as u64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn sparse_fork_with_huge_claimed_table_rejects_truncated_entries() {
        // Advertise a valid 100-million-block layout with a 264-byte prefix.
        // The reader must fail at the first absent entry without reserving
        // metadata for all claimed blocks.
        struct SparseFork {
            bytes: Cursor<Vec<u8>>,
            reported_len: u64,
        }

        impl io::Read for SparseFork {
            fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
                io::Read::read(&mut self.bytes, dst)
            }
        }

        impl io::Seek for SparseFork {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                match pos {
                    SeekFrom::End(0) => Ok(self.reported_len),
                    other => io::Seek::seek(&mut self.bytes, other),
                }
            }
        }

        let block_count = 100_000_000u32;
        let data_end =
            u32::try_from(Zlib::header_size(u64::from(block_count)) + u64::from(block_count))
                .unwrap();
        let mut prefix = vec![0u8; 0x108];
        prefix[..HEADER_LEN].copy_from_slice(&header(data_end));
        prefix[0x100..0x104].copy_from_slice(&u32::to_be_bytes(data_end - 0x104));
        prefix[0x104..0x108].copy_from_slice(&block_count.to_le_bytes());

        let fork = SparseFork {
            bytes: Cursor::new(prefix),
            reported_len: u64::from(data_end) + Zlib::trailer_size(),
        };
        let error =
            Zlib::read_block_info(fork, u64::from(block_count) * BLOCK_SIZE as u64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_empty_overlapping_and_header_overlapping_blocks() {
        let count = 2;
        let data_end = Zlib::header_size(count) as usize + 8;
        let mut cursor = Cursor::new(vec![0u8; data_end]);
        cursor.set_position(data_end as u64);
        Zlib::finish(&mut cursor, &[4, 4]).unwrap();
        let valid = cursor.into_inner();
        let original_size = 2 * BLOCK_SIZE as u64;
        assert_eq!(
            Zlib::read_block_info(Cursor::new(&valid), original_size)
                .unwrap()
                .len(),
            2
        );

        // The first table entry is at 0x108, with offset and length.
        let mut empty = valid.clone();
        empty[0x10c..0x110].copy_from_slice(&0u32.to_le_bytes());
        assert!(Zlib::read_block_info(Cursor::new(empty), original_size).is_err());

        let mut overlapping = valid.clone();
        let relative = (Zlib::header_size(count) - ZLIB_BLOCK_TABLE_START + 2) as u32;
        overlapping[0x110..0x114].copy_from_slice(&relative.to_le_bytes());
        assert!(Zlib::read_block_info(Cursor::new(overlapping), original_size).is_err());

        let mut header_overlap = valid;
        header_overlap[0x108..0x10c].copy_from_slice(&0u32.to_le_bytes());
        assert!(Zlib::read_block_info(Cursor::new(header_overlap), original_size).is_err());
    }

    #[test]
    fn invalid_finalizer_layout_cannot_modify_the_resource_fork() {
        let block_start = Zlib::header_size(1);
        let original = vec![0xa5; (block_start + 16) as usize];
        for (position, sizes) in [
            (0u64, vec![1u32]),
            (block_start, vec![0]),
            (block_start + 2, vec![1]),
            (block_start + 1, vec![u32::MAX]),
        ] {
            let mut cursor = Cursor::new(original.clone());
            cursor.set_position(position);
            let error = Zlib::finish(&mut cursor, &sizes).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(cursor.get_ref(), &original);
            assert_eq!(cursor.position(), position);
        }
    }

    #[test]
    fn rejects_overflowing_block_offset() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        cursor.set_position(Zlib::header_size(1) + 1);
        let _ = cursor.write(&[]).unwrap();
        Zlib::finish(&mut cursor, &[1]).unwrap();
        cursor.get_mut()[0x108..0x10c].copy_from_slice(&u32::MAX.to_le_bytes());
        cursor.rewind().unwrap();

        assert!(Zlib::read_block_info(&mut cursor, BLOCK_SIZE as u64).is_err());
    }
}
