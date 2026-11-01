//! Shared resource-fork framing for decmpfs LZVN, LZFSE and LZBitmap.
//!
//! Each block expands to at most 64 KiB. The fork starts with `n + 1`
//! little-endian absolute offsets, including the final end-of-fork offset.
//! LZBitmap uses this same layout with decmpfs type 14; type 13 is inline.

use crate::decmpfs::BlockInfo;
use std::io::{self, SeekFrom};

pub(super) fn header_size(block_count: u64) -> u64 {
    (block_count + 1) * size_of::<u32>() as u64
}

pub(super) fn read_block_info<R: io::Read + io::Seek>(
    mut reader: R,
    orig_file_size: u64,
) -> io::Result<Vec<BlockInfo>> {
    reader.rewind()?;
    let block_count = crate::num_blocks(orig_file_size);
    let blocks_start =
        u32::try_from(header_size(block_count)).map_err(|_| io::ErrorKind::InvalidInput)?;
    // Each declared block needs one table entry and at least one payload
    // byte. Reject impossible layouts before reading or allocating metadata.
    let fork_len = reader.seek(SeekFrom::End(0))?;
    if fork_len < u64::from(blocks_start) + block_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resource fork shorter than its block table and minimum payload",
        ));
    }
    reader.rewind()?;
    // Grow only after validating each table entry. A forged file size and
    // uncompressed-size header must not reserve gigabytes before any blocks
    // have been read. Fallible growth reports memory pressure as an I/O error.
    let mut result = Vec::new();
    let mut buf = [0; size_of::<u32>()];

    reader.read_exact(&mut buf)?;
    let mut last_offset = u32::from_le_bytes(buf);
    if last_offset != blocks_start {
        return Err(io::Error::other("unexpected first block offset"));
    }

    // The first entry was read above. There is one more offset for every
    // block, with the last entry marking the end of the fork.
    for _ in 0..block_count {
        reader.read_exact(&mut buf)?;
        let next_offset = u32::from_le_bytes(buf);
        let compressed_size = next_offset
            .checked_sub(last_offset)
            .ok_or_else(|| io::Error::other("compressed block overlap"))?;
        if compressed_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty compressed block in resource fork",
            ));
        }
        // Do not retain a malformed block or read further table entries
        // when its end already exceeds the reported fork length.
        if u64::from(next_offset) > fork_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed block extends past resource fork",
            ));
        }
        result.try_reserve(1).map_err(io::Error::other)?;
        result.push(BlockInfo {
            offset: last_offset,
            compressed_size,
        });
        last_offset = next_offset;
    }

    let end_pos = reader.seek(SeekFrom::End(0))?;
    if end_pos != u64::from(last_offset) {
        return Err(io::Error::other("last block does not end resource fork"));
    }
    Ok(result)
}

pub(super) fn finish<W: io::Write + io::Seek>(
    mut writer: W,
    block_sizes: &[u32],
) -> io::Result<()> {
    let block_count = u32::try_from(block_sizes.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let first_offset =
        u32::try_from(header_size(block_count.into())).map_err(|_| io::ErrorKind::InvalidInput)?;

    // Reject invalid tables before rewriting any bytes in the resource fork.
    // A late overflow would otherwise leave a partly replaced offset table.
    let final_offset = block_sizes.iter().try_fold(first_offset, |offset, &size| {
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource-fork blocks must be nonempty",
            ));
        }
        offset.checked_add(size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource-fork offsets exceed 32 bits",
            )
        })
    })?;
    // The writer's position must agree with the payload lengths before any
    // table bytes are published. Otherwise a short or overlong payload could
    // be described as a valid resource fork despite the checked offsets.
    let position = writer.stream_position()?;
    if position != u64::from(final_offset) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resource-fork block lengths do not match written data",
        ));
    }
    // A seekable fork can contain stale bytes past the current write cursor.
    // The offset table must not describe only a prefix of that fork. Check
    // physical EOF before writing any table bytes, restoring the cursor even
    // when the length disagrees.
    let fork_len = writer.seek(SeekFrom::End(0))?;
    writer.seek(SeekFrom::Start(position))?;
    if fork_len != position {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resource-fork contains unreferenced bytes after the final block",
        ));
    }

    writer.rewind()?;
    let mut offset = first_offset;
    for &size in block_sizes {
        writer.write_all(&offset.to_le_bytes())?;
        offset = offset
            .checked_add(size)
            .ok_or_else(|| io::Error::other("Unable to represent offset in 32 bits"))?;
    }
    writer.write_all(&offset.to_le_bytes())?;
    writer.flush()?;

    // stream_position is logically non-modifying, despite taking &mut self.
    #[allow(clippy::debug_assert_with_mut_call)]
    {
        debug_assert_eq!(writer.stream_position()?, header_size(block_count.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BLOCK_SIZE;
    use std::io::{Cursor, Write};

    #[test]
    fn offsets_round_trip() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let block_sizes = &[10, 20, 30, 40, 10];
        let blocks_start = header_size(block_sizes.len() as u64);
        let data_end = 110 + blocks_start as u32;
        cursor.set_position(data_end.into());
        // Extend the in-memory fork to cover the payloads.
        let _ = cursor.write(&[]).unwrap();

        finish(&mut cursor, block_sizes).unwrap();
        assert_eq!(cursor.get_ref().len() as u64, 110 + blocks_start);
        let actual = read_block_info(&mut cursor, (block_sizes.len() * BLOCK_SIZE) as u64).unwrap();
        let expected: Vec<BlockInfo> = block_sizes
            .iter()
            .scan(blocks_start as u32, |offset, &compressed_size| {
                let result = BlockInfo {
                    offset: *offset,
                    compressed_size,
                };
                *offset += compressed_size;
                Some(result)
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn table_is_absolute_little_endian_with_a_terminal_offset() {
        let mut cursor = Cursor::new(vec![0; 18]);
        cursor.set_position(18);
        finish(&mut cursor, &[2, 4]).unwrap();
        assert_eq!(
            &cursor.get_ref()[..12],
            &[12, 0, 0, 0, 14, 0, 0, 0, 18, 0, 0, 0]
        );
        assert_eq!(
            read_block_info(cursor, BLOCK_SIZE as u64 + 1)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn malformed_offsets_and_truncated_tables_are_rejected() {
        let size = BLOCK_SIZE as u64 + 1;
        for offsets in [
            [8u32, 14, 18],
            [12, 11, 18],
            [12, 12, 18], // zero-length first block
            [12, 14, 14], // zero-length final block
            [12, 14, 19],
            [12, 14, 17],
        ] {
            let mut data: Vec<u8> = offsets.into_iter().flat_map(u32::to_le_bytes).collect();
            data.resize(18, 0);
            assert!(read_block_info(Cursor::new(data), size).is_err());
        }
        assert!(read_block_info(Cursor::new(vec![12, 0, 0, 0]), size).is_err());
        let error =
            read_block_info(Cursor::new(vec![0; 4]), 1_000_000 * BLOCK_SIZE as u64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_table_without_one_payload_byte_per_block_before_reading() {
        // A forged length fits two offset entries but only one payload
        // byte. It must fail without reading any bytes from the fork.
        struct SeekOnly(u64);

        impl io::Read for SeekOnly {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("invalid layout must be rejected before reading");
            }
        }

        impl io::Seek for SeekOnly {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                match pos {
                    SeekFrom::Start(0) => Ok(0),
                    SeekFrom::End(0) => Ok(self.0),
                    _ => panic!("invalid layout must be rejected before seeking the table"),
                }
            }
        }

        let count = 2u64;
        let error = read_block_info(
            SeekOnly(header_size(count) + count - 1),
            count * BLOCK_SIZE as u64,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_out_of_fork_offset_before_reading_remaining_table() {
        // The reported fork length is large enough for two minimal blocks,
        // but the first block's end is beyond it. Only two offsets exist;
        // rejecting the second offset must precede a third read.
        struct SparseFork {
            bytes: Cursor<[u8; 8]>,
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

        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&12u32.to_le_bytes());
        bytes[4..].copy_from_slice(&21u32.to_le_bytes());
        let fork = SparseFork {
            bytes: Cursor::new(bytes),
            reported_len: 20,
        };
        let error = read_block_info(fork, BLOCK_SIZE as u64 + 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn huge_claimed_table_with_truncated_entries_fails_without_eager_allocation() {
        // Model a sparse/forged resource fork: its reported length fits a
        // million-block table plus one byte per block, but only the first
        // offset is readable. This exercises the truncated-entry path after
        // the minimum-payload preflight succeeds.
        // The parser must read entries before allocating their metadata.
        struct SparseFork(Cursor<[u8; 4]>);

        impl io::Read for SparseFork {
            fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
                io::Read::read(&mut self.0, dst)
            }
        }

        impl io::Seek for SparseFork {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                match pos {
                    SeekFrom::End(0) => Ok(header_size(1_000_000) + 1_000_000),
                    other => io::Seek::seek(&mut self.0, other),
                }
            }
        }

        let first_offset = u32::try_from(header_size(1_000_000)).unwrap();
        let fork = SparseFork(Cursor::new(first_offset.to_le_bytes()));
        let error = read_block_info(fork, 1_000_000 * BLOCK_SIZE as u64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn invalid_finalizer_offsets_cannot_modify_the_resource_fork() {
        for sizes in [&[0u32][..], &[u32::MAX][..]] {
            let original = vec![0xa5; 32];
            let mut cursor = Cursor::new(original.clone());
            cursor.set_position(17);
            let error = finish(&mut cursor, sizes).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(cursor.get_ref(), &original);
            assert_eq!(cursor.position(), 17);
        }
    }

    #[test]
    fn finalizer_rejects_mismatched_payload_lengths_without_modifying_fork() {
        // Two blocks need a 12-byte table and six payload bytes.
        // Even when the backing fork is long enough, its write cursor must
        // reflect exactly the supplied payload sizes.
        let original = vec![0xa5; 24];
        for position in [0u64, 12, 17, 19, 24] {
            let mut cursor = Cursor::new(original.clone());
            cursor.set_position(position);
            let error = finish(&mut cursor, &[2, 4]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(cursor.get_ref(), &original);
            assert_eq!(cursor.position(), position);
        }
    }

    #[test]
    fn finalizer_rejects_stale_bytes_beyond_payload_without_mutation() {
        // Both blocks fit exactly at byte 18. An older 21-byte fork with
        // the write cursor at 18 must not receive a misleading offset table.
        let payload_end = header_size(2) + 2 + 4;
        let original = vec![0xa5; payload_end as usize + 3];
        let mut cursor = Cursor::new(original.clone());
        cursor.set_position(payload_end);
        let error = finish(&mut cursor, &[2, 4]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(cursor.get_ref(), &original);
        assert_eq!(cursor.position(), payload_end);
    }

    #[test]
    fn unrepresentable_offsets_return_errors() {
        assert!(read_block_info(Cursor::new(Vec::<u8>::new()), u64::MAX).is_err());
        assert!(finish(Cursor::new(Vec::<u8>::new()), &[u32::MAX]).is_err());
    }
}
