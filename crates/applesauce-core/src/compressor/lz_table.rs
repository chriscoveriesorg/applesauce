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
    let mut result = Vec::with_capacity(
        block_count
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidInput)?,
    );
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
    let mut offset =
        u32::try_from(header_size(block_count.into())).map_err(|_| io::ErrorKind::InvalidInput)?;

    writer.rewind()?;
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
        for offsets in [[8u32, 14, 18], [12, 11, 18], [12, 14, 19], [12, 14, 17]] {
            let mut data: Vec<u8> = offsets.into_iter().flat_map(u32::to_le_bytes).collect();
            data.resize(18, 0);
            assert!(read_block_info(Cursor::new(data), size).is_err());
        }
        assert!(read_block_info(Cursor::new(vec![12, 0, 0, 0]), size).is_err());
    }

    #[test]
    fn unrepresentable_offsets_return_errors() {
        assert!(read_block_info(Cursor::new(Vec::<u8>::new()), u64::MAX).is_err());
        assert!(finish(Cursor::new(Vec::<u8>::new()), &[u32::MAX]).is_err());
    }
}
