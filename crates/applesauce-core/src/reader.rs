use crate::decmpfs::{BlockInfo, Storage};
use crate::{compressor, decmpfs};
use std::io::{self, BufReader, Cursor, Read, Seek};

pub trait Open {
    type ResourceFork: Read + Seek;

    fn open_resource_fork(self) -> io::Result<Self::ResourceFork>;
}

impl<R: Read + Seek, F: FnOnce() -> R> Open for F {
    type ResourceFork = R;

    #[inline]
    fn open_resource_fork(self) -> io::Result<Self::ResourceFork> {
        Ok(self())
    }
}

#[derive(Debug)]
enum State<R> {
    Xattr(Cursor<Vec<u8>>),
    ResourceFork {
        // Stored in reverse order, so that we can pop() them off
        block_infos: Vec<BlockInfo>,
        last_offset: u32,
        reader: BufReader<R>,
    },
}

#[derive(Debug)]
pub struct Reader<R> {
    kind: compressor::Kind,
    state: State<R>,
    failed: bool,
}

impl<R: Read + Seek> Reader<R> {
    pub fn new<O>(decmpfs_data: &[u8], open: O) -> io::Result<Self>
    where
        O: Open<ResourceFork = R>,
    {
        let decmpfs_value = decmpfs::Value::from_data(decmpfs_data)?;
        let (kind, storage) = decmpfs_value
            .compression_type
            .compression_storage()
            .filter(|(kind, _)| kind.supported())
            .ok_or_else(|| io::Error::other("unsupported compression kind or storage"))?;
        let state = match storage {
            Storage::Xattr => {
                // An inline xattr represents at most one 64 KiB block.
                // Reject inconsistent metadata before a caller can mistake
                // an absent or truncated payload for end-of-file.
                if decmpfs_value.uncompressed_size > crate::BLOCK_SIZE as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "inline decmpfs data exceeds one uncompressed block",
                    ));
                }
                if decmpfs_value.extra_data.len() > decmpfs::MAX_XATTR_DATA_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "inline decmpfs payload exceeds maximum xattr size",
                    ));
                }
                let empty_file = decmpfs_value.uncompressed_size == 0;
                let empty_payload = decmpfs_value.extra_data.is_empty();
                if empty_file != empty_payload {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "inline decmpfs payload does not match uncompressed size",
                    ));
                }
                State::Xattr(Cursor::new(decmpfs_value.extra_data.to_vec()))
            }
            Storage::ResourceFork => {
                let mut rfork = BufReader::new(open.open_resource_fork()?);
                let mut blocks_info =
                    kind.read_block_info(&mut rfork, decmpfs_value.uncompressed_size)?;

                // Seek back to the beginning of the resource fork
                rfork.rewind()?;
                // Reverse the block infos so that we can pop() them off
                blocks_info.reverse();

                State::ResourceFork {
                    block_infos: blocks_info,
                    last_offset: 0,
                    reader: rfork,
                }
            }
        };
        Ok(Self {
            kind,
            state,
            failed: false,
        })
    }

    /// Appends one compressed block to `dst`. If a read fails, any partial
    /// bytes are discarded and the reader is poisoned so a later call cannot
    /// silently skip the failed block.
    pub fn read_block_into(&mut self, dst: &mut Vec<u8>) -> io::Result<bool> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "compressed reader cannot be reused after a failed read",
            ));
        }

        let original_len = dst.len();
        let result = self.read_block_into_inner(dst);
        if result.is_err() {
            dst.truncate(original_len);
            self.failed = true;
        }
        result
    }

    fn read_block_into_inner(&mut self, dst: &mut Vec<u8>) -> io::Result<bool> {
        match &mut self.state {
            State::Xattr(cursor) => cursor.read_to_end(dst).map(|bytes_read| bytes_read > 0),
            State::ResourceFork {
                block_infos,
                last_offset,
                reader,
            } => {
                let block = match block_infos.last().copied() {
                    Some(block) => block,
                    None => return Ok(false),
                };
                let diff = i64::from(block.offset) - i64::from(*last_offset);
                reader.seek_relative(diff)?;

                // Block lengths are known from the validated resource-fork
                // table. Reuse the caller's buffer and read exactly once
                // rather than growing it in read_to_end increments.
                let size = usize::try_from(block.compressed_size)
                    .map_err(|_| io::ErrorKind::InvalidData)?;
                dst.try_reserve_exact(size).map_err(io::Error::other)?;
                let start = dst.len();
                dst.resize(start + size, 0);
                reader.read_exact(&mut dst[start..])?;

                *last_offset = block
                    .offset
                    .checked_add(block.compressed_size)
                    .ok_or(io::ErrorKind::InvalidData)?;
                block_infos.pop();
                Ok(true)
            }
        }
    }

    #[inline]
    pub fn compression_kind(&self) -> compressor::Kind {
        self.kind
    }

    #[inline]
    pub fn remaining_blocks(&self) -> usize {
        match &self.state {
            State::Xattr(cursor) => {
                let remaining = cursor.get_ref().len() as u64 - cursor.position();
                usize::from(remaining > 0)
            }
            State::ResourceFork { block_infos, .. } => block_infos.len(),
        }
    }
}
