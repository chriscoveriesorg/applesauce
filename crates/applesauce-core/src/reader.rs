use crate::decmpfs::{BlockInfo, Storage};
use crate::{compressor, decmpfs};
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom};

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
        expected_fork_len: u64,
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
                // Resource-fork decmpfs metadata contains only the 16-byte
                // header. Any inline payload is contradictory and must not be
                // silently ignored in favor of the separate fork.
                if !decmpfs_value.extra_data.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "resource-fork decmpfs header contains inline payload",
                    ));
                }
                // An empty file is represented by an empty inline xattr.
                // Do not accept a zero-block fork as valid compressed data.
                if decmpfs_value.uncompressed_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "empty file cannot use resource-fork compression",
                    ));
                }
                let mut rfork = BufReader::new(open.open_resource_fork()?);
                let mut blocks_info =
                    kind.read_block_info(&mut rfork, decmpfs_value.uncompressed_size)?;

                // The validated table fixes the expected physical fork size,
                // including ZLIB's fixed trailer. Keep this snapshot so a
                // later resize cannot silently change the bytes we read.
                let last_block = blocks_info.last().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "resource fork has no blocks")
                })?;
                let expected_fork_len = u64::from(last_block.offset)
                    + u64::from(last_block.compressed_size)
                    + kind.trailer_size();
                if rfork.seek(SeekFrom::End(0))? != expected_fork_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "resource fork changed size during metadata validation",
                    ));
                }
                rfork.rewind()?;
                // Reverse the block infos so that we can pop() them off
                blocks_info.reverse();

                State::ResourceFork {
                    block_infos: blocks_info,
                    expected_fork_len,
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
                expected_fork_len,
                reader,
            } => {
                let block = match block_infos.last().copied() {
                    Some(block) => block,
                    None => return Ok(false),
                };
                // Recheck physical EOF before reading. A fork resized after
                // its offset table was validated is not a consistent snapshot.
                // Seek via BufReader itself so cached bytes are invalidated.
                if reader.seek(SeekFrom::End(0))? != *expected_fork_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "resource fork size changed before block read",
                    ));
                }
                reader.seek(SeekFrom::Start(u64::from(block.offset)))?;

                // A forged sparse fork can advertise a huge block while
                // providing almost no readable payload. Do not allocate the
                // entire declared size before confirming that bytes exist.
                // Valid large blocks still stream into the caller's Vec.
                let mut remaining = usize::try_from(block.compressed_size)
                    .map_err(|_| io::ErrorKind::InvalidData)?;
                while remaining != 0 {
                    let chunk = remaining.min(crate::BLOCK_SIZE);
                    dst.try_reserve_exact(chunk).map_err(io::Error::other)?;
                    let start = dst.len();
                    dst.resize(start + chunk, 0);
                    reader.read_exact(&mut dst[start..])?;
                    remaining -= chunk;
                }

                // Detect resizes that happened while the payload was read.
                // read_block_into will roll back the appended bytes and poison
                // the reader on either mismatch.
                if reader.seek(SeekFrom::End(0))? != *expected_fork_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "resource fork size changed during block read",
                    ));
                }
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
