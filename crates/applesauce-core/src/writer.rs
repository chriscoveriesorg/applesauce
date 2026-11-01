use crate::decmpfs::CompressionType;
use crate::{compressor, decmpfs};
use std::io::{Seek, SeekFrom, Write};
use std::{io, mem};

pub trait Open {
    type ResourceFork: Write + Seek;

    fn open_resource_fork(self) -> io::Result<Self::ResourceFork>;
}

impl<W: Write + Seek, F: FnOnce() -> W> Open for F {
    type ResourceFork = W;

    #[inline]
    fn open_resource_fork(self) -> io::Result<Self::ResourceFork> {
        Ok(self())
    }
}

enum WriterState<O: Open> {
    // Just used as a transition state, should never be there at the end of the write
    Empty,
    SingleBlock {
        // We still need to keep this openable, in case the block is too large to fit in an xattr
        open: O,
        block: Vec<u8>,
    },
    MultipleBlocks {
        block_sizes: Vec<u32>,
        resource_fork: O::ResourceFork,
    },
}

pub struct Writer<O: Open> {
    kind: compressor::Kind,
    uncompressed_size: u64,
    state: WriterState<O>,
    failed: bool,
}

impl<O: Open> Writer<O> {
    pub fn new(kind: compressor::Kind, uncompressed_size: u64, open: O) -> io::Result<Self> {
        if !kind.supported() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{kind} is unavailable in this build or on this host"),
            ));
        }
        let block_count = crate::num_blocks(uncompressed_size);
        let state = if block_count > 1 {
            // Native resource-fork formats use 32-bit block counts/offsets.
            // Validate before opening or seeking into the target resource fork.
            let header_size = kind.header_size(block_count);
            let max_data_end = u64::from(u32::MAX) - kind.trailer_size();
            if header_size
                .checked_add(block_count)
                .is_none_or(|minimum_end| minimum_end > max_data_end)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "resource fork block table, minimum payload and trailer exceed 32-bit offsets",
                ));
            }
            let mut resource_fork = open.open_resource_fork()?;
            resource_fork.seek(SeekFrom::Start(header_size))?;

            WriterState::MultipleBlocks {
                // Do not allocate proportional to a caller-provided file size
                // before any compressed blocks have been supplied.
                block_sizes: Vec::new(),
                resource_fork,
            }
        } else {
            WriterState::SingleBlock {
                open,
                block: Vec::new(),
            }
        };
        Ok(Self {
            kind,
            uncompressed_size,
            state,
            failed: false,
        })
    }

    pub fn add_block(&mut self, new_block: &[u8]) -> io::Result<()> {
        self.ensure_usable()?;
        if self.uncompressed_size == 0 || new_block.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot add an empty compressed block or a block to an empty file",
            ));
        }
        let compressed_size = u32::try_from(new_block.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "compressed block exceeds u32 size",
            )
        })?;

        match &mut self.state {
            WriterState::SingleBlock { block, .. } => {
                if !block.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many compressed blocks for file size",
                    ));
                }
                if new_block.len() > decmpfs::MAX_XATTR_DATA_SIZE {
                    if let Err(error) = self.write_single_block_as_rfork(new_block) {
                        self.failed = true;
                        return Err(error);
                    }
                } else {
                    block.extend_from_slice(new_block);
                }
            }
            WriterState::MultipleBlocks {
                block_sizes,
                resource_fork,
            } => {
                if block_sizes.len() as u64 >= crate::num_blocks(self.uncompressed_size) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many compressed blocks for file size",
                    ));
                }
                if block_sizes.len() + 1 >= u32::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "too many blocks",
                    ));
                }
                // Reject an impossible final layout before writing payload
                // bytes. Leave room for at least one byte in each remaining
                // block and for a codec-specific resource-fork trailer.
                let remaining_blocks =
                    crate::num_blocks(self.uncompressed_size) - block_sizes.len() as u64 - 1;
                let max_data_end = u64::from(u32::MAX) - self.kind.trailer_size();
                let position = resource_fork.stream_position()?;
                if position
                    .checked_add(u64::from(compressed_size))
                    .and_then(|end| end.checked_add(remaining_blocks))
                    .is_none_or(|minimum_end| minimum_end > max_data_end)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "compressed block would exceed 32-bit resource-fork capacity",
                    ));
                }
                // Reserve the metadata slot before touching the fork. An
                // allocation failure must not strand an untracked payload.
                block_sizes.try_reserve(1).map_err(io::Error::other)?;
                if let Err(error) = resource_fork.write_all(new_block) {
                    // A partial write can leave bytes behind. Never allow a
                    // retry to make that incomplete payload publishable.
                    self.failed = true;
                    return Err(error);
                }
                block_sizes.push(compressed_size);
            }
            WriterState::Empty => unreachable!(),
        };
        Ok(())
    }

    pub fn finish_decmpfs_data(self, dst: &mut Vec<u8>) -> io::Result<()> {
        self.ensure_usable()?;
        let mut extra_data = Vec::new();
        let storage = match self.state {
            WriterState::SingleBlock { block, .. } => {
                // A nonempty file must not be published with only a decmpfs
                // header. This must also hold in release builds.
                if self.uncompressed_size != 0 && block.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing compressed block for nonempty file",
                    ));
                }
                extra_data = block;
                decmpfs::Storage::Xattr
            }
            WriterState::MultipleBlocks {
                block_sizes,
                resource_fork,
            } => {
                if block_sizes.len() as u64 != crate::num_blocks(self.uncompressed_size) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Wrong number of blocks",
                    ));
                }
                if block_sizes.contains(&0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "empty compressed block in resource fork",
                    ));
                }
                self.kind.finish(resource_fork, &block_sizes)?;
                decmpfs::Storage::ResourceFork
            }
            WriterState::Empty => unreachable!(),
        };

        let value = decmpfs::Value {
            compression_type: CompressionType::new(self.kind, storage),
            uncompressed_size: self.uncompressed_size,
            extra_data: &extra_data,
        };

        dst.reserve(value.len());
        value.write_to(dst)?;
        Ok(())
    }

    /// Force blocks to be written to the resource fork
    ///
    /// Normally, if a file has a single block, and the block compresses enough,
    /// it will be written embedded in the decmpfs xattr instead of a resource fork.
    ///
    /// Calling this function will ensure that a resource fork is always used.
    pub fn force_resource_fork(&mut self) -> io::Result<()> {
        self.ensure_usable()?;
        if self.uncompressed_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty files have no resource-fork blocks",
            ));
        }
        if matches!(self.state, WriterState::MultipleBlocks { .. }) {
            return Ok(());
        }

        match &mut self.state {
            WriterState::SingleBlock { block, .. } => {
                let block = mem::take(block);
                if let Err(error) = self.write_single_block_as_rfork(&block) {
                    self.failed = true;
                    return Err(error);
                }
            }
            _ => unreachable!("Just checked that we're not already multiple blocks"),
        }

        Ok(())
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.failed {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "resource fork write failed; compressed writer cannot be reused",
            ))
        } else {
            Ok(())
        }
    }

    // Only called on single-block files, to convert to multiple blocks, even with a single block
    // because the block is too large to fit in an xattr
    fn write_single_block_as_rfork(&mut self, new_block: &[u8]) -> io::Result<()> {
        let max_data_end = u64::from(u32::MAX) - self.kind.trailer_size();
        if self
            .kind
            .header_size(1)
            .checked_add(new_block.len() as u64)
            .is_none_or(|end| end > max_data_end)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "single-block resource fork exceeds 32-bit capacity",
            ));
        }
        match mem::replace(&mut self.state, WriterState::Empty) {
            WriterState::SingleBlock { open, block } => {
                debug_assert!(block.is_empty());

                let mut resource_fork = open.open_resource_fork()?;
                resource_fork.seek(SeekFrom::Start(
                    self.kind
                        .header_size(crate::num_blocks(self.uncompressed_size)),
                ))?;
                // Forcing the resource fork before add_block must not insert
                // a phantom zero-length block into the offset table.
                let mut block_sizes = Vec::new();
                if !new_block.is_empty() {
                    resource_fork.write_all(new_block)?;
                    block_sizes.push(new_block.len() as u32);
                }

                self.state = WriterState::MultipleBlocks {
                    block_sizes,
                    resource_fork,
                };
            }
            _ => unreachable!(),
        };
        Ok(())
    }
}
