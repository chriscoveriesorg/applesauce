use crate::xattr;
use applesauce_core::compressor::Kind;
use applesauce_core::decmpfs;
use applesauce_core::BLOCK_SIZE;
use resource_fork::ResourceFork;
use std::fs::File;
use std::io;

pub fn with_compressed_blocks<F, F2>(file: &File, f: F) -> io::Result<()>
where
    F: FnOnce(Kind) -> F2,
    F2: FnMut(&[u8], usize) -> io::Result<()>,
{
    let decmpfs_data = xattr::read(file, decmpfs::XATTR_NAME, decmpfs::MAX_XATTR_SIZE)?
        .ok_or_else(|| io::Error::other("file is not compressed"))?;
    let mut reader =
        applesauce_core::reader::Reader::new(&decmpfs_data, || ResourceFork::new(file))?;
    // Derive the logical size of each 64 KiB block from the same decmpfs
    // header used to validate the resource-fork table. A valid total size
    // alone cannot detect a short block followed by an overlong block.
    let mut remaining = decmpfs::Value::from_data(&decmpfs_data)?.uncompressed_size;

    let mut per_block = f(reader.compression_kind());
    let mut buf = Vec::with_capacity(BLOCK_SIZE);
    loop {
        buf.clear();
        let has_block = reader.read_block_into(&mut buf)?;
        if !has_block {
            break;
        }
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resource fork contains more blocks than declared",
            ));
        }
        let expected_len = remaining.min(BLOCK_SIZE as u64) as usize;
        per_block(&buf, expected_len)?;
        remaining -= expected_len as u64;
    }

    if remaining != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resource fork ended before all logical blocks were read",
        ));
    }
    Ok(())
}
