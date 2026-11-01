use applesauce_core::compressor::Kind;
use applesauce_core::writer::Writer;
use applesauce_core::{decmpfs, BLOCK_SIZE};
use std::io::Cursor;

fn never_called_open() -> Cursor<Vec<u8>> {
    panic!("Should not be called");
}

#[test]
fn unavailable_codec_is_rejected_before_opening_storage() {
    for kind in Kind::ALL.into_iter().filter(|kind| !kind.supported()) {
        for size in [0, 1, BLOCK_SIZE as u64 + 1] {
            let error = Writer::new(kind, size, never_called_open).err().unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        }
    }
}

#[test]
fn unrepresentable_resource_fork_table_fails_before_opening_storage() {
    // Both an overflowing block count and a representable block count
    // whose header + minimum nonempty payload exceeds 32-bit offsets
    // must be rejected without touching the resource fork.
    for kind in Kind::ALL.into_iter().filter(|kind| kind.supported()) {
        for size in [u64::MAX, 900_000_000u64 * BLOCK_SIZE as u64] {
            let error = Writer::new(kind, size, never_called_open).err().unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}

#[test]
fn empty() {
    let writer = Writer::new(Kind::default(), 0, never_called_open).unwrap();

    let mut decmpfs_data = Vec::new();
    writer.finish_decmpfs_data(&mut decmpfs_data).unwrap();

    let value = decmpfs::Value::from_data(&decmpfs_data).unwrap();
    let (kind, storage) = value.compression_type.compression_storage().unwrap();
    assert_eq!(kind, Kind::default());
    assert_eq!(storage, decmpfs::Storage::Xattr);
    assert!(value.extra_data.is_empty());
}

#[test]
fn small_block_store_inplace() {
    // Uses a single block to store this much data
    let uncompressed_size = 10;
    let compressed_block = vec![1, 2, 3];
    let mut writer = Writer::new(Kind::default(), uncompressed_size, never_called_open).unwrap();
    writer.add_block(&compressed_block).unwrap();

    let mut decmpfs_data = Vec::new();
    writer.finish_decmpfs_data(&mut decmpfs_data).unwrap();

    let value = decmpfs::Value::from_data(&decmpfs_data).unwrap();
    let (kind, storage) = value.compression_type.compression_storage().unwrap();
    assert_eq!(kind, Kind::default());
    assert_eq!(storage, decmpfs::Storage::Xattr);
    assert_eq!(value.extra_data, compressed_block);
}

#[test]
fn large_single_block() {
    // Treat a single block which can't fit in the decmpfs xattr when compressed the same way we treat
    // multiple blocks

    let uncompressed_size = BLOCK_SIZE as u64;
    let compressed_block = vec![0x1A; decmpfs::MAX_XATTR_DATA_SIZE + 1];
    let mut resource_fork = Vec::new();

    let mut writer = {
        let rfork_ref = &mut resource_fork;
        Writer::new(Kind::default(), uncompressed_size, move || {
            Cursor::new(rfork_ref)
        })
        .unwrap()
    };

    writer.add_block(&compressed_block).unwrap();

    let mut decmpfs_data = Vec::new();
    writer.finish_decmpfs_data(&mut decmpfs_data).unwrap();

    let value = decmpfs::Value::from_data(&decmpfs_data).unwrap();
    let (kind, storage) = value.compression_type.compression_storage().unwrap();
    assert_eq!(kind, Kind::default());
    assert_eq!(storage, decmpfs::Storage::ResourceFork);
    assert!(value.extra_data.is_empty());

    let block_infos = kind
        .read_block_info(Cursor::new(&resource_fork), uncompressed_size)
        .unwrap();
    assert_eq!(
        block_infos,
        [decmpfs::BlockInfo {
            offset: kind.header_size(1) as u32,
            compressed_size: compressed_block.len() as u32,
        }]
    );
    assert_eq!(
        &resource_fork[kind.header_size(1) as usize..][..compressed_block.len()],
        compressed_block
    );
}

#[test]
fn multiple_small_blocks() {
    let uncompressed_size = 2 * BLOCK_SIZE as u64;
    let compressed_block = vec![0x1A; 10];
    let mut resource_fork = Vec::new();

    let mut writer = {
        let rfork_ref = &mut resource_fork;
        Writer::new(Kind::default(), uncompressed_size, move || {
            Cursor::new(rfork_ref)
        })
        .unwrap()
    };

    writer.add_block(&compressed_block).unwrap();
    writer.add_block(&compressed_block).unwrap();

    let mut decmpfs_data = Vec::new();
    writer.finish_decmpfs_data(&mut decmpfs_data).unwrap();

    let value = decmpfs::Value::from_data(&decmpfs_data).unwrap();
    let (kind, storage) = value.compression_type.compression_storage().unwrap();
    assert_eq!(kind, Kind::default());
    assert_eq!(storage, decmpfs::Storage::ResourceFork);
    assert!(value.extra_data.is_empty());

    let block_infos = kind
        .read_block_info(Cursor::new(&resource_fork), uncompressed_size)
        .unwrap();
    let header_size = kind.header_size(2) as u32;
    assert_eq!(
        block_infos,
        [
            decmpfs::BlockInfo {
                offset: header_size,
                compressed_size: compressed_block.len() as u32,
            },
            decmpfs::BlockInfo {
                offset: (header_size as usize + compressed_block.len()) as u32,
                compressed_size: compressed_block.len() as u32,
            },
        ]
    );
    let resource_fork_data = &resource_fork[header_size as usize..];
    let resource_fork_data = &resource_fork_data[..compressed_block.len() * 2];
    assert_eq!(
        &resource_fork_data[..compressed_block.len()],
        compressed_block
    );
    assert_eq!(
        &resource_fork_data[compressed_block.len()..],
        compressed_block
    );
}

#[test]
fn nonempty_file_requires_a_nonempty_compressed_block() {
    let mut output = vec![0x5a];
    let writer = Writer::new(Kind::default(), 1, never_called_open).unwrap();
    let error = writer.finish_decmpfs_data(&mut output).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(output, [0x5a], "invalid metadata must not be published");

    let mut writer = Writer::new(Kind::default(), 1, never_called_open).unwrap();
    let error = writer.add_block(&[]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    writer.add_block(&[0x42]).unwrap();
    writer.finish_decmpfs_data(&mut output).unwrap();
    assert_eq!(
        decmpfs::Value::from_data(&output[1..]).unwrap().extra_data,
        &[0x42],
    );
}

#[test]
fn empty_file_cannot_receive_compressed_blocks() {
    let mut writer = Writer::new(Kind::default(), 0, never_called_open).unwrap();
    assert_eq!(
        writer.add_block(&[0x42]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
    );
    let mut output = Vec::new();
    writer.finish_decmpfs_data(&mut output).unwrap();
    assert!(decmpfs::Value::from_data(&output)
        .unwrap()
        .extra_data
        .is_empty());
}

#[test]
fn incomplete_resource_fork_cannot_publish_metadata() {
    let mut writer = Writer::new(Kind::default(), BLOCK_SIZE as u64 + 1, || {
        Cursor::new(Vec::new())
    })
    .unwrap();
    assert_eq!(
        writer.add_block(&[]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
    );
    writer.add_block(&[0x42]).unwrap();
    let mut output = vec![0x5a];
    let error = writer.finish_decmpfs_data(&mut output).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        output,
        [0x5a],
        "incomplete resource fork must not be published"
    );
}

#[test]
fn forced_resource_fork_cannot_publish_empty_placeholder() {
    let mut writer = Writer::new(Kind::default(), 1, || Cursor::new(Vec::new())).unwrap();
    writer.force_resource_fork().unwrap();
    let mut output = Vec::new();
    assert_eq!(
        writer.finish_decmpfs_data(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
    );
    assert!(output.is_empty());
}

#[test]
fn forcing_resource_fork_before_first_block_does_not_create_phantom_block() {
    let mut resource_fork = Vec::new();
    let mut writer = {
        let rfork_ref = &mut resource_fork;
        Writer::new(Kind::default(), 1, move || Cursor::new(rfork_ref)).unwrap()
    };
    writer.force_resource_fork().unwrap();
    writer.add_block(&[0x42]).unwrap();
    let mut output = Vec::new();
    writer.finish_decmpfs_data(&mut output).unwrap();
    let value = decmpfs::Value::from_data(&output).unwrap();
    let (kind, storage) = value.compression_type.compression_storage().unwrap();
    assert_eq!(storage, decmpfs::Storage::ResourceFork);
    assert_eq!(
        kind.read_block_info(Cursor::new(&resource_fork), 1)
            .unwrap(),
        [decmpfs::BlockInfo {
            offset: kind.header_size(1) as u32,
            compressed_size: 1,
        }]
    );
}

#[test]
fn empty_file_cannot_force_resource_fork() {
    let mut writer = Writer::new(Kind::default(), 0, never_called_open).unwrap();
    assert_eq!(
        writer.force_resource_fork().unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
    );
}

#[test]
fn single_block_writer_rejects_extra_block_without_panicking() {
    let mut writer = Writer::new(Kind::default(), 1, never_called_open).unwrap();
    writer.add_block(&[0x11]).unwrap();
    assert_eq!(
        writer.add_block(&[0x22]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    let mut output = Vec::new();
    writer.finish_decmpfs_data(&mut output).unwrap();
    assert_eq!(
        decmpfs::Value::from_data(&output).unwrap().extra_data,
        &[0x11]
    );
}

#[test]
fn resource_fork_writer_rejects_extra_block_without_mutation() {
    let mut resource_fork = Vec::new();
    let mut writer = {
        let rfork_ref = &mut resource_fork;
        Writer::new(Kind::default(), BLOCK_SIZE as u64 + 1, move || {
            Cursor::new(rfork_ref)
        })
        .unwrap()
    };
    writer.add_block(&[0x11]).unwrap();
    writer.add_block(&[0x22]).unwrap();
    assert_eq!(
        writer.add_block(&[0x33]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    let mut output = Vec::new();
    writer.finish_decmpfs_data(&mut output).unwrap();
    let value = decmpfs::Value::from_data(&output).unwrap();
    let (kind, storage) = value.compression_type.compression_storage().unwrap();
    assert_eq!(storage, decmpfs::Storage::ResourceFork);
    let blocks = kind
        .read_block_info(Cursor::new(&resource_fork), BLOCK_SIZE as u64 + 1)
        .unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].compressed_size, 1);
    assert_eq!(blocks[1].compressed_size, 1);
    assert_eq!(resource_fork[blocks[0].offset as usize], 0x11);
    assert_eq!(resource_fork[blocks[1].offset as usize], 0x22);
}

struct FailAfterPartialWrite {
    cursor: Cursor<Vec<u8>>,
    writes: usize,
}

impl std::io::Write for FailAfterPartialWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        if self.writes == 1 {
            std::io::Write::write(&mut self.cursor, &buf[..1])
        } else {
            Err(std::io::Error::other("injected write failure"))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for FailAfterPartialWrite {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        std::io::Seek::seek(&mut self.cursor, pos)
    }
}

fn partial_failure_open() -> FailAfterPartialWrite {
    FailAfterPartialWrite {
        cursor: Cursor::new(Vec::new()),
        writes: 0,
    }
}

#[test]
fn partial_resource_fork_write_cannot_be_retried_or_published() {
    let mut writer =
        Writer::new(Kind::default(), BLOCK_SIZE as u64 + 1, partial_failure_open).unwrap();
    assert_eq!(
        writer.add_block(&[0x11, 0x22]).unwrap_err().kind(),
        std::io::ErrorKind::Other
    );
    assert_eq!(
        writer.add_block(&[0x33]).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    let mut output = vec![0x5a];
    assert_eq!(
        writer.finish_decmpfs_data(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert_eq!(output, [0x5a]);
}

#[test]
fn failed_single_block_resource_fork_conversion_cannot_publish() {
    let mut writer = Writer::new(Kind::default(), 1, partial_failure_open).unwrap();
    writer.add_block(&[0x11, 0x22]).unwrap();
    assert_eq!(
        writer.force_resource_fork().unwrap_err().kind(),
        std::io::ErrorKind::Other
    );
    let mut output = Vec::new();
    assert_eq!(
        writer.finish_decmpfs_data(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert!(output.is_empty());
}


struct VirtualNearLimitFork {
    position: u64,
    starting_position: u64,
    writes: std::rc::Rc<std::cell::Cell<usize>>,
}

impl std::io::Write for VirtualNearLimitFork {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writes.set(self.writes.get() + 1);
        self.position += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for VirtualNearLimitFork {
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        match from {
            // Simulate a storage backend reporting a fork cursor near its
            // 32-bit limit without allocating gigabytes of backing storage.
            std::io::SeekFrom::Start(_) => self.position = self.starting_position,
            std::io::SeekFrom::Current(0) => {}
            _ => return Err(std::io::ErrorKind::Unsupported.into()),
        }
        Ok(self.position)
    }
}

fn near_limit_writer(
    kind: Kind,
    position: u64,
    writes: std::rc::Rc<std::cell::Cell<usize>>,
) -> Writer<impl applesauce_core::writer::Open> {
    Writer::new(kind, 2 * BLOCK_SIZE as u64, move || VirtualNearLimitFork {
        position: 0,
        starting_position: position,
        writes,
    })
    .unwrap()
}

#[test]
fn oversized_resource_fork_payload_is_rejected_before_writing() {
    // The second block still needs one byte of space. The first block must
    // fail before any write when it would make the final layout impossible.
    for kind in Kind::ALL.into_iter().filter(|kind| kind.supported()) {
        let writes = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut writer = near_limit_writer(
            kind,
            u64::from(u32::MAX) - 1,
            std::rc::Rc::clone(&writes),
        );
        assert_eq!(
            writer.add_block(&[0x11, 0x22]).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{kind}"
        );
        assert_eq!(writes.get(), 0, "{kind} wrote oversized payload");
    }
}

#[test]
fn zlib_trailer_and_remaining_block_fit_exactly_at_the_limit() {
    if !Kind::Zlib.supported() {
        return;
    }
    let max = u64::from(u32::MAX);
    // 2-byte first payload + 1-byte required final payload + 50-byte trailer.
    for (position, accepted) in [(max - 53, true), (max - 52, false)] {
        let writes = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut writer =
            near_limit_writer(Kind::Zlib, position, std::rc::Rc::clone(&writes));
        let result = writer.add_block(&[0x11, 0x22]);
        assert_eq!(result.is_ok(), accepted, "position={position}");
        assert_eq!(writes.get(), usize::from(accepted));
    }
}

#[test]
fn zlib_trailer_overflow_fails_before_opening_the_resource_fork() {
    if !Kind::Zlib.supported() {
        return;
    }
    // Each block requires 8 table bytes, 1 payload byte, plus the fixed
    // header and trailer. This count fits without the trailer but not with it.
    let max = u64::from(u32::MAX);
    let trailer = applesauce_core::decmpfs::ZLIB_TRAILER.len() as u64;
    let header = Kind::Zlib.header_size(0);
    let blocks = (max - header - trailer) / 9 + 1;
    assert!(Kind::Zlib.header_size(blocks) + blocks <= max);
    let error = Writer::new(Kind::Zlib, blocks * BLOCK_SIZE as u64, never_called_open)
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
