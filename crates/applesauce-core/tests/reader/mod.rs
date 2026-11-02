use applesauce_core::compressor::Kind;
use applesauce_core::decmpfs;
use applesauce_core::reader::Reader;
use std::io::Cursor;

fn never_called_open() -> Cursor<Vec<u8>> {
    panic!("Should not be called");
}

#[test]
fn empty() {
    let reader_err = Reader::new(&[], never_called_open).unwrap_err();
    assert_eq!(reader_err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn invalid_magic() {
    let reader_err = Reader::new(&[0; decmpfs::HEADER_LEN], never_called_open).unwrap_err();
    assert_eq!(reader_err.kind(), std::io::ErrorKind::InvalidData);
}

fn inline_metadata(uncompressed_size: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    decmpfs::Value {
        compression_type: decmpfs::CompressionType::new(Kind::default(), decmpfs::Storage::Xattr),
        uncompressed_size,
        extra_data: payload,
    }
    .write_to(&mut data)
    .unwrap();
    data
}

#[test]
fn inline_reader_rejects_missing_or_impossible_payloads() {
    use applesauce_core::BLOCK_SIZE;

    for (size, payload) in [
        (1, &[][..]),
        (0, &[0x42][..]),
        (BLOCK_SIZE as u64 + 1, &[0x42][..]),
    ] {
        let data = inline_metadata(size, payload);
        let error = Reader::new(&data, never_called_open).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    let oversized = vec![0x42; decmpfs::MAX_XATTR_DATA_SIZE + 1];
    let data = inline_metadata(1, &oversized);
    let error = Reader::new(&data, never_called_open).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn inline_reader_preserves_valid_empty_and_single_block_files() {
    let empty = inline_metadata(0, &[]);
    let mut reader = Reader::new(&empty, never_called_open).unwrap();
    assert_eq!(reader.remaining_blocks(), 0);
    let mut output = vec![0x5a];
    assert!(!reader.read_block_into(&mut output).unwrap());
    assert_eq!(output, [0x5a]);

    let inline = inline_metadata(1, &[0x42]);
    let mut reader = Reader::new(&inline, never_called_open).unwrap();
    assert_eq!(reader.remaining_blocks(), 1);
    assert!(reader.read_block_into(&mut output).unwrap());
    assert_eq!(output, [0x5a, 0x42]);
    assert_eq!(reader.remaining_blocks(), 0);
    assert!(!reader.read_block_into(&mut output).unwrap());
}

#[test]
fn resource_fork_reader_rejects_inline_payload_and_empty_file_before_opening() {
    // The metadata for a resource-fork file is header-only and must
    // describe at least one block. Reject contradictions before I/O.
    for kind in Kind::ALL.into_iter().filter(|kind| kind.supported()) {
        for (size, payload) in [(0, &[][..]), (0, &[0x42][..]), (1, &[0x42][..])] {
            let mut data = Vec::new();
            decmpfs::Value {
                compression_type: decmpfs::CompressionType::new(
                    kind,
                    decmpfs::Storage::ResourceFork,
                ),
                uncompressed_size: size,
                extra_data: payload,
            }
            .write_to(&mut data)
            .unwrap();
            let error = Reader::new(&data, never_called_open).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }
}

#[test]
fn resource_fork_reader_accepts_header_only_single_block() {
    use applesauce_core::writer::Writer;

    let mut resource_fork = Vec::new();
    let rfork_ref = &mut resource_fork;
    let mut writer = Writer::new(Kind::default(), 1, move || Cursor::new(rfork_ref)).unwrap();
    writer.force_resource_fork().unwrap();
    writer.add_block(&[0x42]).unwrap();
    let mut metadata = Vec::new();
    writer.finish_decmpfs_data(&mut metadata).unwrap();
    assert_eq!(metadata.len(), decmpfs::HEADER_LEN);

    let mut reader = Reader::new(&metadata, || Cursor::new(&resource_fork)).unwrap();
    assert_eq!(reader.remaining_blocks(), 1);
    let mut payload = Vec::new();
    assert!(reader.read_block_into(&mut payload).unwrap());
    assert_eq!(payload, [0x42]);
    assert!(!reader.read_block_into(&mut payload).unwrap());
}

#[test]
fn resource_fork_reader_preserves_large_compressed_block_bytes() {
    use applesauce_core::writer::Writer;
    use applesauce_core::BLOCK_SIZE;

    // Exercise multiple read chunks without imposing an undocumented
    // compressed-size ceiling on otherwise valid resource-fork framing.
    let kind = Kind::default();
    let payload = vec![0x42; 2 * BLOCK_SIZE + 17];
    let mut resource_fork = Vec::new();
    let mut writer = {
        let rfork_ref = &mut resource_fork;
        Writer::new(kind, 1, move || Cursor::new(rfork_ref)).unwrap()
    };
    writer.force_resource_fork().unwrap();
    writer.add_block(&payload).unwrap();
    let mut metadata = Vec::new();
    writer.finish_decmpfs_data(&mut metadata).unwrap();

    let mut reader = Reader::new(&metadata, || Cursor::new(&resource_fork)).unwrap();
    let mut output = vec![0xa5, 0x5a];
    assert!(reader.read_block_into(&mut output).unwrap());
    assert_eq!(&output[..2], &[0xa5, 0x5a]);
    assert_eq!(&output[2..], payload);
    assert_eq!(reader.remaining_blocks(), 0);
    assert!(!reader.read_block_into(&mut output).unwrap());
}

#[test]
fn resource_fork_resizes_fail_closed_before_and_during_block_reads() {
    use applesauce_core::writer::Writer;
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Clone, Copy)]
    enum Change {
        GrowBefore,
        ShrinkBefore,
        GrowDuring,
    }

    struct MutatingFork {
        cursor: Cursor<Vec<u8>>,
        trigger: Arc<AtomicBool>,
        change: Change,
    }

    impl Read for MutatingFork {
        fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
            let count = self.cursor.read(dst)?;
            if count > 0
                && matches!(self.change, Change::GrowDuring)
                && self.trigger.swap(false, Ordering::SeqCst)
            {
                self.cursor.get_mut().push(0xa5);
            }
            Ok(count)
        }
    }

    impl Seek for MutatingFork {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            if matches!(pos, SeekFrom::End(0))
                && !matches!(self.change, Change::GrowDuring)
                && self.trigger.swap(false, Ordering::SeqCst)
            {
                match self.change {
                    Change::GrowBefore => self.cursor.get_mut().push(0xa5),
                    Change::ShrinkBefore => {
                        let _ = self.cursor.get_mut().pop();
                    }
                    Change::GrowDuring => unreachable!(),
                }
            }
            self.cursor.seek(pos)
        }
    }

    let mut resource_fork = Vec::new();
    let mut writer = Writer::new(Kind::default(), 1, {
        let rfork_ref = &mut resource_fork;
        move || Cursor::new(rfork_ref)
    })
    .unwrap();
    writer.force_resource_fork().unwrap();
    writer.add_block(&[0x42]).unwrap();
    let mut metadata = Vec::new();
    writer.finish_decmpfs_data(&mut metadata).unwrap();

    for change in [Change::GrowBefore, Change::ShrinkBefore, Change::GrowDuring] {
        let trigger = Arc::new(AtomicBool::new(false));
        let mut reader = Reader::new(&metadata, {
            let trigger = Arc::clone(&trigger);
            let bytes = resource_fork.clone();
            move || MutatingFork {
                cursor: Cursor::new(bytes),
                trigger,
                change,
            }
        })
        .unwrap();

        // Mutate only after the offset table has been validated. Both
        // pre-read and in-flight resizes must discard output and poison the
        // reader instead of returning bytes from a changed fork.
        trigger.store(true, Ordering::SeqCst);
        let mut output = vec![0xa5, 0x5a];
        let error = reader.read_block_into(&mut output).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(output, [0xa5, 0x5a]);
        assert_eq!(reader.remaining_blocks(), 1);
        assert_eq!(
            reader.read_block_into(&mut output).unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(output, [0xa5, 0x5a]);
    }
}

#[test]
fn sparse_resource_fork_does_not_allocate_its_declared_block_before_reading() {
    use std::io::{Read, Seek, SeekFrom};

    // The LZ table has two absolute offsets for a single block. A forged
    // seekable fork can report 32 MiB while only supplying the eight table
    // bytes. This must fail after at most one bounded read allocation.
    let Some(kind) = Kind::ALL
        .into_iter()
        .find(|kind| *kind != Kind::Zlib && kind.supported())
    else {
        return;
    };
    const REPORTED_LEN: u64 = 32 * 1024 * 1024;
    struct SparseFork {
        cursor: Cursor<[u8; 8]>,
    }
    impl Read for SparseFork {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.cursor.read(buf)
        }
    }
    impl Seek for SparseFork {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            match pos {
                SeekFrom::End(0) => Ok(REPORTED_LEN),
                other => self.cursor.seek(other),
            }
        }
    }

    let mut offsets = [0u8; 8];
    offsets[..4].copy_from_slice(&8u32.to_le_bytes());
    offsets[4..].copy_from_slice(&(REPORTED_LEN as u32).to_le_bytes());
    let mut metadata = Vec::new();
    decmpfs::Value {
        compression_type: decmpfs::CompressionType::new(kind, decmpfs::Storage::ResourceFork),
        uncompressed_size: 1,
        extra_data: &[],
    }
    .write_to(&mut metadata)
    .unwrap();

    let mut reader = Reader::new(&metadata, move || SparseFork {
        cursor: Cursor::new(offsets),
    })
    .unwrap();
    let mut output = vec![0xa5, 0x5a];
    assert_eq!(
        reader.read_block_into(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert_eq!(output, [0xa5, 0x5a]);
    assert!(
        output.capacity() < 128 * 1024,
        "truncated sparse fork must not allocate its declared 32 MiB block"
    );
    assert_eq!(reader.remaining_blocks(), 1);
    assert_eq!(
        reader.read_block_into(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[test]
fn same_length_resource_fork_table_mutation_is_rejected_at_open() {
    use applesauce_core::writer::Writer;
    use std::io::{Read, Seek, SeekFrom};

    let Some(kind) = Kind::ALL
        .into_iter()
        .find(|kind| *kind != Kind::Zlib && kind.supported())
    else {
        return;
    };

    // Two LZ blocks have a 12-byte table and four bytes of payload.
    // Both offset layouts are individually valid and have identical EOF.
    let mut fork = Vec::new();
    let mut writer = {
        let rfork_ref = &mut fork;
        Writer::new(kind, BLOCK_SIZE as u64 + 1, move || {
            Cursor::new(rfork_ref)
        })
        .unwrap()
    };
    writer.add_block(&[0x11, 0x12]).unwrap();
    writer.add_block(&[0x21, 0x22]).unwrap();
    let mut metadata = Vec::new();
    writer.finish_decmpfs_data(&mut metadata).unwrap();
    assert!(Reader::new(&metadata, || Cursor::new(fork.clone())).is_ok());

    struct MutatingFork {
        bytes: Cursor<Vec<u8>>,
        eof_checks: usize,
    }

    impl Read for MutatingFork {
        fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
            self.bytes.read(dst)
        }
    }

    impl Seek for MutatingFork {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            if matches!(from, SeekFrom::End(0)) {
                self.eof_checks += 1;
                if self.eof_checks == 3 {
                    // The first parser has completed. Change only the
                    // boundary between the two blocks (14 -> 15), leaving
                    // the table, payload and physical fork length intact.
                    self.bytes.get_mut()[4..8].copy_from_slice(&15u32.to_le_bytes());
                }
            }
            self.bytes.seek(from)
        }
    }

    let error = Reader::new(&metadata, || MutatingFork {
        bytes: Cursor::new(fork),
        eof_checks: 0,
    })
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[cfg(feature = "zlib")]
#[test]
fn partial_resource_fork_read_preserves_output_and_fails_closed() {
    use applesauce_core::writer::Writer;
    use applesauce_core::BLOCK_SIZE;
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Only fail reads after the resource-fork table and trailer have passed
    // validation during Reader::new. A one-byte read followed by an injected
    // error exercises partial payload delivery through BufReader.
    struct FailingRead {
        cursor: Cursor<Vec<u8>>,
        armed: Arc<AtomicBool>,
        delivered: bool,
    }

    impl Read for FailingRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.armed.load(Ordering::SeqCst) {
                return self.cursor.read(buf);
            }
            if self.delivered {
                return Err(std::io::Error::other("injected payload read failure"));
            }
            self.delivered = true;
            let len = buf.len().min(1);
            self.cursor.read(&mut buf[..len])
        }
    }

    impl Seek for FailingRead {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(pos)
        }
    }

    let mut resource_fork = Vec::new();
    let rfork_ref = &mut resource_fork;
    let mut writer = Writer::new(Kind::Zlib, BLOCK_SIZE as u64 + 1, move || {
        Cursor::new(rfork_ref)
    })
    .unwrap();
    writer.add_block(&vec![0x41; 16 * 1024]).unwrap();
    writer.add_block(&[0x42; 4]).unwrap();
    let mut metadata = Vec::new();
    writer.finish_decmpfs_data(&mut metadata).unwrap();

    let armed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&armed);
    let mut reader = Reader::new(&metadata, || FailingRead {
        cursor: Cursor::new(resource_fork),
        armed: flag,
        delivered: false,
    })
    .unwrap();
    assert_eq!(reader.remaining_blocks(), 2);
    armed.store(true, Ordering::SeqCst);

    let mut output = vec![0xa5, 0x5a];
    assert_eq!(
        reader.read_block_into(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::Other
    );
    assert_eq!(output, [0xa5, 0x5a], "partial bytes must be rolled back");
    assert_eq!(reader.remaining_blocks(), 2, "failed block remains pending");
    assert_eq!(
        reader.read_block_into(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe,
        "retry must fail closed rather than skip a corrupted block"
    );
    assert_eq!(output, [0xa5, 0x5a]);
}

fn round_trip(kind: Kind, uncompressed_data: &[u8]) {
    let mut compressor = kind.compressor().unwrap();

    let mut resource_fork = Vec::new();
    let mut writer = applesauce_core::writer::Writer::new(kind, uncompressed_data.len() as u64, {
        let rfork_ref = &mut resource_fork;
        move || Cursor::new(rfork_ref)
    })
    .unwrap();

    let mut compressed_block = vec![0; applesauce_core::BLOCK_SIZE * 2];
    for block in uncompressed_data.chunks(applesauce_core::BLOCK_SIZE) {
        let len = compressor
            .compress(&mut compressed_block, block, 5)
            .unwrap();
        writer.add_block(&compressed_block[..len]).unwrap();
    }

    let mut decmpfs_data = Vec::new();
    writer.finish_decmpfs_data(&mut decmpfs_data).unwrap();

    let mut reader = Reader::new(&decmpfs_data, || Cursor::new(&resource_fork)).unwrap();

    assert_eq!(reader.compression_kind(), kind);
    assert_eq!(
        reader.remaining_blocks(),
        applesauce_core::num_blocks(uncompressed_data.len() as u64) as usize
    );

    let mut clear_data = Vec::new();
    // Need an extra byte, because lzfse/lzvn needs at least one extra byte to differentiate between
    // finishing on the last byte and running out of space
    let mut clear_buf = vec![0; applesauce_core::BLOCK_SIZE + 1];

    loop {
        compressed_block.clear();
        if !reader.read_block_into(&mut compressed_block).unwrap() {
            break;
        }
        let len = compressor
            .decompress(&mut clear_buf, &compressed_block)
            .unwrap();
        let expected_len = if reader.remaining_blocks() != 0
            || uncompressed_data
                .len()
                .is_multiple_of(applesauce_core::BLOCK_SIZE)
        {
            applesauce_core::BLOCK_SIZE
        } else {
            uncompressed_data.len() % applesauce_core::BLOCK_SIZE
        };
        assert_eq!(len, expected_len);
        clear_data.extend_from_slice(&clear_buf[..len]);
    }
    assert_eq!(clear_data, uncompressed_data);
}

macro_rules! round_trip_tests {
    ($($name:ident),* $(,)?) => {
        $(
            mod $name {
                use super::round_trip;
                use applesauce_core::compressor::Compressor;

                #[test]
                fn round_trip_empty() {
                    round_trip(Compressor::$name().kind(), &[]);
                }

                #[test]
                fn round_trip_small() {
                    round_trip(Compressor::$name().kind(), &[1]);
                    round_trip(Compressor::$name().kind(), &[1, 2, 3, 4]);
                }

                #[test]
                fn round_trip_large_compresable() {
                    round_trip(Compressor::$name().kind(), &[1; 1024 * 1024]);
                    round_trip(Compressor::$name().kind(), &[1; 1024 * 1024 - 1]);
                }

                #[test]
                fn round_trip_large_rand() {
                    use rand::Rng;

                    let mut data = vec![0; 1024 * 1024];
                    rand::rng().fill_bytes(&mut data);

                    round_trip(Compressor::$name().kind(), &data);
                }
            }
        )*
    };
}

#[cfg(feature = "lzfse")]
round_trip_tests!(lzfse);

#[cfg(feature = "lzvn")]
round_trip_tests!(lzvn);

#[cfg(feature = "zlib")]
round_trip_tests!(zlib);
