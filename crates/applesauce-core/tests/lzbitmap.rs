#![cfg(all(target_os = "macos", feature = "lzbitmap"))]

use applesauce_core::compressor::Kind;
use applesauce_core::decmpfs::{Storage, Value};
use applesauce_core::{reader::Reader, writer::Writer, BLOCK_SIZE};
use std::io::Cursor;

fn round_trip(input: &[u8], expected_type: u32) -> (Vec<u8>, Vec<u8>) {
    let kind = Kind::Lzbitmap;
    let mut compressor = kind
        .compressor()
        .expect("native tests require macOS 12+ and a working LZBitmap buffer codec");
    let mut fork = Vec::new();
    let mut writer = Writer::new(kind, input.len() as u64, {
        let fork_ref = &mut fork;
        move || Cursor::new(fork_ref)
    })
    .unwrap();
    let mut block = vec![0; BLOCK_SIZE + 1];
    for input in input.chunks(BLOCK_SIZE) {
        let size = compressor.compress(&mut block, input, 0).unwrap();
        writer.add_block(&block[..size]).unwrap();
    }
    let mut attribute = Vec::new();
    writer.finish_decmpfs_data(&mut attribute).unwrap();
    let value = Value::from_data(&attribute).unwrap();
    assert_eq!(value.compression_type.raw_type(), expected_type);
    assert_eq!(value.uncompressed_size, input.len() as u64);
    assert_eq!(
        value.compression_type.compression_storage(),
        Some((
            kind,
            if expected_type == 13 {
                Storage::Xattr
            } else {
                Storage::ResourceFork
            }
        ))
    );

    let mut reader = Reader::new(&attribute, || Cursor::new(&fork)).unwrap();
    let mut decoded = Vec::new();
    let mut output = vec![0; BLOCK_SIZE + 1];
    loop {
        block.clear();
        if !reader.read_block_into(&mut block).unwrap() {
            break;
        }
        let size = compressor.decompress(&mut output, &block).unwrap();
        decoded.extend_from_slice(&output[..size]);
    }
    assert_eq!(decoded, input);
    (attribute, fork)
}

#[test]
fn type13_inline_round_trip() {
    let (_, fork) = round_trip(&vec![b'a'; 16384], 13);
    assert!(fork.is_empty());
}

#[test]
fn type13_stored_tail_is_prefixed_with_ff() {
    let (attribute, _) = round_trip(b"x", 13);
    assert_eq!(
        Value::from_data(&attribute).unwrap().extra_data,
        &[0xff, b'x']
    );
}

#[test]
fn type14_uses_absolute_offsets_and_handles_a_stored_last_block() {
    let mut input = vec![b'a'; BLOCK_SIZE];
    input.push(b'x');
    let (_, fork) = round_trip(&input, 14);
    let offsets: Vec<u32> = fork[..12]
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    assert_eq!(offsets[0], 12);
    assert_eq!(offsets[2] as usize, fork.len());
    assert_eq!(&fork[offsets[1] as usize..], &[0xff, b'x']);
}

#[test]
fn type14_multiblock_round_trip_with_mixed_content() {
    let mut input = vec![b'a'; BLOCK_SIZE];
    let mut state = 0x1234_5678u32;
    input.extend((0..BLOCK_SIZE).map(|_| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state as u8
    }));
    input.extend_from_slice(&[b'b'; 31]);
    round_trip(&input, 14);
}
