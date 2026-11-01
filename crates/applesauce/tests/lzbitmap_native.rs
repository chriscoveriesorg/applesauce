//! Real native filesystem qualification, never user data. Run on an APFS/HFS+
//! macOS 12+ host with `cargo test -p applesauce --features lzbitmap --test lzbitmap_native`.
#![cfg(all(target_os = "macos", feature = "lzbitmap"))]

use applesauce::compressor::Kind;
use applesauce::progress::{Progress, SkipReason, Task};
use applesauce::{info, FileCompressor};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct CaptureProgress(Arc<Mutex<Vec<String>>>);

impl Task for CaptureProgress {
    fn increment(&self, _: u64) {}
    fn error(&self, message: &str) {
        self.0.lock().unwrap().push(message.to_owned());
    }
}

impl Progress for CaptureProgress {
    type Task = Self;

    fn error(&self, path: &Path, message: &str) {
        self.0
            .lock()
            .unwrap()
            .push(format!("{}: {message}", path.display()));
    }

    fn file_skipped(&self, path: &Path, why: SkipReason) {
        self.0
            .lock()
            .unwrap()
            .push(format!("{}: {why}", path.display()));
    }

    fn file_task(&self, _: &Path, _: u64) -> Self::Task {
        self.clone()
    }
}

fn native_round_trip(input: &[u8], expected_type: u32) {
    assert!(
        Kind::Lzbitmap.supported(),
        "requires a working macOS 12+ LZBitmap codec"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("generated-fixture.log");
    fs::write(&path, input).unwrap();
    let original_modified = fs::metadata(&path).unwrap().modified().unwrap();
    let progress = CaptureProgress::default();
    let mut compressor = FileCompressor::new();
    let stats =
        compressor.recursive_compress([path.as_path()], Kind::Lzbitmap, 1.0, 0, &progress, true);
    {
        let errors = progress.0.lock().unwrap();
        assert!(errors.is_empty(), "{errors:?}");
    }
    assert_eq!(stats.compressed_file_count_final.load(Ordering::Relaxed), 1);

    // Read the real metadata, not the requested algorithm or a private queue's
    // success boolean, and exercise ordinary file reads rather than our buffer
    // decoder. Reopening does not evict vnode/page cache: release qualification
    // must additionally repeat readback after unmounting/remounting a test volume.
    let compressed = info::get(&path).unwrap();
    assert!(compressed.is_compressed);
    let metadata = compressed.decmpfs_info.unwrap().unwrap();
    assert_eq!(metadata.compression_type.raw_type(), expected_type);
    assert_eq!(metadata.orig_file_size, input.len() as u64);
    assert_eq!(fs::read(&path).unwrap(), input);
    let mut reopened = File::open(&path).unwrap();
    for offset in [0, input.len() / 2, input.len() - 8] {
        reopened.seek(SeekFrom::Start(offset as u64)).unwrap();
        let mut bytes = [0; 8];
        reopened.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, &input[offset..offset + 8]);
    }
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        original_modified
    );

    // Exercise Applesauce's manual decoder too, then read the restored file.
    compressor.recursive_decompress([path.as_path()], true, &progress, true);
    {
        let errors = progress.0.lock().unwrap();
        assert!(errors.is_empty(), "{errors:?}");
    }
    assert!(!info::get(&path).unwrap().is_compressed);
    assert_eq!(fs::read(&path).unwrap(), input);
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        original_modified
    );
}

#[test]
fn kernel_reads_type13_inline_generated_jsonl() {
    let input = b"{\"role\":\"assistant\",\"content\":\"generated native fixture\"}\n".repeat(256);
    native_round_trip(&input, 13);
}

#[test]
fn kernel_reads_type14_multiblock_with_raw_fallback() {
    let mut input = vec![b'a'; applesauce_core::BLOCK_SIZE];
    let mut state = 0x1234_5678u32;
    input.extend((0..applesauce_core::BLOCK_SIZE).map(|_| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state as u8
    }));
    input.extend_from_slice(&[b'b'; 31]);
    native_round_trip(&input, 14);
}
