//! End-to-end native LZFSE readback on generated disposable files.
//! This exercises the established decmpfs types 11/12 and ordinary kernel
//! reads. It does not probe private codecs or modify user files.
#![cfg(all(target_os = "macos", feature = "lzfse"))]

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

    fn file_skipped(&self, path: &Path, reason: SkipReason) {
        self.0
            .lock()
            .unwrap()
            .push(format!("{}: {reason}", path.display()));
    }

    fn file_task(&self, _: &Path, _: u64) -> Self::Task {
        self.clone()
    }
}

fn assert_no_errors(progress: &CaptureProgress) {
    let errors = progress.0.lock().unwrap();
    assert!(errors.is_empty(), "{errors:?}");
}

fn generated_native_round_trip(input: &[u8], expected_type: u32) {
    assert!(Kind::Lzfse.supported());
    assert!(input.len() >= 32);

    // Only touch this automatically removed temporary fixture. The same
    // logical file is read via normal macOS filesystem APIs, independently
    // of Applesauce's manual decoder.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("generated-lzfse.jsonl");
    fs::write(&path, input).unwrap();
    let original_modified = fs::metadata(&path).unwrap().modified().unwrap();

    let progress = CaptureProgress::default();
    let mut compressor = FileCompressor::new();
    let stats =
        compressor.recursive_compress([path.as_path()], Kind::Lzfse, 1.0, 0, &progress, true);
    assert_no_errors(&progress);
    assert_eq!(stats.compressed_file_count_final.load(Ordering::Relaxed), 1);

    let state = info::get(&path).unwrap();
    assert!(state.is_compressed);
    let metadata = state.decmpfs_info.unwrap().unwrap();
    assert_eq!(metadata.compression_type.raw_type(), expected_type);
    assert_eq!(metadata.orig_file_size, input.len() as u64);

    assert_eq!(fs::read(&path).unwrap(), input);
    let mut reopened = File::open(&path).unwrap();
    let mut offsets = vec![0, input.len() / 2, input.len() - 32];
    if input.len() > applesauce_core::BLOCK_SIZE + 32 {
        offsets.extend([
            applesauce_core::BLOCK_SIZE - 16,
            applesauce_core::BLOCK_SIZE,
        ]);
    }
    for offset in offsets {
        reopened.seek(SeekFrom::Start(offset as u64)).unwrap();
        let mut bytes = [0u8; 32];
        reopened.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, &input[offset..offset + bytes.len()]);
    }
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        original_modified
    );

    // Verify restored bytes against the original kernel-visible contents
    // before publishing the uncompressed replacement.
    compressor.recursive_decompress([path.as_path()], true, &progress, true);
    assert_no_errors(&progress);
    assert!(!info::get(&path).unwrap().is_compressed);
    assert_eq!(fs::read(&path).unwrap(), input);
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        original_modified
    );
}

#[test]
fn native_lzfse_inline_type11_generated_jsonl() {
    let input = b"{\"role\":\"assistant\",\"content\":\"lzfse inline fixture\"}\n".repeat(256);
    generated_native_round_trip(&input, 11);
}

#[test]
fn native_lzfse_multiblock_type12_kernel_readback() {
    // Multiple independent blocks, including a partial final block.
    let input = b"{\"role\":\"assistant\",\"content\":\"lzfse multiblock fixture\"}\n".repeat(4096);
    assert!(input.len() > 2 * applesauce_core::BLOCK_SIZE);
    assert_ne!(input.len() % applesauce_core::BLOCK_SIZE, 0);
    generated_native_round_trip(&input, 12);
}
