//! Native compression readback on disposable generated macOS files.
//! Exercises the kernel-visible path, not user-space decompression.

use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

#[test]
fn verified_compression_reopens_and_hashes_inline_and_resource_fork_files() {
    let dir = tempfile::tempdir().unwrap();
    for length in [8 * 1024, 3 * 65_536 + 37] {
        let path = dir.path().join(format!("generated-{length}.txt"));
        let original: Vec<u8> = (0..length)
            .map(|index| b"generated kernel readback fixture"[index % 33])
            .collect();
        fs::write(&path, &original).unwrap();
        let expected_hash = format!("{:x}", Sha256::digest(&original));

        let result = Command::new(env!("CARGO_BIN_EXE_applesauce"))
            .args(["-v", "compress", "--verify", "-c", "zlib"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "compress failed for length {length}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            applesauce::info::get(&path).unwrap().is_compressed,
            "fixture should produce native compression"
        );
        let output = String::from_utf8_lossy(&result.stderr);
        assert!(
            output.contains(&format!("verified: kernel-read sha256={expected_hash}")),
            "missing post-publication kernel readback for length {length}: {output}"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}
