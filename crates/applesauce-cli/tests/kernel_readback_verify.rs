//! Native compression readback on disposable generated macOS files.
//! Exercises the kernel-visible path, not user-space decompression.

use applesauce_core::decmpfs::Storage;
use sha2::{Digest, Sha256};
use std::fs::{self, File, FileTimes};
use std::process::Command;
use std::time::{Duration, SystemTime};

#[test]
fn verified_compression_reopens_and_hashes_inline_and_resource_fork_files() {
    let dir = tempfile::tempdir().unwrap();
    for (length, expected_storage) in [
        (8 * 1024, Storage::Xattr),
        (3 * 65_536 + 37, Storage::ResourceFork),
    ] {
        let path = dir.path().join(format!("generated-{length}.txt"));
        let original: Vec<u8> = if expected_storage == Storage::Xattr {
            (0..length)
                .map(|index| b"generated kernel readback fixture"[index % 33])
                .collect()
        } else {
            // A repeated 16-KiB high-entropy block compresses well but cannot
            // fit inside the 3,802-byte decmpfs xattr. Exercise fork-backed
            // multi-chunk decoding rather than another tiny inline payload.
            let mut seed = 0x1234_5678u32;
            let block: Vec<u8> = (0..16 * 1024)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    (seed >> 24) as u8
                })
                .collect();
            block.into_iter().cycle().take(length).collect()
        };
        fs::write(&path, &original).unwrap();
        let expected_hash: String = Sha256::digest(&original)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        let result = Command::new(env!("CARGO_BIN_EXE_applesauce"))
            .args(["-v", "compress", "--verify", "--json", "-c", "zlib"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "compress failed for length {length}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let info = applesauce::info::get(&path).unwrap();
        assert!(
            info.is_compressed,
            "fixture should produce native compression"
        );
        let storage = info
            .decmpfs_info
            .expect("compressed fixture must have decmpfs metadata")
            .expect("decmpfs metadata must decode")
            .compression_type
            .compression_storage()
            .expect("native zlib compression type must be recognized")
            .1;
        assert_eq!(
            storage, expected_storage,
            "fixture length {length} must exercise {expected_storage} storage"
        );
        let output = String::from_utf8_lossy(&result.stderr);
        assert!(
            output.contains(&format!("verified: kernel-read sha256={expected_hash}")),
            "missing post-publication kernel readback for length {length}: {output}"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("actual-storage JSON should parse");
        let evidence = report["kernel_readbacks"]
            .as_array()
            .expect("successful verification should produce JSON evidence");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0]["sha256"].as_str(), Some(expected_hash.as_str()));
        assert_eq!(
            evidence[0]["coverage"].as_str(),
            Some("whole_sha256_and_deterministic_pread")
        );
        assert_eq!(
            evidence[0]["cache_state"].as_str(),
            Some("potentially_warm")
        );
        assert_eq!(
            evidence[0]["path"]["display"].as_str(),
            Some(path.to_string_lossy().as_ref())
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn kernel_readback_preserves_saved_atime_even_when_atime_predates_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("generated-old-atime.txt");
    let original = vec![b'R'; 3 * 65_536 + 27];
    fs::write(&path, &original).unwrap();

    // APFS can advance access time when it predates modification time.
    // Force that state to exercise both staging and published kernel reads.
    let atime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
    let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    let original_file = File::options().read(true).write(true).open(&path).unwrap();
    original_file
        .set_times(FileTimes::new().set_accessed(atime).set_modified(mtime))
        .unwrap();
    drop(original_file);
    let before = fs::metadata(&path).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(["compress", "--verify", "-c", "zlib"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "verified compression failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let after = fs::metadata(&path).unwrap();
    assert!(applesauce::info::get(&path).unwrap().is_compressed);
    assert_eq!(after.accessed().unwrap(), before.accessed().unwrap());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(fs::read(&path).unwrap(), original);
}
