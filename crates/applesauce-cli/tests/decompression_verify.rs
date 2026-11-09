//! End-to-end CLI smoke test on disposable generated macOS compressed files.
//! No user paths or experimental native codecs are involved.

use std::fs;
use std::process::Command;
use std::time::{Duration, SystemTime};

#[test]
fn default_and_manual_decompression_verify_generated_native_files() {
    let dir = tempfile::tempdir().unwrap();
    let fixture: Vec<u8> = (0..(3 * 65_536 + 17))
        .map(|index| b"lzfse restored content"[index % 22])
        .collect();

    for (index, manual) in [false, true].into_iter().enumerate() {
        let file = dir.path().join(format!("restoration-{index}.txt"));
        fs::write(&file, &fixture).unwrap();
        // Use an old exact-second timestamp so a successful restore cannot
        // accidentally pass by retaining the freshly created staging time.
        let reference_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_690_000_000);
        fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(reference_time)
            .unwrap();
        let original_modified = fs::metadata(&file).unwrap().modified().unwrap();

        let compressed = Command::new(env!("CARGO_BIN_EXE_applesauce"))
            .args(["compress", "--verify", "-c", "zlib"])
            .arg(&file)
            .output()
            .unwrap();
        assert!(
            compressed.status.success(),
            "compress failed: {}",
            String::from_utf8_lossy(&compressed.stderr)
        );
        assert!(applesauce::info::get(&file).unwrap().is_compressed);
        assert_eq!(
            fs::metadata(&file).unwrap().modified().unwrap(),
            original_modified,
            "compression changed the fixture modification time"
        );

        // The unsafe switch requires --manual and cannot change a file just
        // because the operator supplied it accidentally.
        let rejected = Command::new(env!("CARGO_BIN_EXE_applesauce"))
            .args(["decompress", "--no-verify"])
            .arg(&file)
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        assert!(applesauce::info::get(&file).unwrap().is_compressed);

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_applesauce"));
        cmd.arg("decompress");
        if manual {
            cmd.arg("--manual");
        }
        let restored = cmd.arg(&file).output().unwrap();
        assert!(
            restored.status.success(),
            "decompress failed: {}",
            String::from_utf8_lossy(&restored.stderr)
        );
        assert_eq!(fs::read(&file).unwrap(), fixture);
        assert!(!applesauce::info::get(&file).unwrap().is_compressed);
        assert_eq!(
            fs::metadata(&file).unwrap().modified().unwrap(),
            original_modified,
            "verified restoration did not preserve the original timestamp"
        );
    }
}

#[test]
fn a_missing_restore_root_fails_even_if_other_files_are_restored() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("existing.txt");
    let missing = dir.path().join("missing.txt");
    let source = vec![b'A'; 128 * 1024];
    fs::write(&existing, &source).unwrap();

    let compressed = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(["compress", "--verify", "-c", "zlib"])
        .arg(&existing)
        .output()
        .unwrap();
    assert!(
        compressed.status.success(),
        "compress failed: {}",
        String::from_utf8_lossy(&compressed.stderr)
    );
    assert!(applesauce::info::get(&existing).unwrap().is_compressed);

    // One failing input must make the entire invocation fail, while verified
    // restoration of independent valid inputs can still finish safely.
    let restored = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .arg("decompress")
        .arg(&existing)
        .arg(&missing)
        .output()
        .unwrap();
    assert!(
        !restored.status.success(),
        "decompress silently accepted a nonexistent requested input"
    );
    assert_eq!(fs::read(&existing).unwrap(), source);
    assert!(!applesauce::info::get(&existing).unwrap().is_compressed);
    assert!(!missing.exists());
}

#[test]
fn unsafe_manual_recovery_warns_even_without_tracing_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("unsafe-recovery.txt");
    let source = vec![b'R'; 256 * 1024];
    fs::write(&file, &source).unwrap();

    let compressed = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(["compress", "--verify", "-c", "zlib"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        compressed.status.success(),
        "compress failed: {}",
        String::from_utf8_lossy(&compressed.stderr)
    );
    assert!(applesauce::info::get(&file).unwrap().is_compressed);

    // Ordinary invocations suppress tracing warnings. The unsafe escape hatch
    // must still emit a human-visible warning on stderr before restoration.
    let restored = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(["decompress", "--manual", "--no-verify"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "unsafe manual recovery failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let warning = String::from_utf8_lossy(&restored.stderr);
    assert!(warning.contains("WARNING: --manual --no-verify"), "{warning}");
    assert!(warning.contains("back up the compressed source"), "{warning}");
    assert_eq!(fs::read(&file).unwrap(), source);
    assert!(!applesauce::info::get(&file).unwrap().is_compressed);
}
