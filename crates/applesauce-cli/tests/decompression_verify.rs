//! End-to-end CLI smoke test on disposable generated macOS compressed files.
//! No user paths or experimental native codecs are involved.

use resource_fork::ResourceFork;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
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
        // Multiple 64 KiB blocks use the decmpfs resource fork. Verify the
        // compressed payload exists so the cleanup assertion is meaningful.
        let compressed_file = fs::File::open(&file).unwrap();
        let mut compressed_fork = Vec::new();
        ResourceFork::new(&compressed_file)
            .read_to_end(&mut compressed_fork)
            .unwrap();
        assert!(
            !compressed_fork.is_empty(),
            "generated multi-block fixture should be resource-fork-backed"
        );
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
        let restored_file = fs::File::open(&file).unwrap();
        let mut stale_fork = Vec::new();
        ResourceFork::new(&restored_file)
            .read_to_end(&mut stale_fork)
            .unwrap();
        assert!(
            stale_fork.is_empty(),
            "restored plaintext retained a stale compressed resource fork"
        );
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
    assert!(
        warning.contains("WARNING: --manual --no-verify"),
        "{warning}"
    );
    assert!(
        warning.contains("back up the compressed source"),
        "{warning}"
    );
    assert_eq!(fs::read(&file).unwrap(), source);
    assert!(!applesauce::info::get(&file).unwrap().is_compressed);
}

#[test]
fn explicit_link_restore_roots_exit_nonzero_and_preserve_data() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("data.txt");
    let symlink_root = dir.path().join("linked.txt");
    let hardlink_root = dir.path().join("hardlinked.txt");
    let source = b"generated restore refusal fixture";
    fs::write(&original, source).unwrap();
    symlink(&original, &symlink_root).unwrap();
    fs::hard_link(&original, &hardlink_root).unwrap();

    for path in [&symlink_root, &hardlink_root] {
        let output = Command::new(env!("CARGO_BIN_EXE_applesauce"))
            .arg("decompress")
            .arg(path)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "accepted unsafe restoration root {}",
            path.display()
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("refusing to restore"), "{stderr}");
        assert_eq!(fs::read(&original).unwrap(), source.to_vec());
    }
    assert!(symlink_root
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&hardlink_root).unwrap(), source.to_vec());
}

#[test]
fn explicit_symlink_compression_roots_exit_nonzero_and_preserve_targets() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("outside-selected-root");
    let regular = directory.join("original.txt");
    let file_link = dir.path().join("selected-file.txt");
    let directory_link = dir.path().join("selected-directory");
    let original = vec![b'B'; 3 * 65_536 + 29];

    fs::create_dir(&directory).unwrap();
    fs::write(&regular, &original).unwrap();
    symlink(&regular, &file_link).unwrap();
    symlink(&directory, &directory_link).unwrap();

    for root in [&file_link, &directory_link] {
        let output = Command::new(env!("CARGO_BIN_EXE_applesauce"))
            .args(["compress", "-c", "zlib", "--verify"])
            .arg(root)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "compressed through explicitly selected symlink {}",
            root.display()
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("refusing to compress a symlink input root"),
            "{stderr}"
        );
        assert!(root.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&regular).unwrap(), original);
        assert!(!applesauce::info::get(&regular).unwrap().is_compressed);
    }
}

#[test]
fn restore_failures_produce_bounded_actionable_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_applesauce"));
    cmd.arg("decompress");
    for index in 0..23 {
        cmd.arg(dir.path().join(format!("missing-{index}.txt")));
    }
    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing-0.txt"), "{stderr}");
    assert!(stderr.contains("missing-19.txt"), "{stderr}");
    assert!(
        stderr.contains("3 additional decompression error(s)"),
        "{stderr}"
    );
    assert!(stderr.contains("23 decompression error(s)"), "{stderr}");
}

#[test]
fn compressed_publication_preserves_original_timestamps_with_and_without_verification() {
    // The compressed writer must finalize timestamps on the staging inode.
    // Both modes should preserve birth/modified timestamps across publication.
    let dir = tempfile::tempdir().unwrap();
    for verify in [false, true] {
        let file = dir.path().join(format!("compressed-{verify}.txt"));
        let source = vec![b'T'; 256 * 1024];
        fs::write(&file, &source).unwrap();
        let reference_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_650_000_000);
        fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(reference_time)
            .unwrap();

        let original = fs::metadata(&file).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_applesauce"));
        command.args(["compress", "-c", "zlib"]);
        if verify {
            command.arg("--verify");
        }
        let result = command.arg(&file).output().unwrap();
        assert!(
            result.status.success(),
            "compress (verify={verify}) failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(applesauce::info::get(&file).unwrap().is_compressed);
        let after = fs::metadata(&file).unwrap();
        assert_eq!(
            after.modified().unwrap(),
            original.modified().unwrap(),
            "compression changed modification time (verify={verify})"
        );
        assert_eq!(
            after.created().unwrap(),
            original.created().unwrap(),
            "compression changed creation time (verify={verify})"
        );
        assert_eq!(fs::read(&file).unwrap(), source);
    }
}

#[test]
fn overlapping_restore_roots_publish_one_verified_restoration() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("overlap.txt");
    let original = vec![b'O'; 3 * 65_536 + 47];
    fs::write(&source, &original).unwrap();

    let compressed = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(["compress", "--verify", "-c", "zlib"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        compressed.status.success(),
        "fixture compression failed: {}",
        String::from_utf8_lossy(&compressed.stderr)
    );
    assert!(applesauce::info::get(&source).unwrap().is_compressed);

    // A directory, its contained file and a repeat of the same pathname
    // represent the same compressed inode. Only one restore may be queued.
    let restored = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .arg("decompress")
        .arg(dir.path())
        .arg(&source)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "overlapping restoration failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(fs::read(&source).unwrap(), original);
    assert!(!applesauce::info::get(&source).unwrap().is_compressed);
}

#[test]
fn mixed_directory_restore_skips_uncompressed_ineligible_files() {
    // All three sibling files are ordinary, uncompressed inputs. Their
    // Incompressible classifications only prohibit *compression* and must
    // never dispatch a decompression writer or fail the directory restore.
    let dir = tempfile::tempdir().unwrap();
    let compressed_path = dir.path().join("compressed.txt");
    let empty_path = dir.path().join("empty.txt");
    let huge_path = dir.path().join("large-sparse.txt");
    let fork_path = dir.path().join("has-resource-fork.txt");
    let original = vec![b'C'; 3 * 65_536 + 41];
    fs::write(&compressed_path, &original).unwrap();
    fs::write(&empty_path, []).unwrap();

    // A sparse file exercises the native decmpfs 4 GiB eligibility limit
    // without allocating or reading a multi-gigabyte fixture.
    let huge_size = u64::from(u32::MAX) + 1;
    fs::File::create(&huge_path)
        .unwrap()
        .set_len(huge_size)
        .unwrap();

    fs::write(&fork_path, b"keep the ordinary file and its fork").unwrap();
    let fork_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fork_path)
        .unwrap();
    let fork_bytes = b"uncompressed resource fork fixture";
    ResourceFork::new(&fork_file).write_all(fork_bytes).unwrap();
    drop(fork_file);

    let compressed = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(["compress", "-c", "zlib", "--verify"])
        .arg(&compressed_path)
        .output()
        .unwrap();
    assert!(
        compressed.status.success(),
        "fixture compression failed: {}",
        String::from_utf8_lossy(&compressed.stderr)
    );
    assert!(
        applesauce::info::get(&compressed_path)
            .unwrap()
            .is_compressed
    );

    let restored = Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .arg("decompress")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "mixed restore should skip ineligible uncompressed files: {}",
        String::from_utf8_lossy(&restored.stderr)
    );

    assert_eq!(fs::read(&compressed_path).unwrap(), original);
    assert!(
        !applesauce::info::get(&compressed_path)
            .unwrap()
            .is_compressed
    );
    assert_eq!(fs::metadata(&empty_path).unwrap().len(), 0);
    assert_eq!(fs::metadata(&huge_path).unwrap().len(), huge_size);
    assert_eq!(
        fs::read(&fork_path).unwrap(),
        b"keep the ordinary file and its fork"
    );
    let mut preserved_fork = Vec::new();
    ResourceFork::new(&fs::File::open(&fork_path).unwrap())
        .read_to_end(&mut preserved_fork)
        .unwrap();
    assert_eq!(preserved_fork, fork_bytes);
}
