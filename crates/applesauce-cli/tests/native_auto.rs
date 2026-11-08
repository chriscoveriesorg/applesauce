#![cfg(target_os = "macos")]
//! End-to-end opt-in auto selection on generated disposable source files.

use std::fs;
use std::process::Command;

fn run(arguments: &[&str], path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(arguments)
        .arg(path)
        .output()
        .unwrap()
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn auto_compresses_multiple_files_with_transparent_verified_reads() {
    // Same filesystem as the checkout, so the test observes the real macOS
    // native compression path without altering a user's own files.
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let repeated = vec![b'Q'; 3 * 65_536 + 17];
    let jsonl = (0..8000)
        .map(|i| format!("{{\"index\":{i},\"kind\":\"test\",\"value\":\"abcabcabcabc\"}}\n"))
        .collect::<String>()
        .into_bytes();

    for (name, original) in [("repeat.txt", repeated), ("events.jsonl", jsonl)] {
        let path = dir.path().join(name);
        fs::write(&path, &original).unwrap();

        let compressed = run(&["compress", "--compression", "auto", "--verify"], &path);
        assert_success(&compressed);
        assert!(applesauce::info::get(&path).unwrap().is_compressed);
        assert_eq!(
            fs::read(&path).unwrap(),
            original,
            "transparent read of {name}"
        );

        let restored = run(&["decompress", "--verify"], &path);
        assert_success(&restored);
        assert!(!applesauce::info::get(&path).unwrap().is_compressed);
        assert_eq!(fs::read(&path).unwrap(), original, "restored {name}");
    }
}

#[test]
fn auto_dry_run_refuses_without_mutating_generated_file() {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = dir.path().join("dry-run.txt");
    let original = vec![b'R'; 120_000];
    fs::write(&path, &original).unwrap();

    let output = run(&["compress", "--dry-run", "--compression", "auto"], &path);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not yet supported"));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(!applesauce::info::get(&path).unwrap().is_compressed);
}

#[test]
#[ignore = "manual APFS benchmark: records real allocation and wall time"]
fn native_auto_real_allocation_benchmark() {
    use std::time::Instant;

    // Every test input is generated and written under the checkout's volume.
    // Independent paths prevent APFS compression state from leaking between
    // repetitions. Timings are observations, never a CI pass/fail threshold.
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let repeated = vec![b'A'; 2 * 1024 * 1024];
    let jsonl = (0..40_000)
        .map(|index| format!("{{\"i\":{index},\"v\":\"abcabcabcabc\"}}\n"))
        .collect::<String>()
        .into_bytes();
    let mut mixed = vec![b'Z'; 2 * 1024 * 1024];
    let mut state = 0x1234_5678_u32;
    let random_half = mixed.len() / 2;
    for byte in &mut mixed[..random_half] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = (state >> 8) as u8;
    }

    println!("fixture,codec,repeat,logical_bytes,allocated_bytes,elapsed_microseconds,compressed");
    for (fixture, original) in [("repeated", repeated), ("jsonl", jsonl), ("mixed", mixed)] {
        let codecs = ["zlib", "lzvn", "lzfse", "auto"];
        // Rotating the order counters systematic warm-cache and startup bias:
        // each codec occupies every position once per fixture.
        for iteration in 0..codecs.len() {
            for offset in 0..codecs.len() {
                let codec = codecs[(offset + iteration) % codecs.len()];
                let path = dir.path().join(format!("{fixture}-{codec}-{iteration}.bin"));
                fs::write(&path, &original).unwrap();
                let start = Instant::now();
                let output = run(
                    &[
                        "compress",
                        "--compression",
                        codec,
                        "--minimum-compression-ratio",
                        "1.10",
                        "--verify",
                    ],
                    &path,
                );
                let elapsed = start.elapsed().as_micros();
                assert_success(&output);
                assert_eq!(fs::read(&path).unwrap(), original, "{fixture} {codec}");
                let info = applesauce::info::get(&path).unwrap();
                assert_eq!(info.stat_size, u64::try_from(original.len()).unwrap());
                println!(
                    "{fixture},{codec},{iteration},{},{},{elapsed},{}",
                    info.stat_size, info.on_disk_size, info.is_compressed
                );
            }
        }
    }
}
