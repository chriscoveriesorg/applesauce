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
        assert_eq!(fs::read(&path).unwrap(), original, "transparent read of {name}");

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
