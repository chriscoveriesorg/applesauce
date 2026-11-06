#![cfg(target_os = "macos")]
use serde_json::Value;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt as _};
use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_applesauce"))
        .args(args)
        .output()
        .unwrap()
}
fn arg(s: &str) -> &OsStr {
    OsStr::new(s)
}
fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}
fn info(path: &Path) -> Value {
    let output = run(&[arg("info"), arg("--json"), path.as_os_str()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    json(&output)
}

#[test]
fn sparse_empty_hardlinks_overlapping_roots_and_names_reconcile_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let child = root.join("child");
    fs::create_dir(&child).unwrap();
    let plain = root.join("tiny");
    fs::write(&plain, [b'x'; 100]).unwrap();
    fs::hard_link(&plain, child.join("alias")).unwrap();
    File::create(root.join("sparse"))
        .unwrap()
        .set_len(1024 * 1024)
        .unwrap();
    File::create(root.join("empty")).unwrap();
    let odd = root.join(OsString::from("bad-name"));
    fs::write(&odd, b"odd").unwrap();
    symlink(&plain, root.join("symlink")).unwrap();
    let before = fs::symlink_metadata(&plain).unwrap();
    let output = run(&[
        arg("info"),
        arg("--json"),
        root.as_os_str(),
        child.as_os_str(),
        plain.as_os_str(),
    ]);
    assert!(output.status.success());
    let report = json(&output);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["totals"]["files_included"], 4);
    assert_eq!(report["totals"]["logical_size_bytes"], 1024 * 1024 + 103);
    let allocation = ["tiny", "sparse", "empty"]
        .into_iter()
        .map(|name| fs::metadata(root.join(name)).unwrap().blocks() * 512)
        .sum::<u64>()
        + fs::metadata(&odd).unwrap().blocks() * 512;
    assert_eq!(report["totals"]["current_allocation_bytes"], allocation);
    assert_eq!(report["roots"][1]["totals"]["logical_size_bytes"], 100);
    assert_eq!(report["roots"][2]["totals"]["logical_size_bytes"], 100);
    let entries = report["paths"].as_array().unwrap();
    assert_eq!(entries.len(), 6);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| !entry["duplicate_of"].is_null())
            .count(),
        1
    );
    assert!(entries.iter().any(|entry| entry["path"]["bytes_hex"]
        .as_str()
        .unwrap()
        .ends_with("6261642d6e616d65")));
    let empty = entries
        .iter()
        .find(|entry| {
            entry["path"]["display"]
                .as_str()
                .unwrap()
                .ends_with("/empty")
        })
        .unwrap();
    assert_eq!(empty["savings_fraction"], 0.0);
    let after = fs::symlink_metadata(&plain).unwrap();
    assert_eq!(
        (
            before.ino(),
            before.len(),
            before.blocks(),
            before.st_flags(),
            before.mtime(),
            before.ctime()
        ),
        (
            after.ino(),
            after.len(),
            after.blocks(),
            after.st_flags(),
            after.mtime(),
            after.ctime()
        )
    );
    assert_eq!(fs::read(&plain).unwrap(), [b'x'; 100]);
    let legacy = applesauce::info::get_recursive(root).unwrap();
    assert_eq!(legacy.total_uncompressed_size, 1024 * 1024 + 103);
    assert_eq!(legacy.total_compressed_size, allocation);
}

#[test]
fn native_stable_codecs_report_payload_framing_and_identical_compress_snapshot() {
    // Only the stable codecs this build enables (CI also tests `--no-default-features --features zlib`).
    let codecs = [
        ("zlib", cfg!(feature = "zlib")),
        ("lzvn", cfg!(feature = "lzvn")),
        ("lzfse", cfg!(feature = "lzfse")),
    ];
    for codec in codecs.iter().filter(|(_, on)| *on).map(|(c, _)| *c) {
        for len in [4096usize, 1024 * 1024] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("native");
            fs::write(&path, vec![b'x'; len]).unwrap();
            let output = run(&[
                arg("compress"),
                arg("--json"),
                arg("-c"),
                arg(codec),
                path.as_os_str(),
            ]);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let compressed = json(&output);
            let current = info(&path);
            assert_eq!(compressed, current);
            let entry = &current["paths"][0];
            assert_eq!(entry["source"], "decmpfs");
            assert_eq!(entry["codec"], codec);
            assert_eq!(entry["logical_size_bytes"], len as u64);
            assert_eq!(
                entry["current_allocation_bytes"],
                fs::metadata(&path).unwrap().blocks() * 512
            );
            assert!(entry["raw_compressed_bytes"].as_u64().unwrap() > 0);
            assert!(entry["decmpfs_type"].is_u64());
            let raw = entry["raw_compressed_bytes"].as_u64().unwrap();
            if len == 4096 {
                assert_eq!(entry["storage"], "inline_xattr");
                assert_eq!(entry["decmpfs_xattr_bytes"], raw + 16);
                assert_eq!(entry["resource_fork_bytes"], 0);
            } else {
                assert_eq!(entry["storage"], "resource_fork");
                assert_eq!(entry["decmpfs_xattr_bytes"], 16);
                assert!(entry["resource_fork_bytes"].as_u64().unwrap() > raw);
            }
        }
    }
}

fn set_decmpfs(path: &Path, bytes: &[u8]) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: fixture path/name are terminated and bytes points to bytes.len() live bytes.
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"com.apple.decmpfs".as_ptr(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            libc::XATTR_SHOWCOMPRESSION,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}
#[test]
fn errors_fail_closed_unknown_types_are_never_guessed_and_info_creates_no_trace() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");
    let output = run(&[arg("info"), arg("--json"), missing.as_os_str()]);
    assert!(!output.status.success());
    let report = json(&output);
    assert_eq!(report["complete"], false);
    assert_eq!(report["paths"][0]["error"]["kind"], "not_found");
    assert!(report["totals"]["logical_size_bytes"].is_null());
    let broken = temp.path().join("broken.ascf");
    fs::write(&broken, b"ASCF0001").unwrap();
    let output = run(&[arg("info"), arg("--json"), broken.as_os_str()]);
    assert!(!output.status.success());
    assert_eq!(json(&output)["paths"][0]["source"], "ascf");
    let trace = temp.path().join("trace");
    let output = run(&[
        arg("--chrome-tracing"),
        trace.as_os_str(),
        arg("info"),
        arg("--json"),
        broken.as_os_str(),
    ]);
    assert!(!output.status.success());
    assert!(!trace.exists());
    let native = temp.path().join("unknown");
    fs::write(&native, b"x").unwrap();
    let mut header = b"fpmc".to_vec();
    header.extend_from_slice(&0xdead_u32.to_le_bytes());
    header.extend_from_slice(&1_u64.to_le_bytes());
    set_decmpfs(&native, &header);
    let output = run(&[arg("info"), arg("--json"), native.as_os_str()]);
    let report = json(&output);
    assert_eq!(report["paths"][0]["codec"], "unknown");
    assert_eq!(report["paths"][0]["decmpfs_type"], 0xdead);
    assert!(report["paths"][0]["storage"].is_null());
    assert!(report["paths"][0]["raw_compressed_bytes"].is_null());
    // A valid type on an ordinary file is still contradictory metadata.
    header[4..8].copy_from_slice(&3_u32.to_le_bytes());
    set_decmpfs(&native, &header);
    let output = run(&[arg("info"), arg("--json"), native.as_os_str()]);
    assert!(!output.status.success());
    assert!(json(&output)["totals"]["current_allocation_bytes"].is_null());
}

#[test]
fn compression_missing_input_is_incomplete_and_nonzero() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");
    let output = run(&[arg("compress"), arg("--json"), missing.as_os_str()]);
    assert!(!output.status.success());
    let report = json(&output);
    assert_eq!(report["complete"], false);
}
