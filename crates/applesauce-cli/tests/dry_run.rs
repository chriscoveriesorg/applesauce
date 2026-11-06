#![cfg(target_os = "macos")]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, Metadata, Permissions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_applesauce"))
}

fn run(args: &[&OsStr]) -> Output {
    Command::new(binary()).args(args).output().unwrap()
}

fn arg(value: &str) -> &OsStr {
    OsStr::new(value)
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn set_xattr(path: &Path, name: &CStr, value: &[u8]) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: all pointers and lengths refer to live buffers and both C strings
    // are NUL terminated. The fixture is disposable.
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_SHOWCOMPRESSION,
        )
    };
    assert_eq!(rc, 0, "{}", io::Error::last_os_error());
}

fn xattrs(path: &Path) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let flags = libc::XATTR_SHOWCOMPRESSION | libc::XATTR_NOFOLLOW;
    // SAFETY: null/zero is the documented size probe.
    let length = unsafe { libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0, flags) };
    assert!(length >= 0, "{}", io::Error::last_os_error());
    let mut names = vec![0; length as usize];
    // SAFETY: `names` is writable for the provided length.
    let actual =
        unsafe { libc::listxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len(), flags) };
    assert!(actual >= 0, "{}", io::Error::last_os_error());
    names.truncate(actual as usize);

    let mut result = BTreeMap::new();
    for raw_name in names.split_inclusive(|byte| *byte == 0) {
        if raw_name.is_empty() {
            continue;
        }
        let name = CStr::from_bytes_with_nul(raw_name).unwrap();
        // SAFETY: null/zero is the documented value-size probe.
        let length = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                flags,
            )
        };
        assert!(length >= 0, "{}", io::Error::last_os_error());
        let mut value = vec![0; length as usize];
        // SAFETY: `value` is writable for the provided length.
        let actual = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                flags,
            )
        };
        assert!(actual >= 0, "{}", io::Error::last_os_error());
        value.truncate(actual as usize);
        result.insert(name.to_bytes().to_vec(), value);
    }
    result
}

fn descriptor_xattrs(file: &File) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let flags = libc::XATTR_SHOWCOMPRESSION;
    // SAFETY: null/zero is the documented size probe for this live descriptor.
    let length = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, flags) };
    assert!(length >= 0, "{}", io::Error::last_os_error());
    let mut names = vec![0; length as usize];
    // SAFETY: `names` is writable for the provided length.
    let actual = unsafe {
        libc::flistxattr(
            file.as_raw_fd(),
            names.as_mut_ptr().cast(),
            names.len(),
            flags,
        )
    };
    assert!(actual >= 0, "{}", io::Error::last_os_error());
    names.truncate(actual as usize);

    let mut result = BTreeMap::new();
    for raw_name in names.split_inclusive(|byte| *byte == 0) {
        if raw_name.is_empty() {
            continue;
        }
        let name = CStr::from_bytes_with_nul(raw_name).unwrap();
        // SAFETY: null/zero is the documented value-size probe.
        let length = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                flags,
            )
        };
        assert!(length >= 0, "{}", io::Error::last_os_error());
        let mut value = vec![0; length as usize];
        // SAFETY: `value` is writable for the provided length.
        let actual = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                flags,
            )
        };
        assert!(actual >= 0, "{}", io::Error::last_os_error());
        value.truncate(actual as usize);
        result.insert(name.to_bytes().to_vec(), value);
    }
    result
}

#[derive(Debug, Eq, PartialEq)]
struct SnapshotEntry {
    relative_path: Vec<u8>,
    entry_type: &'static str,
    bytes: Option<Vec<u8>>,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    flags: u32,
    mode: u32,
    logical_size: u64,
    allocated_bytes: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    directory_listing: Vec<Vec<u8>>,
}

fn snapshot(root: &Path) -> Vec<SnapshotEntry> {
    fn visit(root: &Path, path: &Path, entries: &mut Vec<SnapshotEntry>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let entry_type = if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_dir() {
            "directory"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        };
        let mut listing = Vec::new();
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                listing.push(entry.unwrap().file_name().as_bytes().to_vec());
            }
            listing.sort();
        }
        entries.push(SnapshotEntry {
            relative_path: path
                .strip_prefix(root)
                .unwrap()
                .as_os_str()
                .as_bytes()
                .to_vec(),
            entry_type,
            bytes: metadata.is_file().then(|| fs::read(path).unwrap()),
            xattrs: xattrs(path),
            flags: metadata.st_flags(),
            mode: metadata.mode(),
            logical_size: metadata.len(),
            allocated_bytes: metadata.blocks() * 512,
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            directory_listing: listing,
        });
        if metadata.is_dir() {
            let mut children: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            children.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
            for child in children {
                visit(root, &child, entries);
            }
        }
    }

    let mut result = Vec::new();
    visit(root, root, &mut result);
    result
}

#[derive(Debug, Eq, PartialEq)]
struct RestrictedSnapshot {
    bytes: Vec<u8>,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    flags: u32,
    mode: u32,
    logical_size: u64,
    allocated_bytes: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    parent_mode: u32,
    parent_listing: Vec<Vec<u8>>,
}

fn descriptor_listing(directory: &File) -> Vec<Vec<u8>> {
    // SAFETY: duplicate is called with a live directory descriptor.
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    assert!(duplicate >= 0, "{}", io::Error::last_os_error());
    // SAFETY: fdopendir takes ownership of the duplicate only.
    let stream = unsafe { libc::fdopendir(duplicate) };
    assert!(!stream.is_null(), "{}", io::Error::last_os_error());
    let mut listing = Vec::new();
    loop {
        // SAFETY: stream remains live until closed below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated and copied before the next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            listing.push(name.to_vec());
        }
    }
    // SAFETY: stream was returned by fdopendir and is closed exactly once.
    assert_eq!(unsafe { libc::closedir(stream) }, 0);
    listing.sort();
    listing
}

fn restricted_snapshot(descriptor: &mut File, parent_descriptor: &File) -> RestrictedSnapshot {
    descriptor.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    descriptor.read_to_end(&mut bytes).unwrap();
    let metadata = descriptor.metadata().unwrap();
    let parent_metadata = parent_descriptor.metadata().unwrap();
    RestrictedSnapshot {
        bytes,
        xattrs: descriptor_xattrs(descriptor),
        flags: metadata.st_flags(),
        mode: metadata.mode(),
        logical_size: metadata.len(),
        allocated_bytes: metadata.blocks() * 512,
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
        parent_mode: parent_metadata.mode(),
        parent_listing: descriptor_listing(parent_descriptor),
    }
}

fn pseudorandom(size: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..size)
        .map(|_| {
            state ^= state << 7;
            state ^= state >> 9;
            state ^= state << 8;
            state as u8
        })
        .collect()
}

fn create_fixture(root: &Path, codec: &str) {
    fs::create_dir_all(root.join("nested/deeper")).unwrap();
    fs::write(
        root.join("inline.txt"),
        b"inline generated line\n".repeat(64),
    )
    .unwrap();
    fs::write(
        root.join("resource.jsonl"),
        b"{\"generated\":\"resource fork fixture\"}\n".repeat(6000),
    )
    .unwrap();
    fs::write(root.join("uncompressible.bin"), pseudorandom(96 * 1024)).unwrap();
    fs::write(
        root.join("nested/xattrs.txt"),
        b"xattr fixture\n".repeat(800),
    )
    .unwrap();
    set_xattr(
        &root.join("nested/xattrs.txt"),
        c"com.example.applesauce-test",
        b"preserved metadata",
    );
    File::create(root.join("empty")).unwrap();
    fs::write(root.join("required-decmpfs"), b"must be skipped").unwrap();
    set_xattr(
        &root.join("required-decmpfs"),
        c"com.apple.decmpfs",
        b"fpmc-required-fixture",
    );
    fs::write(root.join("required-resource-fork"), b"must be skipped").unwrap();
    set_xattr(
        &root.join("required-resource-fork"),
        c"com.apple.ResourceFork",
        b"required fixture fork",
    );
    fs::write(root.join("hard-a"), b"hard link fixture").unwrap();
    fs::hard_link(root.join("hard-a"), root.join("hard-b")).unwrap();
    symlink("inline.txt", root.join("file-symlink")).unwrap();
    symlink("nested", root.join("directory-symlink")).unwrap();
    let non_utf8 = root.join(OsStr::from_bytes(b"non-utf8-\xff"));
    if let Err(error) = fs::write(non_utf8, b"non utf8 generated bytes\n".repeat(32)) {
        // APFS rejects ill-formed UTF-8 with EILSEQ; a managed sandbox may
        // reject the name before it reaches the filesystem. The CLI still
        // exercises lossless encoding below with a missing non-UTF-8 input.
        assert!(
            error.kind() == io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(libc::EILSEQ),
            "unexpected non-UTF-8 fixture error: {error}"
        );
    }
    fs::write(
        root.join("nested/deeper/already-compressed"),
        b"already compressed fixture line\n".repeat(1500),
    )
    .unwrap();
    let already = root.join("nested/deeper/already-compressed");
    let output = run(&[
        arg("compress"),
        arg("--compression"),
        arg(codec),
        arg("--minimum-compression-ratio"),
        arg("1"),
        already.as_os_str(),
    ]);
    assert_success(&output);
}

fn copy_fixture(source: &Path, destination: &Path) {
    fn native_path(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    fn copy_metadata(source: &Path, destination: &Path) {
        let source = native_path(source);
        let destination = native_path(destination);
        // SAFETY: both paths are live NUL-terminated strings. The fixture and
        // destination are inside one disposable temporary directory.
        let rc = unsafe {
            libc::copyfile(
                source.as_ptr(),
                destination.as_ptr(),
                std::ptr::null_mut(),
                libc::COPYFILE_METADATA | libc::COPYFILE_NOFOLLOW,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    }

    fn visit(source: &Path, destination: &Path, hard_links: &mut BTreeMap<(u64, u64), PathBuf>) {
        let metadata = fs::symlink_metadata(source).unwrap();
        if metadata.file_type().is_symlink() {
            symlink(fs::read_link(source).unwrap(), destination).unwrap();
            copy_metadata(source, destination);
        } else if metadata.is_dir() {
            fs::create_dir(destination).unwrap();
            let mut children: Vec<_> = fs::read_dir(source)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            children.sort_by(|left, right| {
                left.file_name()
                    .as_bytes()
                    .cmp(right.file_name().as_bytes())
            });
            for child in children {
                visit(
                    &child.path(),
                    &destination.join(child.file_name()),
                    hard_links,
                );
            }
            copy_metadata(source, destination);
        } else if metadata.is_file() {
            let identity = (metadata.dev(), metadata.ino());
            if let Some(existing) = hard_links.get(&identity) {
                fs::hard_link(existing, destination).unwrap();
                return;
            }
            let source_c = native_path(source);
            let destination_c = native_path(destination);
            // SAFETY: both paths are live NUL-terminated strings on the same
            // APFS test volume. clonefile preserves data, xattrs, flags, and
            // compression state without mutating the source.
            let rc = unsafe { libc::clonefile(source_c.as_ptr(), destination_c.as_ptr(), 0) };
            assert_eq!(rc, 0, "{}", io::Error::last_os_error());
            hard_links.insert(identity, destination.to_owned());
        } else {
            panic!("unexpected fixture entry: {}", source.display());
        }
    }

    visit(source, destination, &mut BTreeMap::new());
}

fn assert_fixture_copy(source: &Path, copy: &Path) {
    let source_entries = snapshot(source);
    let copy_entries = snapshot(copy);
    assert_eq!(source_entries.len(), copy_entries.len());
    for (source_entry, copy_entry) in source_entries.iter().zip(&copy_entries) {
        assert_eq!(source_entry.relative_path, copy_entry.relative_path);
        assert_eq!(source_entry.entry_type, copy_entry.entry_type);
        assert_eq!(source_entry.bytes, copy_entry.bytes);
        assert_eq!(source_entry.xattrs, copy_entry.xattrs);
        assert_eq!(source_entry.flags, copy_entry.flags);
        assert_eq!(source_entry.mode, copy_entry.mode);
        assert_eq!(source_entry.logical_size, copy_entry.logical_size);
        assert_eq!(source_entry.mtime, copy_entry.mtime);
        assert_eq!(source_entry.directory_listing, copy_entry.directory_listing);
    }
    assert_eq!(
        fs::read_link(source.join("file-symlink")).unwrap(),
        fs::read_link(copy.join("file-symlink")).unwrap()
    );
    assert_eq!(
        fs::read_link(source.join("directory-symlink")).unwrap(),
        fs::read_link(copy.join("directory-symlink")).unwrap()
    );
    let source_a = fs::metadata(source.join("hard-a")).unwrap();
    let source_b = fs::metadata(source.join("hard-b")).unwrap();
    let copy_a = fs::metadata(copy.join("hard-a")).unwrap();
    let copy_b = fs::metadata(copy.join("hard-b")).unwrap();
    assert_eq!(source_a.ino(), source_b.ino());
    assert_eq!(copy_a.ino(), copy_b.ino());
    assert_ne!(source_a.ino(), copy_a.ino());
    assert_ne!(source_a.dev(), 0);
    assert_eq!(source_a.nlink(), copy_a.nlink());
}

fn included_entries<'a>(report: &'a Value, directory: &Path) -> Vec<&'a Value> {
    report["paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            if entry["entry_type"] != "file" || entry["reason"] == "hard_link" {
                return false;
            }
            let path = path_from_hex(entry["path"]["bytes_hex"].as_str().unwrap());
            path.starts_with(directory)
        })
        .collect()
}

fn hard_links_below(report: &Value, directory: &Path) -> u64 {
    report["paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["reason"] == "hard_link"
                && path_from_hex(entry["path"]["bytes_hex"].as_str().unwrap())
                    .starts_with(directory)
        })
        .count() as u64
}

fn assert_totals_match_entries(totals: &Value, entries: &[&Value], hard_links: u64) {
    let sum = |field: &str| -> u64 {
        entries
            .iter()
            .map(|entry| entry[field].as_u64().unwrap())
            .sum()
    };
    let logical = sum("logical_size_bytes");
    let current = sum("current_allocation_bytes");
    let projected = sum("projected_native_allocation_bytes");
    let upper = sum("projected_native_allocation_upper_bound_bytes");
    assert_eq!(totals["complete"], true);
    assert_eq!(totals["files_included"], entries.len() as u64);
    assert_eq!(
        totals["files_would_compress"],
        entries
            .iter()
            .filter(|entry| entry["would_compress"] == true)
            .count() as u64
    );
    assert_eq!(
        totals["files_skipped"],
        entries
            .iter()
            .filter(|entry| entry["would_compress"] == false)
            .count() as u64
    );
    assert_eq!(totals["hard_links_excluded"], hard_links);
    assert_eq!(totals["logical_size_bytes"], logical);
    assert_eq!(totals["current_allocation_bytes"], current);
    assert_eq!(totals["projected_native_allocation_bytes"], projected);
    assert_eq!(
        totals["projected_native_allocation_upper_bound_bytes"],
        upper
    );
    assert_eq!(
        totals["savings_bytes"].as_i64().unwrap(),
        i64::try_from(current).unwrap() - i64::try_from(projected).unwrap()
    );
    assert!(upper >= projected);
}

fn assert_report_totals(report: &Value, root: &Path) {
    let root_entries = included_entries(report, root);
    assert_totals_match_entries(
        &report["totals"],
        &root_entries,
        hard_links_below(report, root),
    );
    for relative in [Path::new("nested"), Path::new("nested/deeper")] {
        let directory_path = root.join(relative);
        let directory = report["directories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| {
                path_from_hex(entry["path"]["bytes_hex"].as_str().unwrap()) == directory_path
            })
            .unwrap_or_else(|| panic!("missing directory {}", directory_path.display()));
        let entries = included_entries(report, &directory_path);
        assert_totals_match_entries(
            &directory["totals"],
            &entries,
            hard_links_below(report, &directory_path),
        );
    }
}

fn json_dry_run(root: &Path, codec: &str, extra: &[&OsStr]) -> (Output, Value) {
    let mut args = vec![
        arg("compress"),
        arg("--dry-run"),
        arg("--json"),
        arg("--compression"),
        arg(codec),
    ];
    args.extend_from_slice(extra);
    args.push(root.as_os_str());
    let output = run(&args);
    let json = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "bad JSON: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, json)
}

#[test]
fn dry_run_is_structurally_read_only_and_schema_is_fail_closed() {
    let temp = tempdir();
    let root = temp.path().join("tree");
    create_fixture(&root, "lzfse");
    let before = snapshot(&root);

    let (output, json) = json_dry_run(&root, "lzfse", &[root.join("nested").as_os_str()]);
    assert_success(&output);
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["complete"], true);
    assert_eq!(json["full_encoding"], true);
    assert!(json["totals"]["logical_size_bytes"].is_u64());
    assert!(json["totals"]["current_allocation_bytes"].is_u64());
    assert!(json["totals"]["projected_native_allocation_bytes"].is_u64());
    assert!(json["totals"]["savings_bytes"].is_i64());
    assert_eq!(json["totals"]["hard_links_excluded"], 2);
    let reasons: BTreeSet<_> = json["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["reason"].as_str().unwrap())
        .collect();
    for reason in [
        "compress",
        "already_compressed",
        "below_minimum_ratio",
        "empty_file",
        "required_compression_xattr",
        "hard_link",
        "symlink",
    ] {
        assert!(reasons.contains(reason), "missing {reason}: {reasons:?}");
    }
    assert_report_totals(&json, &root);
    assert_eq!(snapshot(&root), before);

    let text = run(&[
        arg("compress"),
        arg("--dry-run"),
        arg("--compression"),
        arg("lzfse"),
        root.as_os_str(),
    ]);
    assert_success(&text);
    let text = String::from_utf8(text.stdout).unwrap();
    let directory_line = text
        .lines()
        .find(|line| line.starts_with(&format!("{}: directory ", root.display())))
        .unwrap_or_else(|| panic!("missing root directory line:\n{text}"));
    assert!(
        directory_line.contains("savings_bytes="),
        "{directory_line}"
    );

    let missing_non_utf8 = root.join(OsStr::from_bytes(b"missing-non-utf8-\xff"));
    let (output, non_utf8_json) = json_dry_run(&missing_non_utf8, "lzfse", &[]);
    assert!(!output.status.success());
    assert_eq!(non_utf8_json["complete"], false);
    assert_eq!(
        non_utf8_json["paths"][0]["path"]["bytes_hex"],
        bytes_hex(missing_non_utf8.as_os_str().as_bytes())
    );
    assert!(non_utf8_json["paths"][0]["path"]["display"]
        .as_str()
        .is_some());

    let no_dry = run(&[arg("compress"), arg("--json"), root.as_os_str()]);
    assert!(!no_dry.status.success());

    let trace = temp.path().join("must-not-exist.trace");
    let tracing = run(&[
        arg("--chrome-tracing"),
        trace.as_os_str(),
        arg("compress"),
        arg("--dry-run"),
        root.as_os_str(),
    ]);
    assert!(!tracing.status.success());
    assert!(!trace.exists());
}

#[test]
fn symlinks_are_never_followed_and_errors_make_totals_null() {
    let temp = tempdir();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("secret"), b"must not be encoded").unwrap();
    let root_link = temp.path().join("root-link");
    symlink(&target, &root_link).unwrap();
    let (output, json) = json_dry_run(&root_link, "lzfse", &[]);
    assert_success(&output);
    assert_eq!(json["paths"].as_array().unwrap().len(), 1);
    assert_eq!(json["paths"][0]["reason"], "symlink");

    let ancestor = temp.path().join("ancestor-link");
    symlink(&target, &ancestor).unwrap();
    let (output, json) = json_dry_run(&ancestor.join("secret"), "lzfse", &[]);
    assert!(!output.status.success());
    assert_eq!(json["complete"], false);
    assert!(json["totals"]["logical_size_bytes"].is_null());
    assert_eq!(json["paths"][0]["reason"], "error");

    let denied_parent = temp.path().join("denied-parent");
    fs::create_dir(&denied_parent).unwrap();
    let denied = denied_parent.join("denied");
    fs::write(&denied, b"permission denied fixture").unwrap();
    set_xattr(&denied, c"com.example.denied", b"preserve me");
    let mut denied_descriptor = File::open(&denied).unwrap();
    let denied_parent_before = File::open(&denied_parent).unwrap();
    let denied_parent_after = File::open(&denied_parent).unwrap();
    let original = fs::metadata(&denied_parent).unwrap().permissions();
    fs::set_permissions(&denied_parent, Permissions::from_mode(0o0)).unwrap();
    let denied_before = restricted_snapshot(&mut denied_descriptor, &denied_parent_before);
    let (output, json) = json_dry_run(&denied, "lzfse", &[]);
    assert!(!output.status.success());
    assert_eq!(json["complete"], false);
    assert_eq!(json["paths"][0]["error"]["kind"], "permission_denied");
    assert!(json["totals"]["current_allocation_bytes"].is_null());
    assert_eq!(
        restricted_snapshot(&mut denied_descriptor, &denied_parent_after),
        denied_before
    );
    fs::set_permissions(&denied_parent, original).unwrap();
}

#[test]
fn ratio_edges_nonfinite_values_and_non_native_codecs_are_stable() {
    let temp = tempdir();
    let file = temp.path().join("ratio.bin");
    fs::write(&file, pseudorandom(32 * 1024)).unwrap();

    let (zero_output, zero) = json_dry_run(
        &file,
        "lzfse",
        &[arg("--minimum-compression-ratio"), arg("0")],
    );
    assert_success(&zero_output);
    assert_eq!(zero["minimum_compression_ratio"], 0.0);
    assert_eq!(zero["paths"][0]["would_compress"], false);
    assert_eq!(zero["paths"][0]["reason"], "below_minimum_ratio");

    let (forced_output, forced) = json_dry_run(
        &file,
        "lzfse",
        &[arg("--minimum-compression-ratio"), arg("2")],
    );
    assert_success(&forced_output);
    assert_eq!(forced["minimum_compression_ratio"], 2.0);
    assert_eq!(forced["paths"][0]["would_compress"], true);

    for value in ["NaN", "inf", "-inf"] {
        let ratio = format!("--minimum-compression-ratio={value}");
        let output = run(&[
            arg("compress"),
            arg("--dry-run"),
            arg("--json"),
            ratio.as_ref(),
            file.as_os_str(),
        ]);
        assert!(!output.status.success(), "accepted {value}");
        assert!(output.stdout.is_empty(), "{value} wrote unstable JSON");
        assert!(String::from_utf8_lossy(&output.stderr).contains("must be finite"));
    }

    let trace = temp.path().join("nonfinite.trace");
    let nonfinite_real = run(&[
        arg("--chrome-tracing"),
        trace.as_os_str(),
        arg("compress"),
        arg("--minimum-compression-ratio"),
        arg("NaN"),
        file.as_os_str(),
    ]);
    assert!(!nonfinite_real.status.success());
    assert!(!trace.exists());

    for codec in ["lzraven", "lzmesh", "lzbitmap", "default"] {
        if codec == "lzbitmap" && cfg!(feature = "lzbitmap") {
            continue;
        }
        let output = run(&[
            arg("compress"),
            arg("--dry-run"),
            arg("--compression"),
            arg(codec),
            file.as_os_str(),
        ]);
        assert!(
            !output.status.success(),
            "accepted non-native codec {codec}"
        );
    }

    let help = run(&[arg("compress"), arg("--help")]);
    assert_success(&help);
    let help = String::from_utf8(help.stdout).unwrap();
    assert_eq!(help.contains("lzbitmap"), cfg!(feature = "lzbitmap"));
    assert!(help.contains("Every eligible regular file is encoded in full"));
    assert!(!help.contains("Every regular file is encoded in full"));
}

#[test]
fn accuracy_all_stable_codecs_projection_table() {
    println!(
        "codec\tpath\tblock\tprojected\tupper\tactual\terror\tcompressed\n-----\t----\t-----\t---------\t-----\t------\t-----\t----------"
    );
    for codec in ["zlib", "lzvn", "lzfse"] {
        let temp = tempdir();
        let source = temp.path().join("source");
        let copy = temp.path().join("copy");
        create_fixture(&source, codec);
        let (dry_output, report) = json_dry_run(&source, codec, &[]);
        assert_success(&dry_output);
        assert_report_totals(&report, &source);

        // This is a real recursive copy made only after the projection. `cp -a`
        // uses macOS copyfile facilities and retains compression xattrs/flags,
        // ordinary xattrs, hard-link topology, and symlinks.
        copy_fixture(&source, &copy);
        assert_fixture_copy(&source, &copy);

        let real = run(&[
            arg("compress"),
            arg("--compression"),
            arg(codec),
            arg("--minimum-compression-ratio"),
            arg("0.95"),
            copy.as_os_str(),
        ]);
        assert_success(&real);

        let mut projected_total = 0u64;
        let mut upper_total = 0u64;
        let mut actual_total = 0u64;
        for entry in report["paths"].as_array().unwrap() {
            if entry["entry_type"] != "file" || entry["reason"] == "hard_link" {
                continue;
            }
            let source_path = path_from_hex(entry["path"]["bytes_hex"].as_str().unwrap());
            let relative = source_path.strip_prefix(&source).unwrap();
            let actual_path = copy.join(relative);
            let metadata: Metadata = fs::symlink_metadata(&actual_path).unwrap();
            let actual = metadata.blocks() * 512;
            let projected = entry["projected_native_allocation_bytes"].as_u64().unwrap();
            let upper = entry["projected_native_allocation_upper_bound_bytes"]
                .as_u64()
                .unwrap();
            let block = entry["allocation_block_bytes"]
                .as_u64()
                .unwrap_or_else(|| filesystem_block_size(&actual_path));
            let error = projected.abs_diff(actual);
            let reason = entry["reason"].as_str().unwrap();
            let compressed = metadata.st_flags() & libc::UF_COMPRESSED != 0;
            let expected_compressed =
                entry["would_compress"] == true || reason == "already_compressed";
            assert_eq!(
                compressed,
                expected_compressed,
                "{codec} {} reason={reason}",
                relative.display()
            );
            if reason == "below_minimum_ratio" {
                assert!(!compressed, "ratio-rejected file was compressed");
            }
            println!(
                "{codec}\t{}\t{block}\t{projected}\t{upper}\t{actual}\t{error}\t{compressed}",
                relative.display(),
            );
            assert!(
                error <= block,
                "{codec} {} projected={projected} actual={actual} block={block}",
                relative.display()
            );
            assert!(
                actual <= upper,
                "{codec} {} actual={actual} accounting_upper={upper}",
                relative.display()
            );
            projected_total += projected;
            upper_total += upper;
            actual_total += actual;
        }
        assert_eq!(
            report["totals"]["projected_native_allocation_bytes"],
            projected_total
        );
        assert_eq!(
            report["totals"]["projected_native_allocation_upper_bound_bytes"],
            upper_total
        );
        let total_error = projected_total.abs_diff(actual_total);
        let block = filesystem_block_size(&copy);
        println!(
            "{codec}\tTOTAL\t{block}\t{projected_total}\t{upper_total}\t{actual_total}\t{total_error}\t-"
        );
        assert!(
            actual_total <= upper_total,
            "{codec} total actual={actual_total} accounting_upper={upper_total}"
        );
    }
}

fn filesystem_block_size(path: &Path) -> u64 {
    let file = File::open(path).unwrap_or_else(|_| File::open(path.parent().unwrap()).unwrap());
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid descriptor and writable output structure.
    let rc = unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) };
    assert_eq!(rc, 0);
    // SAFETY: fstatfs succeeded.
    u64::from(unsafe { stat.assume_init().f_bsize })
}

fn path_from_hex(hex: &str) -> PathBuf {
    assert_eq!(hex.len() % 2, 0);
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect();
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
