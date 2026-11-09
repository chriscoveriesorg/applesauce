//! Actual storage measurements shared by `info` and the post-compression report.
use applesauce::compressor::Kind;
use applesauce_core::{cold_archive::ArchiveReader, decmpfs};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt};
use std::path::{Path, PathBuf};

type Identity = (u64, u64);

#[derive(Clone, Serialize)]
pub struct EncodedPath {
    display: String,
    bytes_hex: String,
}
impl EncodedPath {
    fn new(path: &Path) -> Self {
        Self {
            display: path.to_string_lossy().into_owned(),
            bytes_hex: path
                .as_os_str()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct ReportError {
    kind: &'static str,
    message: String,
}
impl ReportError {
    fn new(error: &io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::InvalidInput => "invalid_input",
            io::ErrorKind::InvalidData => "invalid_data",
            io::ErrorKind::UnexpectedEof => "unexpected_eof",
            io::ErrorKind::Unsupported => "unsupported",
            io::ErrorKind::WouldBlock => "would_block",
            _ => "io_error",
        };
        Self {
            kind,
            message: error.to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct PathReport {
    path: EncodedPath,
    entry_type: &'static str,
    source: &'static str,
    codec: &'static str,
    decmpfs_type: Option<u32>,
    storage: Option<&'static str>,
    logical_size_bytes: Option<u64>,
    current_allocation_bytes: Option<u64>,
    raw_compressed_bytes: Option<u64>,
    decmpfs_xattr_bytes: Option<u64>,
    resource_fork_bytes: Option<u64>,
    archive_bytes: Option<u64>,
    entry_count: Option<u64>,
    savings_bytes: Option<i128>,
    savings_fraction: Option<f64>,
    /// Repeated names still carry their own measurements.
    duplicate_of: Option<EncodedPath>,
    error: Option<ReportError>,
}
impl PathReport {
    fn empty(path: &Path, entry_type: &'static str) -> Self {
        Self {
            path: EncodedPath::new(path),
            entry_type,
            source: "none",
            codec: "none",
            decmpfs_type: None,
            storage: None,
            logical_size_bytes: None,
            current_allocation_bytes: None,
            raw_compressed_bytes: None,
            decmpfs_xattr_bytes: None,
            resource_fork_bytes: None,
            archive_bytes: None,
            entry_count: None,
            savings_bytes: None,
            savings_fraction: None,
            duplicate_of: None,
            error: None,
        }
    }
}

#[derive(Clone, Copy)]
struct Measurement {
    logical: u64,
    allocation: u64,
    raw: Option<u64>,
    decmpfs: u64,
    resource_fork: u64,
    archive: u64,
    entries: u64,
    codec: &'static str,
    storage: Option<&'static str>,
}
#[derive(Default)]
struct Subtree {
    files: BTreeMap<Identity, Measurement>,
    failed: bool,
}
impl Subtree {
    fn sum(&self, value: impl Fn(&Measurement) -> Option<u64>) -> Option<u64> {
        self.files
            .values()
            .try_fold(0u64, |sum, m| sum.checked_add(value(m)?))
    }
    fn merge(&mut self, other: &Self) {
        self.files
            .extend(other.files.iter().map(|(key, value)| (*key, *value)));
        self.failed |= other.failed;
    }
    fn totals(&self) -> Totals {
        let logical = self
            .files
            .values()
            .try_fold(0u64, |sum, m| sum.checked_add(m.logical));
        let allocation = self
            .files
            .values()
            .try_fold(0u64, |sum, m| sum.checked_add(m.allocation));
        let complete = !self.failed && logical.is_some() && allocation.is_some();
        let logical = logical.filter(|_| complete);
        let allocation = allocation.filter(|_| complete);
        Totals {
            complete,
            files_included: self.files.len() as u64,
            logical_size_bytes: logical,
            current_allocation_bytes: allocation,
            savings_bytes: logical
                .zip(allocation)
                .map(|(l, a)| i128::from(l) - i128::from(a)),
            savings_fraction: logical.zip(allocation).map(|(l, a)| fraction(l, a)),
            raw_compressed_bytes: self.sum(|m| m.raw).filter(|_| complete),
            decmpfs_xattr_bytes: self.sum(|m| Some(m.decmpfs)).filter(|_| complete),
            resource_fork_bytes: self.sum(|m| Some(m.resource_fork)).filter(|_| complete),
            archive_bytes: self.sum(|m| Some(m.archive)).filter(|_| complete),
            entry_count: self.sum(|m| Some(m.entries)).filter(|_| complete),
            codecs: self
                .files
                .values()
                .map(|m| m.codec)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            storage_forms: self
                .files
                .values()
                .filter_map(|m| m.storage)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }
}
#[derive(Serialize)]
pub struct Totals {
    raw_compressed_bytes: Option<u64>,
    decmpfs_xattr_bytes: Option<u64>,
    resource_fork_bytes: Option<u64>,
    archive_bytes: Option<u64>,
    entry_count: Option<u64>,
    codecs: Vec<&'static str>,
    storage_forms: Vec<&'static str>,
    complete: bool,
    files_included: u64,
    logical_size_bytes: Option<u64>,
    current_allocation_bytes: Option<u64>,
    savings_bytes: Option<i128>,
    savings_fraction: Option<f64>,
}
#[derive(Serialize)]
pub struct DirectoryReport {
    path: EncodedPath,
    totals: Totals,
    error: Option<ReportError>,
}
#[derive(Serialize)]
pub struct OperationError {
    path: EncodedPath,
    error: ReportError,
}
/// Successful operation attestations, distinct from a later filesystem scan.
#[derive(Serialize)]
struct KernelReadback {
    path: EncodedPath,
    sha256: String,
    coverage: &'static str,
    cache_state: &'static str,
}

#[derive(Serialize)]
pub struct Report {
    schema_version: u32,
    report_kind: &'static str,
    savings_basis: &'static str,
    pub complete: bool,
    allocation_measurement: &'static str,
    allocation_estimate_limitations: Vec<&'static str>,
    pub paths: Vec<PathReport>,
    directories: Vec<DirectoryReport>,
    roots: Vec<DirectoryReport>,
    totals: Totals,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kernel_readbacks: Vec<KernelReadback>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    operation_errors: Vec<OperationError>,
}
impl Report {
    pub fn kernel_verifications(&mut self, records: Vec<(PathBuf, String)>) {
        self.kernel_readbacks = records
            .into_iter()
            .map(|(path, sha256)| KernelReadback {
                path: EncodedPath::new(&path),
                sha256,
                coverage: "whole_sha256_and_deterministic_pread",
                cache_state: "potentially_warm",
            })
            .collect();
    }

    pub fn operation_errors(&mut self, errors: Vec<(PathBuf, String)>) {
        if !errors.is_empty() {
            self.complete = false;
        }
        self.operation_errors = errors
            .into_iter()
            .map(|(path, message)| OperationError {
                path: EncodedPath::new(&path),
                error: ReportError {
                    kind: "operation_failed",
                    message,
                },
            })
            .collect();
    }
}

pub fn analyze(paths: &[PathBuf]) -> Report {
    let mut report = Report {
        schema_version: 1,
        report_kind: "actual_storage",
        savings_basis: "logical_size_bytes - current_allocation_bytes",
        complete: true,
        allocation_measurement: "st_blocks * 512",
        allocation_estimate_limitations: vec![
            "Per-file stat allocation; shared clone extents and snapshots are not deduplicated.",
            "Directory inodes and filesystem metadata are excluded.",
            "This is not exclusive physical usage or reclaimable space.",
        ],
        paths: Vec::new(),
        directories: Vec::new(),
        roots: Vec::new(),
        totals: Subtree::default().totals(),
        kernel_readbacks: Vec::new(),
        operation_errors: Vec::new(),
    };
    let mut seen_paths = BTreeSet::new();
    let mut seen_files = BTreeMap::new();
    let mut combined = Subtree::default();
    let mut ancestors = BTreeSet::new();
    for path in paths {
        let subtree = walk(
            path,
            &mut report,
            &mut seen_paths,
            &mut seen_files,
            &mut ancestors,
        );
        report.roots.push(DirectoryReport {
            path: EncodedPath::new(path),
            totals: subtree.totals(),
            error: None,
        });
        combined.merge(&subtree);
    }
    report.totals = combined.totals();
    report.complete = report.totals.complete;
    report
}

#[allow(clippy::filetype_is_file)]
fn walk(
    path: &Path,
    report: &mut Report,
    seen_paths: &mut BTreeSet<PathBuf>,
    seen_files: &mut BTreeMap<Identity, EncodedPath>,
    ancestors: &mut BTreeSet<Identity>,
) -> Subtree {
    let mut subtree = Subtree::default();
    let first_path = seen_paths.insert(absolute(path));
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            subtree.failed = true;
            if first_path {
                let mut entry = PathReport::empty(path, "unknown");
                entry.error = Some(ReportError::new(&error));
                report.paths.push(entry);
            }
            return subtree;
        }
    };
    if metadata.is_dir() {
        let mut error = None;
        let identity = (metadata.dev(), metadata.ino());
        if !ancestors.insert(identity) {
            subtree.failed = true;
            if first_path {
                report.directories.push(DirectoryReport {
                    path: EncodedPath::new(path),
                    totals: subtree.totals(),
                    error: Some(ReportError::new(&invalid(
                        "directory cycle during inspection",
                    ))),
                });
            }
            return subtree;
        }
        match directory_names(path, &metadata) {
            Ok(children) => {
                for child in children {
                    subtree.merge(&walk(
                        &path.join(child),
                        report,
                        seen_paths,
                        seen_files,
                        ancestors,
                    ));
                }
            }
            Err(e) => {
                error = Some(ReportError::new(&e));
                subtree.failed = true;
            }
        }
        ancestors.remove(&identity);
        if first_path {
            report.directories.push(DirectoryReport {
                path: EncodedPath::new(path),
                totals: subtree.totals(),
                error,
            });
        }
    } else if metadata.file_type().is_file() {
        let mut entry = PathReport::empty(path, "file");
        if let Err(error) = measure(path, &metadata, &mut entry) {
            entry.error = Some(ReportError::new(&error));
            // A partial measurement must not look like a complete zero.
            entry.logical_size_bytes = None;
            entry.savings_bytes = None;
            entry.savings_fraction = None;
            subtree.failed = true;
        } else if let (Some(logical), Some(allocation)) =
            (entry.logical_size_bytes, entry.current_allocation_bytes)
        {
            let identity = (metadata.dev(), metadata.ino());
            subtree.files.insert(
                identity,
                Measurement {
                    logical,
                    allocation,
                    raw: if entry.source == "none" {
                        Some(0)
                    } else {
                        entry.raw_compressed_bytes
                    },
                    decmpfs: entry.decmpfs_xattr_bytes.unwrap_or(0),
                    resource_fork: entry.resource_fork_bytes.unwrap_or(0),
                    archive: entry.archive_bytes.unwrap_or(0),
                    entries: entry.entry_count.unwrap_or(0),
                    codec: entry.codec,
                    storage: entry.storage,
                },
            );
            entry.duplicate_of = seen_files.get(&identity).cloned();
            seen_files
                .entry(identity)
                .or_insert_with(|| entry.path.clone());
        }
        if first_path {
            report.paths.push(entry);
        }
    } else if first_path {
        report.paths.push(PathReport::empty(
            path,
            if metadata.file_type().is_symlink() {
                "symlink"
            } else {
                "other"
            },
        ));
    }
    subtree
}

// Preserve `..`: lexical collapse could identify distinct paths across a symlink.
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    }
}
fn directory_names(path: &Path, expected: &Metadata) -> io::Result<Vec<std::ffi::OsString>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    let actual = file.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(invalid("directory changed during inspection"));
    }
    let descriptor = file.into_raw_fd();
    // SAFETY: descriptor is an owned open directory; ownership transfers on success.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not take descriptor ownership.
        unsafe {
            libc::close(descriptor);
        }
        return Err(error);
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: this guard owns one live DIR and closes it once.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Stream(stream);
    let mut names = Vec::new();
    loop {
        // SAFETY: __error is this thread's errno; stream owns a live DIR.
        let entry = unsafe {
            *libc::__error() = 0;
            libc::readdir(stream.0)
        };
        if entry.is_null() {
            // SAFETY: __error returns a valid thread-local errno slot.
            let errno = unsafe { *libc::__error() };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            break;
        }
        // SAFETY: readdir returned a live dirent; d_name is terminated until next readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(std::ffi::OsString::from_vec(name.to_vec()));
        }
    }
    names.sort();
    Ok(names)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn fraction(logical: u64, allocation: u64) -> f64 {
    if logical == 0 {
        0.0
    } else {
        1.0 - allocation as f64 / logical as f64
    }
}
fn codec_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Zlib => "zlib",
        Kind::Lzvn => "lzvn",
        Kind::Lzfse => "lzfse",
        Kind::Lzbitmap => "lzbitmap",
    }
}
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
fn measure(path: &Path, metadata: &Metadata, entry: &mut PathReport) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if !same_file(metadata, &opened) {
        return Err(invalid("file changed during inspection"));
    }
    let allocation = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| invalid("allocation overflow"))?;
    entry.logical_size_bytes = Some(metadata.len());
    entry.current_allocation_bytes = Some(allocation);
    let decmpfs_len = xattr_len(&file, decmpfs::XATTR_NAME)?;
    entry.decmpfs_xattr_bytes = Some(decmpfs_len.unwrap_or(0));
    entry.resource_fork_bytes = Some(xattr_len(&file, resource_fork::XATTR_NAME)?.unwrap_or(0));
    if let Some(len) = decmpfs_len {
        entry.source = "decmpfs";
        entry.codec = "unknown";
        if len > decmpfs::MAX_XATTR_SIZE as u64 {
            return Err(invalid("oversized decmpfs attribute"));
        }
        let data = xattr_data(&file, decmpfs::XATTR_NAME, len as usize)?;
        let value = decmpfs::Value::from_data(&data)?;
        entry.decmpfs_type = Some(value.compression_type.raw_type());
        if metadata.st_flags() & libc::UF_COMPRESSED == 0 {
            return Err(invalid("decmpfs attribute exists without compressed flag"));
        }
        if value.uncompressed_size != metadata.len() {
            return Err(invalid("decmpfs logical size disagrees with stat"));
        }
        if let Some((kind, storage)) = value.compression_type.compression_storage() {
            entry.codec = codec_name(kind);
            match storage {
                decmpfs::Storage::Xattr => {
                    if metadata.len() > applesauce_core::BLOCK_SIZE as u64
                        || value.extra_data.is_empty() != (metadata.len() == 0)
                    {
                        return Err(invalid("invalid inline decmpfs payload size"));
                    }
                    entry.storage = Some("inline_xattr");
                    entry.raw_compressed_bytes = Some(value.extra_data.len() as u64);
                }
                decmpfs::Storage::ResourceFork => {
                    entry.storage = Some("resource_fork");
                    if !value.extra_data.is_empty() || metadata.len() == 0 {
                        return Err(invalid("invalid resource-fork decmpfs header"));
                    }
                    let mut fork = resource_fork::ResourceFork::new(&file);
                    let blocks = kind.read_block_info(&mut fork, metadata.len())?;
                    entry.raw_compressed_bytes = Some(
                        blocks
                            .iter()
                            .map(|block| u64::from(block.compressed_size))
                            .sum(),
                    );
                }
            }
        }
    } else if metadata.st_flags() & libc::UF_COMPRESSED != 0 {
        return Err(invalid("compressed file has no decmpfs attribute"));
    } else {
        let mut magic = [0; 8];
        let bytes = file.read(&mut magic)?;
        if bytes == 8 && magic == *b"ASCF0001" || path.extension().is_some_and(|ext| ext == "ascf")
        {
            entry.source = "ascf";
            entry.codec = "unknown";
            entry.archive_bytes = Some(metadata.len());
            file.rewind()?;
            let archive = ArchiveReader::open(&mut file)?;
            entry.logical_size_bytes = Some(archive.logical_size());
            entry.codec = match archive.codec() {
                applesauce_core::apple_buffer::Codec::Lzraven => "lzraven",
                applesauce_core::apple_buffer::Codec::Lzmesh => "lzmesh",
                _ => "unknown",
            };
            entry.entry_count = Some(archive.chunk_count() as u64);
            entry.raw_compressed_bytes = Some(archive.raw_compressed_bytes());
        }
    }
    if !same_file(&opened, &file.metadata()?) {
        return Err(invalid("file changed during inspection"));
    }
    entry.savings_bytes = entry
        .logical_size_bytes
        .map(|logical| i128::from(logical) - i128::from(allocation));
    entry.savings_fraction = entry
        .logical_size_bytes
        .map(|logical| fraction(logical, allocation));
    Ok(())
}
fn xattr_len(file: &File, name: &CStr) -> io::Result<Option<u64>> {
    // SAFETY: file owns a valid fd, name is terminated, and a null/zero buffer probes length only.
    let len = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_SHOWCOMPRESSION,
        )
    };
    if len >= 0 {
        return Ok(Some(len as u64));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOATTR) {
        Ok(None)
    } else {
        Err(error)
    }
}
fn xattr_data(file: &File, name: &CStr, len: usize) -> io::Result<Vec<u8>> {
    let mut data = vec![0; len];
    // SAFETY: fd/name are valid and data has len writable bytes.
    let read = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            data.as_mut_ptr().cast(),
            len,
            0,
            libc::XATTR_SHOWCOMPRESSION,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if read as usize != len {
        return Err(invalid("attribute changed during inspection"));
    }
    Ok(data)
}

pub fn display(report: &Report, json: bool) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if json {
        serde_json::to_writer_pretty(&mut output, report).map_err(io::Error::other)?;
        writeln!(output)?;
    } else {
        writeln!(
            output,
            "REPORT: kind={} savings_basis={} complete={}",
            report.report_kind, report.savings_basis, report.complete
        )?;
        for path in &report.paths {
            writeln!(output, "{}: source={} codec={} decmpfs_type={} storage={} logical_size_bytes={} current_allocation_bytes={} raw_compressed_bytes={} decmpfs_xattr_bytes={} resource_fork_bytes={} archive_bytes={} entry_count={} savings_bytes={} savings_fraction={}",
                path.path.display, path.source, path.codec, optional(path.decmpfs_type), path.storage.unwrap_or("none"), optional(path.logical_size_bytes), optional(path.current_allocation_bytes), optional(path.raw_compressed_bytes), optional(path.decmpfs_xattr_bytes), optional(path.resource_fork_bytes), optional(path.archive_bytes), optional(path.entry_count), optional(path.savings_bytes), optional(path.savings_fraction))?;
            if let Some(error) = &path.error {
                writeln!(output, "  error[{}]: {}", error.kind, error.message)?;
            }
        }
        for directory in &report.directories {
            display_total(&mut output, &directory.path.display, &directory.totals)?;
            if let Some(error) = &directory.error {
                writeln!(output, "  error[{}]: {}", error.kind, error.message)?;
            }
        }
        for root in &report.roots {
            display_total(
                &mut output,
                &format!("ROOT {}", root.path.display),
                &root.totals,
            )?;
        }
        display_total(&mut output, "TOTAL", &report.totals)?;
        for error in &report.operation_errors {
            writeln!(
                output,
                "{}: error[{}]: {}",
                error.path.display, error.error.kind, error.error.message
            )?;
        }
    }
    Ok(())
}
fn optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}
fn display_total(output: &mut impl Write, name: &str, totals: &Totals) -> io::Result<()> {
    writeln!(output, "{name}: files={} logical_size_bytes={} current_allocation_bytes={} savings_bytes={} savings_fraction={} complete={} raw_compressed_bytes={} decmpfs_xattr_bytes={} resource_fork_bytes={} archive_bytes={} entry_count={} codecs={} storage_forms={}", totals.files_included, optional(totals.logical_size_bytes), optional(totals.current_allocation_bytes), optional(totals.savings_bytes), optional(totals.savings_fraction), totals.complete, optional(totals.raw_compressed_bytes), optional(totals.decmpfs_xattr_bytes), optional(totals.resource_fork_bytes), optional(totals.archive_bytes), optional(totals.entry_count), totals.codecs.join(","), totals.storage_forms.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use applesauce::progress::{Progress as _, Task as _};

    #[test]
    fn pathname_encoding_preserves_non_utf8_without_creating_a_file() {
        let path = Path::new(std::ffi::OsStr::from_bytes(b"a\xffb"));
        assert_eq!(EncodedPath::new(path).bytes_hex, "61ff62");
    }

    #[test]
    fn notified_operation_failure_survives_readable_postscan() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("readable");
        fs::write(&file, b"original").unwrap();
        let progress = crate::progress::ProgressBars::new(crate::progress::Verbosity::Quiet);
        progress
            .file_task(&file, 8)
            .error("fixture operation failed");
        let mut report = analyze(std::slice::from_ref(&file));
        assert!(report.complete);
        report.operation_errors(progress.errors());
        assert!(!report.complete);
        assert_eq!(report.operation_errors.len(), 1);
        assert!(report.totals.complete); // actual measurements remain available
        assert_eq!(fs::read(&file).unwrap(), b"original");
    }

    #[test]
    fn verified_kernel_readback_is_reported_as_operation_evidence_even_when_quiet() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("generated");
        fs::write(&path, b"generated contents").unwrap();
        let progress = crate::progress::ProgressBars::new(crate::progress::Verbosity::Quiet);
        progress
            .file_task(&path, 18)
            .kernel_verified(&"ab".repeat(32));

        let mut report = analyze(std::slice::from_ref(&path));
        let before = serde_json::to_value(&report).unwrap();
        assert!(before.get("kernel_readbacks").is_none());
        report.kernel_verifications(progress.kernel_readbacks());
        let proof = serde_json::to_value(&report).unwrap();
        let proof = &proof["kernel_readbacks"][0];
        assert_eq!(
            proof["sha256"].as_str(),
            Some("abababababababababababababababababababababababababababababababab")
        );
        assert_eq!(proof["cache_state"].as_str(), Some("potentially_warm"));
        assert_eq!(
            proof["coverage"].as_str(),
            Some("whole_sha256_and_deterministic_pread")
        );
        assert_eq!(
            proof["path"]["bytes_hex"].as_str(),
            Some(EncodedPath::new(&path).bytes_hex.as_str())
        );
    }

    #[test]
    fn directory_open_rejects_symlink_and_changed_identity() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("directory");
        let other = temp.path().join("other");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&other).unwrap();
        let metadata = fs::metadata(&directory).unwrap();
        assert!(directory_names(&other, &metadata).is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(directory_names(&link, &metadata).is_err());
    }
}
