//! Read-only, full-encoding compression projection.
//!
//! This module intentionally does not use the normal scanner: that scanner
//! creates per-volume temporary directories and directory timestamp resetters.

use crate::{compressed_payload_is_allowed, vol_supports_compression_cap, xattr};
use applesauce_core::compressor::{Compressor, Kind};
use applesauce_core::{decmpfs, round_to_block_size, BLOCK_SIZE};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

const SCHEMA_VERSION: u32 = 1;

/// Read-only candidate classifiers. These profiles do not permit native writes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Profile {
    Caches,
    Bundles,
}

impl Profile {
    const fn name(self) -> &'static str {
        match self {
            Self::Caches => "caches",
            Self::Bundles => "bundles",
        }
    }
}

/// Decide from path components, never substring matches. No-follow descriptor
/// traversal still checks identity; refuse parent traversal in profile mode.
fn profile_exclusion(profile: Profile, path: &Path) -> Option<&'static str> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Some("profile_parent_traversal");
    }
    let parts: Vec<&OsStr> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            _ => None,
        })
        .collect();
    match profile {
        Profile::Caches => {
            if parts.iter().any(|part| code_container(part)) {
                return Some("cache_contains_code_bundle");
            }
            if parts
                .windows(2)
                .any(|pair| pair[0] == OsStr::new("Library") && pair[1] == OsStr::new("Caches"))
            {
                None
            } else {
                Some("outside_library_caches")
            }
        }
        Profile::Bundles => {
            let Some(app_index) = parts
                .iter()
                .position(|part| part.as_bytes().ends_with(b".app"))
            else {
                return Some("outside_app_bundle");
            };
            if parts.get(app_index + 1).copied() != Some(OsStr::new("Contents"))
                || parts.get(app_index + 2).copied() != Some(OsStr::new("Resources"))
                || parts.len() <= app_index + 3
            {
                return Some("bundle_non_resource");
            }
            let resources = &parts[app_index + 3..];
            if resources.iter().any(|part| {
                code_container(part)
                    || part.as_bytes() == b"_CodeSignature"
                    || part.as_bytes() == b"_MASReceipt"
            }) {
                return Some("bundle_nested_code_or_signature");
            }
            // A candidate resource still needs codesign and launch tests
            // on a disposable app before any write is ever authorized.
            const EXECUTABLE_SUFFIXES: [&[u8]; 8] = [
                b".dylib",
                b".so",
                b".a",
                b".o",
                b".sh",
                b".command",
                b".metallib",
                b".exe",
            ];
            if resources.last().is_some_and(|file| {
                EXECUTABLE_SUFFIXES
                    .iter()
                    .any(|suffix| file.as_bytes().ends_with(suffix))
            }) {
                return Some("bundle_executable_resource");
            }
            None
        }
    }
}

fn code_container(name: &OsStr) -> bool {
    const CODE_SUFFIXES: [&[u8]; 9] = [
        b".app",
        b".framework",
        b".appex",
        b".xpc",
        b".bundle",
        b".plugin",
        b".qlgenerator",
        b".kext",
        b".component",
    ];
    CODE_SUFFIXES
        .iter()
        .any(|suffix| name.as_bytes().ends_with(suffix))
}

#[derive(Debug, Clone, Serialize)]
pub struct EncodedPath {
    /// Human-readable rendering. `bytes_hex` is authoritative and lossless.
    pub display: String,
    /// Lowercase hexadecimal Unix pathname bytes.
    pub bytes_hex: String,
}

impl EncodedPath {
    fn new(path: &Path) -> Self {
        let bytes = path.as_os_str().as_bytes();
        let mut bytes_hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut bytes_hex, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self {
            display: path.to_string_lossy().into_owned(),
            bytes_hex,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportError {
    pub kind: &'static str,
    pub message: String,
}

impl ReportError {
    fn from_io(error: &io::Error) -> Self {
        Self {
            kind: error_kind(error.kind()),
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PathReport {
    pub path: EncodedPath,
    pub entry_type: &'static str,
    pub codec: String,
    pub would_compress: bool,
    pub reason: &'static str,
    pub logical_size_bytes: Option<u64>,
    pub current_allocation_bytes: Option<u64>,
    pub allocation_block_bytes: Option<u64>,
    pub raw_compressed_bytes: Option<u64>,
    pub decmpfs_xattr_bytes: Option<u64>,
    pub resource_fork_bytes: Option<u64>,
    pub storage: Option<&'static str>,
    pub projected_native_allocation_bytes: Option<u64>,
    pub projected_native_allocation_upper_bound_bytes: Option<u64>,
    pub savings_bytes: Option<i64>,
    pub error: Option<ReportError>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Totals {
    pub complete: bool,
    pub files_included: u64,
    pub files_would_compress: u64,
    pub files_skipped: u64,
    pub hard_links_excluded: u64,
    pub logical_size_bytes: Option<u64>,
    pub current_allocation_bytes: Option<u64>,
    pub projected_native_allocation_bytes: Option<u64>,
    pub projected_native_allocation_upper_bound_bytes: Option<u64>,
    pub savings_bytes: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryReport {
    pub path: EncodedPath,
    pub totals: Totals,
    pub error: Option<ReportError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub complete: bool,
    pub codec: String,
    pub minimum_compression_ratio: f64,
    /// Included only in explicit opt-in read-only policy audits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<&'static str>,
    pub full_encoding: bool,
    pub paths: Vec<PathReport>,
    pub directories: Vec<DirectoryReport>,
    pub totals: Totals,
    pub allocation_estimate_limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Default)]
struct Accumulator {
    complete: bool,
    files_included: u64,
    files_would_compress: u64,
    files_skipped: u64,
    hard_links_excluded: u64,
    logical: u64,
    current: u64,
    projected: u64,
    upper: u64,
}

impl Accumulator {
    fn empty() -> Self {
        Self {
            complete: true,
            ..Self::default()
        }
    }

    fn error() -> Self {
        Self {
            complete: false,
            ..Self::default()
        }
    }

    fn add(&mut self, other: &Self) {
        self.complete &= other.complete;
        self.files_included += other.files_included;
        self.files_would_compress += other.files_would_compress;
        self.files_skipped += other.files_skipped;
        self.hard_links_excluded += other.hard_links_excluded;
        self.logical = self.logical.saturating_add(other.logical);
        self.current = self.current.saturating_add(other.current);
        self.projected = self.projected.saturating_add(other.projected);
        self.upper = self.upper.saturating_add(other.upper);
    }

    fn totals(&self) -> Totals {
        let (logical, current, projected, upper, savings) = if self.complete {
            (
                Some(self.logical),
                Some(self.current),
                Some(self.projected),
                Some(self.upper),
                Some(signed_difference(self.current, self.projected)),
            )
        } else {
            (None, None, None, None, None)
        };
        Totals {
            complete: self.complete,
            files_included: self.files_included,
            files_would_compress: self.files_would_compress,
            files_skipped: self.files_skipped,
            hard_links_excluded: self.hard_links_excluded,
            logical_size_bytes: logical,
            current_allocation_bytes: current,
            projected_native_allocation_bytes: projected,
            projected_native_allocation_upper_bound_bytes: upper,
            savings_bytes: savings,
        }
    }
}

pub fn analyze(
    paths: &[PathBuf],
    kind: Kind,
    minimum_compression_ratio: f64,
    level: u32,
) -> Report {
    analyze_with_profile(paths, kind, minimum_compression_ratio, level, None)
}

/// Read-only candidate inspection. The mutating compressor does not accept a profile.
pub fn analyze_with_profile(
    paths: &[PathBuf],
    kind: Kind,
    minimum_compression_ratio: f64,
    level: u32,
    profile: Option<Profile>,
) -> Report {
    let mut analyzer = Analyzer {
        kind,
        minimum_compression_ratio,
        level,
        profile,
        paths: Vec::new(),
        directories: Vec::new(),
        visited_directories: HashSet::new(),
        visited_files: HashSet::new(),
    };
    let roots = deduplicate_roots(paths);
    let mut total = Accumulator::empty();
    for root in roots {
        total.add(&analyzer.visit(&root, true));
    }
    let totals = total.totals();
    Report {
        schema_version: SCHEMA_VERSION,
        complete: totals.complete,
        codec: codec_name(kind).to_owned(),
        minimum_compression_ratio,
        profile: profile.map(Profile::name),
        full_encoding: true,
        paths: analyzer.paths,
        directories: analyzer.directories,
        totals,
        allocation_estimate_limitations: vec![
            "APFS/HFS+ may store small xattrs inline; central projection allocates finalized resource-fork bytes and carries forward observable non-data allocation",
            "the accounting upper estimate rounds the measured resource fork and every xattr independently and is always at least the central projection, but is not a filesystem-wide physical allocation guarantee",
            "filesystem metadata, cloning, sparsity, and compression-attribute placement are not observable exactly without writing",
        ],
    }
}

struct Analyzer {
    kind: Kind,
    minimum_compression_ratio: f64,
    level: u32,
    profile: Option<Profile>,
    paths: Vec<PathReport>,
    directories: Vec<DirectoryReport>,
    visited_directories: HashSet<(u64, u64)>,
    visited_files: HashSet<(u64, u64)>,
}

impl Analyzer {
    fn visit(&mut self, path: &Path, root: bool) -> Accumulator {
        // Refuse a profile root with lexical parent traversal before any
        // metadata lookup or directory enumeration outside its audit scope.
        if root
            && self.profile.is_some()
            && path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return self.push_error(
                path,
                "unknown",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "profile audit root cannot contain parent traversal",
                ),
            );
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => return self.push_error(path, "unknown", error),
        };
        if metadata.file_type().is_symlink() {
            self.paths
                .push(skipped(path, "symlink", self.kind, "symlink", None));
            return Accumulator::empty();
        }
        if root {
            if let Err(error) = reject_symlink_ancestors(path) {
                return self.push_error(path, "unknown", error);
            }
        }
        if metadata.is_dir() {
            return self.visit_directory(path, &metadata);
        }
        #[allow(clippy::filetype_is_file)]
        if metadata.file_type().is_file() {
            return self.visit_file(path, &metadata);
        }
        self.paths.push(skipped(
            path,
            "other",
            self.kind,
            "not_regular_file",
            Some(&metadata),
        ));
        Accumulator::empty()
    }

    fn visit_directory(&mut self, path: &Path, metadata: &Metadata) -> Accumulator {
        let directory = match open_directory(path, metadata) {
            Ok(directory) => directory,
            Err(error) => {
                let error_report = ReportError::from_io(&error);
                self.directories.push(DirectoryReport {
                    path: EncodedPath::new(path),
                    totals: Accumulator::error().totals(),
                    error: Some(error_report),
                });
                return Accumulator::error();
            }
        };
        let opened = match directory.metadata() {
            Ok(opened) => opened,
            Err(error) => {
                let error_report = ReportError::from_io(&error);
                self.directories.push(DirectoryReport {
                    path: EncodedPath::new(path),
                    totals: Accumulator::error().totals(),
                    error: Some(error_report),
                });
                return Accumulator::error();
            }
        };
        let identity = (opened.dev(), opened.ino());
        if !self.visited_directories.insert(identity) {
            return Accumulator::empty();
        }
        let mut subtotal = Accumulator::empty();
        let names = match directory_names(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                let error_report = ReportError::from_io(&error);
                self.directories.push(DirectoryReport {
                    path: EncodedPath::new(path),
                    totals: Accumulator::error().totals(),
                    error: Some(error_report),
                });
                return Accumulator::error();
            }
        };
        for name in names {
            subtotal.add(&self.visit(&path.join(name), false));
        }
        self.directories.push(DirectoryReport {
            path: EncodedPath::new(path),
            totals: subtotal.totals(),
            error: None,
        });
        subtotal
    }

    fn visit_file(&mut self, path: &Path, scanned: &Metadata) -> Accumulator {
        // A policy exclusion needs only the no-follow stat from visit(). Do not
        // open excluded code/signature files: they may be deliberately unreadable.
        if let Some(reason) = self
            .profile
            .and_then(|profile| profile_exclusion(profile, path))
        {
            // Preserve the existing hard-link accounting without opening the file.
            let reason = if scanned.nlink() > 1 { "hard_link" } else { reason };
            let report = skipped(path, "file", self.kind, reason, Some(scanned));
            let result = accumulate_report(&report);
            self.paths.push(report);
            return result;
        }
        let file = match open_regular_file(path, scanned) {
            Ok(file) => file,
            Err(error) => return self.push_error(path, "file", error),
        };
        let opened = match file.metadata() {
            Ok(opened) => opened,
            Err(error) => return self.push_error(path, "file", error),
        };
        if opened.nlink() > 1 {
            self.paths
                .push(skipped(path, "file", self.kind, "hard_link", Some(&opened)));
            let mut result = Accumulator::empty();
            result.hard_links_excluded = 1;
            return result;
        }
        let identity = (opened.dev(), opened.ino());
        if !self.visited_files.insert(identity) {
            return Accumulator::empty();
        }
        match self.measure_file(path, &file, &opened) {
            Ok(report) => {
                let result = accumulate_report(&report);
                self.paths.push(report);
                result
            }
            Err(error) => self.push_error(path, "file", error),
        }
    }

    fn measure_file(&self, path: &Path, file: &File, opened: &Metadata) -> io::Result<PathReport> {
        let fs = file_system(file)?;
        let block = fs.block_size;
        let logical = opened.len();
        let current = opened.blocks().checked_mul(512).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "allocated byte count overflow")
        })?;

        if opened.st_flags() & libc::UF_COMPRESSED != 0 {
            return Ok(skipped_with_sizes(
                path,
                self.kind,
                "already_compressed",
                logical,
                current,
                block,
            ));
        }
        if logical == 0 {
            return Ok(skipped_with_sizes(
                path,
                self.kind,
                "empty_file",
                logical,
                current,
                block,
            ));
        }
        if logical >= u64::from(u32::MAX) {
            return Ok(skipped_with_sizes(
                path,
                self.kind,
                "too_large",
                logical,
                current,
                block,
            ));
        }
        if !fs.supports_compression {
            return Ok(skipped_with_sizes(
                path,
                self.kind,
                "filesystem_unsupported",
                logical,
                current,
                block,
            ));
        }

        let mut non_compression_xattr_sizes = Vec::new();
        let mut required = false;
        xattr::with_names(file, |name| {
            if name == decmpfs::XATTR_NAME || name == resource_fork::XATTR_NAME {
                required = true;
            } else {
                let size = xattr::len(file, name)?
                    .ok_or_else(|| io::Error::other("listed xattr disappeared while measuring"))?;
                non_compression_xattr_sizes.push(size as u64);
            }
            Ok(())
        })?;
        if required {
            return Ok(skipped_with_sizes(
                path,
                self.kind,
                "required_compression_xattr",
                logical,
                current,
                block,
            ));
        }

        let encoded = encode_and_measure(file, self.kind, logical, self.level)?;
        ensure_same_file(opened, &file.metadata()?)?;
        let would_compress = compressed_payload_is_allowed(
            encoded.raw_compressed_bytes,
            logical,
            self.minimum_compression_ratio,
        );
        if !would_compress {
            let mut report = skipped_with_sizes(
                path,
                self.kind,
                "below_minimum_ratio",
                logical,
                current,
                block,
            );
            report.raw_compressed_bytes = Some(encoded.raw_compressed_bytes);
            report.decmpfs_xattr_bytes = Some(encoded.decmpfs_xattr_bytes);
            report.resource_fork_bytes = Some(encoded.resource_fork_bytes);
            report.storage = Some(encoded.storage);
            return Ok(report);
        }

        // Inline xattrs normally consume inode metadata rather than separately
        // allocated extents. Preserve any allocation already attributable to
        // non-data metadata, then add the finalized resource fork allocation.
        // The independently rounded accounting estimate below models the case
        // where those measured attributes spill out of line.
        let existing_metadata_allocation =
            current.saturating_sub(round_to_block_size(logical, block));
        let projected = round_to_block_size(encoded.resource_fork_bytes, block)
            .checked_add(existing_metadata_allocation)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "projection overflow"))?;
        let mut upper = round_to_block_size(encoded.resource_fork_bytes, block)
            .checked_add(round_to_block_size(encoded.decmpfs_xattr_bytes, block))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "projection overflow"))?;
        for size in non_compression_xattr_sizes {
            upper = upper
                .checked_add(round_to_block_size(size, block))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "projection overflow"))?;
        }
        upper = upper.max(projected);

        Ok(PathReport {
            path: EncodedPath::new(path),
            entry_type: "file",
            codec: codec_name(self.kind).to_owned(),
            would_compress: true,
            reason: "compress",
            logical_size_bytes: Some(logical),
            current_allocation_bytes: Some(current),
            allocation_block_bytes: Some(block),
            raw_compressed_bytes: Some(encoded.raw_compressed_bytes),
            decmpfs_xattr_bytes: Some(encoded.decmpfs_xattr_bytes),
            resource_fork_bytes: Some(encoded.resource_fork_bytes),
            storage: Some(encoded.storage),
            projected_native_allocation_bytes: Some(projected),
            projected_native_allocation_upper_bound_bytes: Some(upper),
            savings_bytes: Some(signed_difference(current, projected)),
            error: None,
        })
    }

    fn push_error(
        &mut self,
        path: &Path,
        entry_type: &'static str,
        error: io::Error,
    ) -> Accumulator {
        self.paths
            .push(error_path(path, entry_type, self.kind, &error));
        Accumulator::error()
    }
}

fn open_regular_file(path: &Path, scanned: &Metadata) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC)
        .open(path)?;
    ensure_same_file(scanned, &file.metadata()?)?;
    Ok(file)
}

fn open_directory(path: &Path, scanned: &Metadata) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC)
        .open(path)?;
    ensure_same_directory(scanned, &directory.metadata()?)?;
    Ok(directory)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned by `fdopendir` and remains owned by
        // this wrapper until this single `closedir` call.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn directory_names(directory: &File) -> io::Result<Vec<OsString>> {
    // fdopendir takes ownership of its descriptor, so give it an independent
    // duplicate and leave the File's descriptor available for identity checks.
    // SAFETY: `directory` owns a live descriptor for this call.
    let duplicate: RawFd = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is an open directory descriptor. On success the DIR
    // owns it; on failure we close it below.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so ownership of `duplicate` was not taken.
        unsafe {
            libc::close(duplicate);
        }
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        // readdir signals end-of-directory and errors with the same null
        // pointer, so clear errno before each call and inspect it afterward.
        // SAFETY: `__error` returns the calling thread's errno slot on macOS.
        unsafe {
            *libc::__error() = 0;
        }
        // SAFETY: `stream` owns a live DIR for the duration of this loop.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            // SAFETY: reading the thread-local errno slot is valid.
            let errno = unsafe { *libc::__error() };
            if errno == 0 {
                break;
            }
            return Err(io::Error::from_raw_os_error(errno));
        }
        // SAFETY: readdir returned a live dirent whose d_name is NUL-terminated
        // and remains valid until the next readdir call. Copy it immediately.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

struct FileSystem {
    block_size: u64,
    supports_compression: bool,
}

fn file_system(file: &File) -> io::Result<FileSystem> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: file owns a valid descriptor and `stat` points to writable storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded and initialized the output structure.
    let stat = unsafe { stat.assume_init() };
    let block_size = u64::from(stat.f_bsize);
    if block_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem reports zero allocation block size",
        ));
    }
    let mount = CStr::from_bytes_until_nul(
        // SAFETY: c_char and u8 have identical size and alignment on macOS.
        unsafe {
            std::slice::from_raw_parts(
                stat.f_mntonname.as_ptr().cast::<u8>(),
                stat.f_mntonname.len(),
            )
        },
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mount path is not terminated"))?;
    Ok(FileSystem {
        block_size,
        supports_compression: vol_supports_compression_cap(mount)?,
    })
}

#[derive(Default)]
struct SinkState {
    position: u64,
    length: u64,
}

struct CountingSink(Rc<RefCell<SinkState>>);

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.borrow_mut();
        state.position = state
            .position
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sink position overflow"))?;
        state.length = state.length.max(state.position);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for CountingSink {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let mut state = self.0.borrow_mut();
        let base = match from {
            SeekFrom::Start(position) => {
                state.position = position;
                return Ok(position);
            }
            SeekFrom::End(offset) => (state.length, offset),
            SeekFrom::Current(offset) => (state.position, offset),
        };
        let position = i128::from(base.0) + i128::from(base.1);
        if !(0..=i128::from(u64::MAX)).contains(&position) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"));
        }
        state.position = position as u64;
        Ok(state.position)
    }
}

struct EncodedMeasurement {
    raw_compressed_bytes: u64,
    decmpfs_xattr_bytes: u64,
    resource_fork_bytes: u64,
    storage: &'static str,
}

fn encode_and_measure(
    mut file: &File,
    kind: Kind,
    logical_size: u64,
    level: u32,
) -> io::Result<EncodedMeasurement> {
    let state = Rc::new(RefCell::new(SinkState::default()));
    let sink_state = Rc::clone(&state);
    let mut writer =
        applesauce_core::writer::Writer::new(kind, logical_size, move || CountingSink(sink_state))?;
    let mut compressor: Compressor = kind.compressor().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{kind} is unavailable in this build or on this host"),
        )
    })?;
    let mut input = vec![0; BLOCK_SIZE];
    let mut output = vec![0; BLOCK_SIZE + 1024];
    let mut remaining = logical_size;
    let mut raw = 0u64;
    while remaining != 0 {
        let size = remaining.min(BLOCK_SIZE as u64) as usize;
        file.read_exact(&mut input[..size])?;
        let encoded = compressor.compress(&mut output, &input[..size], level)?;
        raw = raw
            .checked_add(encoded as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload size overflow"))?;
        writer.add_block(&output[..encoded])?;
        remaining -= size as u64;
    }
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(io::Error::other("file grew while it was being encoded"));
    }
    let mut decmpfs_data = Vec::with_capacity(decmpfs::MAX_XATTR_SIZE);
    writer.finish_decmpfs_data(&mut decmpfs_data)?;
    let resource_fork_bytes = state.borrow().length;
    Ok(EncodedMeasurement {
        raw_compressed_bytes: raw,
        decmpfs_xattr_bytes: decmpfs_data.len() as u64,
        resource_fork_bytes,
        storage: if resource_fork_bytes == 0 {
            "inline_xattr"
        } else {
            "resource_fork"
        },
    })
}

#[allow(clippy::filetype_is_file)]
fn ensure_same_file(expected: &Metadata, actual: &Metadata) -> io::Result<()> {
    if actual.file_type().is_file()
        && expected.dev() == actual.dev()
        && expected.ino() == actual.ino()
        && expected.nlink() == actual.nlink()
        && expected.len() == actual.len()
        && expected.mtime() == actual.mtime()
        && expected.mtime_nsec() == actual.mtime_nsec()
        && expected.ctime() == actual.ctime()
        && expected.ctime_nsec() == actual.ctime_nsec()
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file changed between traversal, open, and encoding",
        ))
    }
}

fn ensure_same_directory(expected: &Metadata, actual: &Metadata) -> io::Result<()> {
    if actual.is_dir() && expected.dev() == actual.dev() && expected.ino() == actual.ino() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory changed between traversal and open",
        ))
    }
}

fn reject_symlink_ancestors(path: &Path) -> io::Result<()> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    let components: Vec<_> = absolute.components().collect();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("symlink ancestor is not allowed: {}", current.display()),
            ));
        }
    }
    Ok(())
}

fn deduplicate_roots(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots: Vec<(PathBuf, PathBuf)> = paths
        .iter()
        .map(|path| (lexical_absolute(path), path.clone()))
        .collect();
    roots.sort_by(|(left, _), (right, _)| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| {
                left.as_os_str()
                    .as_bytes()
                    .cmp(right.as_os_str().as_bytes())
            })
    });
    let mut selected: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (normalized, original) in roots {
        if selected
            .iter()
            .any(|(parent, _)| normalized == *parent || normalized.starts_with(parent))
        {
            continue;
        }
        selected.push((normalized, original));
    }
    selected.into_iter().map(|(_, original)| original).collect()
}

fn lexical_absolute(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut result = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            _ => result.push(component.as_os_str()),
        }
    }
    result
}

#[allow(clippy::filetype_is_file)]
fn skipped(
    path: &Path,
    entry_type: &'static str,
    kind: Kind,
    reason: &'static str,
    metadata: Option<&Metadata>,
) -> PathReport {
    let logical = metadata
        .filter(|m| m.file_type().is_file())
        .map(Metadata::len);
    let allocation = metadata
        .filter(|m| m.file_type().is_file())
        .and_then(|m| m.blocks().checked_mul(512));
    PathReport {
        path: EncodedPath::new(path),
        entry_type,
        codec: codec_name(kind).to_owned(),
        would_compress: false,
        reason,
        logical_size_bytes: logical,
        current_allocation_bytes: allocation,
        allocation_block_bytes: None,
        raw_compressed_bytes: None,
        decmpfs_xattr_bytes: None,
        resource_fork_bytes: None,
        storage: None,
        projected_native_allocation_bytes: allocation,
        projected_native_allocation_upper_bound_bytes: allocation,
        savings_bytes: allocation.map(|_| 0),
        error: None,
    }
}

fn skipped_with_sizes(
    path: &Path,
    kind: Kind,
    reason: &'static str,
    logical: u64,
    current: u64,
    block: u64,
) -> PathReport {
    let mut report = skipped(path, "file", kind, reason, None);
    report.logical_size_bytes = Some(logical);
    report.current_allocation_bytes = Some(current);
    report.allocation_block_bytes = Some(block);
    report.projected_native_allocation_bytes = Some(current);
    report.projected_native_allocation_upper_bound_bytes = Some(current);
    report.savings_bytes = Some(0);
    report
}

fn error_path(path: &Path, entry_type: &'static str, kind: Kind, error: &io::Error) -> PathReport {
    PathReport {
        path: EncodedPath::new(path),
        entry_type,
        codec: codec_name(kind).to_owned(),
        would_compress: false,
        reason: "error",
        logical_size_bytes: None,
        current_allocation_bytes: None,
        allocation_block_bytes: None,
        raw_compressed_bytes: None,
        decmpfs_xattr_bytes: None,
        resource_fork_bytes: None,
        storage: None,
        projected_native_allocation_bytes: None,
        projected_native_allocation_upper_bound_bytes: None,
        savings_bytes: None,
        error: Some(ReportError::from_io(error)),
    }
}

fn accumulate_report(report: &PathReport) -> Accumulator {
    if report.reason == "hard_link" {
        let mut result = Accumulator::empty();
        result.hard_links_excluded = 1;
        return result;
    }
    let (Some(logical), Some(current), Some(projected), Some(upper)) = (
        report.logical_size_bytes,
        report.current_allocation_bytes,
        report.projected_native_allocation_bytes,
        report.projected_native_allocation_upper_bound_bytes,
    ) else {
        return Accumulator::empty();
    };
    let mut result = Accumulator::empty();
    result.files_included = 1;
    result.files_would_compress = u64::from(report.would_compress);
    result.files_skipped = u64::from(!report.would_compress);
    result.logical = logical;
    result.current = current;
    result.projected = projected;
    result.upper = upper;
    result
}

fn signed_difference(left: u64, right: u64) -> i64 {
    let difference = i128::from(left) - i128::from(right);
    difference.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn error_kind(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::InvalidInput => "invalid_input",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        io::ErrorKind::Unsupported => "unsupported",
        io::ErrorKind::WouldBlock => "would_block",
        _ => "io_error",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn audit_profiles_reject_code_and_outside_roots() {
        let cases: &[(Profile, &str, Option<&str>)] = &[
            (Profile::Caches, "/Users/a/Library/Caches/data.log", None),
            (
                Profile::Caches,
                "/Users/a/Library/Caches/Foo.app/Contents/Resources/a.json",
                Some("cache_contains_code_bundle"),
            ),
            (
                Profile::Caches,
                "/Users/a/Caches/data.log",
                Some("outside_library_caches"),
            ),
            (
                Profile::Caches,
                "/Users/a/Library/Caches/../MacOS/app",
                Some("profile_parent_traversal"),
            ),
            (
                Profile::Bundles,
                "/Applications/Foo.app/Contents/Resources/icon.icns",
                None,
            ),
            (
                Profile::Bundles,
                "/Applications/Foo.app/Contents/MacOS/Foo",
                Some("bundle_non_resource"),
            ),
            (
                Profile::Bundles,
                "/Applications/Foo.app/Contents/_CodeSignature/CodeResources",
                Some("bundle_non_resource"),
            ),
            (
                Profile::Bundles,
                "/Applications/Foo.app/Contents/Resources/Nested.bundle/file",
                Some("bundle_nested_code_or_signature"),
            ),
            (
                Profile::Bundles,
                "/Applications/Foo.app/Contents/Resources/helper.dylib",
                Some("bundle_executable_resource"),
            ),
            (
                Profile::Bundles,
                "/Applications/Foo.app/Contents/Resources/../MacOS/Foo",
                Some("profile_parent_traversal"),
            ),
            (
                Profile::Bundles,
                "/Applications/Foo.app/Contents/Resources/icon.app",
                Some("bundle_nested_code_or_signature"),
            ),
            (
                Profile::Bundles,
                "/Applications/data.json",
                Some("outside_app_bundle"),
            ),
        ];
        for &(profile, path, expected) in cases {
            assert_eq!(
                profile_exclusion(profile, Path::new(path)),
                expected,
                "{path}"
            );
        }
    }

    #[test]
    fn profile_audit_refuses_parent_traversal_before_touching_root() {
        let path = PathBuf::from("nonexistent-root/../outside");
        for profile in [Profile::Caches, Profile::Bundles] {
            let audit = analyze_with_profile(std::slice::from_ref(&path), Kind::Zlib, 0.95, 5, Some(profile));
            assert!(!audit.complete);
            assert_eq!(audit.paths.len(), 1);
            assert_eq!(audit.paths[0].reason, "error");
            assert_eq!(audit.paths[0].error.as_ref().unwrap().kind, "invalid_input");
        }
    }

    #[test]
    fn bundle_audit_excludes_signed_code_before_encoding() {
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let app = temp.path().join("Fixture.app");
        let executable = app.join("Contents/MacOS/Fixture");
        let signature = app.join("Contents/_CodeSignature/CodeResources");
        let resource = app.join("Contents/Resources/localization.strings");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::create_dir_all(signature.parent().unwrap()).unwrap();
        fs::create_dir_all(resource.parent().unwrap()).unwrap();
        fs::write(&executable, b"test executable").unwrap();
        fs::write(&signature, b"test signature").unwrap();
        fs::write(&resource, b"test resource").unwrap();
        // Excluded sealed code may not be readable by the current user.
        // The audit must skip it by pathname policy without ever opening it.
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&signature, fs::Permissions::from_mode(0o000)).unwrap();

        let audit = analyze_with_profile(&[app], Kind::Zlib, 0.95, 5, Some(Profile::Bundles));
        assert_eq!(audit.profile, Some("bundles"));
        assert!(audit.complete);
        for protected in [executable, signature] {
            let entry = audit
                .paths
                .iter()
                .find(|entry| entry.path.display == protected.to_string_lossy())
                .unwrap();
            assert_eq!(entry.reason, "bundle_non_resource");
            assert!(!entry.would_compress);
            assert_eq!(entry.raw_compressed_bytes, None);
        }
        assert_eq!(audit.paths.len(), 3);
    }

    #[test]
    fn unprofiled_projection_keeps_its_existing_optional_fields_absent() {
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let input = temp.path().join("input");
        fs::write(&input, b"fixture").unwrap();
        let report = analyze(&[input], Kind::Zlib, 0.95, 5);
        assert_eq!(report.profile, None);
        assert_eq!(report.schema_version, 1);
    }

    #[test]
    fn overlapping_roots_are_deduplicated_lexically() {
        let roots = deduplicate_roots(&[
            PathBuf::from("/tmp/tree/child"),
            PathBuf::from("/tmp/tree"),
            PathBuf::from("/tmp/tree"),
        ]);
        assert_eq!(roots, [PathBuf::from("/tmp/tree")]);
    }

    #[test]
    fn encoded_path_is_lossless_for_non_utf8_bytes() {
        use std::ffi::OsStr;
        let path = Path::new(OsStr::from_bytes(b"a\xffb"));
        let encoded = EncodedPath::new(path);
        assert_eq!(encoded.bytes_hex, "61ff62");
    }

    #[test]
    fn descriptor_directory_walk_rejects_symlink_paths() {
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("child"), b"fixture").unwrap();
        let scanned = fs::symlink_metadata(&real).unwrap();
        let directory = open_directory(&real, &scanned).unwrap();
        assert_eq!(
            directory_names(&directory).unwrap(),
            [OsString::from("child")]
        );

        let link = temp.path().join("link");
        symlink(&real, &link).unwrap();
        let link_metadata = fs::metadata(&link).unwrap();
        assert!(open_directory(&link, &link_metadata).is_err());

        let descendant = link.join("child-directory");
        fs::create_dir(real.join("child-directory")).unwrap();
        let descendant_metadata = fs::metadata(&descendant).unwrap();
        assert!(open_directory(&descendant, &descendant_metadata).is_err());
    }
}
