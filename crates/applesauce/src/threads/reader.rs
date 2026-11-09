use crate::seq_queue::Slot;
use crate::threads::{compressing, writer, BgWork, Context, Mode, WorkHandler};
use crate::{rfork_storage, seq_queue, try_read_all};
use applesauce_core::compressor::Kind;
use applesauce_core::BLOCK_SIZE;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::num::NonZeroUsize;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use std::{io, thread};

pub(super) struct WorkItem {
    pub context: Arc<Context>,
}

pub(super) struct Work {
    pub compressor: compressing::Sender,
    pub writer: writer::Sender,
}

impl BgWork for Work {
    type Item = WorkItem;
    type Handler = Handler;
    const NAME: &'static str = "reader";

    fn make_handler(&self) -> Self::Handler {
        Handler::new(self.compressor.clone(), self.writer.clone())
    }

    fn queue_capacity(&self) -> usize {
        // Allow quite a few queued up paths, to allow the total progress bar to be accurate
        100 * 1024
    }
}

pub(super) struct Handler {
    compressor: compressing::Sender,
    writer: writer::Sender,
}

// Read at most the remaining logical bytes, capped at 64 KiB. Reserving
// only the required capacity avoids a 64 KiB allocation for each tiny final
// block. Allocation failure is reported instead of panicking; read_to_end
// initializes only bytes actually read.
fn read_chunk<R: Read>(reader: R, limit: usize) -> io::Result<Vec<u8>> {
    let limit = limit.min(BLOCK_SIZE);
    let mut buf = Vec::new();
    buf.try_reserve_exact(limit).map_err(io::Error::other)?;
    reader.take(limit as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

// Revalidate the exact inode scanned by the walker before sampling or
// queuing compression. No-follow and nonblocking flags stop a swapped symlink
// or FIFO from being followed/opened while its type is still unknown.
// The writer repeats the descriptor/path snapshot before publication.
fn open_scanned_regular_file(path: &Path, scanned: &Metadata) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    writer::ensure_source_path_matches_open_file(&file, path, scanned)?;
    Ok(file)
}

/// At most 64 KiB of logical input is sampled, using independent head/tail
/// windows or head/middle/tail windows for larger files. The source cursor is
/// unchanged; the normal reader starts at byte zero after selection.
fn sample_windows(file_size: u64) -> Vec<(u64, usize)> {
    const BUDGET: usize = BLOCK_SIZE;
    if file_size <= BUDGET as u64 {
        return vec![(0, file_size as usize)];
    }
    if file_size < (BUDGET * 3) as u64 {
        let half = BUDGET / 2;
        return vec![(0, half), (file_size - half as u64, half)];
    }
    let side = BUDGET / 3;
    let tail = BUDGET - side * 2;
    vec![
        (0, side),
        (file_size / 2 - (side / 2) as u64, side),
        (file_size - tail as u64, tail),
    ]
}

fn read_sample(file: &File, offset: u64, length: usize) -> io::Result<Vec<u8>> {
    let mut data = vec![0; length];
    let mut done = 0usize;
    while done < data.len() {
        let absolute = offset
            .checked_add(done as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sample offset overflow"))?;
        let read = file.read_at(&mut data[done..], absolute)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source truncated while sampling",
            ));
        }
        done += read;
    }
    Ok(data)
}

/// Deterministic ratio-first selection across stable native codecs, excluding
/// experimental LZBitmap. An individual failed trial cannot silently win.
fn select_native_codec(
    file: &File,
    file_size: u64,
    level: u32,
) -> io::Result<(Kind, usize, usize)> {
    let geometry = sample_windows(file_size);
    let windows: Vec<Vec<u8>> = geometry
        .iter()
        .map(|(start, length)| read_sample(file, *start, *length))
        .collect::<io::Result<_>>()?;
    let sampled_bytes = windows.iter().map(Vec::len).sum();
    let mut best: Option<(Kind, usize)> = None;
    // Ordered tie break: prefer the existing default on equal encoded bytes.
    for kind in [Kind::Lzfse, Kind::Lzvn, Kind::Zlib] {
        let Some(mut encoder) = kind.compressor() else {
            continue;
        };
        let mut output = vec![0u8; BLOCK_SIZE + 1024];
        let mut decoded = vec![0u8; BLOCK_SIZE];
        let mut total = 0usize;
        let mut valid = true;
        for window in &windows {
            match encoder.compress(&mut output, window, level) {
                Ok(n) => match encoder.decompress(&mut decoded, &output[..n]) {
                    Ok(decoded_size)
                        if decoded_size == window.len()
                            && decoded[..decoded_size] == window[..] =>
                    {
                        total += n;
                    }
                    _ => {
                        tracing::debug!(codec = %kind, "native auto sample roundtrip failed");
                        valid = false;
                        break;
                    }
                },
                Err(error) => {
                    tracing::debug!(codec = %kind, %error, "native auto sample failed");
                    valid = false;
                    break;
                }
            }
        }
        if valid && best.is_none_or(|(_, previous)| total < previous) {
            best = Some((kind, total));
        }
    }
    best.map(|(kind, _)| (kind, sampled_bytes, windows.len()))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "no native codec could encode the sample",
            )
        })
}

impl Handler {
    fn new(compressor: compressing::Sender, writer: writer::Sender) -> Self {
        Self { compressor, writer }
    }

    fn read_file_into(
        &mut self,
        context: &Arc<Context>,
        file: &File,
        expected_len: u64,
        selected_kind: Option<Kind>,
        tx: &seq_queue::Sender<writer::Chunk, io::Error>,
    ) -> io::Result<()> {
        match context.operation.mode {
            Mode::Compress { .. } | Mode::CompressAuto { .. } => {
                let kind = selected_kind.ok_or_else(|| {
                    io::Error::other("native compression requires a selected codec")
                })?;
                let compressor = self.compressor.clone();
                self.with_file_chunks(file, expected_len, tx, |slot, data| {
                    let _enter = tracing::debug_span!("waiting to send to compressor").entered();
                    compressor
                        .send(compressing::WorkItem {
                            context: Arc::clone(context),
                            data,
                            slot,
                            kind,
                            expected_decoded_size: None,
                        })
                        .unwrap();
                    Ok(())
                })?;
            }
            Mode::DecompressManually => {
                rfork_storage::with_compressed_blocks(file, |kind| {
                    move |data, expected_decoded_size| {
                        // TODO: This waits for a slot after we have already read.
                        // TODO: This should be able to exit early, without an error
                        let slot = tx
                            .prepare_send()
                            .ok_or_else(|| io::Error::other("error must have occurred writing"))?;
                        let _enter =
                            tracing::debug_span!("waiting to send to compressor").entered();
                        self.compressor
                            .send(compressing::WorkItem {
                                context: Arc::clone(context),
                                data: data.to_vec(),
                                slot,
                                kind,
                                expected_decoded_size: Some(expected_decoded_size),
                            })
                            .unwrap();
                        Ok(())
                    }
                })?;
            }
            Mode::DecompressByReading => {
                self.with_file_chunks(file, expected_len, tx, |slot, data| {
                    let orig_size = data.len() as u64;
                    let res = slot.finish(writer::Chunk {
                        block: data,
                        orig_size,
                    });
                    if let Err(e) = res {
                        // This should only happen if the writer had an error
                        tracing::debug!("error finishing chunk: {e}");
                    }
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    // return true if reading succeeded, false if the writer closed the channel
    fn with_file_chunks(
        &mut self,
        file: &File,
        expected_len: u64,
        tx: &seq_queue::Sender<writer::Chunk, io::Error>,
        mut f: impl FnMut(Slot<writer::Chunk, io::Error>, Vec<u8>) -> io::Result<()>,
    ) -> io::Result<bool> {
        let mut total_read = 0;
        let block_span = tracing::debug_span!("reading blocks");
        loop {
            let _enter = block_span.enter();

            // make sure we don't reserve a slot if we won't be sending a chunk
            if total_read == expected_len {
                let mut buf = [0];
                let n = try_read_all(file, &mut buf)?;
                total_read += u64::try_from(n).unwrap();
                // Outside the loop, we'll error if we read more than expected_len
                break;
            }

            let slot = {
                let _enter = tracing::debug_span!("waiting for free slot").entered();
                match tx.prepare_send() {
                    Some(slot) => slot,
                    None => return Ok(false),
                }
            };

            let remaining = expected_len - total_read;
            let limit = remaining.min(BLOCK_SIZE as u64) as usize;
            let buf = read_chunk(file, limit)?;
            if buf.is_empty() {
                break;
            }
            total_read += u64::try_from(buf.len()).unwrap();
            if total_read > expected_len {
                return Err(io::Error::other("file size changed while reading"));
            }

            f(slot, buf)?;
        }
        if total_read != expected_len {
            // The writer will be notified by returning an error
            return Err(io::Error::other("file size changed while reading"));
        }
        Ok(true)
    }
}

impl WorkHandler<WorkItem> for Handler {
    fn handle_item(&mut self, item: WorkItem) {
        let WorkItem { context } = item;
        let _guard = tracing::info_span!("reading file", path=%context.path.display()).entered();
        let file = match open_scanned_regular_file(&context.path, &context.orig_metadata) {
            Ok(file) => file,
            Err(e) => {
                context
                    .progress
                    .error(&format!("Error opening {}: {}", context.path.display(), e));
                return;
            }
        };
        let file_size = context.orig_metadata.len();
        let selected_kind = match context.operation.mode {
            Mode::Compress { kind, .. } => Some(kind),
            Mode::CompressAuto { level, .. } => {
                match select_native_codec(&file, file_size, level) {
                    Ok((kind, sampled_bytes, windows)) => {
                        tracing::info!(
                            codec = %kind,
                            sampled_bytes,
                            windows,
                            "auto-selected native compression codec for {}",
                            context.path.display()
                        );
                        Some(kind)
                    }
                    Err(error) => {
                        context.progress.error(&format!(
                            "Error selecting a codec for {}: {error}",
                            context.path.display()
                        ));
                        return;
                    }
                }
            }
            Mode::DecompressManually | Mode::DecompressByReading => None,
        };
        let file = Arc::new(file);

        let (tx, rx) = seq_queue::bounded(
            thread::available_parallelism()
                .map(NonZeroUsize::get)
                .unwrap_or(4),
        );

        {
            let _enter = tracing::debug_span!("waiting for space in writer").entered();
            self.writer
                .send(writer::WorkItem {
                    context: Arc::clone(&context),
                    file: Arc::clone(&file),
                    compression_kind: selected_kind,
                    blocks: rx,
                })
                .unwrap();
        }

        let result = self.read_file_into(&context, &file, file_size, selected_kind, &tx);
        // ensure the file is dropped before tx is finished
        drop(file);
        if let Err(e) = &result {
            context
                .progress
                .error(&format!("Error reading {}: {}", context.path.display(), e));
        }
        tx.finish(result);
    }
}

#[cfg(test)]
mod tests {
    use super::read_chunk;
    use applesauce_core::BLOCK_SIZE;
    use std::io::{self, Cursor, Read};

    #[test]
    fn auto_sampling_has_fixed_budget_and_nonoverlapping_windows() {
        use super::sample_windows;
        for length in [
            1,
            63,
            65_536,
            65_537,
            131_071,
            131_072,
            196_607,
            196_608,
            1_000_000,
            u64::from(u32::MAX),
        ] {
            let geometry = sample_windows(length);
            assert!(!geometry.is_empty());
            assert!(geometry.len() <= 3);
            assert_eq!(
                geometry.iter().map(|(_, bytes)| bytes).sum::<usize>(),
                length.min(65_536) as usize
            );
            let mut end = 0;
            for (offset, bytes) in geometry {
                assert!(offset >= end);
                end = offset + bytes as u64;
                assert!(end <= length);
            }
        }
    }

    #[test]
    fn native_auto_selection_preserves_open_descriptor_cursor_and_roundtrips() {
        use super::select_native_codec;
        use applesauce_core::compressor::Kind;
        use std::io::{Read, Seek, SeekFrom};

        let mut input = tempfile::tempfile().unwrap();
        let content: Vec<u8> = (0..(4 * BLOCK_SIZE + 17))
            .map(|n| b"deterministic native codec test fixture"[n % 39])
            .collect();
        io::Write::write_all(&mut input, &content).unwrap();
        input.seek(SeekFrom::Start(23)).unwrap();
        let (selected, measured, windows) =
            select_native_codec(&input, content.len() as u64, 5).unwrap();
        assert!(matches!(selected, Kind::Zlib | Kind::Lzvn | Kind::Lzfse));
        assert!(selected.supported());
        assert_eq!(measured, BLOCK_SIZE);
        assert_eq!(windows, 3);
        let mut next = [0; 7];
        input.read_exact(&mut next).unwrap();
        assert_eq!(&next[..], &content[23..30]);
    }

    #[test]
    fn native_auto_choice_matches_verified_sample_sizes_on_heterogeneous_files() {
        use super::{read_sample, sample_windows, select_native_codec};
        use applesauce_core::compressor::Kind;
        use std::io::Write;

        // Exercise a constant file, a mixed file whose middle differs from the
        // edges, and deterministic high-entropy input. All files are disposable.
        let constant = vec![b'Q'; 4 * BLOCK_SIZE + 17];
        let mut mixed = vec![b'R'; 4 * BLOCK_SIZE + 17];
        for byte in &mut mixed[BLOCK_SIZE..3 * BLOCK_SIZE] {
            *byte = b'X';
        }
        let mut entropy = vec![0u8; 4 * BLOCK_SIZE + 17];
        let mut state = 0x1234_5678_u32;
        for byte in &mut entropy {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = (state >> 8) as u8;
        }

        for input in [constant, mixed, entropy] {
            let mut source = tempfile::tempfile().unwrap();
            source.write_all(&input).unwrap();
            let mut best: Option<(Kind, usize)> = None;
            for kind in [Kind::Lzfse, Kind::Lzvn, Kind::Zlib] {
                let Some(mut encoder) = kind.compressor() else {
                    continue;
                };
                let mut score = 0usize;
                let mut valid = true;
                for (offset, length) in sample_windows(input.len() as u64) {
                    let window = read_sample(&source, offset, length).unwrap();
                    let mut encoded = vec![0; BLOCK_SIZE + 1024];
                    let mut decoded = vec![0; BLOCK_SIZE];
                    let Ok(size) = encoder.compress(&mut encoded, &window, 5) else {
                        valid = false;
                        break;
                    };
                    let Ok(restored) = encoder.decompress(&mut decoded, &encoded[..size]) else {
                        valid = false;
                        break;
                    };
                    if restored != window.len() || decoded[..restored] != window[..] {
                        valid = false;
                        break;
                    }
                    score += size;
                }
                if valid && best.is_none_or(|(_, size)| score < size) {
                    best = Some((kind, score));
                }
            }
            let (selected, measured, windows) =
                select_native_codec(&source, input.len() as u64, 5).unwrap();
            assert_eq!(selected, best.expect("at least one stable codec").0);
            assert_eq!(measured, BLOCK_SIZE);
            assert_eq!(windows, 3);
        }
    }

    #[test]
    fn native_auto_refuses_truncated_source_during_sampling() {
        use super::select_native_codec;
        use std::io::{Seek, SeekFrom, Write};

        let mut source = tempfile::tempfile().unwrap();
        source.write_all(b"short").unwrap();
        source.seek(SeekFrom::Start(3)).unwrap();
        let error = select_native_codec(&source, 200_000, 5).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(source.stream_position().unwrap(), 3);
    }

    #[test]
    fn native_auto_source_preflight_rejects_swaps_before_sampling() {
        use super::open_scanned_regular_file;
        use std::fs;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("selected-source");
        let old = dir.path().join("old-source");
        fs::write(&path, b"generated source bytes").unwrap();
        let scanned = fs::symlink_metadata(&path).unwrap();
        open_scanned_regular_file(&path, &scanned).unwrap();

        // A same-length replacement with a different inode must not be read
        // merely because its path and apparent length still match the scan.
        fs::rename(&path, &old).unwrap();
        fs::write(&path, b"generated source bytes").unwrap();
        assert_eq!(
            open_scanned_regular_file(&path, &scanned)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        // A pathname replaced by a link must not resolve to the old inode.
        fs::remove_file(&path).unwrap();
        symlink(&old, &path).unwrap();
        assert!(open_scanned_regular_file(&path, &scanned).is_err());
        assert_eq!(fs::read(&old).unwrap(), b"generated source bytes");
    }

    #[test]
    fn native_auto_source_preflight_refuses_fifo_without_blocking() {
        use super::open_scanned_regular_file;
        use std::ffi::CString;
        use std::fs;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::FileTypeExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("selected-source");
        fs::write(&path, b"generated regular file").unwrap();
        let scanned = fs::symlink_metadata(&path).unwrap();
        fs::remove_file(&path).unwrap();

        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a NUL-terminated path inside a disposable directory.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());

        // O_NONBLOCK allows the descriptor check to reject a FIFO even when
        // no writer exists. A normal blocking open would hang the worker.
        assert!(open_scanned_regular_file(&path, &scanned).is_err());
    }

    #[test]
    fn chunk_reader_preserves_generated_bytes_and_boundaries() {
        for len in [
            0,
            1,
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            2 * BLOCK_SIZE + 13,
        ] {
            let input: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
            let mut cursor = Cursor::new(&input);
            let mut recovered = Vec::new();
            loop {
                let chunk = read_chunk(&mut cursor, BLOCK_SIZE).unwrap();
                if chunk.is_empty() {
                    break;
                }
                assert!(chunk.len() <= BLOCK_SIZE);
                recovered.extend_from_slice(&chunk);
            }
            assert_eq!(recovered, input, "length {len}");
        }
    }

    #[test]
    fn chunk_reader_handles_short_reads_without_exposing_unwritten_bytes() {
        struct OneByteReader<'a>(&'a [u8]);

        impl Read for OneByteReader<'_> {
            fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() || dst.is_empty() {
                    return Ok(0);
                }
                dst[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }

        let input: Vec<u8> = (0..BLOCK_SIZE + 7)
            .map(|index| (index % 251) as u8)
            .collect();
        let mut reader = OneByteReader(&input);
        assert_eq!(
            read_chunk(&mut reader, BLOCK_SIZE).unwrap(),
            input[..BLOCK_SIZE]
        );
        assert_eq!(
            read_chunk(&mut reader, BLOCK_SIZE).unwrap(),
            input[BLOCK_SIZE..]
        );
        assert!(read_chunk(&mut reader, BLOCK_SIZE).unwrap().is_empty());
    }

    #[test]
    fn chunk_reader_obeys_remaining_byte_budget() {
        let input: Vec<u8> = (0..BLOCK_SIZE + 13).map(|i| (i % 251) as u8).collect();
        let mut cursor = Cursor::new(input.as_slice());
        let first = read_chunk(&mut cursor, 7).unwrap();
        assert_eq!(first, input[..7]);
        assert_eq!(cursor.position(), 7);

        // A zero remaining budget must not touch the reader.
        assert!(read_chunk(&mut cursor, 0).unwrap().is_empty());
        assert_eq!(cursor.position(), 7);

        // An accidental oversized request still respects the 64 KiB limit.
        let next = read_chunk(&mut cursor, BLOCK_SIZE + 100).unwrap();
        assert_eq!(next, input[7..7 + BLOCK_SIZE]);
        assert_eq!(cursor.position(), (7 + BLOCK_SIZE) as u64);
        assert_eq!(
            read_chunk(&mut cursor, BLOCK_SIZE).unwrap(),
            input[7 + BLOCK_SIZE..]
        );
    }

    #[test]
    fn chunk_reader_returns_read_errors_after_partial_input() {
        struct FailingReader(bool);
        impl Read for FailingReader {
            fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    Err(io::Error::other("synthetic read failure"))
                } else {
                    self.0 = true;
                    dst[0] = 0x42;
                    Ok(1)
                }
            }
        }
        assert_eq!(
            read_chunk(FailingReader(false), 8).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }
}
