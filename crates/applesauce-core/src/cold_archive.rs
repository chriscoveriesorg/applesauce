//! Experimental, seekable LZRAVEN/LZMESH cold-file container.
//!
//! This is an application-level storage format and a building block for a
//! *separately mounted* FSKit filesystem. It is NOT APFS decmpfs compression:
//! no native filesystem type, xattr or kernel decoder is involved. Callers
//! must write into a new, private staging file and publish it only after
//! their own fsync, reopen, full verification and atomic rename.
//!
//! Every chunk is compressed independently with Apple's public macOS 27+
//! buffer API, has a SHA-256 digest of its logical bytes, and is addressable
//! without decoding preceding chunks. The format is experimental (v1) and
//! must not be used as the only copy of data.

use crate::apple_buffer::Codec;
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};

const MAGIC: &[u8; 8] = b"ASCF0001";
const HEADER_BYTES: usize = 64;
const ENTRY_BYTES: usize = 48;

/// Bounds the memory needed for decoding and reading individual chunks.
pub const MIN_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CHUNKS: usize = 65_536;
/// A single random read is bounded; clients can issue successive reads.
pub const MAX_READ_BYTES: usize = 8 * 1024 * 1024;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn bad_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn u32_at(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four-byte header slice"))
}

fn u64_at(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight-byte header slice"))
}

/// Validate ASCF v1 chunk geometry before attempting codec work or creating
/// staged output. Callers that perform extra preflight can use the same bounds
/// as the writer and reader, avoiding a second, divergent size policy.
pub fn validate_archive_geometry(logical_size: u64, chunk_size: usize) -> io::Result<usize> {
    chunk_count(logical_size, chunk_size)
}

fn chunk_count(logical_size: u64, chunk_size: usize) -> io::Result<usize> {
    if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&chunk_size) || !chunk_size.is_power_of_two() {
        return Err(bad_input(
            "archive chunk size must be a power of two from 64 KiB to 8 MiB",
        ));
    }
    if logical_size == 0 {
        return Err(bad_input("archive logical size must be nonzero"));
    }
    let count = logical_size.div_ceil(chunk_size as u64);
    if count == 0 || count > MAX_CHUNKS as u64 {
        return Err(bad_input("archive exceeds maximum chunk count"));
    }
    Ok(count as usize)
}

fn bounded_encoded_len(clear_len: usize) -> usize {
    // Same policy as Codec::encode: at most 2x + 64 KiB.
    clear_len * 2 + MIN_CHUNK_BYTES
}

// Archive inputs are bounded but can be 8 MiB per chunk. Return a recoverable
// allocation error instead of invoking vec![0; size]'s infallible growth.
fn allocate_buffer(size: usize) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    grow_buffer(&mut buffer, size)?;
    Ok(buffer)
}

// Fallible, monotonic per-reader storage growth. Keeping the previous buffer
// allocation avoids O(chunks) large heap allocations during full verification
// and repeated mounted-file reads. Lengths remain bounded by the archive index.
fn grow_buffer(buffer: &mut Vec<u8>, size: usize) -> io::Result<()> {
    if size > buffer.len() {
        buffer
            .try_reserve_exact(size - buffer.len())
            .map_err(io::Error::other)?;
        buffer.resize(size, 0);
    }
    Ok(())
}

fn file_codec(raw: u32) -> io::Result<Codec> {
    match raw {
        0xD05 => Ok(Codec::Lzraven),
        0xE05 => Ok(Codec::Lzmesh),
        _ => Err(invalid("unknown cold-file codec; no fallback decoder")),
    }
}

#[derive(Debug, Clone)]
struct Entry {
    offset: u64,
    stored_len: u32,
    clear_len: u32,
    clear_sha256: [u8; 32],
}

impl Entry {
    fn from_bytes(data: &[u8; ENTRY_BYTES]) -> Self {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[16..48]);
        Self {
            offset: u64_at(&data[..8]),
            stored_len: u32_at(&data[8..12]),
            clear_len: u32_at(&data[12..16]),
            clear_sha256: digest,
        }
    }

    fn to_bytes(&self) -> [u8; ENTRY_BYTES] {
        let mut data = [0u8; ENTRY_BYTES];
        data[..8].copy_from_slice(&self.offset.to_le_bytes());
        data[8..12].copy_from_slice(&self.stored_len.to_le_bytes());
        data[12..16].copy_from_slice(&self.clear_len.to_le_bytes());
        data[16..48].copy_from_slice(&self.clear_sha256);
        data
    }
}

/// Writer result, recording encoded payload and logical-content identity.
/// Physical APFS allocation and native transparent compression are not measured.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveStats {
    pub logical_size: u64,
    pub archive_bytes: u64,
    pub chunk_count: usize,
    pub logical_sha256: [u8; 32],
}

/// Write a versioned Raven/Mesh archive to an **empty staging sink**.
///
/// The caller supplies the exact plaintext length; a short or overlong source
/// is rejected. Partial output on failure is untrusted and must be discarded.
/// The writer neither changes APFS metadata nor publishes the result.
pub fn write_archive<R: Read, W: Write + Seek>(
    mut source: R,
    mut destination: W,
    logical_size: u64,
    codec: Codec,
    chunk_size: usize,
) -> io::Result<ArchiveStats> {
    if !matches!(codec, Codec::Lzraven | Codec::Lzmesh) {
        return Err(bad_input(
            "cold-file archive only supports LZRAVEN and LZMESH buffers",
        ));
    }
    let count = chunk_count(logical_size, chunk_size)?;
    if !codec.is_supported() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "selected Apple buffer codec is unavailable on this host",
        ));
    }
    if destination.seek(SeekFrom::End(0))? != 0 {
        return Err(bad_input(
            "archive destination must be a new empty staging file",
        ));
    }
    // Scratch and working buffers are allocated once for the entire file.
    // Repeated 64 KiB chunks would otherwise pay Apple's scratch setup and
    // three heap allocations per chunk, obscuring codec throughput.
    let mut scratch = codec.reusable_scratch()?;
    // A one-byte archive configured with 8 MiB chunks still needs only one
    // byte of plaintext storage. Bound the working set by the largest
    // chunk this particular archive will contain.
    let max_clear_len = logical_size.min(chunk_size as u64) as usize;
    let mut clear_storage = allocate_buffer(max_clear_len)?;
    let mut encoded_storage = allocate_buffer(bounded_encoded_len(max_clear_len))?;
    // Apple's decoder can fill the entire destination on truncated output.
    // The extra byte detects overlong results before any staged success.
    let mut decoded_storage = allocate_buffer(max_clear_len + 1)?;

    let table_bytes = count * ENTRY_BYTES;
    destination.seek(SeekFrom::Start(0))?;
    destination.write_all(&[0u8; HEADER_BYTES])?;
    destination.write_all(&allocate_buffer(table_bytes)?)?;

    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(io::Error::other)?;
    let mut total_hash = Sha256::new();
    let mut remaining = logical_size;
    let mut next_offset = (HEADER_BYTES + table_bytes) as u64;
    for _ in 0..count {
        let clear_len = remaining.min(chunk_size as u64) as usize;
        let clear = &mut clear_storage[..clear_len];
        source.read_exact(clear)?;
        total_hash.update(&clear[..]);
        let digest: [u8; 32] = Sha256::digest(&clear[..]).into();
        // Bound each compressed chunk by its own logical size, including the
        // final short chunk. No per-chunk allocation or scratch setup occurs.
        let encoded_len = scratch.encode_into(
            &mut encoded_storage[..bounded_encoded_len(clear_len)],
            clear,
        )?;
        if encoded_len == 0 || encoded_len > bounded_encoded_len(clear_len) {
            return Err(invalid("encoder produced an invalid chunk length"));
        }
        // Never report successful staged output on encode-only evidence.
        // Check the exact length and bytes with a one-byte decode guard.
        let decoded_len = scratch.decode_into(
            &mut decoded_storage[..clear_len + 1],
            &encoded_storage[..encoded_len],
        )?;
        if decoded_len != clear_len || decoded_storage[..clear_len] != clear[..] {
            return Err(invalid("encoder failed exact-byte chunk round-trip"));
        }
        let stored_len = u32::try_from(encoded_len)
            .map_err(|_| invalid("encoded chunk length exceeds field width"))?;
        destination.write_all(&encoded_storage[..encoded_len])?;
        entries.push(Entry {
            offset: next_offset,
            stored_len,
            clear_len: clear_len as u32,
            clear_sha256: digest,
        });
        next_offset = next_offset
            .checked_add(encoded_len as u64)
            .ok_or_else(|| invalid("archive offset overflow"))?;
        remaining -= clear_len as u64;
    }
    let mut extra = [0u8; 1];
    if source.read(&mut extra)? != 0 {
        return Err(bad_input(
            "source has extra bytes after declared logical size",
        ));
    }
    if remaining != 0 {
        return Err(invalid("archive writer missed source bytes"));
    }
    let logical_sha256: [u8; 32] = total_hash.finalize().into();
    destination.seek(SeekFrom::Start(HEADER_BYTES as u64))?;
    for entry in &entries {
        destination.write_all(&entry.to_bytes())?;
    }

    // The magic and content hash are published last so interrupted staging
    // writes never masquerade as an already finalized archive.
    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&(codec as u32).to_le_bytes());
    header[12..16].copy_from_slice(&(chunk_size as u32).to_le_bytes());
    header[16..24].copy_from_slice(&logical_size.to_le_bytes());
    header[24..28].copy_from_slice(&(count as u32).to_le_bytes());
    header[32..64].copy_from_slice(&logical_sha256);
    destination.seek(SeekFrom::Start(0))?;
    destination.write_all(&header)?;
    destination.flush()?;
    Ok(ArchiveStats {
        logical_size,
        archive_bytes: next_offset,
        chunk_count: count,
        logical_sha256,
    })
}

/// Bounded, checked, seekable reader. Parsing metadata is portable; decoding
/// requires the selected public Apple buffer codec on macOS 27+.
pub struct ArchiveReader<R> {
    source: R,
    codec: Codec,
    chunk_size: usize,
    logical_size: u64,
    logical_sha256: [u8; 32],
    entries: Vec<Entry>,
    // Lazy so portable metadata inspection works without Apple codecs.
    // Reuse aligned decoder scratch and bounded I/O buffers across verification
    // and random reads. The pread staging buffer preserves atomic caller writes.
    decode_scratch: Option<crate::apple_buffer::Scratch>,
    encoded_storage: Vec<u8>,
    decoded_storage: Vec<u8>,
    read_staging: Vec<u8>,
    // Last independently verified chunk. Cache reuse still re-reads and
    // SHA-256-authenticates its compressed bytes on every new request.
    // A changed payload is decoded again and checked against the index.
    verified_encoded_chunk: Option<(usize, [u8; 32])>,
    #[cfg(test)]
    verified_cache_hits: usize,
}

impl<R: Read + Seek> ArchiveReader<R> {
    pub fn open(mut source: R) -> io::Result<Self> {
        let file_bytes = source.seek(SeekFrom::End(0))?;
        if file_bytes < (HEADER_BYTES + ENTRY_BYTES) as u64 {
            return Err(invalid("truncated archive header or index"));
        }
        source.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_BYTES];
        source.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(invalid("invalid or unfinalized cold-file magic"));
        }
        if header[28..32].iter().any(|byte| *byte != 0) {
            return Err(invalid("archive header has nonzero reserved bytes"));
        }
        let codec = file_codec(u32_at(&header[8..12]))?;
        let chunk_size = u32_at(&header[12..16]) as usize;
        let logical_size = u64_at(&header[16..24]);
        let count = chunk_count(logical_size, chunk_size)
            .map_err(|_| invalid("archive declares invalid size or chunk count"))?;
        if u32_at(&header[24..28]) as usize != count {
            return Err(invalid("archive chunk count disagrees with logical size"));
        }
        let mut logical_sha256 = [0u8; 32];
        logical_sha256.copy_from_slice(&header[32..64]);
        let index_end = (HEADER_BYTES + count * ENTRY_BYTES) as u64;
        if index_end > file_bytes {
            return Err(invalid("truncated cold-file chunk index"));
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(io::Error::other)?;
        let mut offset = index_end;
        let mut remaining = logical_size;
        for _ in 0..count {
            let mut bytes = [0u8; ENTRY_BYTES];
            source.read_exact(&mut bytes)?;
            let entry = Entry::from_bytes(&bytes);
            let expected_clear = remaining.min(chunk_size as u64) as usize;
            if entry.offset != offset
                || entry.clear_len as usize != expected_clear
                || entry.stored_len == 0
                || entry.stored_len as usize > bounded_encoded_len(expected_clear)
            {
                return Err(invalid("invalid archive chunk offset, length or ordering"));
            }
            offset = offset
                .checked_add(u64::from(entry.stored_len))
                .ok_or_else(|| invalid("archive chunk offset overflow"))?;
            if offset > file_bytes {
                return Err(invalid("truncated archive payload"));
            }
            remaining -= expected_clear as u64;
            entries.push(entry);
        }
        if remaining != 0 || offset != file_bytes {
            return Err(invalid("archive has missing or trailing payload bytes"));
        }
        Ok(Self {
            source,
            codec,
            chunk_size,
            logical_size,
            logical_sha256,
            entries,
            decode_scratch: None,
            encoded_storage: Vec::new(),
            decoded_storage: Vec::new(),
            read_staging: Vec::new(),
            verified_encoded_chunk: None,
            #[cfg(test)]
            verified_cache_hits: 0,
        })
    }

    #[must_use]
    pub const fn logical_size(&self) -> u64 {
        self.logical_size
    }

    #[must_use]
    pub const fn codec(&self) -> Codec {
        self.codec
    }

    /// Stored archive chunk size in logical bytes; metadata only.
    #[must_use]
    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Number of authenticated chunks declared by the validated archive index.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.entries.len()
    }

    /// Sum of encoded chunk payload lengths, excluding the archive header and index.
    /// This inspects validated metadata without decoding or reading payload bytes.
    #[must_use]
    pub fn raw_compressed_bytes(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| u64::from(entry.stored_len))
            .sum()
    }

    #[must_use]
    pub const fn logical_sha256(&self) -> [u8; 32] {
        self.logical_sha256
    }

    // A decoded chunk is borrowed from reusable, bounded storage. It is never
    // returned until both Apple's guarded exact-length check and the stored
    // SHA-256 have passed. The next decode invalidates the borrowed slice.
    // Read the current compressed payload even when a previously decoded
    // chunk is cached. Metadata alone cannot detect all in-place edits.
    fn load_encoded_chunk(&mut self, index: usize) -> io::Result<()> {
        let entry = &self.entries[index];
        let stored_len = entry.stored_len as usize;
        grow_buffer(&mut self.encoded_storage, stored_len)?;
        self.source.seek(SeekFrom::Start(entry.offset))?;
        self.source
            .read_exact(&mut self.encoded_storage[..stored_len])?;
        Ok(())
    }

    // Decode only bytes already read into the bounded encoded buffer.
    fn decode_loaded_chunk(&mut self, index: usize) -> io::Result<&[u8]> {
        let entry = &self.entries[index];
        let stored_len = entry.stored_len as usize;
        let clear_len = entry.clear_len as usize;
        if self.decode_scratch.is_none() {
            self.decode_scratch = Some(self.codec.reusable_scratch()?);
        }
        // Apple's decoder can fill the destination on truncated output.
        // One extra byte detects overlong output before exposing data.
        grow_buffer(&mut self.decoded_storage, clear_len + 1)?;
        let decoded_len = self
            .decode_scratch
            .as_mut()
            .expect("scratch initialized above")
            .decode_into(
                &mut self.decoded_storage[..clear_len + 1],
                &self.encoded_storage[..stored_len],
            )?;
        if decoded_len != clear_len {
            return Err(invalid("archive decoder returned wrong logical length"));
        }
        let decoded = &self.decoded_storage[..clear_len];
        let digest: [u8; 32] = Sha256::digest(decoded).into();
        if digest != entry.clear_sha256 {
            return Err(invalid("archive chunk SHA-256 mismatch"));
        }
        Ok(decoded)
    }

    // The full-file publication gate always independently decodes every
    // chunk, including one that a previous logical read had cached.
    fn decode_chunk(&mut self, index: usize) -> io::Result<&[u8]> {
        self.verified_encoded_chunk = None;
        self.load_encoded_chunk(index)?;
        self.decode_loaded_chunk(index)
    }

    // Finder and ordinary apps often issue several small reads within one
    // ASCF chunk. Avoid decoding that chunk repeatedly while remaining
    // fail-closed on source mutations: hash the newly read compressed bytes
    // before reusing any previously authenticated plaintext. This cache
    // retains at most one chunk and uses existing bounded buffers.
    fn read_verified_chunk(&mut self, index: usize) -> io::Result<&[u8]> {
        if let Err(error) = self.load_encoded_chunk(index) {
            self.verified_encoded_chunk = None;
            return Err(error);
        }
        let stored_len = self.entries[index].stored_len as usize;
        let encoded_digest: [u8; 32] = Sha256::digest(&self.encoded_storage[..stored_len]).into();
        if self.verified_encoded_chunk == Some((index, encoded_digest)) {
            #[cfg(test)]
            {
                self.verified_cache_hits += 1;
            }
            return Ok(&self.decoded_storage[..self.entries[index].clear_len as usize]);
        }
        self.verified_encoded_chunk = None;
        self.decode_loaded_chunk(index)?;
        self.verified_encoded_chunk = Some((index, encoded_digest));
        Ok(&self.decoded_storage[..self.entries[index].clear_len as usize])
    }

    fn read_range_into(&mut self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        if destination.len() > MAX_READ_BYTES {
            return Err(bad_input("archive read exceeds 8 MiB per call"));
        }
        if offset > self.logical_size || destination.len() as u64 > self.logical_size - offset {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond archive EOF",
            ));
        }
        let end = offset + destination.len() as u64;
        let mut current = offset;
        while current < end {
            let index = (current / self.chunk_size as u64) as usize;
            let chunk_start = (index as u64) * self.chunk_size as u64;
            let chunk = self.read_verified_chunk(index)?;
            let within = (current - chunk_start) as usize;
            let n = ((end - current) as usize).min(chunk.len() - within);
            let dst = (current - offset) as usize;
            destination[dst..dst + n].copy_from_slice(&chunk[within..within + n]);
            current += n as u64;
        }
        Ok(())
    }

    /// Return a verified logical range. Failed reads cannot expose a partially
    /// filled output vector, and each decoded chunk is SHA-256 authenticated.
    pub fn read_range(&mut self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        if length > MAX_READ_BYTES {
            return Err(bad_input("archive read exceeds 8 MiB per call"));
        }
        // Reject invalid ranges before reserving up to 8 MiB of output.
        // This also keeps malformed requests from creating allocation pressure.
        if offset > self.logical_size || length as u64 > self.logical_size - offset {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond archive EOF",
            ));
        }
        let mut result = allocate_buffer(length)?;
        self.read_range_into(offset, &mut result)?;
        Ok(result)
    }

    /// Stage into reusable memory; copy to caller only after all affected
    /// chunks have passed decoding and SHA-256 checks. Failure leaves the
    /// destination unchanged, including for reads spanning many chunks.
    pub fn read_exact_at(&mut self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        if destination.len() > MAX_READ_BYTES {
            return Err(bad_input("archive read exceeds 8 MiB per call"));
        }
        // Check bounds before growing retained staging storage. In particular,
        // invalid FSKit pread offsets must not trigger large allocations.
        if offset > self.logical_size || destination.len() as u64 > self.logical_size - offset {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond archive EOF",
            ));
        }
        if destination.is_empty() {
            return Ok(());
        }
        // Most Finder and FSKit reads fit in one archive chunk. Decode and
        // authenticate the complete chunk before copying the requested slice
        // directly into caller memory. No intermediate 8 MiB read buffer is
        // needed, and errors still leave the caller's bytes untouched.
        let index = (offset / self.chunk_size as u64) as usize;
        let within = (offset % self.chunk_size as u64) as usize;
        if destination.len() <= self.entries[index].clear_len as usize - within {
            let chunk = self.read_verified_chunk(index)?;
            destination.copy_from_slice(&chunk[within..within + destination.len()]);
            return Ok(());
        }

        // Cross-chunk reads retain the atomic staging contract: if any
        // later chunk fails authentication, no partial prefix escapes.
        let mut staging = std::mem::take(&mut self.read_staging);
        let result = (|| {
            grow_buffer(&mut staging, destination.len())?;
            self.read_range_into(offset, &mut staging[..destination.len()])?;
            destination.copy_from_slice(&staging[..destination.len()]);
            Ok(())
        })();
        self.read_staging = staging;
        result
    }

    /// Validate every chunk and the whole-file SHA-256 before publication.
    pub fn verify_all(&mut self) -> io::Result<()> {
        self.verify_all_cancellable(|| false)
    }

    /// FSKit unload can interrupt lengthy verification between chunks.
    /// Check once before decoding and again before reporting success.
    /// Successful calls retain the identical whole-file SHA-256 guarantee.
    pub fn verify_all_cancellable(
        &mut self,
        mut cancelled: impl FnMut() -> bool,
    ) -> io::Result<()> {
        let interrupted =
            || io::Error::new(io::ErrorKind::Interrupted, "ASCF verification cancelled");
        let mut hash = Sha256::new();
        for index in 0..self.entries.len() {
            if cancelled() {
                return Err(interrupted());
            }
            hash.update(self.decode_chunk(index)?);
        }
        if cancelled() {
            return Err(interrupted());
        }
        let digest: [u8; 32] = hash.finalize().into();
        if digest != self.logical_sha256 {
            return Err(invalid("archive whole-file SHA-256 mismatch"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Portable metadata fixture. Payload is deliberately not a valid Raven
    // stream, so parsing cannot be mistaken for decoder compatibility.
    fn fake_archive() -> Vec<u8> {
        let data = b"not a codec payload";
        let mut result = vec![0u8; HEADER_BYTES + ENTRY_BYTES];
        result[..8].copy_from_slice(MAGIC);
        result[8..12].copy_from_slice(&(Codec::Lzraven as u32).to_le_bytes());
        result[12..16].copy_from_slice(&(MIN_CHUNK_BYTES as u32).to_le_bytes());
        result[16..24].copy_from_slice(&1u64.to_le_bytes());
        result[24..28].copy_from_slice(&1u32.to_le_bytes());
        result[32..64].copy_from_slice(&Sha256::digest(b"x"));
        result[64..72].copy_from_slice(&((HEADER_BYTES + ENTRY_BYTES) as u64).to_le_bytes());
        result[72..76].copy_from_slice(&(data.len() as u32).to_le_bytes());
        result[76..80].copy_from_slice(&1u32.to_le_bytes());
        result[80..112].copy_from_slice(&Sha256::digest(b"x"));
        result.extend_from_slice(data);
        result
    }

    #[test]
    fn cancelled_full_verification_stops_before_untrusted_decode() {
        let mut reader = ArchiveReader::open(Cursor::new(fake_archive())).unwrap();
        let mut checks = 0;
        let failure = reader
            .verify_all_cancellable(|| {
                checks += 1;
                true
            })
            .unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::Interrupted);
        assert_eq!(checks, 1, "cancellation must precede chunk decoding");
        assert!(reader.verify_all().is_err());
    }

    #[test]
    fn reused_buffer_grows_fallibly_and_preserves_bytes() {
        let mut buffer = vec![0x5a, 0xa5];
        let original = buffer.as_ptr();
        grow_buffer(&mut buffer, 1).unwrap();
        assert_eq!(buffer.as_ptr(), original);
        assert_eq!(buffer, vec![0x5a, 0xa5]);
        grow_buffer(&mut buffer, 4).unwrap();
        assert_eq!(buffer, vec![0x5a, 0xa5, 0, 0]);
        assert!(grow_buffer(&mut buffer, usize::MAX).is_err());
        assert_eq!(buffer, vec![0x5a, 0xa5, 0, 0]);
    }

    #[test]
    fn synthetic_header_is_readable_without_claiming_codec_support() {
        let reader = ArchiveReader::open(Cursor::new(fake_archive())).unwrap();
        assert_eq!(reader.codec(), Codec::Lzraven);
        assert_eq!(reader.logical_size(), 1);
        assert_eq!(reader.chunk_count(), 1);
        assert_eq!(reader.chunk_size(), MIN_CHUNK_BYTES);
        let expected: [u8; 32] = Sha256::digest(b"x").into();
        assert_eq!(reader.logical_sha256(), expected);
        // Metadata inspection must not allocate platform-dependent scratch.
        assert!(reader.decode_scratch.is_none());
    }

    #[test]
    fn invalid_reads_do_not_allocate_or_initialize_decoder() {
        let mut reader = ArchiveReader::open(Cursor::new(fake_archive())).unwrap();
        assert_eq!(
            reader
                .read_range(u64::MAX, MAX_READ_BYTES)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut output = [0xa5; 32];
        assert_eq!(
            reader.read_exact_at(1, &mut output).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(output, [0xa5; 32]);
        assert!(reader.read_staging.is_empty());
        assert!(reader.encoded_storage.is_empty());
        assert!(reader.decoded_storage.is_empty());
        assert!(reader.decode_scratch.is_none());
    }

    #[test]
    fn malformed_index_and_unknown_codec_fail_closed() {
        let original = fake_archive();
        let mut cases = Vec::new();
        let mut broken = original.clone();
        broken[0] = 0;
        cases.push(broken);
        let mut broken = original.clone();
        broken[8..12].copy_from_slice(&0x702u32.to_le_bytes());
        cases.push(broken);
        let mut broken = original.clone();
        broken[12..16].copy_from_slice(&12345u32.to_le_bytes());
        cases.push(broken);
        let mut broken = original.clone();
        broken[24..28].copy_from_slice(&2u32.to_le_bytes());
        cases.push(broken);
        let mut broken = original.clone();
        broken[28] = 1;
        cases.push(broken);
        let mut broken = original.clone();
        broken[64..72].copy_from_slice(&0u64.to_le_bytes());
        cases.push(broken);
        let mut broken = original.clone();
        broken[72..76].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(broken);
        let mut broken = original.clone();
        broken.pop();
        cases.push(broken);
        let mut broken = original;
        broken.push(0);
        cases.push(broken);
        for bytes in cases {
            assert!(ArchiveReader::open(Cursor::new(bytes)).is_err());
        }
    }

    #[test]
    fn size_bounds_reject_excessive_table_or_read() {
        assert!(allocate_buffer(usize::MAX).is_err());
        // The same fallible allocation path backs archive index staging,
        // compressed chunk reads, and caller-visible range results.
        assert!(chunk_count(0, MIN_CHUNK_BYTES).is_err());
        assert!(chunk_count(1, MIN_CHUNK_BYTES - 1).is_err());
        assert!(chunk_count(1, MAX_CHUNK_BYTES * 2).is_err());
        assert!(chunk_count(
            MAX_CHUNKS as u64 * MAX_CHUNK_BYTES as u64 + 1,
            MAX_CHUNK_BYTES
        )
        .is_err());
        let mut reader = ArchiveReader::open(Cursor::new(fake_archive())).unwrap();
        assert!(reader.read_range(0, MAX_READ_BYTES + 1).is_err());
        assert!(reader.read_range(1, 1).is_err());
        assert_eq!(reader.read_range(1, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn buffer_codec_ids_are_never_native_decmpfs_ids() {
        assert_eq!(file_codec(0xD05).unwrap(), Codec::Lzraven);
        assert_eq!(file_codec(0xE05).unwrap(), Codec::Lzmesh);
        for id in [3, 4, 11, 12, 13, 14, 15, 16, 0x702] {
            assert!(file_codec(id).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos27_cached_chunk_rechecks_compressed_bytes_after_in_place_edit() {
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            if !codec.is_supported() {
                continue;
            }
            let clear = vec![0x5au8; MIN_CHUNK_BYTES + 13];
            let mut output = Cursor::new(Vec::new());
            write_archive(
                clear.as_slice(),
                &mut output,
                clear.len() as u64,
                codec,
                MIN_CHUNK_BYTES,
            )
            .unwrap();
            let mut reader = ArchiveReader::open(Cursor::new(output.into_inner())).unwrap();

            let mut observed = [0u8; 48];
            reader.read_exact_at(3, &mut observed).unwrap();
            assert_eq!(observed, [0x5a; 48]);
            assert!(reader.read_staging.is_empty());
            assert_eq!(reader.verified_cache_hits, 0);
            let cached = reader.verified_encoded_chunk.unwrap();
            assert_eq!(cached.0, 0);

            reader.read_exact_at(17, &mut observed).unwrap();
            assert_eq!(observed, [0x5a; 48]);
            assert!(reader.read_staging.is_empty());
            assert_eq!(reader.verified_cache_hits, 1);
            assert_eq!(reader.verified_encoded_chunk, Some(cached));

            // An in-place payload mutation must invalidate the cache even
            // when the next read touches the very same logical chunk.
            let offset = reader.entries[0].offset as usize;
            reader.source.get_mut()[offset] ^= 0xff;
            let mut untouched = [0xa5u8; 48];
            assert!(reader.read_exact_at(17, &mut untouched).is_err());
            assert_eq!(untouched, [0xa5; 48]);
            assert!(reader.verified_encoded_chunk.is_none());

            // Full verification never substitutes a prior cached read for
            // an independent decode and whole-file digest check.
            assert!(reader.verify_all().is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos27_writer_rejects_wrong_source_lengths_and_occupied_staging() {
        // Only generated data. Failure must not publish a valid archive magic.
        let clear = vec![0x5au8; MIN_CHUNK_BYTES + 1];
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            if !codec.is_supported() {
                continue;
            }
            let mut short = Cursor::new(Vec::new());
            assert!(write_archive(
                &clear[..clear.len() - 1],
                &mut short,
                clear.len() as u64,
                codec,
                MIN_CHUNK_BYTES,
            )
            .is_err());
            assert!(ArchiveReader::open(Cursor::new(short.into_inner())).is_err());

            let mut extra = Cursor::new(Vec::new());
            assert!(write_archive(
                &clear[..],
                &mut extra,
                (clear.len() - 1) as u64,
                codec,
                MIN_CHUNK_BYTES,
            )
            .is_err());
            assert!(ArchiveReader::open(Cursor::new(extra.into_inner())).is_err());

            let mut occupied = Cursor::new(vec![0xa5]);
            assert!(write_archive(
                &clear[..],
                &mut occupied,
                clear.len() as u64,
                codec,
                MIN_CHUNK_BYTES,
            )
            .is_err());
            assert_eq!(occupied.into_inner(), vec![0xa5]);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos27_roundtrip_random_reads_and_corruption_rejection() {
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            if !codec.is_supported() {
                continue;
            }
            let mut clear = vec![0u8; MIN_CHUNK_BYTES * 2 + 17];
            for (index, byte) in clear.iter_mut().enumerate() {
                *byte = if index % 91 < 80 {
                    b'A' + (index % 7) as u8
                } else {
                    ((index * 17) % 256) as u8
                };
            }
            let mut output = Cursor::new(Vec::new());
            let stats = write_archive(
                &clear[..],
                &mut output,
                clear.len() as u64,
                codec,
                MIN_CHUNK_BYTES,
            )
            .unwrap();
            assert_eq!(stats.logical_size, clear.len() as u64);
            assert_eq!(stats.chunk_count, 3);
            assert_eq!(stats.archive_bytes, output.get_ref().len() as u64);
            let expected: [u8; 32] = Sha256::digest(&clear).into();
            assert_eq!(stats.logical_sha256, expected);
            let stored = output.into_inner();
            let mut archive = ArchiveReader::open(Cursor::new(stored.clone())).unwrap();
            assert!(archive.decode_scratch.is_none());
            archive.verify_all().unwrap();
            assert!(archive.decode_scratch.is_some());
            for (start, length) in [
                (0, 1),
                (MIN_CHUNK_BYTES - 9, 29),
                (MIN_CHUNK_BYTES, MIN_CHUNK_BYTES + 2),
                (clear.len() - 17, 17),
            ] {
                assert_eq!(
                    archive.read_range(start as u64, length).unwrap(),
                    &clear[start..start + length]
                );
            }
            // Decode and pread storage must be retained across repeated
            // random reads instead of reallocating up to 24 MiB on each
            // FSKit call. verify_all above has visited every source chunk.
            let mut mounted_read = vec![0xa5; 128];
            archive
                .read_exact_at((MIN_CHUNK_BYTES - 16) as u64, &mut mounted_read)
                .unwrap();
            assert_eq!(
                mounted_read,
                &clear[MIN_CHUNK_BYTES - 16..MIN_CHUNK_BYTES - 16 + 128]
            );
            let encoded_ptr = archive.encoded_storage.as_ptr();
            let decoded_ptr = archive.decoded_storage.as_ptr();
            let staging_ptr = archive.read_staging.as_ptr();
            for offset in [0, MIN_CHUNK_BYTES - 16, MIN_CHUNK_BYTES + 7, 100] {
                archive
                    .read_exact_at(offset as u64, &mut mounted_read)
                    .unwrap();
                assert_eq!(mounted_read, &clear[offset..offset + 128]);
                assert_eq!(archive.encoded_storage.as_ptr(), encoded_ptr);
                assert_eq!(archive.decoded_storage.as_ptr(), decoded_ptr);
                assert_eq!(archive.read_staging.as_ptr(), staging_ptr);
            }
            let mut untouched = [0xa5; 8];
            assert!(archive
                .read_exact_at(clear.len() as u64, &mut untouched)
                .is_err());
            assert_eq!(untouched, [0xa5; 8]);

            let mut sentinel = vec![0xa5u8; 100];
            let mut damaged = stored.clone();
            let first_payload = archive.entries[0].offset as usize;
            damaged[first_payload] ^= 0xff;
            let mut damaged_reader = ArchiveReader::open(Cursor::new(damaged)).unwrap();
            assert!(damaged_reader.read_exact_at(0, &mut sentinel).is_err());
            assert_eq!(sentinel, vec![0xa5u8; 100]);
            // A later corrupt chunk must not leak a previously verified prefix
            // through the caller-owned destination. This spans the boundary
            // between two independently authenticated archive chunks.
            let mut late_corruption = stored.clone();
            let second_payload = archive.entries[1].offset as usize;
            late_corruption[second_payload] ^= 0xff;
            let mut late_reader = ArchiveReader::open(Cursor::new(late_corruption)).unwrap();
            let mut destination = vec![0xa5u8; 32];
            assert!(late_reader
                .read_exact_at((MIN_CHUNK_BYTES - 16) as u64, &mut destination)
                .is_err());
            assert_eq!(destination, vec![0xa5u8; 32]);
            // A failed cross-chunk read must not poison retained staging or
            // prevent later reads of independently authenticated chunks.
            // The source remains corrupted, so only the first chunk is safe.
            let retained_staging = late_reader.read_staging.as_ptr();
            let mut recovered = [0xa5u8; 32];
            late_reader.read_exact_at(7, &mut recovered).unwrap();
            assert_eq!(&recovered[..], &clear[7..39]);
            assert_eq!(late_reader.read_staging.as_ptr(), retained_staging);
            assert!(late_reader
                .read_exact_at((MIN_CHUNK_BYTES - 16) as u64, &mut destination)
                .is_err());
            assert_eq!(destination, vec![0xa5u8; 32]);

            let mut bad_hash = stored;
            bad_hash[32] ^= 1;
            assert!(ArchiveReader::open(Cursor::new(bad_hash))
                .unwrap()
                .verify_all()
                .is_err());
        }
    }

    #[test]
    fn writer_rejects_non_archive_codecs_before_writing() {
        // The cold-file container is deliberately Raven/Mesh-only, even
        // though the buffer enum carries legacy codecs too.
        for codec in [Codec::Zlib, Codec::Lzfse, Codec::Lzbitmap] {
            let mut destination = Cursor::new(Vec::new());
            let source = &b"only raven and mesh are archive codecs"[..];
            assert_eq!(
                write_archive(
                    source,
                    &mut destination,
                    source.len() as u64,
                    codec,
                    MIN_CHUNK_BYTES
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(destination.get_ref().is_empty());
        }
    }

    #[test]
    fn mutated_index_fields_fail_closed() {
        // Beyond magic/count/type corruption: entries that look plausible
        // but disagree with the declared layout must also be refused.
        let original = fake_archive();
        let payload_len = "not a codec payload".len() as u32;
        let mut cases = Vec::new();
        // clear_len disagrees with the logical size and chunk geometry.
        let mut broken = original.clone();
        broken[76..80].copy_from_slice(&2u32.to_le_bytes());
        cases.push(broken);
        // An entry must start exactly where the index ends.
        let mut broken = original.clone();
        broken[64..72].copy_from_slice(&((HEADER_BYTES + ENTRY_BYTES + 1) as u64).to_le_bytes());
        cases.push(broken);
        // Zero stored_len is refused outright.
        let mut broken = original.clone();
        broken[72..76].copy_from_slice(&0u32.to_le_bytes());
        cases.push(broken);
        // A short stored_len leaves unexplained trailing payload bytes.
        let mut broken = original.clone();
        broken[72..76].copy_from_slice(&(payload_len - 1).to_le_bytes());
        cases.push(broken);
        // A long stored_len runs the payload past the end of the file.
        let mut broken = original.clone();
        broken[72..76].copy_from_slice(&(payload_len + 1).to_le_bytes());
        cases.push(broken);
        for bytes in cases {
            assert!(ArchiveReader::open(Cursor::new(bytes)).is_err());
        }
    }

    #[test]
    fn read_exact_at_empty_destination_at_eof_is_ok() {
        let mut reader = ArchiveReader::open(Cursor::new(fake_archive())).unwrap();
        // An empty pread at exact EOF is a legal no-op for mounted readers.
        reader.read_exact_at(1, &mut []).unwrap();
        let mut empty = Vec::new();
        reader.read_exact_at(0, &mut empty).unwrap();
        assert!(empty.is_empty());
        assert!(reader.read_staging.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn forged_chunk_digests_and_tiny_archives_are_handled() {
        for codec in [Codec::Lzraven, Codec::Lzmesh] {
            if !codec.is_supported() {
                continue;
            }
            // A one-byte archive exercises the minimal-chunk path.
            let mut tiny = Cursor::new(Vec::new());
            let stats = write_archive(&[0xabu8][..], &mut tiny, 1, codec, MIN_CHUNK_BYTES).unwrap();
            assert_eq!(stats.chunk_count, 1);
            let mut reader = ArchiveReader::open(Cursor::new(tiny.into_inner())).unwrap();
            reader.verify_all().unwrap();
            assert_eq!(reader.read_range(0, 1).unwrap(), vec![0xab]);

            // Corrupting a stored chunk digest, not the payload, must still
            // fail: decoding alone is never enough for publication.
            let payload = b"forged chunk digest coverage".repeat(100);
            let mut stored = Cursor::new(Vec::new());
            write_archive(
                &payload[..],
                &mut stored,
                payload.len() as u64,
                codec,
                MIN_CHUNK_BYTES,
            )
            .unwrap();
            let mut forged = stored.into_inner();
            // First entry's clear_sha256 begins at index base + 16.
            forged[HEADER_BYTES + 16] ^= 0xff;
            let mut reader = ArchiveReader::open(Cursor::new(forged)).unwrap();
            assert_eq!(
                reader.verify_all().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            let mut destination = vec![0xa5u8; 16];
            assert!(reader.read_exact_at(0, &mut destination).is_err());
            assert_eq!(destination, vec![0xa5u8; 16]);
        }
    }
}
