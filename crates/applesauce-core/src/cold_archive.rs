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
    let table_bytes = count * ENTRY_BYTES;
    destination.seek(SeekFrom::Start(0))?;
    destination.write_all(&[0u8; HEADER_BYTES])?;
    destination.write_all(&vec![0u8; table_bytes])?;

    let mut entries = Vec::with_capacity(count);
    let mut total_hash = Sha256::new();
    let mut remaining = logical_size;
    let mut next_offset = (HEADER_BYTES + table_bytes) as u64;
    for _ in 0..count {
        let clear_len = remaining.min(chunk_size as u64) as usize;
        let mut clear = vec![0u8; clear_len];
        source.read_exact(&mut clear)?;
        total_hash.update(&clear);
        let digest: [u8; 32] = Sha256::digest(&clear).into();
        let encoded = codec.encode(&clear)?;
        if encoded.is_empty() || encoded.len() > bounded_encoded_len(clear_len) {
            return Err(invalid("encoder produced an invalid chunk length"));
        }
        // Never report a successful staged archive on encode-only evidence:
        // prove the public buffer decoder reconstructs the exact chunk bytes.
        let decoded = codec.decode_exact(&encoded, clear_len)?;
        if decoded != clear {
            return Err(invalid("encoder failed exact-byte chunk round-trip"));
        }
        let stored_len = u32::try_from(encoded.len())
            .map_err(|_| invalid("encoded chunk length exceeds field width"))?;
        destination.write_all(&encoded)?;
        entries.push(Entry {
            offset: next_offset,
            stored_len,
            clear_len: clear_len as u32,
            clear_sha256: digest,
        });
        next_offset = next_offset
            .checked_add(encoded.len() as u64)
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
        let mut entries = Vec::with_capacity(count);
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

    #[must_use]
    pub const fn logical_sha256(&self) -> [u8; 32] {
        self.logical_sha256
    }

    fn decode_chunk(&mut self, index: usize) -> io::Result<Vec<u8>> {
        let entry = &self.entries[index];
        let mut encoded = vec![0u8; entry.stored_len as usize];
        self.source.seek(SeekFrom::Start(entry.offset))?;
        self.source.read_exact(&mut encoded)?;
        let decoded = self
            .codec
            .decode_exact(&encoded, entry.clear_len as usize)?;
        let digest: [u8; 32] = Sha256::digest(&decoded).into();
        if digest != entry.clear_sha256 {
            return Err(invalid("archive chunk SHA-256 mismatch"));
        }
        Ok(decoded)
    }

    /// Return a verified logical range, never exposing partial bytes on error.
    /// Reading an already-opened archive never rewrites the original file.
    pub fn read_range(&mut self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        if length > MAX_READ_BYTES {
            return Err(bad_input("archive read exceeds 8 MiB per call"));
        }
        if offset > self.logical_size || length as u64 > self.logical_size - offset {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond archive EOF",
            ));
        }
        let mut result = vec![0u8; length];
        if length == 0 {
            return Ok(result);
        }
        let end = offset + length as u64;
        let mut current = offset;
        while current < end {
            let index = (current / self.chunk_size as u64) as usize;
            let chunk = self.decode_chunk(index)?;
            let chunk_start = (index as u64) * self.chunk_size as u64;
            let within = (current - chunk_start) as usize;
            let n = ((end - current) as usize).min(chunk.len() - within);
            let dst = (current - offset) as usize;
            result[dst..dst + n].copy_from_slice(&chunk[within..within + n]);
            current += n as u64;
        }
        Ok(result)
    }

    /// Copy only after every affected chunk was decoded and SHA-256 checked.
    /// On corruption or decode failure the caller's output remains unchanged.
    pub fn read_exact_at(&mut self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        let verified = self.read_range(offset, destination.len())?;
        destination.copy_from_slice(&verified);
        Ok(())
    }

    /// Validate every logical chunk plus the whole-file digest. This is the
    /// publication gate for a staged archive, independent of APFS allocation.
    pub fn verify_all(&mut self) -> io::Result<()> {
        let mut hash = Sha256::new();
        for index in 0..self.entries.len() {
            hash.update(self.decode_chunk(index)?);
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
    fn synthetic_header_is_readable_without_claiming_codec_support() {
        let reader = ArchiveReader::open(Cursor::new(fake_archive())).unwrap();
        assert_eq!(reader.codec(), Codec::Lzraven);
        assert_eq!(reader.logical_size(), 1);
        let expected: [u8; 32] = Sha256::digest(b"x").into();
        assert_eq!(reader.logical_sha256(), expected);
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
            archive.verify_all().unwrap();
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
            let mut sentinel = vec![0xa5u8; 100];
            let mut damaged = stored.clone();
            let first_payload = archive.entries[0].offset as usize;
            damaged[first_payload] ^= 0xff;
            let mut damaged_reader = ArchiveReader::open(Cursor::new(damaged)).unwrap();
            assert!(damaged_reader.read_exact_at(0, &mut sentinel).is_err());
            assert_eq!(sentinel, vec![0xa5u8; 100]);
            let mut bad_hash = stored;
            bad_hash[32] ^= 1;
            assert!(ArchiveReader::open(Cursor::new(bad_hash))
                .unwrap()
                .verify_all()
                .is_err());
        }
    }
}
