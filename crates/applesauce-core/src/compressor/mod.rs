#[cfg(all(target_os = "macos", feature = "lzbitmap"))]
use self::lzbitmap::Lzbitmap;
// Enable if feature lzfse or system-lzfse is enabled:
#[cfg(any(feature = "lzfse", feature = "system-lzfse"))]
use self::lzfse::Lzfse;
#[cfg(feature = "lzvn")]
use self::lzvn::Lzvn;
#[cfg(feature = "zlib")]
use self::zlib::Zlib;
use crate::decmpfs::BlockInfo;
use std::{fmt, io};

#[cfg(any(feature = "lzfse", feature = "lzvn"))]
mod lz;
#[cfg(any(
    feature = "lzfse",
    feature = "lzvn",
    all(target_os = "macos", feature = "lzbitmap")
))]
mod lz_table;
#[cfg(all(target_os = "macos", feature = "lzbitmap"))]
mod lzbitmap;
#[cfg(feature = "lzfse")]
mod lzfse;
#[cfg(feature = "lzvn")]
mod lzvn;
#[cfg(feature = "zlib")]
mod zlib;

/// Defensive ceiling for one native decmpfs encoded block. A logical block
/// expands to at most 64 KiB; allow 16x overhead for unusual but valid
/// encoders while rejecting attacker-controlled multi-megabyte blocks before
/// decoder work or resource-fork allocation. This is not an APFS codec ID.
pub(crate) const MAX_COMPRESSED_BLOCK_BYTES: usize = crate::BLOCK_SIZE * 16;

pub(crate) trait CompressorImpl {
    /// The offset to start data at, for the specified number of blocks
    #[must_use]
    fn header_size(block_count: u64) -> u64;

    #[must_use]
    fn trailer_size() -> u64 {
        0
    }

    fn compress(&mut self, dst: &mut [u8], src: &[u8], level: u32) -> io::Result<usize>;
    fn decompress(&mut self, dst: &mut [u8], src: &[u8]) -> io::Result<usize>;

    fn read_block_info<R: io::Read + io::Seek>(
        reader: R,
        orig_file_size: u64,
    ) -> io::Result<Vec<BlockInfo>>;

    fn finish<W: io::Write + io::Seek>(writer: W, block_sizes: &[u32]) -> io::Result<()>;
}

pub struct Compressor(Data);

impl Compressor {
    #[cfg(feature = "zlib")]
    #[must_use]
    pub fn zlib() -> Self {
        Self(Data::Zlib(Zlib::new()))
    }

    #[cfg(feature = "lzfse")]
    #[must_use]
    pub fn lzfse() -> Self {
        Self(Data::Lzfse(Lzfse::new()))
    }

    #[cfg(feature = "lzvn")]
    #[must_use]
    pub fn lzvn() -> Self {
        Self(Data::Lzvn(Lzvn::new()))
    }

    /// Construct the opt-in native LZBitmap compressor when this host supports it.
    ///
    /// This checks macOS availability and a cached buffer-codec round trip. It
    /// does not establish that an arbitrary target volume supports decmpfs.
    #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
    #[must_use]
    pub fn lzbitmap() -> Option<Self> {
        Lzbitmap::new().map(|compressor| Self(Data::Lzbitmap(compressor)))
    }

    #[must_use]
    pub fn kind(&self) -> Kind {
        match self.0 {
            #[cfg(feature = "zlib")]
            Data::Zlib(_) => Kind::Zlib,
            #[cfg(feature = "lzfse")]
            Data::Lzfse(_) => Kind::Lzfse,
            #[cfg(feature = "lzvn")]
            Data::Lzvn(_) => Kind::Lzvn,
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Data::Lzbitmap(_) => Kind::Lzbitmap,
        }
    }
}

enum Data {
    #[cfg(feature = "zlib")]
    Zlib(Zlib),
    #[cfg(feature = "lzfse")]
    Lzfse(Lzfse),
    #[cfg(feature = "lzvn")]
    Lzvn(Lzvn),
    #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
    Lzbitmap(Lzbitmap),
}

impl Compressor {
    #[must_use]
    pub fn blocks_start(&self, block_count: u64) -> u64 {
        self.kind().header_size(block_count)
    }

    pub fn compress(&mut self, dst: &mut [u8], src: &[u8], level: u32) -> io::Result<usize> {
        // A compressed block must contain logical data. Empty inputs can
        // produce marker-only stored blocks that the decoders rightly reject.
        // Fail before invoking any codec or modifying the caller's buffer.
        if src.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot compress an empty block",
            ));
        }
        // The native decmpfs framing describes independent 64 KiB logical
        // blocks. A larger input could produce a perfectly valid buffer-codec
        // stream that the filesystem reader cannot interpret as one block.
        // Larger buffer workloads belong in apple_buffer instead.
        if src.len() > crate::BLOCK_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native compressed block exceeds 64 KiB",
            ));
        }
        match self.0 {
            #[cfg(feature = "zlib")]
            Data::Zlib(ref mut i) => i.compress(dst, src, level),
            #[cfg(feature = "lzfse")]
            Data::Lzfse(ref mut i) => i.compress(dst, src, level),
            #[cfg(feature = "lzvn")]
            Data::Lzvn(ref mut i) => i.compress(dst, src, level),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Data::Lzbitmap(ref mut i) => i.compress(dst, src, level),
        }
    }

    pub fn decompress(&mut self, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        if src.len() > MAX_COMPRESSED_BLOCK_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native compressed block exceeds defensive size ceiling",
            ));
        }
        // Stored-marker blocks are copied directly into the caller's buffer
        // by their codec backends. Reject an overlong logical block before
        // that copy, so malformed input cannot modify output on this path.
        let stored_marker = match self.kind() {
            Kind::Zlib | Kind::Lzbitmap => Some(0xff),
            Kind::Lzvn => Some(0x06),
            Kind::Lzfse => None,
        };
        if src.len() > crate::BLOCK_SIZE + 1
            && stored_marker.is_some_and(|marker| src.first() == Some(&marker))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native stored block exceeds 64 KiB",
            ));
        }
        // A compressed payload can expand past a native 64 KiB logical
        // block before the post-decode size check runs. Bound the destination
        // handed to every codec so malformed data cannot overwrite the
        // caller's output beyond the logical block boundary.
        let bounded_len = dst.len().min(crate::BLOCK_SIZE);
        let bounded_dst = &mut dst[..bounded_len];
        let decoded_size = match self.0 {
            #[cfg(feature = "zlib")]
            Data::Zlib(ref mut i) => i.decompress(bounded_dst, src),
            #[cfg(feature = "lzfse")]
            Data::Lzfse(ref mut i) => i.decompress(bounded_dst, src),
            #[cfg(feature = "lzvn")]
            Data::Lzvn(ref mut i) => i.decompress(bounded_dst, src),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Data::Lzbitmap(ref mut i) => i.decompress(bounded_dst, src),
        }?;
        // Keep stored-marker fallbacks subject to the same 64 KiB logical
        // block limit as compressed output. A large caller-owned destination
        // must not turn malformed decmpfs data into an accepted block.
        if decoded_size > crate::BLOCK_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native decoded block exceeds 64 KiB",
            ));
        }
        Ok(decoded_size)
    }

    pub fn finish<W: io::Write + io::Seek>(
        &mut self,
        writer: W,
        block_sizes: &[u32],
    ) -> io::Result<()> {
        self.kind().finish(writer, block_sizes)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Zlib = 0,
    Lzvn,
    Lzfse,
    /// Native decmpfs types 13/14; enabling it requires the `lzbitmap` feature.
    Lzbitmap,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Kind {
    /// Every recognized codec, including codecs unavailable in this build.
    ///
    /// The order agrees with the discriminants used by compressor worker caches.
    pub const ALL: [Self; 4] = [Self::Zlib, Self::Lzvn, Self::Lzfse, Self::Lzbitmap];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Zlib => "ZLIB",
            Kind::Lzvn => "LZVN",
            Kind::Lzfse => "LZFSE",
            Kind::Lzbitmap => "LZBITMAP",
        }
    }

    #[must_use]
    #[inline]
    pub fn supported(self) -> bool {
        // Clippy falsely sees these arms as identical:
        //   https://github.com/rust-lang/rust-clippy/issues/9775
        #[allow(clippy::match_same_arms)]
        match self {
            Kind::Zlib => cfg!(feature = "zlib"),
            Kind::Lzvn => cfg!(feature = "lzvn"),
            Kind::Lzfse => cfg!(feature = "lzfse"),
            Kind::Lzbitmap => {
                #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
                {
                    Lzbitmap::supported()
                }
                #[cfg(not(all(target_os = "macos", feature = "lzbitmap")))]
                {
                    false
                }
            }
        }
    }

    #[must_use]
    pub fn compressor(self) -> Option<Compressor> {
        let data = match self {
            #[cfg(feature = "zlib")]
            Kind::Zlib => Data::Zlib(Zlib::new()),
            #[cfg(feature = "lzfse")]
            Kind::Lzfse => Data::Lzfse(Lzfse::new()),
            #[cfg(feature = "lzvn")]
            Kind::Lzvn => Data::Lzvn(Lzvn::new()),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Kind::Lzbitmap => Data::Lzbitmap(Lzbitmap::new()?),
            #[allow(unreachable_patterns)]
            _ => return None,
        };
        Some(Compressor(data))
    }

    #[must_use]
    pub fn header_size(self, block_count: u64) -> u64 {
        match self {
            #[cfg(feature = "zlib")]
            Kind::Zlib => Zlib::header_size(block_count),
            #[cfg(feature = "lzvn")]
            Kind::Lzvn => Lzvn::header_size(block_count),
            #[cfg(feature = "lzfse")]
            Kind::Lzfse => Lzfse::header_size(block_count),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Kind::Lzbitmap => Lzbitmap::header_size(block_count),
            #[allow(unreachable_patterns)]
            _ => panic!("Unsupported compression kind {self}"),
        }
    }

    /// Fixed footer bytes reserved for native resource-fork metadata.
    #[must_use]
    pub(crate) fn trailer_size(self) -> u64 {
        match self {
            #[cfg(feature = "zlib")]
            Kind::Zlib => Zlib::trailer_size(),
            #[cfg(feature = "lzvn")]
            Kind::Lzvn => Lzvn::trailer_size(),
            #[cfg(feature = "lzfse")]
            Kind::Lzfse => Lzfse::trailer_size(),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Kind::Lzbitmap => Lzbitmap::trailer_size(),
            #[allow(unreachable_patterns)]
            _ => panic!("Unsupported compression kind {self}"),
        }
    }

    pub fn read_block_info<R: io::Read + io::Seek>(
        self,
        reader: R,
        orig_file_size: u64,
    ) -> io::Result<Vec<BlockInfo>> {
        match self {
            #[cfg(feature = "zlib")]
            Kind::Zlib => Zlib::read_block_info(reader, orig_file_size),
            #[cfg(feature = "lzvn")]
            Kind::Lzvn => Lzvn::read_block_info(reader, orig_file_size),
            #[cfg(feature = "lzfse")]
            Kind::Lzfse => Lzfse::read_block_info(reader, orig_file_size),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Kind::Lzbitmap => Lzbitmap::read_block_info(reader, orig_file_size),
            #[allow(unreachable_patterns)]
            _ => panic!("Unsupported compression kind {self}"),
        }
    }

    pub fn finish<W: io::Write + io::Seek>(self, writer: W, block_sizes: &[u32]) -> io::Result<()> {
        match self {
            #[cfg(feature = "zlib")]
            Kind::Zlib => Zlib::finish(writer, block_sizes),
            #[cfg(feature = "lzvn")]
            Kind::Lzvn => Lzvn::finish(writer, block_sizes),
            #[cfg(feature = "lzfse")]
            Kind::Lzfse => Lzfse::finish(writer, block_sizes),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Kind::Lzbitmap => Lzbitmap::finish(writer, block_sizes),
            #[allow(unreachable_patterns)]
            _ => panic!("Unsupported compression kind {self}"),
        }
    }
}

impl Default for Kind {
    #[inline]
    fn default() -> Self {
        if Self::Lzfse.supported() {
            Self::Lzfse
        } else if Self::Zlib.supported() {
            Self::Zlib
        } else {
            Self::Lzvn
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &[u8] = include_bytes!("mod.rs");

    #[test]
    fn recognized_kinds_have_dense_cache_indices() {
        for (index, kind) in Kind::ALL.into_iter().enumerate() {
            assert_eq!(kind as usize, index);
        }
    }

    #[test]
    fn insufficient_encode_capacity_fails_without_mutation() {
        let input = [0xa5; 32];
        for kind in Kind::ALL {
            let Some(mut compressor) = kind.compressor() else {
                continue;
            };
            for capacity in [0, 1, input.len()] {
                let mut output = vec![0x5a; capacity];
                let error = compressor.compress(&mut output, &input, 5).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::WriteZero, "{kind}");
                assert!(output.iter().all(|&byte| byte == 0x5a), "{kind}");
            }
        }
    }

    #[test]
    fn empty_compressor_input_is_rejected_without_modifying_destination() {
        for kind in Kind::ALL {
            let Some(mut compressor) = kind.compressor() else {
                continue;
            };
            for capacity in [0, 1, 16] {
                let mut output = vec![0xa5; capacity];
                let error = compressor.compress(&mut output, &[], 5).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{kind}");
                assert!(output.iter().all(|&byte| byte == 0xa5), "{kind}");
            }
        }
    }

    #[test]
    fn native_compression_rejects_overlong_input_before_touching_destination() {
        let oversized = vec![0x5a; crate::BLOCK_SIZE + 1];
        for kind in Kind::ALL {
            let Some(mut compressor) = kind.compressor() else {
                continue;
            };
            let mut output = vec![0xa5; oversized.len() + 1024];
            let error = compressor.compress(&mut output, &oversized, 5).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{kind}");
            assert!(output.iter().all(|&byte| byte == 0xa5), "{kind}");
        }
    }

    #[test]
    fn oversized_native_payload_is_rejected_before_decoder_touches_output() {
        let oversized = vec![0xff; MAX_COMPRESSED_BLOCK_BYTES + 1];
        for kind in Kind::ALL {
            let Some(mut compressor) = kind.compressor() else {
                continue;
            };
            let mut output = [0xa5; 64];
            let error = compressor.decompress(&mut output, &oversized).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{kind}");
            assert_eq!(output, [0xa5; 64], "{kind}");
        }
    }

    #[test]
    fn stored_blocks_cannot_decode_beyond_the_native_block_boundary() {
        // ZLIB, LZVN and opt-in LZBitmap support raw-block markers. Their
        // decoders accept any destination that fits the declared raw bytes;
        // the public native compressor must still enforce decmpfs's limit.
        for (kind, marker) in [
            (Kind::Zlib, 0xff),
            (Kind::Lzvn, 0x06),
            (Kind::Lzbitmap, 0xff),
        ] {
            let Some(mut compressor) = kind.compressor() else {
                continue;
            };
            let mut stored = vec![marker];
            stored.resize(crate::BLOCK_SIZE + 1, 0x42);
            let mut output = vec![0; crate::BLOCK_SIZE + 1024];
            let size = compressor.decompress(&mut output, &stored).unwrap();
            assert_eq!(size, crate::BLOCK_SIZE, "{kind}");
            assert_eq!(&output[..size], &stored[1..], "{kind}");

            stored.push(0x42);
            output.fill(0xa5);
            let error = compressor.decompress(&mut output, &stored).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{kind}");
            assert!(
                output.iter().all(|&byte| byte == 0xa5),
                "{kind} modified output for an oversized stored block"
            );
        }
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn full_native_zlib_block_round_trips_without_touching_destination_tail() {
        // A complete 64 KiB compressed logical block must still decode
        // exactly, even when the caller supplies a larger output buffer.
        let payload = vec![0x42; crate::BLOCK_SIZE];
        let mut encoded = vec![0; payload.len() + 1024];
        let used = Zlib::new().compress(&mut encoded, &payload, 5).unwrap();
        encoded.truncate(used);
        assert_ne!(encoded[0], 0xff, "fixture must use compressed framing");

        let mut output = vec![0xa5; crate::BLOCK_SIZE + 128];
        let size = Compressor::zlib()
            .decompress(&mut output, &encoded)
            .unwrap();
        assert_eq!(size, crate::BLOCK_SIZE);
        assert_eq!(&output[..size], payload.as_slice());
        assert!(output[crate::BLOCK_SIZE..].iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn full_native_lz_blocks_round_trip_without_touching_destination_tail() {
        // Full LZVN/LZFSE/LZBitmap blocks require an overflow guard to
        // distinguish an exact 64 KiB decode from a truncated stream.
        for kind in [Kind::Lzvn, Kind::Lzfse, Kind::Lzbitmap] {
            let Some(mut compressor) = kind.compressor() else {
                continue;
            };
            let payload = vec![0x42; crate::BLOCK_SIZE];
            let mut encoded = vec![0; payload.len() + 1024];
            let used = compressor.compress(&mut encoded, &payload, 5).unwrap();
            encoded.truncate(used);
            if kind == Kind::Lzvn {
                assert_ne!(encoded[0], 0x06, "LZVN fixture must be compressed");
            }
            if kind == Kind::Lzbitmap {
                assert_ne!(encoded[0], 0xff, "LZBitmap fixture must be compressed");
            }

            let mut output = vec![0xa5; crate::BLOCK_SIZE + 128];
            let size = compressor.decompress(&mut output, &encoded).unwrap();
            assert_eq!(size, crate::BLOCK_SIZE, "{kind}");
            assert_eq!(&output[..size], payload.as_slice(), "{kind}");
            assert!(
                output[crate::BLOCK_SIZE..].iter().all(|&byte| byte == 0xa5),
                "{kind} modified destination tail"
            );
        }
    }

    #[cfg(feature = "lzvn")]
    #[test]
    fn overlong_compressed_lzvn_block_fails_without_modifying_caller_output() {
        // The low-level codec can encode 64 KiB + 1 bytes, but a native
        // decmpfs block must reject it without leaking the overflow byte.
        let payload = vec![0x42; crate::BLOCK_SIZE + 1];
        let mut encoded = vec![0; payload.len() + 1024];
        let used = Lzvn::new().compress(&mut encoded, &payload, 0).unwrap();
        encoded.truncate(used);
        assert_ne!(encoded[0], 0x06, "fixture must use compressed framing");

        let mut output = vec![0xa5; crate::BLOCK_SIZE + 128];
        let error = Compressor::lzvn()
            .decompress(&mut output, &encoded)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert!(output.iter().all(|&byte| byte == 0xa5));
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn overlong_compressed_block_cannot_overwrite_past_native_boundary() {
        // Exercise a real compressed (not stored-marker) stream. The lower
        // level codec can encode more than one filesystem logical block; the
        // native wrapper must refuse it without writing past 64 KiB.
        let payload = vec![0x42; crate::BLOCK_SIZE + 1];
        let mut encoded = vec![0; payload.len() + 1024];
        let used = Zlib::new().compress(&mut encoded, &payload, 5).unwrap();
        encoded.truncate(used);
        assert_ne!(encoded[0], 0xff, "fixture must use compressed framing");

        let mut output = vec![0xa5; crate::BLOCK_SIZE + 128];
        let error = Compressor::zlib()
            .decompress(&mut output, &encoded)
            .unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::Other | io::ErrorKind::InvalidData
            ),
            "unexpected decompression error: {error}"
        );
        assert!(
            output[crate::BLOCK_SIZE..].iter().all(|&byte| byte == 0xa5),
            "overlong compressed stream modified bytes past the native block boundary"
        );
    }

    #[cfg(not(all(target_os = "macos", feature = "lzbitmap")))]
    #[test]
    fn lzbitmap_is_unavailable_without_native_opt_in() {
        assert!(!Kind::Lzbitmap.supported());
        assert!(Kind::Lzbitmap.compressor().is_none());
    }

    pub(super) fn compressor_round_trip<C: CompressorImpl>(c: &mut C) {
        let mut buf = vec![0u8; PLAINTEXT.len() * 2];
        let len = c.compress(&mut buf, PLAINTEXT, 6).unwrap();
        assert!(len > 0);
        assert!(len < buf.len());
        let ciphertext = &buf[..len];
        let mut buf = vec![0u8; PLAINTEXT.len() + 1];
        let len = c.decompress(&mut buf, ciphertext).unwrap();
        assert_eq!(&buf[..len], PLAINTEXT);
    }
}
