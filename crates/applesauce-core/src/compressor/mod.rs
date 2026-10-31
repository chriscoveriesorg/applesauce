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
        match self.0 {
            #[cfg(feature = "zlib")]
            Data::Zlib(ref mut i) => i.decompress(dst, src),
            #[cfg(feature = "lzfse")]
            Data::Lzfse(ref mut i) => i.decompress(dst, src),
            #[cfg(feature = "lzvn")]
            Data::Lzvn(ref mut i) => i.decompress(dst, src),
            #[cfg(all(target_os = "macos", feature = "lzbitmap"))]
            Data::Lzbitmap(ref mut i) => i.decompress(dst, src),
        }
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
