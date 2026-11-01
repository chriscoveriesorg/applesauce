//! Apple's public, in-memory Compression API.
//!
//! This is deliberately separate from [`crate::compressor::Kind`]. A buffer
//! codec identifier is NOT a `decmpfs` type, and a successful buffer round trip
//! does not mean the kernel can transparently read files using that codec.
//! No function in this module changes files, attributes or filesystem flags.

use std::fmt;
use std::io;

/// Bound for the allocating helpers. The slice-based API does not allocate
/// input/output buffers on the caller's behalf.
pub const MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// Public Compression API selectors from Apple's `compression.h`.
///
/// LZBITMAP, LZMESH and LZRAVEN support the buffer API, not the stream API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Codec {
    Zlib = 0x205,
    Lzfse = 0x801,
    Lzbitmap = 0x702,
    Lzmesh = 0xE05,
    Lzraven = 0xD05,
}

impl Codec {
    pub const ALL: [Self; 5] = [
        Self::Zlib,
        Self::Lzfse,
        Self::Lzbitmap,
        Self::Lzmesh,
        Self::Lzraven,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Lzfse => "lzfse",
            Self::Lzbitmap => "lzbitmap",
            Self::Lzmesh => "lzmesh",
            Self::Lzraven => "lzraven",
        }
    }

    #[must_use]
    pub const fn minimum_macos(self) -> (u32, u32) {
        match self {
            Self::Zlib | Self::Lzfse => (10, 11),
            Self::Lzbitmap => (12, 0),
            Self::Lzmesh | Self::Lzraven => (27, 0),
        }
    }

    /// Whether this OS advertises the API version needed by this codec.
    /// Use [`Self::verify_roundtrip`] to check the actual implementation too.
    #[must_use]
    pub fn is_supported(self) -> bool {
        macos_version().is_some_and(|version| self.supported_on(version))
    }

    fn supported_on(self, version: MacOsVersion) -> bool {
        (version.major, version.minor) >= self.minimum_macos()
    }

    fn ensure_supported(self) -> io::Result<()> {
        if self.is_supported() {
            Ok(())
        } else {
            let (major, minor) = self.minimum_macos();
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{} buffer API requires macOS {major}.{minor} or newer; host version is {}",
                    self.name(),
                    macos_version().map_or_else(
                        || "unavailable (or not macOS)".to_owned(),
                        |v| v.to_string()
                    )
                ),
            ))
        }
    }

    /// Encode into caller-owned storage. `WriteZero` means the bounded output
    /// did not fit OR the encoder failed. It does not prove an unknown codec.
    pub fn encode_into(self, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        self.ensure_supported()?;
        if src.is_empty() || dst.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty buffer"));
        }
        platform::encode(self, dst, src)
    }

    /// Decode into caller-owned storage.
    ///
    /// IMPORTANT: Apple's API returns `dst.len()` on truncated output too. A
    /// full destination is not proof of success. Prefer [`Self::decode_exact`]
    /// when the expected size is known; it reserves a one-byte overflow guard.
    pub fn decode_into(self, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        self.ensure_supported()?;
        if src.is_empty() || dst.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty buffer"));
        }
        platform::decode(self, dst, src)
    }

    /// Allocate a bounded output buffer and encode a nonempty input of at most
    /// 64 MiB. The capacity is a policy limit, not a promised codec size bound.
    pub fn encode(self, src: &[u8]) -> io::Result<Vec<u8>> {
        let capacity = encoded_capacity(src.len())?;
        self.ensure_supported()?;
        let mut encoded = allocate(capacity)?;
        let count = self.encode_into(&mut encoded, src)?;
        encoded.truncate(count);
        Ok(encoded)
    }

    /// Decode with an exact expected size and reject partial/overlong output.
    /// A successful decode is not a content checksum; compare bytes or a hash
    /// separately when validating a round trip.
    pub fn decode_exact(self, src: &[u8], expected_size: usize) -> io::Result<Vec<u8>> {
        validate_size(expected_size)?;
        self.ensure_supported()?;
        let mut decoded = allocate(expected_size + 1)?;
        let count = self.decode_into(&mut decoded, src)?;
        if count != expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded size {count} does not match expected size {expected_size}"),
            ));
        }
        decoded.truncate(count);
        Ok(decoded)
    }

    /// Small positive control using generated data, never a user's files.
    /// Scratch-size zero is legal and is intentionally not used as a probe.
    pub fn verify_roundtrip(self) -> io::Result<()> {
        let input =
            b"{\"role\":\"assistant\",\"message\":\"applesauce buffer self-test\"}\n".repeat(256);
        let encoded = self.encode(&input)?;
        let decoded = self.decode_exact(&encoded, input.len())?;
        if decoded != input {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer round-trip mismatch",
            ));
        }
        Ok(())
    }
}

fn validate_size(size: usize) -> io::Result<()> {
    if size == 0 || size > MAX_BUFFER_BYTES {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "buffer size must be 1 byte through 64 MiB",
        ))
    } else {
        Ok(())
    }
}

fn encoded_capacity(size: usize) -> io::Result<usize> {
    validate_size(size)?;
    Ok(size * 2 + 64 * 1024)
}

fn allocate(size: usize) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(size).map_err(io::Error::other)?;
    buffer.resize(size, 0);
    Ok(buffer)
}

/// Product version from the kernel, unaffected by SYSTEM_VERSION_COMPAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacOsVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl MacOsVersion {
    fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().map_or(Some(0), |v| v.parse().ok())?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for MacOsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[must_use]
pub fn macos_version() -> Option<MacOsVersion> {
    static VERSION: std::sync::OnceLock<Option<MacOsVersion>> = std::sync::OnceLock::new();
    *VERSION
        .get_or_init(|| MacOsVersion::parse(&platform::sysctl_string(c"kern.osproductversion")?))
}

#[must_use]
pub fn macos_build() -> Option<String> {
    platform::sysctl_string(c"kern.osversion")
}

#[cfg(target_os = "macos")]
mod platform {
    use super::Codec;
    use std::ffi::{c_void, CStr};
    use std::{io, ptr};

    #[link(name = "compression")]
    unsafe extern "C" {
        fn compression_encode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut c_void,
            algorithm: u32,
        ) -> usize;
        fn compression_decode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut c_void,
            algorithm: u32,
        ) -> usize;
    }

    pub(super) fn encode(codec: Codec, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        // SAFETY: nonoverlapping borrowed slices have the supplied lengths.
        // The caller checked OS availability. NULL requests API-owned scratch.
        let count = unsafe {
            compression_encode_buffer(
                dst.as_mut_ptr(),
                dst.len(),
                src.as_ptr(),
                src.len(),
                ptr::null_mut(),
                codec as u32,
            )
        };
        if count == 0 {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Apple buffer encoder failed or output capacity was insufficient",
            ))
        } else if count > dst.len() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid encoded size",
            ))
        } else {
            Ok(count)
        }
    }

    pub(super) fn decode(codec: Codec, dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
        // SAFETY: nonoverlapping borrowed slices have the supplied lengths.
        // The caller checked OS availability. NULL requests API-owned scratch.
        let count = unsafe {
            compression_decode_buffer(
                dst.as_mut_ptr(),
                dst.len(),
                src.as_ptr(),
                src.len(),
                ptr::null_mut(),
                codec as u32,
            )
        };
        if count == 0 || count > dst.len() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Apple buffer decoder failed",
            ))
        } else {
            Ok(count)
        }
    }

    pub(super) fn sysctl_string(name: &CStr) -> Option<String> {
        let mut bytes = [0u8; 128];
        let mut length = bytes.len();
        // SAFETY: name is NUL-terminated, bytes is writable for length bytes,
        // and no new value is supplied, so this is a read-only sysctl query.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                ptr::null_mut(),
                0,
            )
        };
        if result != 0 || length > bytes.len() {
            return None;
        }
        Some(
            CStr::from_bytes_until_nul(&bytes[..length])
                .ok()?
                .to_str()
                .ok()?
                .to_owned(),
        )
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::Codec;
    use std::ffi::CStr;
    use std::io;

    pub(super) fn encode(_: Codec, _: &mut [u8], _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
    pub(super) fn decode(_: Codec, _: &mut [u8], _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
    pub(super) fn sysctl_string(_: &CStr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_selectors_are_not_decmpfs_types() {
        assert_eq!(Codec::Lzbitmap as u32, 0x702);
        assert_eq!(Codec::Lzraven as u32, 0xD05);
        assert_eq!(Codec::Lzmesh as u32, 0xE05);
        for codec in Codec::ALL {
            assert!(crate::decmpfs::CompressionType::from_raw_type(codec as u32)
                .compression_storage()
                .is_none());
        }
    }

    #[test]
    fn version_boundaries_do_not_require_27_2_for_buffers() {
        let before = MacOsVersion::parse("26.9.9").unwrap();
        for name in ["27.0", "27.0.1", "27.2", "28.0"] {
            for codec in [Codec::Lzraven, Codec::Lzmesh] {
                assert!(!codec.supported_on(before));
                assert!(codec.supported_on(MacOsVersion::parse(name).unwrap()));
            }
        }
        assert!(!Codec::Lzbitmap.supported_on(MacOsVersion::parse("11.7.10").unwrap()));
        assert!(Codec::Lzbitmap.supported_on(MacOsVersion::parse("12.0").unwrap()));
        for invalid in ["", "27", "27.x", "27.0.x", "27.0.1.2", "garbage"] {
            assert!(MacOsVersion::parse(invalid).is_none());
        }
    }

    #[test]
    fn allocations_are_bounded() {
        assert!(encoded_capacity(0).is_err());
        assert!(encoded_capacity(MAX_BUFFER_BYTES + 1).is_err());
        assert!(encoded_capacity(usize::MAX).is_err());
        assert_eq!(
            encoded_capacity(MAX_BUFFER_BYTES).unwrap(),
            2 * MAX_BUFFER_BYTES + 65536
        );
        assert!(Codec::Lzraven.decode_exact(&[1], usize::MAX).is_err());
    }

    #[test]
    fn unavailable_codecs_fail_closed() {
        for codec in Codec::ALL {
            if !codec.is_supported() {
                assert_eq!(
                    codec.verify_roundtrip().unwrap_err().kind(),
                    io::ErrorKind::Unsupported
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn available_codecs_roundtrip_and_reject_truncation() {
        let repeated = b"{\"session\":42,\"message\":\"generated codec test\"}\n".repeat(2048);
        let mut state = 0x69a5_6be3_d12f_7031u64;
        let noise: Vec<u8> = (0..131_071)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        for codec in Codec::ALL.into_iter().filter(|codec| codec.is_supported()) {
            codec.verify_roundtrip().unwrap();
            for source in [&repeated[..], &noise[..], &[42][..]] {
                let encoded = codec.encode(source).unwrap();
                assert_eq!(codec.decode_exact(&encoded, source.len()).unwrap(), source);
                if source.len() > 1 {
                    assert!(codec.decode_exact(&encoded, source.len() - 1).is_err());
                }
                assert!(codec.decode_exact(&encoded, source.len() + 1).is_err());
            }
        }
    }
}
