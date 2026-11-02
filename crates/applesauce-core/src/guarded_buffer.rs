//! Allocation-free exact-length decoding of Apple Compression buffer blocks.
//!
//! Apple's buffer decoder may report a full destination when a compressed
//! stream actually expands beyond it. A caller must provide one spare byte
//! beyond the known plaintext length to distinguish success from truncation.
//! These methods neither write files nor grant native APFS compression support.

use crate::apple_buffer::{Codec, Scratch, MAX_BUFFER_BYTES};
use crate::BLOCK_SIZE;
use std::io;

/// Derive a trusted plaintext length from a writable output including its guard.
fn checked_expected_size(guarded_len: usize) -> io::Result<usize> {
    let expected = guarded_len.checked_sub(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing one-byte decode guard")
    })?;
    if expected == 0 || expected > MAX_BUFFER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guarded plaintext must be between 1 byte and 64 MiB",
        ));
    }
    Ok(expected)
}

fn decode_guarded(
    guarded_dst: &mut [u8],
    encoded: &[u8],
    mut decode: impl FnMut(&mut [u8], &[u8]) -> io::Result<usize>,
) -> io::Result<usize> {
    let expected = checked_expected_size(guarded_dst.len())?;
    if encoded.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty compressed input"));
    }
    // Match the allocating helper's defensive encoded-input ceiling. This is
    // a local buffer-format bound, not a general-purpose archive size limit.
    if encoded.len() > expected * 2 + BLOCK_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed buffer exceeds defensive size ceiling",
        ));
    }
    let count = decode(guarded_dst, encoded)?;
    if count != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decoded size {count} does not match expected size {expected}"),
        ));
    }
    Ok(count)
}

impl Codec {
    /// Decode into caller-owned storage and verify its exact logical length.
    ///
    /// Pass exactly `expected_plaintext_bytes + 1` writable bytes. Apple's
    /// decoder can otherwise report a truncated result as successful when
    /// the output fills the destination. The extra byte is an overflow guard.
    ///
    /// On success, only the returned number of bytes are plaintext. On error,
    /// the destination may have been modified and must be discarded.
    /// No allocation is performed by this wrapper; the Apple API may still
    /// allocate internal scratch storage.
    pub fn decode_exact_into(self, guarded_dst: &mut [u8], encoded: &[u8]) -> io::Result<usize> {
        decode_guarded(guarded_dst, encoded, |dst, src| self.decode_into(dst, src))
    }
}

impl Scratch {
    /// Exact-length decoding with a one-byte output guard and reusable scratch.
    ///
    /// The caller controls both the output allocation and the scratch lifetime.
    /// This is intended for repeatedly decoding independent, externally framed
    /// blocks while preserving each block's logical byte count.
    pub fn decode_exact_into(
        &mut self,
        guarded_dst: &mut [u8],
        encoded: &[u8],
    ) -> io::Result<usize> {
        decode_guarded(guarded_dst, encoded, |dst, src| self.decode_into(dst, src))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_size_guard_bounds_and_malformed_lengths() {
        for invalid in [0, 1, MAX_BUFFER_BYTES + 2, usize::MAX] {
            assert_eq!(
                checked_expected_size(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for expected in [
            1,
            4095,
            4096,
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            MAX_BUFFER_BYTES,
        ] {
            assert_eq!(checked_expected_size(expected + 1).unwrap(), expected);
        }
        let mut dest = [0x55; 2];
        let mut called = false;
        let err = decode_guarded(&mut dest, &[], |_, _| {
            called = true;
            Ok(1)
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!called);
        assert_eq!(dest, [0x55; 2]);
        let big = vec![0x01; 2 + BLOCK_SIZE + 1];
        let err = decode_guarded(&mut dest, &big, |_, _| {
            called = true;
            Ok(1)
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!called);
        assert_eq!(dest, [0x55; 2]);
    }

    #[test]
    fn decoder_full_destination_is_not_accepted_as_exact_output() {
        for returned in [1, 3] {
            let mut dest = [0; 3]; // expected plaintext is two bytes
            assert_eq!(
                decode_guarded(&mut dest, &[0x01], |_, _| Ok(returned))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut dest = [0; 3];
        assert_eq!(
            decode_guarded(&mut dest, &[0x01], |_, _| Ok(2)).unwrap(),
            2
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn all_available_codecs_guard_reused_output_at_64k_boundaries() {
        let sizes = [
            1,
            63,
            4096,
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            2 * BLOCK_SIZE + 1,
        ];
        for codec in Codec::ALL.into_iter().filter(|codec| codec.is_supported()) {
            let mut scratch = codec.reusable_scratch().unwrap();
            let mut dest = vec![0x55; 2 * BLOCK_SIZE + 3];
            for size in sizes {
                let plain: Vec<u8> = (0..size)
                    .map(|i| ((i as u64 * 73 + ((i as u64 >> 7) * 19)) & 255) as u8)
                    .collect();
                let encoded = codec.encode(&plain).unwrap();
                let exact = &mut dest[..size + 1];
                assert_eq!(codec.decode_exact_into(exact, &encoded).unwrap(), size);
                assert_eq!(&exact[..size], plain.as_slice(), "{codec:?} {size}");
                exact.fill(0x55);
                assert_eq!(scratch.decode_exact_into(exact, &encoded).unwrap(), size);
                assert_eq!(&exact[..size], plain.as_slice(), "{codec:?} {size}");
                if size > 1 {
                    assert!(codec.decode_exact_into(&mut dest[..size], &encoded).is_err());
                    assert!(scratch
                        .decode_exact_into(&mut dest[..size], &encoded)
                        .is_err());
                }
                assert!(codec
                    .decode_exact_into(&mut dest[..size + 2], &encoded)
                    .is_err());
                assert!(scratch
                    .decode_exact_into(&mut dest[..size + 2], &encoded)
                    .is_err());
            }
        }
    }
}
