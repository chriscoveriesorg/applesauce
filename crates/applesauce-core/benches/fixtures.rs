//! Versioned, deterministic, synthetic compression inputs.
//! Shared verbatim with `tests/benchmark_fixtures.rs`; never reads user data.

pub const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workload {
    ChatJsonl,
    MixedJsonl,
    BinaryRecords,
    Entropy,
    Zeros,
}

impl Workload {
    pub const ALL: [Self; 5] = [
        Self::ChatJsonl,
        Self::MixedJsonl,
        Self::BinaryRecords,
        Self::Entropy,
        Self::Zeros,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::ChatJsonl => "chat-jsonl",
            Self::MixedJsonl => "mixed-jsonl",
            Self::BinaryRecords => "binary-records",
            Self::Entropy => "entropy",
            Self::Zeros => "zeros",
        }
    }
}

#[derive(Clone, Copy)]
struct Xorshift64(u64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

fn repeat_lines(size: usize, mut line: impl FnMut(usize) -> String) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    let mut counter = 0;
    while bytes.len() < size {
        let next = line(counter);
        bytes.extend_from_slice(next.as_bytes());
        counter += 1;
    }
    // The final record can be truncated to make sizes exactly comparable.
    bytes.truncate(size);
    bytes
}

#[must_use]
pub fn generate(workload: Workload, size: usize) -> Vec<u8> {
    assert!(size > 0 && size <= 8 * 1024 * 1024, "benchmark size bound");
    let mut rng = Xorshift64(0x9172_74df_5ac8_29a1);
    match workload {
        Workload::ChatJsonl => repeat_lines(size, |counter| {
            format!(
                "{{\"session\":\"s{:03}\",\"role\":\"assistant\",\"content\":\"The build passed; collect the next chunk and keep the conversation searchable.\",\"turn\":{}}}\n",
                counter % 13,
                counter % 97
            )
        }),
        Workload::MixedJsonl => repeat_lines(size, |counter| {
            format!(
                "{{\"time\":\"2026-11-01T09:{:02}:00Z\",\"event_id\":\"{:016x}{:016x}\",\"kind\":\"{}\",\"message\":\"{}\"}}\n",
                counter % 60,
                rng.next(),
                rng.next(),
                if counter.is_multiple_of(5) { "tool" } else { "message" },
                if counter.is_multiple_of(3) {
                    "Search index updated; validate span offsets"
                } else {
                    "Cache received a new session record"
                }
            )
        }),
        Workload::BinaryRecords => {
            let mut data = vec![0; size];
            for (counter, chunk) in data.chunks_mut(512).enumerate() {
                // Fixed headers, repeated bodies, and intermittently random
                // records mimic structured binary files with noisy fields.
                for (position, byte) in chunk.iter_mut().enumerate() {
                    *byte = ((position % 31) as u8).wrapping_mul(7);
                }
                let id = (counter % 16).to_le_bytes();
                let header_len = id.len().min(chunk.len());
                chunk[..header_len].copy_from_slice(&id[..header_len]);
                if counter.is_multiple_of(4) && chunk.len() > 32 {
                    rng.fill(&mut chunk[32..]);
                }
            }
            data
        }
        Workload::Entropy => {
            let mut bytes = vec![0; size];
            rng.fill(&mut bytes);
            bytes
        }
        Workload::Zeros => vec![0; size],
    }
}

#[cfg(test)]
mod tests {
    // Criterion benches use harness = false: when clippy checks all targets,
    // #[test] functions can be omitted while this import remains compiled.
    // The same fixture tests also run through the normal integration harness.
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn deterministic_distinct_exact_size() {
        for size in [4096, 65536, 1_048_576, 8_388_608] {
            let samples: Vec<_> = Workload::ALL
                .into_iter()
                .map(|profile| {
                    assert!(!profile.name().is_empty());
                    let a = generate(profile, size);
                    assert_eq!(a.len(), size);
                    assert_eq!(a, generate(profile, size));
                    a
                })
                .collect();
            for (i, a) in samples.iter().enumerate() {
                for b in samples.iter().skip(i + 1) {
                    assert_ne!(a, b, "benchmark workloads must not alias");
                }
            }
        }
        assert_eq!(VERSION, 1);
    }

    #[test]
    fn entropy_is_not_all_repeated_and_zeros_are() {
        let noise = generate(Workload::Entropy, 65536);
        let unique_bytes: std::collections::HashSet<_> = noise.iter().collect();
        assert_eq!(unique_bytes.len(), 256);
        assert!(generate(Workload::Zeros, 65536).iter().all(|b| *b == 0));
        assert!(generate(Workload::ChatJsonl, 4096).starts_with(b"{\"session\":"));
    }

    #[test]
    fn golden_fixture_digests() {
        use sha2::{Digest, Sha256};
        let expected = [
            "f7aa044146c520080ec1e9c4887df117089ba2fc2c2a3a980421360d9e3176d3",
            "0ed513f185de6f4d93c7afcccdbfd608cb4c14a3fea57751e9678e47cdb44fb5",
            "eb26bf0865f4cbf53283485b94323cc0c435ccb14709fcc9a584349d52bba4bb",
            "cd42c3209f13fef9f77f3390859af4198ee7a6c81383ec02638adfff0267f9b2",
            "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31",
        ];
        for (workload, expected_digest) in Workload::ALL.into_iter().zip(expected) {
            let digest = Sha256::digest(generate(workload, 65_536));
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(
                hex,
                expected_digest,
                "{} fixture changed without a version bump",
                workload.name()
            );
        }
    }
}
