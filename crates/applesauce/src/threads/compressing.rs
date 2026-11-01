use crate::seq_queue;
use crate::threads::{writer, BgWork, Context, Mode, WorkHandler};
use applesauce_core::compressor::{self, Compressor};
use applesauce_core::BLOCK_SIZE;
use std::io;
use std::sync::Arc;

pub(super) type Sender = crossbeam_channel::Sender<WorkItem>;

pub(super) struct WorkItem {
    pub context: Arc<Context>,
    pub data: Vec<u8>,
    pub kind: compressor::Kind,
    /// Expected logical bytes for a manually decoded decmpfs block.
    /// Compression jobs have no decoded-size expectation.
    pub expected_decoded_size: Option<usize>,
    pub slot: seq_queue::Slot<writer::Chunk, io::Error>,
}

pub(super) struct Work;

impl BgWork for Work {
    type Item = WorkItem;
    type Handler = Handler;
    const NAME: &'static str = "compressor";

    fn make_handler(&self) -> Self::Handler {
        Handler {
            compressors: compressor::Kind::ALL.iter().map(|_| None).collect(),
            buf: vec![0; BLOCK_SIZE + 1024],
        }
    }

    fn queue_capacity(&self) -> usize {
        8
    }
}

pub(super) struct Handler {
    compressors: Vec<Option<Compressor>>,
    buf: Vec<u8>,
}

fn validate_decoded_block_size(actual: usize, expected: Option<usize>) -> io::Result<()> {
    if expected.is_some_and(|expected| actual != expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decoded block length does not match decmpfs metadata",
        ));
    }
    Ok(())
}

impl WorkHandler<WorkItem> for Handler {
    fn handle_item(&mut self, item: WorkItem) {
        let _entered =
            tracing::debug_span!("compressing block", path=%item.context.path.display()).entered();

        let cached = &mut self.compressors[item.kind as usize];
        if cached.is_none() {
            *cached = item.kind.compressor();
        }
        let Some(compressor) = cached.as_mut() else {
            item.slot.error(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{} is unavailable in this build or on this host", item.kind),
            ));
            return;
        };
        let size = match item.context.operation.mode {
            Mode::Compress { kind, level, .. } => {
                debug_assert_eq!(kind, item.kind);
                compressor.compress(&mut self.buf, &item.data, level)
            }
            Mode::DecompressManually => compressor.decompress(&mut self.buf, &item.data),
            Mode::DecompressByReading => {
                panic!("decompressing by reading should not be using the compressor thread")
            }
        };
        let size = match size {
            Ok(size) => size,
            Err(e) => {
                item.slot.error(e);
                return;
            }
        };
        if let Err(error) = validate_decoded_block_size(size, item.expected_decoded_size) {
            item.slot.error(error);
            return;
        }
        debug_assert!(size != 0);

        let chunk = writer::Chunk {
            block: self.buf[..size].to_vec(),
            orig_size: item.data.len().try_into().unwrap(),
        };
        if item.slot.finish(chunk).is_err() {
            // This should only be because of a failure already reported by the writer
            tracing::debug!("unable to finish slot");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_decoded_block_size;
    use std::io;

    #[test]
    fn manual_decode_requires_exact_size_of_every_block() {
        for expected in [1, 4096, 65536] {
            assert!(validate_decoded_block_size(expected, Some(expected)).is_ok());
            for actual in [0, expected - 1, expected + 1] {
                assert_eq!(
                    validate_decoded_block_size(actual, Some(expected))
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
        // Compression jobs are not manual decompression jobs.
        assert!(validate_decoded_block_size(3, None).is_ok());
    }

    #[test]
    fn generated_codec_blocks_round_trip_with_exact_logical_lengths() {
        use applesauce_core::compressor::Kind;
        use applesauce_core::BLOCK_SIZE;

        let input = vec![0x5a; BLOCK_SIZE + 7];
        for kind in Kind::ALL {
            let Some(mut compressor) = kind.compressor() else {
                continue;
            };
            for block in input.chunks(BLOCK_SIZE) {
                let mut encoded = vec![0; block.len() + 1024];
                let encoded_len = compressor.compress(&mut encoded, block, 5).unwrap();
                let mut decoded = vec![0; BLOCK_SIZE + 1024];
                let decoded_len = compressor
                    .decompress(&mut decoded, &encoded[..encoded_len])
                    .unwrap();
                validate_decoded_block_size(decoded_len, Some(block.len())).unwrap();
                assert_eq!(&decoded[..decoded_len], block, "{kind}");
                assert_eq!(
                    validate_decoded_block_size(decoded_len, Some(block.len() + 1))
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidData,
                    "{kind}"
                );
            }
        }
    }
}
