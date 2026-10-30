// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_compression::{
    COMP_ALGO_DEFLATE, COMP_ALGO_STORE, COMP_ALGO_ZSTD, CompressionError, CompressionOptions,
    DecompressionOptions, decode_stream, encode_stream,
};

fn roundtrip(algo_id: u8) -> Vec<u8> {
    let input = b"hello hello hello zstd/deflate/store".repeat(16);
    let mut encoded = Vec::new();
    encode_stream(
        algo_id,
        &mut input.as_slice(),
        &mut encoded,
        CompressionOptions { level: Some(6) },
    )
    .expect("encode");
    let mut decoded = Vec::new();
    decode_stream(
        algo_id,
        &mut encoded.as_slice(),
        &mut decoded,
        DecompressionOptions {
            max_output_size: u64::try_from(input.len()).expect("len"),
        },
    )
    .expect("decode");
    assert_eq!(decoded, input);
    encoded
}

#[test]
fn store_roundtrip() {
    roundtrip(COMP_ALGO_STORE);
}

#[test]
fn deflate_roundtrip() {
    roundtrip(COMP_ALGO_DEFLATE);
}

#[test]
fn zstd_roundtrip() {
    roundtrip(COMP_ALGO_ZSTD);
}

#[test]
fn unsupported_and_reserved_registry_values_error() {
    let input = b"abc";
    let mut out = Vec::new();
    let unsupported = encode_stream(
        0x03,
        &mut input.as_slice(),
        &mut out,
        CompressionOptions::default(),
    )
    .expect_err("unsupported");
    assert!(matches!(unsupported, CompressionError::Unsupported(0x03)));

    let reserved = encode_stream(
        0x80,
        &mut input.as_slice(),
        &mut out,
        CompressionOptions::default(),
    )
    .expect_err("reserved");
    assert!(matches!(reserved, CompressionError::ReservedValue(0x80)));
}

#[test]
fn corrupted_deflate_fails() {
    let mut decoded = Vec::new();
    let err = decode_stream(
        COMP_ALGO_DEFLATE,
        &mut b"not-a-deflate-stream".as_slice(),
        &mut decoded,
        DecompressionOptions {
            max_output_size: 1024,
        },
    )
    .expect_err("must fail");
    assert!(matches!(err, CompressionError::DecompressionFailed(_)));
}

#[test]
fn corrupted_zstd_fails() {
    let mut decoded = Vec::new();
    let err = decode_stream(
        COMP_ALGO_ZSTD,
        &mut b"not-a-zstd-stream".as_slice(),
        &mut decoded,
        DecompressionOptions {
            max_output_size: 1024,
        },
    )
    .expect_err("must fail");
    assert!(matches!(err, CompressionError::DecompressionFailed(_)));
}

#[test]
fn decompression_limit_enforced() {
    let encoded = roundtrip(COMP_ALGO_STORE);
    let mut decoded = Vec::new();
    let err = decode_stream(
        COMP_ALGO_STORE,
        &mut encoded.as_slice(),
        &mut decoded,
        DecompressionOptions { max_output_size: 8 },
    )
    .expect_err("must exceed limit");
    assert!(matches!(err, CompressionError::LimitExceeded));
}

struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("source failure"))
    }
}

struct FailingWriter;

impl std::io::Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("sink failure"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serves a prefix of valid data, then fails with the given error kind on every later read.
struct FailAfterPrefix {
    data: Vec<u8>,
    pos: usize,
    kind: std::io::ErrorKind,
}

impl std::io::Read for FailAfterPrefix {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.data.len() {
            let n = buf.len().min(self.data.len() - self.pos).min(4);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        Err(std::io::Error::from(self.kind))
    }
}

#[test]
fn decode_source_failure_after_valid_prefix_is_io_including_interrupted() {
    let input = b"hello hello hello zstd/deflate/store".repeat(64);
    for algo in [COMP_ALGO_STORE, COMP_ALGO_DEFLATE, COMP_ALGO_ZSTD] {
        let mut encoded = Vec::new();
        encode_stream(
            algo,
            &mut input.as_slice(),
            &mut encoded,
            CompressionOptions::default(),
        )
        .expect("encode");
        let prefix = encoded[..encoded.len() / 2].to_vec();
        for kind in [
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let err = decode_stream(
                algo,
                &mut FailAfterPrefix {
                    data: prefix.clone(),
                    pos: 0,
                    kind,
                },
                &mut Vec::new(),
                DecompressionOptions {
                    max_output_size: 1 << 20,
                },
            )
            .expect_err("must fail");
            assert!(
                matches!(err, CompressionError::Io(_)),
                "algo {algo} kind {kind:?}: {err:?}"
            );
        }
    }
}

#[test]
fn decode_zstd_clean_eof_on_truncated_stream_is_malformed_not_io() {
    let input = b"hello hello hello zstd".repeat(64);
    let mut encoded = Vec::new();
    encode_stream(
        COMP_ALGO_ZSTD,
        &mut input.as_slice(),
        &mut encoded,
        CompressionOptions::default(),
    )
    .expect("encode");
    encoded.truncate(encoded.len() / 2);
    let err = decode_stream(
        COMP_ALGO_ZSTD,
        &mut encoded.as_slice(),
        &mut Vec::new(),
        DecompressionOptions {
            max_output_size: 1 << 20,
        },
    )
    .expect_err("truncated stream must fail");
    assert!(
        matches!(err, CompressionError::DecompressionFailed(_)),
        "{err:?}"
    );
}

#[test]
fn decode_source_io_failure_is_io_not_malformed() {
    for algo in [COMP_ALGO_STORE, COMP_ALGO_DEFLATE, COMP_ALGO_ZSTD] {
        let mut decoded = Vec::new();
        let err = decode_stream(
            algo,
            &mut FailingReader,
            &mut decoded,
            DecompressionOptions {
                max_output_size: 1024,
            },
        )
        .expect_err("must fail");
        assert!(
            matches!(err, CompressionError::Io(_)),
            "algo {algo}: {err:?}"
        );
    }
}

#[test]
fn decode_sink_io_failure_is_io() {
    for algo in [COMP_ALGO_STORE, COMP_ALGO_DEFLATE, COMP_ALGO_ZSTD] {
        let mut encoded = Vec::new();
        encode_stream(
            algo,
            &mut b"payload payload payload".as_slice(),
            &mut encoded,
            CompressionOptions::default(),
        )
        .expect("encode");
        let err = decode_stream(
            algo,
            &mut encoded.as_slice(),
            &mut FailingWriter,
            DecompressionOptions {
                max_output_size: 1024,
            },
        )
        .expect_err("must fail");
        assert!(
            matches!(err, CompressionError::Io(_)),
            "algo {algo}: {err:?}"
        );
    }
}

#[test]
fn encode_io_failures_are_io() {
    for algo in [COMP_ALGO_STORE, COMP_ALGO_DEFLATE, COMP_ALGO_ZSTD] {
        let err = encode_stream(
            algo,
            &mut FailingReader,
            &mut Vec::new(),
            CompressionOptions::default(),
        )
        .expect_err("source must fail");
        assert!(
            matches!(err, CompressionError::Io(_)),
            "algo {algo}: {err:?}"
        );

        let err = encode_stream(
            algo,
            &mut b"payload payload payload".as_slice(),
            &mut FailingWriter,
            CompressionOptions::default(),
        )
        .expect_err("sink must fail");
        assert!(
            matches!(err, CompressionError::Io(_)),
            "algo {algo}: {err:?}"
        );
    }
}

fn zstd_frame_with_window_log(window_log: u32) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut encoded, 1).expect("encoder");
    encoder.window_log(window_log).expect("window log");
    std::io::Write::write_all(&mut encoder, b"window test payload").expect("write");
    encoder.finish().expect("finish");
    encoded
}

#[test]
fn zstd_frame_at_window_limit_decodes() {
    let encoded = zstd_frame_with_window_log(sar_compression::ZSTD_MAX_WINDOW_LOG);
    let mut decoded = Vec::new();
    decode_stream(
        COMP_ALGO_ZSTD,
        &mut encoded.as_slice(),
        &mut decoded,
        DecompressionOptions {
            max_output_size: 1024,
        },
    )
    .expect("decode at limit");
    assert_eq!(decoded, b"window test payload");
}

#[test]
fn zstd_frame_above_window_limit_is_rejected() {
    let encoded = zstd_frame_with_window_log(sar_compression::ZSTD_MAX_WINDOW_LOG + 1);
    let mut decoded = Vec::new();
    let err = decode_stream(
        COMP_ALGO_ZSTD,
        &mut encoded.as_slice(),
        &mut decoded,
        DecompressionOptions {
            max_output_size: 1024,
        },
    )
    .expect_err("window above limit");
    assert!(matches!(err, CompressionError::DecompressionFailed(_)));
    assert!(decoded.is_empty());
}
