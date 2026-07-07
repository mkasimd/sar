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
