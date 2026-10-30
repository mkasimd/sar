// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_imports)]
use std::io::Cursor;

use sar_archive::{ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::{
    GlobalFlags, SarError,
    format::{GlobalHeader, KmsData, write_global_header},
};

#[test]
fn payload_out_of_bounds_is_rejected() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");

    // Header Size 21 = 4+2+2+2+4+4+2 fixed bytes + 1 name byte (previously the
    // incorrect value 17 only passed via an accidental truncation).
    bytes.extend_from_slice(&21u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"x");
    bytes.extend_from_slice(b"abc");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header parse");
    let err = reader.next_entry().expect_err("must fail");
    assert!(matches!(err, SarError::Truncated(_)));
}

#[test]
fn global_encrypted_with_plaintext_entry_passes_through() {
    let header = GlobalHeader {
        version: 1,
        flags: GlobalFlags::ENCRYPTED | GlobalFlags::NO_INDEX,
        kms: Some(KmsData {
            mode_id: 0x01,
            payload: pbkdf2_payload(),
        }),
    };
    let mut bytes = write_global_header(&header).expect("header");
    bytes.extend_from_slice(&46u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&[0u8; 24]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"x");
    bytes.extend_from_slice(b"a");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let _ = reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("next").expect("entry");
    assert_eq!(entry.payload, b"a");
}

#[test]
fn writer_reader_store_no_index_roundtrip() {
    let mut out = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new(
        &mut out,
        sar_archive::ArchiveWriterOptions {
            no_index: true,
            encryption: None,
            fec: None,
            sparse: false,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(sar_archive::EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(out)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("next").expect("entry");
    assert_eq!(entry.metadata.name, "a.txt");
    assert_eq!(entry.payload, b"abc");
}

fn read_vector(rel: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .join(rel);
    std::fs::read(path).expect("read vector")
}

#[test]
fn truncated_global_header_vector_is_truncated() {
    let bytes = read_vector("invalid/structure/truncated-gh/truncated_global_header.sar");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let err = reader.read_global_header().expect_err("truncated");
    assert!(matches!(err, SarError::Truncated(_)), "{err:?}");
}

#[test]
fn truncated_lfh_vector_is_truncated() {
    let bytes = read_vector("invalid/structure/truncated-lfh/truncated_lfh.sar");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let err = reader
        .read_global_header()
        .and_then(|_| reader.next_entry().map(|_| ()))
        .expect_err("truncated");
    assert!(matches!(err, SarError::Truncated(_)), "{err:?}");
}

#[test]
fn clean_end_of_data_area_is_not_truncation() {
    let flags = GlobalFlags::NO_INDEX;
    let bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    assert!(reader.next_entry().expect("clean eof").is_none());
}

struct FailingReader {
    inner: Cursor<Vec<u8>>,
    fail_after: u64,
}

impl std::io::Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inner.position() >= self.fail_after {
            return Err(std::io::Error::other("injected failure"));
        }
        self.inner.read(buf)
    }
}

impl std::io::Seek for FailingReader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn non_eof_io_failure_stays_io() {
    let bytes = read_vector("invalid/structure/truncated-gh/truncated_global_header.sar");
    let mut reader = ArchiveReader::new(FailingReader {
        inner: Cursor::new(bytes),
        fail_after: 0,
    })
    .expect("reader");
    let err = reader.read_global_header().expect_err("io");
    assert!(matches!(err, SarError::Io(_)), "{err:?}");
}

// ---- WP-2a: Global Header / Global Flags conformance across read paths ----

use sar_archive::{StreamArchiveParser, StreamStep};

const RESERVED_FLAG_BITS: [u32; 11] = [6, 7, 11, 12, 13, 14, 15, 21, 22, 23, 31];

fn fixed_header(flags: u32) -> Vec<u8> {
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes
}

fn stream_error(bytes: &[u8], chunk: usize, finalize: bool) -> Option<SarError> {
    let mut parser = StreamArchiveParser::new();
    for piece in bytes.chunks(chunk) {
        parser.push_bytes(piece).expect("push");
        if let Err(err) = parser.step() {
            return Some(err);
        }
    }
    if finalize {
        parser.finalize_input();
        loop {
            match parser.step() {
                Err(err) => return Some(err),
                Ok(StreamStep::Complete) => return None,
                Ok(_) => {}
            }
        }
    }
    None
}

#[test]
fn reader_and_stream_reject_each_reserved_flag_bit_identically() {
    for bit in RESERVED_FLAG_BITS {
        let bytes = fixed_header(1 << bit);
        let mut reader = ArchiveReader::new(Cursor::new(bytes.clone())).expect("reader");
        let err = reader.read_global_header().expect_err("reader must fail");
        assert!(
            matches!(err, SarError::ReservedValue(_)),
            "reader bit {bit}"
        );
        let err = stream_error(&bytes, bytes.len(), false).expect("stream must fail");
        assert!(
            matches!(err, SarError::ReservedValue(_)),
            "stream bit {bit}"
        );
    }
}

#[test]
fn stream_rejects_bad_prefix_and_flags_without_waiting_for_extension() {
    // Flags Size is rejected as soon as the 8-byte prefix is available.
    let mut bytes = fixed_header(0);
    bytes[6] = 5;
    let err = stream_error(&bytes[..8], 8, false).expect("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)));

    // A reserved bit alongside ENCRYPTED fails before any KMS byte arrives.
    let bytes = fixed_header(GlobalFlags::ENCRYPTED.bits() | (1 << 6));
    let err = stream_error(&bytes, 12, false).expect("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));

    // Unassigned version is rejected from the prefix alone.
    let mut bytes = fixed_header(0);
    bytes[4] = 0;
    let err = stream_error(&bytes[..8], 8, false).expect("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn reader_and_stream_reject_invalid_flags_size() {
    for size in [0u16, 3, 5, 65_535] {
        let mut bytes = fixed_header(0);
        bytes[6..8].copy_from_slice(&size.to_le_bytes());
        let mut reader = ArchiveReader::new(Cursor::new(bytes.clone())).expect("reader");
        let err = reader.read_global_header().expect_err("reader must fail");
        assert!(
            matches!(err, SarError::InvalidLength(_)),
            "reader size {size}"
        );
        let err = stream_error(&bytes, bytes.len(), false).expect("stream must fail");
        assert!(
            matches!(err, SarError::InvalidLength(_)),
            "stream size {size}"
        );
    }
}

#[test]
fn truncated_global_header_is_truncated_in_reader_and_stream() {
    let bytes = fixed_header(GlobalFlags::NO_INDEX.bits());
    for len in 1..bytes.len() {
        let mut reader = ArchiveReader::new(Cursor::new(bytes[..len].to_vec())).expect("reader");
        let err = reader.read_global_header().expect_err("reader must fail");
        assert!(matches!(err, SarError::Truncated(_)), "reader len {len}");
        let err = stream_error(&bytes[..len], len, true).expect("stream must fail");
        assert!(matches!(err, SarError::Truncated(_)), "stream len {len}");
    }
}

#[test]
fn partitioned_header_is_accepted_but_processing_is_unsupported() {
    let bytes = fixed_header((GlobalFlags::NO_INDEX | GlobalFlags::PARTITIONED_ARCHIVE).bits());

    let mut reader = ArchiveReader::new(Cursor::new(bytes.clone())).expect("reader");
    let err = reader.read_global_header().expect_err("reader gate");
    assert!(matches!(err, SarError::Unsupported(_)));

    let err = stream_error(&bytes, bytes.len(), false).expect("stream gate");
    assert!(matches!(err, SarError::Unsupported(_)));

    let err = sar_archive::inspect_recovery_metadata(&bytes, &sar_core::ResourceLimits::default())
        .expect_err("recovery gate");
    assert!(matches!(err, SarError::Unsupported(_)));
}

#[test]
fn partition_gate_runs_after_header_validation() {
    // Bit 3 plus a reserved bit must report RESERVED_VALUE, not UNSUPPORTED.
    let bytes = fixed_header((GlobalFlags::PARTITIONED_ARCHIVE.bits()) | (1 << 6));
    let mut reader = ArchiveReader::new(Cursor::new(bytes.clone())).expect("reader");
    assert!(matches!(
        reader.read_global_header().expect_err("must fail"),
        SarError::ReservedValue(_)
    ));
    assert!(matches!(
        stream_error(&bytes, bytes.len(), false).expect("must fail"),
        SarError::ReservedValue(_)
    ));
}

#[test]
fn stream_parses_valid_archive_split_at_every_byte() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.txt", b"hello".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");
    assert!(stream_error(&buf, 1, true).is_none());
}

// ---- WP-2a: encrypted partitioned Global Header ----

fn pbkdf2_payload() -> Vec<u8> {
    sar_crypto::serialize_kms_payload(&sar_crypto::KmsParams::Pbkdf2(sar_crypto::Pbkdf2Params {
        prf_algo_id: sar_crypto::PBKDF2_PRF_HMAC_SHA256,
        salt: vec![7; 16],
        iterations: 100_000,
        derived_key_length: 32,
    }))
    .expect("serialize KMS payload")
}

fn encrypted_partitioned_header(mode_id: u8, payload: &[u8]) -> Vec<u8> {
    let flags = GlobalFlags::ENCRYPTED | GlobalFlags::PARTITIONED_ARCHIVE;
    let mut bytes = fixed_header(flags.bits());
    bytes.push(mode_id);
    bytes.extend_from_slice(&u32::try_from(payload.len()).expect("len").to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn reader_error(bytes: &[u8]) -> SarError {
    let mut reader = ArchiveReader::new(Cursor::new(bytes.to_vec())).expect("reader");
    reader.read_global_header().expect_err("reader must fail")
}

#[test]
fn encrypted_partitioned_header_parses_but_processing_is_unsupported() {
    let payload = pbkdf2_payload();
    let bytes = encrypted_partitioned_header(sar_crypto::KMS_PBKDF2, &payload);

    let (header, consumed) =
        sar_core::format::parse_global_header(&bytes, &sar_core::ResourceLimits::default())
            .expect("core parser accepts the header");
    assert!(header.flags.contains(GlobalFlags::ENCRYPTED));
    assert!(header.flags.contains(GlobalFlags::PARTITIONED_ARCHIVE));
    assert_eq!(consumed, 12 + 5 + payload.len());
    assert_eq!(consumed, bytes.len());
    assert_eq!(header.kms.expect("kms").payload, payload);

    assert!(matches!(reader_error(&bytes), SarError::Unsupported(_)));
    let err = stream_error(&bytes, bytes.len(), false).expect("stream gate");
    assert!(matches!(err, SarError::Unsupported(_)));
    let err = stream_error(&bytes, 1, true).expect("byte-wise stream gate");
    assert!(matches!(err, SarError::Unsupported(_)));
}

#[test]
fn encrypted_partitioned_header_kms_errors_are_not_masked_by_unsupported() {
    let limits = sar_core::ResourceLimits::default();
    let valid = encrypted_partitioned_header(sar_crypto::KMS_PBKDF2, &pbkdf2_payload());

    // Reserved KMS mode identifier.
    let reserved_mode = encrypted_partitioned_header(0x05, &[]);
    let err = sar_core::format::parse_global_header(&reserved_mode, &limits).expect_err("core");
    assert!(matches!(err, SarError::ReservedValue(_)));
    assert!(matches!(
        reader_error(&reserved_mode),
        SarError::ReservedValue(_)
    ));
    let err = stream_error(&reserved_mode, reserved_mode.len(), false).expect("stream");
    assert!(matches!(err, SarError::ReservedValue(_)));

    // Structurally complete KMS extension whose PBKDF2 payload is malformed.
    let bad_payload = encrypted_partitioned_header(
        sar_crypto::KMS_PBKDF2,
        &[sar_crypto::PBKDF2_PRF_HMAC_SHA256],
    );
    let core_ok = sar_core::format::parse_global_header(&bad_payload, &limits).is_ok();
    assert!(core_ok, "core parser only checks KMS structure");
    let reader = reader_error(&bad_payload);
    assert!(
        matches!(reader, SarError::Malformed(_)),
        "reader: {reader:?}"
    );
    let stream = stream_error(&bad_payload, bad_payload.len(), false).expect("stream");
    assert!(
        matches!(stream, SarError::Malformed(_)),
        "stream: {stream:?}"
    );

    // Truncation at every point inside the required KMS extension.
    for len in 12..valid.len() {
        let cut = &valid[..len];
        let err = sar_core::format::parse_global_header(cut, &limits).expect_err("core");
        assert!(
            matches!(err, SarError::Truncated(_)),
            "core len {len}: {err:?}"
        );
        assert!(
            matches!(reader_error(cut), SarError::Truncated(_)),
            "reader len {len}"
        );

        // The incremental parser waits for the extension rather than gating early.
        assert!(
            stream_error(cut, cut.len(), false).is_none(),
            "stream waited, len {len}"
        );
        let err = stream_error(cut, cut.len(), true).expect("stream at EOF");
        assert!(
            matches!(err, SarError::Truncated(_)),
            "stream len {len}: {err:?}"
        );
    }
}
