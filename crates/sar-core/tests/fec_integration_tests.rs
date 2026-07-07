//! Integration tests for FEC metadata in `sar-core`:
//! - LFH Selective FEC parsing and validation.
//! - Data Recovery TLV parsing and validation.
//! - `verify()` FEC TLV validation.
//! - `EntryMetadata.fec` field in `inspect` output.

use sar_core::{
    GlobalFlags, SarError,
    fec::{parse_lfh_fec_value, validate_recovery_tlv},
    format::{LocalFileHeader, parse_lfh, write_lfh},
    tlv::{Tlv, parse_tlvs, write_tlvs},
};
use sar_fec::{FecOptions, FecValue, RsCodec, XorCodec, types::FecCodec};

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_xor_fec_value(stripe: u8, bsi: u8, data: &[u8]) -> FecValue {
    let codec = XorCodec::new(stripe, bsi).expect("codec");
    codec.encode_recovery(data, FecOptions).expect("encode")
}

fn build_rs_fec_value(k: u8, pc: u8, ss: u32, data: &[u8]) -> FecValue {
    let codec = RsCodec::new(k, pc, ss).expect("codec");
    codec.encode_recovery(data, FecOptions).expect("encode")
}

// ---------------------------------------------------------------------------
// LFH FEC integration
// ---------------------------------------------------------------------------

#[test]
fn lfh_fec_xor_roundtrip_parse() {
    let data = vec![0xABu8; 512];
    let fec = build_xor_fec_value(2, 0x00, &data); // stripe=2, block=256

    // Build minimal LFH with SELECTIVE_FEC
    let flags = GlobalFlags::SELECTIVE_FEC;
    let mut lfh = LocalFileHeader::minimal_store(b"test.bin".to_vec(), 512);
    lfh.fec_algo_id = Some(0x14);
    lfh.fec_value = fec.data.clone();

    let bytes = write_lfh(&flags, &lfh).expect("write lfh");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");

    assert_eq!(parsed.fec_algo_id, Some(0x14));
    assert_eq!(parsed.fec_value, fec.data);
}

#[test]
fn lfh_fec_rs_roundtrip_parse() {
    let data = vec![1u8; 1024];
    let fec = build_rs_fec_value(4, 2, 256, &data); // k=4, n-k=2, sym=256

    let flags = GlobalFlags::SELECTIVE_FEC;
    let mut lfh = LocalFileHeader::minimal_store(b"test.bin".to_vec(), 1024);
    lfh.fec_algo_id = Some(0x11);
    lfh.fec_value = fec.data.clone();

    let bytes = write_lfh(&flags, &lfh).expect("write lfh");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");

    assert_eq!(parsed.fec_algo_id, Some(0x11));
    assert_eq!(parsed.fec_value, fec.data);
}

#[test]
fn lfh_fec_disabled_roundtrip() {
    let flags = GlobalFlags::SELECTIVE_FEC;
    let mut lfh = LocalFileHeader::minimal_store(b"test.bin".to_vec(), 100);
    lfh.fec_algo_id = Some(0x00); // disabled
    lfh.fec_value = vec![]; // no FEC data

    let bytes = write_lfh(&flags, &lfh).expect("write lfh");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");

    assert_eq!(parsed.fec_algo_id, Some(0x00));
    assert!(parsed.fec_value.is_empty());
}

#[test]
fn parse_lfh_fec_value_xor_returns_summary() {
    let data = vec![0u8; 256];
    let fec = build_xor_fec_value(1, 0x00, &data);
    let summary = parse_lfh_fec_value(0x14, &fec.data, &unlimited_limits())
        .expect("parse")
        .expect("some");
    // Summary should have serializable structure
    let _ = serde_json::to_string(&summary).expect("serialize");
}

#[test]
fn parse_lfh_fec_value_rs_returns_summary() {
    let data = vec![1u8; 1024];
    let fec = build_rs_fec_value(4, 2, 256, &data);
    let summary = parse_lfh_fec_value(0x11, &fec.data, &unlimited_limits())
        .expect("parse")
        .expect("some");
    let _ = serde_json::to_string(&summary).expect("serialize");
}

#[test]
fn parse_lfh_fec_value_disabled_returns_none() {
    let result = parse_lfh_fec_value(0x00, &[], &unlimited_limits()).expect("parse");
    assert!(result.is_none());
}

#[test]
fn parse_lfh_fec_value_reserved_id_0x10_fails() {
    let err = parse_lfh_fec_value(0x10, &[1, 2, 3], &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn parse_lfh_fec_value_unsupported_id_0x12_fails() {
    let err = parse_lfh_fec_value(0x12, &[1, 2, 3], &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::Unsupported(_)));
}

// ---------------------------------------------------------------------------
// Data Recovery TLV integration
// ---------------------------------------------------------------------------

#[test]
fn recovery_tlv_xor_parse_validate() {
    let data = vec![0x55u8; 768];
    let fec = build_xor_fec_value(3, 0x00, &data); // 3 blocks × 256 = 768

    let summary = validate_recovery_tlv(0x14, &fec.data, &unlimited_limits()).expect("validate");
    let json = serde_json::to_string(&summary).expect("serialize");
    assert!(json.contains("\"algorithm\":\"xor\""));
    assert!(json.contains("\"stripe_size\":3"));
}

#[test]
fn recovery_tlv_rs_parse_validate() {
    let data = vec![0xAAu8; 1024];
    let fec = build_rs_fec_value(4, 2, 256, &data);

    let summary = validate_recovery_tlv(0x11, &fec.data, &unlimited_limits()).expect("validate");
    let json = serde_json::to_string(&summary).expect("serialize");
    assert!(json.contains("\"algorithm\":\"reed-solomon\""));
    assert!(json.contains("\"k\":4"));
}

#[test]
fn recovery_tlv_reserved_0x10_fails() {
    let err = validate_recovery_tlv(0x10, &[], &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn recovery_tlv_unsupported_0x12_fails() {
    let err = validate_recovery_tlv(0x12, &[], &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::Unsupported(_)));
}

#[test]
fn recovery_tlv_round_trip_in_cd_metadata() {
    let data = vec![0xBBu8; 512];
    let fec = build_xor_fec_value(2, 0x00, &data);

    // Encode as a TLV
    let tlv = Tlv {
        type_id: 0x14,
        value: fec.data.clone(),
    };
    let encoded = write_tlvs(&[tlv]).expect("encode TLVs");

    // Parse back
    let parsed = parse_tlvs(&encoded, &unlimited_limits()).expect("parse TLVs");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].type_id, 0x14);
    assert_eq!(parsed[0].value, fec.data);
}

#[test]
fn recovery_tlv_0x17_reserved_in_parse() {
    // Type 0x17 is reserved; parse_tlvs should reject it
    let mut bytes = vec![0x17u8];
    bytes.extend_from_slice(&4u32.to_le_bytes()); // length=4
    bytes.extend_from_slice(&[1, 2, 3, 4]); // value
    // pad to 8-byte alignment
    bytes.extend_from_slice(&[0, 0, 0]);
    let err = parse_tlvs(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}
