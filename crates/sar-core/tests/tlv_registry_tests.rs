// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Exhaustive Section 9.1 TLV type classification over all 256 identifiers.

use sar_core::{
    SarError,
    limits::ResourceLimits,
    tlv::{Tlv, parse_tlvs, write_tlvs},
};

#[derive(Debug, PartialEq, Eq)]
enum Class {
    Accepted,
    Unsupported,
    Reserved,
}

fn expected(id: u8) -> Class {
    match id {
        0x01..=0x04 | 0x11 | 0x14 | 0x30..=0x32 | 0x40 | 0x41 | 0x4F => Class::Accepted,
        0x12 | 0x13 | 0x15 | 0x16 | 0x21..=0x29 => Class::Unsupported,
        _ => Class::Reserved,
    }
}

fn classify(r: Result<(), SarError>) -> Class {
    match r {
        Ok(()) => Class::Accepted,
        Err(SarError::Unsupported(_)) => Class::Unsupported,
        Err(SarError::ReservedValue(_)) => Class::Reserved,
        Err(e) => panic!("unexpected error {e:?}"),
    }
}

fn raw_block(id: u8, value: &[u8]) -> Vec<u8> {
    let mut b = vec![id];
    b.extend_from_slice(&u32::try_from(value.len()).expect("len").to_le_bytes());
    b.extend_from_slice(value);
    while b.len() % 8 != 0 {
        b.push(0);
    }
    b
}

#[test]
fn all_256_type_ids_classified_on_write_path() {
    for id in 0u8..=255 {
        let r = write_tlvs(&[Tlv {
            type_id: id,
            value: vec![1, 2, 3],
        }])
        .map(|_| ());
        assert_eq!(classify(r), expected(id), "write type 0x{id:02X}");
    }
}

#[test]
fn all_256_type_ids_classified_on_parse_path() {
    let limits = ResourceLimits::default();
    for id in 0u8..=255 {
        let r = parse_tlvs(&raw_block(id, &[1, 2, 3]), &limits).map(|_| ());
        assert_eq!(classify(r), expected(id), "parse type 0x{id:02X}");
    }
}

#[test]
fn previously_accepted_reserved_ids_are_rejected() {
    let limits = ResourceLimits::default();
    for id in (0x05u8..=0x0F)
        .chain([0x20])
        .chain(0x2A..=0x2F)
        .chain(0x33..=0x3F)
    {
        assert!(
            matches!(
                parse_tlvs(&raw_block(id, &[0; 8]), &limits),
                Err(SarError::ReservedValue(_))
            ),
            "0x{id:02X}"
        );
    }
}

#[test]
fn duplicate_assigned_tlvs_remain_accepted() {
    let mut bytes = raw_block(0x02, b"a");
    bytes.extend(raw_block(0x02, b"b"));
    let parsed = parse_tlvs(&bytes, &ResourceLimits::default()).expect("duplicates preserved");
    assert_eq!(parsed.len(), 2);
}
