use std::io::Cursor;

use sar_archive::{
    ArchiveReader, ArchiveRecoverySettings, ArchiveWriter, ArchiveWriterOptions, EntryInput,
    recovery::{
        ErasureInput, ErasureRange, inspect_recovery_metadata, plan_archive_repair, repair_archive,
    },
};
use sar_core::{
    GlobalFlags, ResourceLimits, SarError,
    format::{
        GLOBAL_HEADER_FLAGS_OFFSET, parse_central_dictionary, parse_footer, parse_global_header,
    },
};
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR};

const ARCHIVE_RECOVERY_STRIPE_SIZE: u8 = 1;
const ARCHIVE_RECOVERY_BLOCK_SIZE_INDEX: u8 = 0x00;
const ARCHIVE_RECOVERY_BLOCK_SIZE: u64 = 256;
const RS_K: u8 = 4;
const RS_PARITY: u8 = 2;
const RS_SYMBOL_SIZE: u32 = 256;
const CORRUPTION_BLOCK_INDEX: u64 = 1;
const ENTRY_PAYLOAD_LEN: usize = 1024;

fn make_payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index & 0xFF) as u8).collect()
}

fn archive_recovery_xor_settings() -> ArchiveRecoverySettings {
    ArchiveRecoverySettings {
        algo_id: FEC_ALGO_XOR,
        config0: ARCHIVE_RECOVERY_STRIPE_SIZE,
        config1: ARCHIVE_RECOVERY_BLOCK_SIZE_INDEX,
        symbol_size: 0,
    }
}

fn archive_recovery_rs_settings() -> ArchiveRecoverySettings {
    ArchiveRecoverySettings {
        algo_id: FEC_ALGO_REED_SOLOMON,
        config0: RS_K,
        config1: RS_PARITY,
        symbol_size: RS_SYMBOL_SIZE,
    }
}

fn build_archive(recovery_settings: ArchiveRecoverySettings) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut archive,
        ArchiveWriterOptions {
            no_index: false,
            archive_recovery: Some(recovery_settings),
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file(
            "data.bin",
            make_payload(ENTRY_PAYLOAD_LEN),
        ))
        .expect("entry");
    writer.finish().expect("finish");
    archive
}

fn parse_cd(
    archive: &[u8],
) -> (
    sar_core::format::GlobalHeader,
    sar_core::format::CentralDictionary,
    u64,
) {
    let limits = ResourceLimits::default();
    let (header, _) = parse_global_header(archive, &limits).expect("global header");
    let footer = parse_footer(&archive[archive.len() - 8..]).expect("footer");
    let cd_offset = footer.cd_offset;
    let cd_start = usize::try_from(cd_offset).expect("cd offset usize");
    let archive_end_without_footer = archive.len() - 8;
    let (cd, _) = parse_central_dictionary(
        &archive[cd_start..archive_end_without_footer],
        header.flags,
        &limits,
    )
    .expect("central dictionary");
    (header, cd, cd_offset)
}

fn assert_writer_emits_valid_archive_recovery(archive: &[u8], expected_algo_id: u8) {
    let (header, cd, cd_offset) = parse_cd(archive);

    assert!(header.flags.contains(GlobalFlags::HAS_GLOBAL_EC));
    assert!(header.flags.contains(GlobalFlags::OPT_PRESENT));
    assert_eq!(cd.metadata.len(), 1);
    assert_eq!(cd.metadata[0].type_id, expected_algo_id);

    let recovery = inspect_recovery_metadata(archive, &ResourceLimits::default()).expect("inspect");
    assert!(recovery.has_global_ec);
    assert!(recovery.repair_possible);
    assert_eq!(recovery.recovery_tlvs.len(), 1);

    let protected_range = recovery.protected_range.expect("protected range");
    assert_eq!(protected_range.offset, GLOBAL_HEADER_FLAGS_OFFSET);
    assert_eq!(
        protected_range.length,
        cd_offset - GLOBAL_HEADER_FLAGS_OFFSET
    );
    assert_eq!(
        GLOBAL_HEADER_FLAGS_OFFSET + protected_range.length,
        cd_offset,
        "protected range must stop before the Central Dictionary",
    );
}

fn assert_repair_round_trip(recovery_settings: ArchiveRecoverySettings, block_size: u64) {
    let original_archive = build_archive(recovery_settings);
    let recovery =
        inspect_recovery_metadata(&original_archive, &ResourceLimits::default()).expect("inspect");
    let protected_range = recovery.protected_range.expect("protected range");
    let corruption_offset = protected_range.offset + (CORRUPTION_BLOCK_INDEX * block_size);
    let corruption_end = corruption_offset + block_size;
    let protected_end = protected_range.offset + protected_range.length;
    assert!(
        corruption_end <= protected_end,
        "test corruption range must remain inside protected range",
    );

    let mut corrupted_archive = original_archive.clone();
    let start = usize::try_from(corruption_offset).expect("corruption start usize");
    let end = usize::try_from(corruption_end).expect("corruption end usize");
    for byte in &mut corrupted_archive[start..end] {
        *byte ^= 0xA5;
    }

    let plan = plan_archive_repair(
        &corrupted_archive,
        ErasureInput {
            entries: Vec::new(),
            archive_ranges: vec![ErasureRange {
                offset: corruption_offset,
                length: block_size,
            }],
        },
        &ResourceLimits::default(),
    )
    .expect("repair plan");

    let (repaired_archive, report) =
        repair_archive(&corrupted_archive, &plan, &ResourceLimits::default()).expect("repair");
    assert!(report.success);
    assert_eq!(repaired_archive, original_archive);

    let mut reader = ArchiveReader::new(Cursor::new(repaired_archive.clone())).expect("reader");
    let verification = reader.verify().expect("verify");
    assert!(verification.valid);
    let mut payload_reader = ArchiveReader::new(Cursor::new(repaired_archive)).expect("reader");
    payload_reader
        .read_global_header()
        .expect("read_global_header");
    let entry = payload_reader
        .next_entry()
        .expect("next_entry")
        .expect("entry");
    assert_eq!(entry.payload, make_payload(ENTRY_PAYLOAD_LEN));
}

#[test]
fn writer_rejects_archive_recovery_with_no_index() {
    let err = ArchiveWriter::new(
        Vec::new(),
        ArchiveWriterOptions {
            no_index: true,
            archive_recovery: Some(archive_recovery_xor_settings()),
            ..Default::default()
        },
    )
    .err()
    .expect("archive recovery must reject NO_INDEX");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn writer_emits_archive_recovery_xor_tlv() {
    let archive = build_archive(archive_recovery_xor_settings());
    assert_writer_emits_valid_archive_recovery(&archive, FEC_ALGO_XOR);
}

#[test]
fn writer_emits_archive_recovery_rs_tlv() {
    let archive = build_archive(archive_recovery_rs_settings());
    assert_writer_emits_valid_archive_recovery(&archive, FEC_ALGO_REED_SOLOMON);
}

#[test]
fn archive_recovery_xor_repair_round_trip() {
    assert_repair_round_trip(archive_recovery_xor_settings(), ARCHIVE_RECOVERY_BLOCK_SIZE);
}

#[test]
fn archive_recovery_rs_repair_round_trip() {
    // RS repair currently uses explicit, block-aligned erasures where block size
    // matches symbol size.
    assert_repair_round_trip(archive_recovery_rs_settings(), u64::from(RS_SYMBOL_SIZE));
}
