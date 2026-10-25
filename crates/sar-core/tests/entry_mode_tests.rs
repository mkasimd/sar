// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::{EntryMode, GlobalFlags, SarError, validate_entry_mode_against_global};

#[test]
fn entry_mode_from_bits_round_trips_raw_bits() {
    let bits = EntryMode::ENCRYPTED
        | EntryMode::COMPRESSED
        | EntryMode::FRAGMENT
        | EntryMode::LAST_FRAGMENT
        | EntryMode::LOSS_TOLERANT;
    let mode = EntryMode::from_bits(bits);

    assert_eq!(mode.bits(), bits);
}

#[test]
fn entry_mode_reports_encrypted_bit() {
    let mode = EntryMode::from_bits(EntryMode::ENCRYPTED);

    assert!(mode.is_encrypted());
    assert!(!mode.is_compressed());
}

#[test]
fn entry_mode_reports_compressed_bit() {
    let mode = EntryMode::from_bits(EntryMode::COMPRESSED);

    assert!(mode.is_compressed());
    assert!(!mode.is_encrypted());
}

#[test]
fn entry_mode_reports_fragment_bits() {
    let mode = EntryMode::from_bits(EntryMode::FRAGMENT | EntryMode::LAST_FRAGMENT);

    assert!(mode.is_fragment());
    assert!(mode.is_last_fragment());
}

#[test]
fn entry_mode_reports_loss_tolerant_bit() {
    let mode = EntryMode::from_bits(EntryMode::FRAGMENT | EntryMode::LOSS_TOLERANT);

    assert!(mode.is_fragment());
    assert!(mode.is_loss_tolerant());
}

#[test]
fn entry_mode_reports_session_and_sync_bits() {
    let mode = EntryMode::from_bits(
        EntryMode::HIDDEN_ATTR
            | EntryMode::SESSION_CONTROL
            | EntryMode::ATOMIC_WRITE
            | EntryMode::FORCE_SYNC,
    );

    assert!(mode.is_hidden_attr());
    assert!(mode.is_session_control());
    assert!(mode.is_atomic_write());
    assert!(mode.is_force_sync());
}

#[test]
fn entry_mode_validation_requires_matching_global_flags() {
    let compressed_err = validate_entry_mode_against_global(
        GlobalFlags::NO_INDEX,
        EntryMode::from_bits(EntryMode::COMPRESSED),
    )
    .expect_err("compressed entries require the global COMPRESSED flag");
    assert!(matches!(compressed_err, SarError::FlagConflict(_)));

    let encrypted_err = validate_entry_mode_against_global(
        GlobalFlags::NO_INDEX,
        EntryMode::from_bits(EntryMode::ENCRYPTED),
    )
    .expect_err("encrypted entries require the global ENCRYPTED flag");
    assert!(matches!(encrypted_err, SarError::FlagConflict(_)));

    let last_fragment_err = validate_entry_mode_against_global(
        GlobalFlags::FILE_FRAGMENTATION,
        EntryMode::from_bits(EntryMode::LAST_FRAGMENT),
    )
    .expect_err("LAST_FRAGMENT requires FRAGMENT");
    assert!(matches!(last_fragment_err, SarError::FlagConflict(_)));
}

#[test]
fn entry_mode_validation_accepts_consistent_bits() {
    let global_flags = GlobalFlags::NO_INDEX
        | GlobalFlags::COMPRESSED
        | GlobalFlags::ENCRYPTED
        | GlobalFlags::FILE_FRAGMENTATION;
    let entry_mode = EntryMode::from_bits(
        EntryMode::ENCRYPTED
            | EntryMode::COMPRESSED
            | EntryMode::FRAGMENT
            | EntryMode::LAST_FRAGMENT
            | EntryMode::LOSS_TOLERANT,
    );

    validate_entry_mode_against_global(global_flags, entry_mode)
        .expect("entry mode should be valid");
}

const NO_INDEX: GlobalFlags = GlobalFlags::NO_INDEX;

fn mode(bits: u16) -> EntryMode {
    EntryMode::from_bits(bits)
}

fn is_conflict(r: Result<(), SarError>) -> bool {
    matches!(r, Err(SarError::FlagConflict(_)))
}

fn partitioned() -> GlobalFlags {
    GlobalFlags::NO_INDEX | GlobalFlags::PARTITIONED_ARCHIVE | GlobalFlags::FILE_FRAGMENTATION
}

#[test]
fn partition_manifest_bit_is_assigned_not_reserved() {
    let m = mode(EntryMode::PARTITION_MANIFEST);
    assert_eq!(EntryMode::PARTITION_MANIFEST, 1 << 12);
    assert!(m.is_partition_manifest());
    assert!(!mode(0).is_partition_manifest());
    validate_entry_mode_against_global(partitioned(), m).expect("valid manifest mode");
    // Preserves non-prohibited bits such as HIDDEN_ATTR and IS_ENCRYPTED.
    let with_optional = mode(EntryMode::PARTITION_MANIFEST | EntryMode::HIDDEN_ATTR);
    assert_eq!(with_optional.bits(), (1 << 12) | (1 << 4));
    validate_entry_mode_against_global(partitioned(), with_optional).expect("hidden allowed");
}

#[test]
fn partition_manifest_requires_partitioned_archive() {
    let m = mode(EntryMode::PARTITION_MANIFEST);
    assert!(is_conflict(validate_entry_mode_against_global(NO_INDEX, m)));
}

#[test]
fn partition_manifest_prohibited_bits_conflict() {
    let global = partitioned()
        | GlobalFlags::HAS_SYMLINKS
        | GlobalFlags::COMPRESSED
        | GlobalFlags::FILE_FRAGMENTATION;
    for bit in [
        EntryMode::IS_SYMLINK,
        EntryMode::IS_DIRECTORY,
        EntryMode::COMPRESSED,
        EntryMode::FRAGMENT,
        EntryMode::LAST_FRAGMENT,
        EntryMode::LOSS_TOLERANT,
        EntryMode::SESSION_CONTROL,
        EntryMode::ATOMIC_WRITE,
        EntryMode::FORCE_SYNC,
    ] {
        let r =
            validate_entry_mode_against_global(global, mode(EntryMode::PARTITION_MANIFEST | bit));
        assert!(is_conflict(r), "bit {bit:#06x} must conflict");
    }
    for op in 1u16..=0x4 {
        let r = validate_entry_mode_against_global(
            global,
            mode(EntryMode::PARTITION_MANIFEST | (op << 8)),
        );
        assert!(is_conflict(r), "opcode {op:#x} must conflict");
    }
}

#[test]
fn fragment_prohibited_combinations_conflict() {
    let global = GlobalFlags::NO_INDEX
        | GlobalFlags::FILE_FRAGMENTATION
        | GlobalFlags::HAS_SYMLINKS
        | GlobalFlags::PARTITIONED_ARCHIVE;
    for bit in [
        EntryMode::IS_DIRECTORY,
        EntryMode::IS_SYMLINK,
        EntryMode::SESSION_CONTROL,
        EntryMode::PARTITION_MANIFEST,
    ] {
        let r = validate_entry_mode_against_global(global, mode(EntryMode::FRAGMENT | bit));
        assert!(is_conflict(r), "FRAGMENT with {bit:#06x} must conflict");
    }
    validate_entry_mode_against_global(global, mode(EntryMode::FRAGMENT)).expect("plain fragment");
}

#[test]
fn loss_tolerant_without_fragment_is_valid() {
    validate_entry_mode_against_global(NO_INDEX, mode(EntryMode::LOSS_TOLERANT))
        .expect("LOSS_TOLERANT does not require IS_FRAGMENT");
}

#[test]
fn loss_tolerant_with_encryption_is_structurally_valid() {
    let global = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
    validate_entry_mode_against_global(
        global,
        mode(EntryMode::LOSS_TOLERANT | EntryMode::ENCRYPTED),
    )
    .expect("structurally permissible");
}

#[test]
fn reserved_filesystem_opcodes_fail_closed() {
    for op in 0x5u16..=0xF {
        let r = validate_entry_mode_against_global(NO_INDEX, mode(op << 8));
        assert!(
            matches!(r, Err(SarError::ReservedValue(_))),
            "filesystem opcode {op:#x}"
        );
    }
    for op in 0x0u16..=0x4 {
        validate_entry_mode_against_global(NO_INDEX, mode(op << 8)).expect("assigned fs opcode");
    }
}

#[test]
fn reserved_session_opcodes_fail_closed() {
    for op in 0x8u16..=0xF {
        let r = validate_entry_mode_against_global(
            NO_INDEX,
            mode((op << 8) | EntryMode::SESSION_CONTROL),
        );
        assert!(
            matches!(r, Err(SarError::ReservedValue(_))),
            "session opcode {op:#x}"
        );
    }
    for op in 0x0u16..=0x7 {
        validate_entry_mode_against_global(NO_INDEX, mode((op << 8) | EntryMode::SESSION_CONTROL))
            .expect("assigned session opcode");
    }
}

#[test]
fn opcode_namespace_depends_on_session_control() {
    // 0x5 is assigned in session context but reserved in filesystem context.
    validate_entry_mode_against_global(NO_INDEX, mode((5 << 8) | EntryMode::SESSION_CONTROL))
        .expect("session ACK");
    assert!(validate_entry_mode_against_global(NO_INDEX, mode(5 << 8)).is_err());
}

#[test]
fn writer_rejects_structurally_invalid_entry_modes() {
    use sar_core::{LocalFileHeader, format::write_lfh};
    for bits in [
        5u16 << 8,
        EntryMode::PARTITION_MANIFEST,
        EntryMode::FRAGMENT | EntryMode::IS_DIRECTORY,
    ] {
        let mut lfh = LocalFileHeader::minimal_store(b"x".to_vec(), 0);
        lfh.entry_mode = mode(bits);
        assert!(write_lfh(&NO_INDEX, &lfh).is_err(), "bits {bits:#06x}");
    }
}
