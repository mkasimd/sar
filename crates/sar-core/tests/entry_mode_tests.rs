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

    let loss_tolerant_err = validate_entry_mode_against_global(
        GlobalFlags::FILE_FRAGMENTATION,
        EntryMode::from_bits(EntryMode::LOSS_TOLERANT),
    )
    .expect_err("LOSS_TOLERANT requires FRAGMENT");
    assert!(matches!(loss_tolerant_err, SarError::FlagConflict(_)));
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
