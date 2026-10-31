// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! `SAR-M13b3-PARTITION-P0-IMPLEMENTATION-001`: Central Dictionary conformance
//! (spec §§7, 7.1, 7.2): Empty Area exclusion, Data Area CRC32, offset arrays.

use std::io::Cursor;

use sar_archive::{
    ArchiveAuditOptions, ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings,
    EncryptionSettings, EntryInput, FecSettings, PayloadAuditPolicy,
};
use sar_compression::COMP_ALGO_DEFLATE;
use sar_core::{
    CentralDictionary, GlobalFlags, ResourceLimits, SarError, parse_central_dictionary,
    parse_footer, parse_global_header, write_central_dictionary, write_footer,
};
use sar_crypto::{
    ENCR_AES256_GCM, KeyProvider, KmsContext, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params,
    SarCryptoError, SecretBytes, SecretString,
};

struct Pw;

impl KeyProvider for Pw {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(Some(SecretString::new("pw".to_string())))
    }
    fn unwrap_key(
        &self,
        _ctx: &KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
    fn external_key(&self, _ctx: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
}

fn indexed() -> ArchiveWriterOptions {
    ArchiveWriterOptions {
        no_index: false,
        ..Default::default()
    }
}

/// `a`, Empty Area (8 payload bytes), `b`, `c`.
fn write_with(
    options: ArchiveWriterOptions,
    crc: bool,
    compression: CompressionSettings,
    provider: Option<Box<dyn KeyProvider>>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut out),
        options,
        compression,
        provider,
    )
    .expect("writer");
    if crc {
        writer = writer.with_data_area_crc32().expect("enable CRC");
    }
    writer
        .add_entry(EntryInput::file("a.txt", b"aaaaaaaaaaaaaaaa".to_vec()))
        .expect("a");
    writer
        .add_entry(EntryInput::file("", b"EMPTYARE".to_vec()))
        .expect("empty area");
    writer
        .add_entry(EntryInput::file("b.txt", b"bbbbbbbbbbbbbbbb".to_vec()))
        .expect("b");
    writer
        .add_entry(EntryInput::file("c.txt", b"cccccccccccccccc".to_vec()))
        .expect("c");
    let summary = writer.finish().expect("finish");
    assert_eq!(summary.entry_count, 4, "summary counts physical entries");
    out
}

fn write_plain(crc: bool) -> Vec<u8> {
    write_with(indexed(), crc, CompressionSettings::store(), None)
}

struct Layout {
    flags: GlobalFlags,
    header_len: usize,
    cd_offset: usize,
    cd: CentralDictionary,
}

fn layout(archive: &[u8]) -> Layout {
    let limits = ResourceLimits::default();
    let (header, header_len) = parse_global_header(archive, &limits).expect("header");
    let footer = parse_footer(&archive[archive.len() - 8..]).expect("footer");
    let cd_offset = usize::try_from(footer.cd_offset).expect("cd offset");
    let (cd, _) = parse_central_dictionary(
        &archive[cd_offset..archive.len() - 8],
        header.flags,
        &limits,
    )
    .expect("cd");
    Layout {
        flags: header.flags,
        header_len,
        cd_offset,
        cd,
    }
}

/// Re-assembles `archive` with the CD bytes replaced (padding and footer rebuilt).
fn with_cd_bytes(archive: &[u8], l: &Layout, cd_bytes: &[u8]) -> Vec<u8> {
    let mut out = archive[..l.cd_offset].to_vec();
    out.extend_from_slice(cd_bytes);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    out.extend_from_slice(&write_footer(sar_core::Footer {
        cd_offset: u64::try_from(l.cd_offset).expect("u64"),
    }));
    out
}

fn with_cd(archive: &[u8], mutate: impl FnOnce(&mut CentralDictionary)) -> Vec<u8> {
    let l = layout(archive);
    let mut cd = l.cd.clone();
    mutate(&mut cd);
    let bytes = write_central_dictionary(&cd, l.flags).expect("cd bytes");
    with_cd_bytes(archive, &l, &bytes)
}

/// Replaces the offset array with arbitrary (possibly unordered) 32-bit values
/// while keeping the Entry Count.
fn with_raw_offsets(archive: &[u8], offsets: &[u64]) -> Vec<u8> {
    let l = layout(archive);
    assert_eq!(offsets.len(), l.cd.offsets.len());
    let mut cd = l.cd.clone();
    cd.offsets = (0..offsets.len() as u64).collect();
    let mut bytes = write_central_dictionary(&cd, l.flags).expect("cd bytes");
    let tail = bytes.len() - offsets.len() * 4;
    for (i, offset) in offsets.iter().enumerate() {
        let at = tail + i * 4;
        bytes[at..at + 4].copy_from_slice(&u32::try_from(*offset).expect("u32").to_le_bytes());
    }
    with_cd_bytes(archive, &l, &bytes)
}

fn verify(archive: &[u8]) -> Result<(), SarError> {
    let mut reader = ArchiveReader::new(Cursor::new(archive.to_vec()))?;
    reader.verify().map(|_| ())
}

fn audit(archive: &[u8]) -> Result<(), SarError> {
    let mut reader = ArchiveReader::new(Cursor::new(archive.to_vec()))?;
    reader
        .audit(ArchiveAuditOptions {
            payload_policy: PayloadAuditPolicy::MetadataOnly,
            ..Default::default()
        })
        .map(|_| ())
}

fn phys_offsets(archive: &[u8]) -> Vec<(u64, String)> {
    let mut reader = ArchiveReader::new(Cursor::new(archive.to_vec())).expect("reader");
    reader.read_global_header().expect("header");
    let mut out = Vec::new();
    while let Some(e) = reader.next_entry().expect("entry") {
        out.push((e.metadata.lfh_offset, e.metadata.name.clone()));
    }
    out
}

// ---------------------------------------------------------------------------
// Empty Areas (§7.1)
// ---------------------------------------------------------------------------

#[test]
fn indexed_cd_excludes_empty_area_but_data_area_keeps_it() {
    let archive = write_plain(false);
    let phys = phys_offsets(&archive);
    assert_eq!(phys.len(), 4);
    assert_eq!(phys[1].1, "", "Empty Area is physically present");

    let l = layout(&archive);
    assert_eq!(l.cd.file_count, 3);
    assert_eq!(
        l.cd.offsets,
        vec![phys[0].0, phys[2].0, phys[3].0],
        "Empty Area offset must not be indexed"
    );
    let report = {
        let mut r = ArchiveReader::new(Cursor::new(archive.clone())).expect("reader");
        r.verify().expect("conforming archive verifies")
    };
    assert_eq!(report.entry_count, 4);
    audit(&archive).expect("audit accepts conforming archive");
}

#[test]
fn legacy_cd_listing_empty_area_offset_is_rejected() {
    let archive = write_plain(true);
    let phys = phys_offsets(&archive);
    let legacy = with_cd(&archive, |cd| {
        cd.offsets = phys.iter().map(|(o, _)| *o).collect();
        cd.file_count = 4;
    });
    assert!(matches!(verify(&legacy), Err(SarError::Malformed(_))));
    assert!(matches!(audit(&legacy), Err(SarError::Malformed(_))));
}

#[test]
fn cd_omitting_indexable_lfh_is_rejected() {
    let archive = write_plain(true);
    let missing = with_cd(&archive, |cd| {
        cd.offsets.remove(1);
        cd.file_count = 2;
    });
    assert!(matches!(verify(&missing), Err(SarError::InvalidLength(_))));
    assert!(matches!(audit(&missing), Err(SarError::InvalidLength(_))));

    // Entry Count claims 3 but the array carries 2 offsets: writer refuses.
    let l = layout(&archive);
    let mut cd = l.cd.clone();
    cd.offsets.remove(1);
    assert!(write_central_dictionary(&cd, l.flags).is_err());
}

#[test]
fn indexed_archive_without_empty_area_is_unchanged() {
    let mut out = Vec::new();
    let mut w = ArchiveWriter::new(Cursor::new(&mut out), indexed()).expect("writer");
    w.add_entry(EntryInput::file("x", b"x".to_vec()))
        .expect("x");
    w.add_entry(EntryInput::file("y", b"y".to_vec()))
        .expect("y");
    w.finish().expect("finish");
    let l = layout(&out);
    assert_eq!(l.cd.file_count, 2);
    assert_eq!(l.cd.global_crc32, None);
    verify(&out).expect("verify");
}

// ---------------------------------------------------------------------------
// Data Area CRC32 (§7.2)
// ---------------------------------------------------------------------------

#[test]
fn crc_covers_exactly_the_encoded_data_area() {
    let archive = write_plain(true);
    let l = layout(&archive);
    assert!(l.flags.contains(GlobalFlags::HAS_GLOBAL_CRC32));
    let data = &archive[l.header_len..l.cd_offset];
    assert_eq!(l.cd.global_crc32, Some(crc32fast::hash(data)));
    // Header and CD bytes do not contribute.
    assert_ne!(
        l.cd.global_crc32,
        Some(crc32fast::hash(&archive[..l.cd_offset]))
    );
    assert_ne!(
        l.cd.global_crc32,
        Some(crc32fast::hash(&archive[l.header_len..archive.len() - 8]))
    );
    verify(&archive).expect("correct CRC accepted");
    audit(&archive).expect("audit accepts correct CRC");
}

#[test]
fn data_area_byte_corruption_is_detected_as_crc_mismatch() {
    let archive = write_plain(true);
    let l = layout(&archive);
    // Every byte of the Data Area is covered: sample each position.
    for pos in (l.header_len..l.cd_offset).step_by(7) {
        let mut bad = archive.clone();
        bad[pos] ^= 0x01;
        assert!(
            matches!(verify(&bad), Err(SarError::CrcMismatch(_))),
            "byte {pos}"
        );
    }
}

#[test]
fn empty_area_bytes_contribute_to_crc() {
    let archive = write_plain(true);
    let phys = phys_offsets(&archive);
    let l = layout(&archive);
    let empty_start = usize::try_from(phys[1].0).expect("usize");
    let empty_end = usize::try_from(phys[2].0).expect("usize");
    assert!(empty_end > empty_start);
    for pos in [empty_start, empty_end - 8, empty_end - 1] {
        assert!(pos >= l.header_len);
        let mut bad = archive.clone();
        bad[pos] ^= 0x80;
        assert!(
            matches!(verify(&bad), Err(SarError::CrcMismatch(_))),
            "byte {pos}"
        );
    }
}

#[test]
fn stored_crc_corruption_is_detected() {
    let archive = write_plain(true);
    let bad = with_cd(&archive, |cd| {
        cd.global_crc32 = cd.global_crc32.map(|c| c ^ 1);
    });
    assert!(matches!(verify(&bad), Err(SarError::CrcMismatch(_))));
    assert!(matches!(audit(&bad), Err(SarError::CrcMismatch(_))));

    // Reading individual entries does not claim CRC verification.
    assert_eq!(phys_offsets(&bad).len(), 4);
}

#[test]
fn crc_is_over_encoded_bytes_not_decoded_payloads() {
    let compression = CompressionSettings {
        algo_id: COMP_ALGO_DEFLATE,
        level: None,
    };
    let archive = write_with(indexed(), true, compression, None);
    let l = layout(&archive);
    let stored = l.cd.global_crc32.expect("crc");
    assert_eq!(stored, crc32fast::hash(&archive[l.header_len..l.cd_offset]));

    let mut reader = ArchiveReader::new(Cursor::new(archive.clone())).expect("reader");
    let files = reader.read_all_logical_files(false).expect("logical");
    let decoded: Vec<u8> = files.iter().flat_map(|f| f.data.clone()).collect();
    assert_ne!(stored, crc32fast::hash(&decoded));
    verify(&archive).expect("verify");

    // Corrupting encoded payload bytes is reported by the CRC check first.
    let mut bad = archive.clone();
    bad[l.cd_offset - 1] ^= 0xFF;
    assert!(matches!(verify(&bad), Err(SarError::CrcMismatch(_))));
}

#[test]
fn crc_with_encryption_and_fec_covers_tags_and_fec_fields() {
    let options = ArchiveWriterOptions {
        encryption: Some(EncryptionSettings {
            algo_id: ENCR_AES256_GCM,
            kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
                salt: vec![7; 16],
                iterations: 100_000,
                derived_key_length: 32,
            }),
        }),
        fec: Some(FecSettings::default_xor()),
        ..indexed()
    };
    let archive = write_with(
        options,
        true,
        CompressionSettings::store(),
        Some(Box::new(Pw)),
    );
    let l = layout(&archive);
    assert_eq!(
        l.cd.global_crc32,
        Some(crc32fast::hash(&archive[l.header_len..l.cd_offset]))
    );
    let mut reader = ArchiveReader::new(Cursor::new(archive.clone()))
        .expect("reader")
        .with_key_provider(Box::new(Pw));
    reader.verify().expect("verify");

    // Last byte of the Data Area is an AEAD tag byte; the raw-byte CRC
    // reports it before any authentication failure.
    let mut bad = archive.clone();
    bad[l.cd_offset - 1] ^= 0x01;
    let mut reader = ArchiveReader::new(Cursor::new(bad))
        .expect("reader")
        .with_key_provider(Box::new(Pw));
    assert!(matches!(reader.verify(), Err(SarError::CrcMismatch(_))));
}

#[test]
fn flag_off_archive_has_no_crc_field_and_verifies() {
    let off = write_plain(false);
    let l = layout(&off);
    assert!(!l.flags.contains(GlobalFlags::HAS_GLOBAL_CRC32));
    assert_eq!(l.cd.global_crc32, None);
    verify(&off).expect("verify");

    let on = write_plain(true);
    let lo = layout(&on);
    // Exactly the 4-byte CRC field is added to the CD (padding may absorb it).
    let consumed = |archive: &[u8], l: &Layout| {
        parse_central_dictionary(
            &archive[l.cd_offset..archive.len() - 8],
            l.flags,
            &ResourceLimits::default(),
        )
        .expect("cd")
        .1
    };
    assert_eq!(layout(&on).header_len, l.header_len);
    assert_eq!(consumed(&on, &lo) - consumed(&off, &l), 4);
}

#[test]
fn no_index_conflicts_with_data_area_crc() {
    let writer = ArchiveWriter::new(Cursor::new(Vec::new()), ArchiveWriterOptions::default())
        .expect("default writer is NO_INDEX");
    let err = writer.with_data_area_crc32().err().expect("conflict");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn data_area_crc_must_be_selected_before_header_emission() {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), indexed()).expect("writer");
    writer
        .add_entry(EntryInput::file("x", b"x".to_vec()))
        .expect("x");
    let err = writer.with_data_area_crc32().err().expect("too late");
    assert!(matches!(err, SarError::Malformed(_)));
}

#[test]
fn default_options_do_not_enable_data_area_crc() {
    let mut out = Vec::new();
    let mut w = ArchiveWriter::new(Cursor::new(&mut out), indexed()).expect("writer");
    w.add_entry(EntryInput::file("x", b"x".to_vec()))
        .expect("x");
    w.finish().expect("finish");
    let l = layout(&out);
    assert!(!l.flags.contains(GlobalFlags::HAS_GLOBAL_CRC32));
    assert_eq!(l.cd.global_crc32, None);
}

/// Compile-time regression: the exhaustive struct literal (every field named,
/// no `..Default::default()`) that was valid before P0 must keep compiling.
#[test]
fn exhaustive_options_literal_still_compiles() {
    let options = ArchiveWriterOptions {
        no_index: false,
        encryption: None,
        fec: None,
        archive_recovery: None,
        sparse: false,
        with_path: false,
        with_permissions: false,
        with_uid_gid: false,
        with_timestamps: false,
        with_per_file_crc: false,
        with_content_hash: false,
        with_symlinks: false,
        with_delta: false,
        lfh_size_field_policy: sar_archive::LfhSizeFieldPolicy::Auto,
        limits: ResourceLimits::default(),
    };
    ArchiveWriter::new(Cursor::new(Vec::new()), options).expect("writer");
}

// ---------------------------------------------------------------------------
// Offset array (§7.1)
// ---------------------------------------------------------------------------

#[test]
fn valid_ordered_offsets_are_accepted() {
    let archive = write_plain(true);
    let l = layout(&archive);
    let same = with_raw_offsets(&archive, &l.cd.offsets);
    assert_eq!(same, archive, "rebuild is byte-exact");
    verify(&same).expect("valid");
}

#[test]
fn duplicate_and_descending_offsets_are_malformed() {
    let archive = write_plain(true);
    let o = layout(&archive).cd.offsets;
    for bad in [
        vec![o[0], o[0], o[2]],
        vec![o[0], o[1], o[1]],
        vec![o[2], o[1], o[0]],
    ] {
        let mutated = with_raw_offsets(&archive, &bad);
        assert!(
            matches!(verify(&mutated), Err(SarError::Malformed(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn offsets_inside_lfh_or_payload_are_malformed() {
    let archive = write_plain(true);
    let o = layout(&archive).cd.offsets;
    for bad in [o[1] - 1, o[1] + 1, o[0] + 1] {
        let mutated = with_raw_offsets(&archive, &[o[0], bad.max(o[0] + 1), o[2]]);
        let res = verify(&mutated);
        assert!(matches!(res, Err(SarError::Malformed(_))), "{bad}: {res:?}");
    }
}

#[test]
fn offset_inside_global_header_is_malformed() {
    let archive = write_plain(true);
    let o = layout(&archive).cd.offsets;
    let mutated = with_raw_offsets(&archive, &[4, o[1], o[2]]);
    assert!(matches!(verify(&mutated), Err(SarError::Malformed(_))));
}

#[test]
fn offsets_into_cd_padding_or_footer_are_malformed() {
    let archive = write_plain(true);
    let l = layout(&archive);
    let o = &l.cd.offsets;
    let len = u64::try_from(archive.len()).expect("u64");
    let cd_off = u64::try_from(l.cd_offset).expect("u64");
    for bad in [cd_off, cd_off + 3, len - 8, len - 1] {
        let mutated = with_raw_offsets(&archive, &[o[0], o[1], bad]);
        let res = verify(&mutated);
        assert!(matches!(res, Err(SarError::Malformed(_))), "{bad}: {res:?}");
    }
}

#[test]
fn offsets_beyond_member_are_bounds_errors() {
    let archive = write_plain(true);
    let o = layout(&archive).cd.offsets;
    let len = u64::try_from(archive.len()).expect("u64");
    for bad in [len, len + 100, u64::from(u32::MAX)] {
        let mutated = with_raw_offsets(&archive, &[o[0], o[1], bad]);
        let res = verify(&mutated);
        assert!(matches!(res, Err(SarError::Bounds(_))), "{bad}: {res:?}");
    }
}

#[test]
fn in_range_offset_at_non_indexed_lfh_boundary_is_malformed_not_bounds() {
    // Boundary inside Data Area between entries but not an LFH: o[2] - 1.
    let archive = write_plain(true);
    let o = layout(&archive).cd.offsets;
    let mutated = with_raw_offsets(&archive, &[o[0], o[1], o[2] - 1]);
    assert!(matches!(verify(&mutated), Err(SarError::Malformed(_))));
}

#[test]
fn pure_offset_layout_check_separates_structural_invariants() {
    let archive = write_plain(true);
    let l = layout(&archive);
    let (hdr, cdo, len) = (
        u64::try_from(l.header_len).expect("u64"),
        u64::try_from(l.cd_offset).expect("u64"),
        u64::try_from(archive.len()).expect("u64"),
    );
    l.cd.validate_offset_layout(hdr, cdo, len).expect("valid");

    let mut cd = l.cd.clone();
    cd.offsets[2] = len;
    assert!(matches!(
        cd.validate_offset_layout(hdr, cdo, len),
        Err(SarError::Bounds(_))
    ));
    let mut cd = l.cd.clone();
    cd.offsets[2] = cdo;
    assert!(matches!(
        cd.validate_offset_layout(hdr, cdo, len),
        Err(SarError::Malformed(_))
    ));
    let mut cd = l.cd.clone();
    cd.file_count += 1;
    assert!(matches!(
        cd.validate_offset_layout(hdr, cdo, len),
        Err(SarError::InvalidLength(_))
    ));
}
