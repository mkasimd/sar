// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! PR5 profile-rejection regression tests.
//!
//! Validates that `validate_archive_profile` rejects archives whose global
//! flags conflict with the selected compliance profile and that valid
//! archives are accepted by profiles that allow them.
//!
//! These tests cover profile-level rejection only (above parse-level).
//! Parse-level rejections (wrong magic, invalid version, flag conflicts in
//! `validate_global_flags`) are covered separately in
//! `crates/sar-core/tests/global_header_tests.rs`.
//!
//! No filesystem extraction is performed. No production API or wire-format
//! changes are made.

use sar_archive::{
    ArchiveMetadata,
    profile::{ComplianceProfile, validate_archive_profile},
};
use sar_core::{
    GlobalFlags,
    format::{CentralDictionary, GlobalHeader},
};

/// Build a minimal [`ArchiveMetadata`] with the given global flags.
fn metadata_with_flags(flags: GlobalFlags) -> ArchiveMetadata {
    ArchiveMetadata {
        global_header: GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        },
        central_dictionary: None,
    }
}

/// Build a minimal [`ArchiveMetadata`] for an empty indexed archive (no entries).
fn minimal_indexed_metadata() -> ArchiveMetadata {
    let flags = GlobalFlags::empty();
    ArchiveMetadata {
        global_header: GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        },
        central_dictionary: Some(CentralDictionary {
            version: 1,
            file_count: 0,
            partition_info: None,
            global_crc32: None,
            metadata: Vec::new(),
            offsets: Vec::new(),
        }),
    }
}

// ---------------------------------------------------------------------------
// NO_INDEX archives: rejected by static-archive, package; accepted by backup
// ---------------------------------------------------------------------------

#[test]
fn no_index_archive_rejected_by_static_archive_profile() {
    let meta = metadata_with_flags(GlobalFlags::NO_INDEX);
    let report = validate_archive_profile(&meta, ComplianceProfile::StaticArchive);
    assert!(
        !report.compliant,
        "static-archive profile must reject NO_INDEX archives"
    );
    assert!(
        !report.findings.is_empty(),
        "findings must describe the rejection reason"
    );
}

#[test]
fn no_index_archive_rejected_by_package_profile() {
    let meta = metadata_with_flags(GlobalFlags::NO_INDEX);
    let report = validate_archive_profile(&meta, ComplianceProfile::Package);
    assert!(
        !report.compliant,
        "package profile must reject NO_INDEX archives"
    );
    assert!(!report.findings.is_empty());
}

#[test]
fn no_index_archive_accepted_by_backup_profile() {
    let meta = metadata_with_flags(GlobalFlags::NO_INDEX);
    let report = validate_archive_profile(&meta, ComplianceProfile::Backup);
    assert!(
        report.compliant,
        "backup profile must accept NO_INDEX archives; findings: {:?}",
        report.findings
    );
}

#[test]
fn no_index_archive_accepted_by_telemetry_profile() {
    let meta = metadata_with_flags(GlobalFlags::NO_INDEX);
    let report = validate_archive_profile(&meta, ComplianceProfile::Telemetry);
    assert!(
        report.compliant,
        "telemetry profile must accept NO_INDEX archives; findings: {:?}",
        report.findings
    );
}

#[test]
fn no_index_archive_accepted_by_stream_package_profile() {
    let meta = metadata_with_flags(GlobalFlags::NO_INDEX);
    let report = validate_archive_profile(&meta, ComplianceProfile::StreamPackage);
    assert!(
        report.compliant,
        "stream-package profile must accept NO_INDEX archives; findings: {:?}",
        report.findings
    );
}

// ---------------------------------------------------------------------------
// Indexed archives: accepted by static-archive and package profiles
// ---------------------------------------------------------------------------

#[test]
fn indexed_archive_accepted_by_static_archive_profile() {
    let meta = minimal_indexed_metadata();
    let report = validate_archive_profile(&meta, ComplianceProfile::StaticArchive);
    assert!(
        report.compliant,
        "static-archive profile must accept indexed archives; findings: {:?}",
        report.findings
    );
}

#[test]
fn indexed_archive_accepted_by_package_profile() {
    let meta = minimal_indexed_metadata();
    let report = validate_archive_profile(&meta, ComplianceProfile::Package);
    assert!(
        report.compliant,
        "package profile must accept indexed archives; findings: {:?}",
        report.findings
    );
}

// ---------------------------------------------------------------------------
// MinimalInteroperableArchive profile: rejects ENCRYPTED
// ---------------------------------------------------------------------------

#[test]
fn encrypted_archive_rejected_by_minimal_interoperable_archive_profile() {
    let meta = metadata_with_flags(GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED);
    let report = validate_archive_profile(&meta, ComplianceProfile::MinimalInteroperableArchive);
    assert!(
        !report.compliant,
        "minimal-interoperable-archive profile must reject ENCRYPTED archives"
    );
    assert!(!report.findings.is_empty());
}

// ---------------------------------------------------------------------------
// Unknown/reserved profile identifiers: from_canonical_name rejects unknowns
// ---------------------------------------------------------------------------

#[test]
fn unknown_profile_name_is_not_recognised() {
    assert!(
        ComplianceProfile::from_canonical_name("reserved-future-profile-v99").is_none(),
        "unknown profile names must not be resolved to a known profile"
    );
}

#[test]
fn empty_profile_name_is_not_recognised() {
    assert!(ComplianceProfile::from_canonical_name("").is_none());
}

#[test]
fn profile_canonical_names_round_trip() {
    let profiles = [
        ComplianceProfile::MinimalInteroperableArchive,
        ComplianceProfile::StaticArchive,
        ComplianceProfile::Package,
        ComplianceProfile::StreamPackage,
        ComplianceProfile::Backup,
        ComplianceProfile::Telemetry,
        ComplianceProfile::LiveMedia,
    ];
    for profile in profiles {
        let name = profile.canonical_name();
        let parsed = ComplianceProfile::from_canonical_name(name)
            .expect("known profile name must round-trip");
        assert_eq!(profile, parsed);
    }
}
