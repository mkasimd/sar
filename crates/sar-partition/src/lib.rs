// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Partition support for SAR archives.
//!
//! # Current scope (M13b.3 P1-P2)
//!
//! P1: the status vocabulary for **one physical Partition**.  The Manifest
//! Version 1 codec lives in `sar-core`; the validated result
//! (`sar_archive::ValidatedPartition`) lives in `sar-archive` and can only be
//! produced by `ArchiveReader::inspect_partition`.
//!
//! P2: [`assess_partition_set`], the pure, metadata-only Partition Set rules
//! (identity, canonical order, replicas, predecessor links, header/KMS
//! consistency, completeness, limits) over [`UnverifiedPartitionFacts`].  The
//! facts are caller-asserted and carry no physical-validation claim; the
//! trusted wrapper is `sar_archive::ValidatedPartitionSet`, constructible only
//! from validated Partitions.  Nothing here pins a source, authenticates the
//! logical set, reconstructs Entries, orchestrates KMS or extracts; fragment
//! grouping and extraction remain future work.

mod set;

pub use set::{
    AssessedPartition, LinkStatus, MissingRange, PartitionKmsProfile, PartitionSetAssessment,
    PartitionSetLimits, PartitionSetMode, SetBoundary, UnverifiedPartitionFacts,
    assess_partition_set,
};

/// Marker for not-yet-implemented partition functionality.
///
/// Retained for source compatibility; Partition Set processing remains
/// unimplemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotImplemented;

/// How the Manifest of a locally validated Partition was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestAuthentication {
    /// Plaintext Manifest: only the unkeyed Current Partition Hash was
    /// checked.  This does not establish authenticity (spec §19.1.12).
    Unauthenticated,
    /// The Manifest was AEAD-decrypted and authenticated under the current
    /// Partition's KMS Master Secret.
    Aead,
}

/// Declared predecessor relationship; never reported as verified by P1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredecessorLink {
    /// Partition Index zero: no predecessor (all-zero digest verified).
    NotApplicable,
    /// The declared `Previous Partition Hash`, not compared with any
    /// predecessor.
    Unverified([u8; 32]),
}

/// Partition Set level status of a single locally validated Partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionSetStatus {
    /// No Partition Set rule was evaluated; the set is not known complete.
    NotEvaluated,
}
