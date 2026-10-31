// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Partition support for SAR archives.
//!
//! # Current scope (M13b.3 P1)
//!
//! This crate owns only the status vocabulary reported for **one physical
//! Partition**.  The Manifest Version 1 codec lives in `sar-core`.  The
//! validated result (`sar_archive::ValidatedPartition`) lives in `sar-archive`
//! and can only be produced by `ArchiveReader::inspect_partition`, which owns
//! physical verification; this crate deliberately offers no constructor that
//! could forge a validation or authentication claim.
//!
//! A validated Partition establishes only individual physical Partition
//! validity.  It is **not** a Partition Set validator: predecessor links,
//! set-wide consistency (UUID, total, hash algorithm, Global Header, KMS),
//! duplicate resolution, completeness, fragment reconstruction and extraction
//! are not evaluated.  Partition Set assembly remains future work.

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
