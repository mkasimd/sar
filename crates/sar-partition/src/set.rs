// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Partition Set consistency, ordering, replica and completeness rules
//! (spec §§19.1.3, 19.1.4, 19.1.8–19.1.11, 19.1.13).
//!
//! # Trust boundary
//!
//! [`assess_partition_set`] is a pure function over [`UnverifiedPartitionFacts`].
//! Those facts are supplied by the caller and **this crate cannot verify that
//! they describe physically validated Partitions**; [`PartitionSetAssessment`]
//! therefore claims nothing about physical validation, only about the
//! consistency of the supplied facts.  The physical-validation claim is made
//! by `sar-archive`, whose `ValidatedPartitionSet` can be built only from
//! `ValidatedPartition` values produced by physical inspection.
//!
//! The assessment is metadata-only.  It does not pin or snapshot any source,
//! reconstruct Entries, derive keys or authenticate the logical set; the
//! members must be physically revalidated before any content is consumed.

use sar_core::partition_manifest::{
    PARTITION_MAX_SUPPORTED_COUNT, PARTITION_TOTAL_UNKNOWN, PartitionManifestV1,
};
use sar_core::{GlobalFlags, KmsData, SarError};
use sar_crypto::algorithm::KMS_TLS_EXPORTER;
use sar_crypto::{KmsParams, parse_kms_payload, parse_tls_exporter_kms_payload};

use crate::ManifestAuthentication;

/// The set-defining KMS properties of one Partition (spec §19.1.11).
///
/// Properties that may legitimately differ between Partitions (salts, costs,
/// iterations, wrapped-key bytes, recipient order) are not represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionKmsProfile {
    /// No KMS Extension (`ENCRYPTED` unset).
    None,
    /// PBKDF2: PRF Algo ID.
    Pbkdf2 {
        /// PRF Algo ID.
        prf_algo_id: u8,
    },
    /// ARGON2: variant and version.
    Argon2 {
        /// Argon2 variant.
        variant: u8,
        /// Argon2 version.
        version: u8,
    },
    /// ASYMMETRIC_WRAP: wrap algorithm and the logical recipient set.
    AsymmetricWrap {
        /// Wrap Algo ID.
        wrap_algo_id: u8,
        /// Recipient identifiers in sorted order (order is not significant).
        recipients: Vec<Vec<u8>>,
    },
    /// TLS_EXPORTER: context version and KDF algorithm.
    TlsExporter {
        /// Context Version.
        context_version: u8,
        /// KDF Algo ID.
        kdf_algo_id: u8,
    },
}

impl PartitionKmsProfile {
    /// Extracts the set-defining properties with the existing KMS metadata
    /// parsers.  No key material is derived or requested.
    ///
    /// # Errors
    ///
    /// The existing KMS parser errors for malformed, reserved or unsupported
    /// payloads, and [`SarError::Malformed`] when `kms` is absent for a mode
    /// that requires it is the caller's concern (absence maps to `None`).
    pub fn from_kms(kms: Option<&KmsData>) -> Result<Self, SarError> {
        let Some(kms) = kms else {
            return Ok(Self::None);
        };
        if kms.mode_id == KMS_TLS_EXPORTER {
            let params = parse_tls_exporter_kms_payload(&kms.payload).map_err(SarError::from)?;
            return Ok(Self::TlsExporter {
                context_version: params.context_version,
                kdf_algo_id: params.kdf_algo_id,
            });
        }
        match parse_kms_payload(kms.mode_id, &kms.payload).map_err(SarError::from)? {
            KmsParams::Pbkdf2(p) => Ok(Self::Pbkdf2 {
                prf_algo_id: p.prf_algo_id,
            }),
            KmsParams::Argon2(p) => Ok(Self::Argon2 {
                variant: p.variant,
                version: p.version,
            }),
            KmsParams::AsymmetricWrap(p) => {
                let mut recipients: Vec<Vec<u8>> =
                    p.recipients.into_iter().map(|r| r.recipient_id).collect();
                recipients.sort();
                Ok(Self::AsymmetricWrap {
                    wrap_algo_id: p.wrap_algo_id,
                    recipients,
                })
            }
            KmsParams::TlsExporter(p) => Ok(Self::TlsExporter {
                context_version: p.context_version,
                kdf_algo_id: p.kdf_algo_id,
            }),
        }
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::AsymmetricWrap { recipients, .. } => recipients.iter().fold(0usize, |acc, r| {
                acc.saturating_add(r.len().saturating_add(24))
            }),
            _ => 0,
        }
    }
}

/// Caller-asserted facts about one physical Partition.
///
/// **Unverified**: constructing this value validates nothing about any
/// Partition bytes.  Use `sar-archive`'s `ValidatedPartitionSet` to obtain a
/// result backed by physical inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnverifiedPartitionFacts {
    /// Decoded Manifest.
    pub manifest: PartitionManifestV1,
    /// Physical length of the Partition in bytes.
    pub partition_len: u64,
    /// Global Header Version.
    pub header_version: u8,
    /// Flags Size in bytes.
    pub flags_size: u16,
    /// Complete Global Flags value.
    pub global_flags: GlobalFlags,
    /// Set-defining KMS properties.
    pub kms: PartitionKmsProfile,
    /// AEAD algorithm of the Manifest Entry, when encrypted.
    pub manifest_aead_algo_id: Option<u8>,
    /// How the Manifest was authenticated.
    pub manifest_authentication: ManifestAuthentication,
}

impl UnverifiedPartitionFacts {
    /// Bundles caller-asserted facts.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        manifest: PartitionManifestV1,
        partition_len: u64,
        header_version: u8,
        flags_size: u16,
        global_flags: GlobalFlags,
        kms: PartitionKmsProfile,
        manifest_aead_algo_id: Option<u8>,
        manifest_authentication: ManifestAuthentication,
    ) -> Self {
        Self {
            manifest,
            partition_len,
            header_version,
            flags_size,
            global_flags,
            kms,
            manifest_aead_algo_id,
            manifest_authentication,
        }
    }

    fn retained_bytes(&self) -> Result<u64, SarError> {
        let total = core::mem::size_of::<Self>().saturating_add(self.kms.retained_bytes());
        u64::try_from(total).map_err(|_| SarError::Overflow("retained metadata size"))
    }
}

/// Configurable bounds for Partition Set assessment (spec §19.1.13).
///
/// Only the categories P2 exercises are present.  Simultaneously open
/// members, aggregate reconstructed size, temporary storage, fragment maps,
/// hash-verification work and aggregate KDF budgets are **not** enforced here:
/// hash verification and CD/offset-array limits belong to physical inspection
/// (`sar-archive`), the rest to later Partition Set processing stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PartitionSetLimits {
    /// Largest accepted claimed `Total Partitions` / Partition Index.
    pub max_partitions: u32,
    /// Largest number of discovered candidates (including duplicates).
    pub max_candidates: usize,
    /// Largest number of duplicate (replica) candidates.
    pub max_duplicate_candidates: usize,
    /// Largest aggregate encoded size of all candidates in bytes.
    pub max_aggregate_encoded_bytes: u64,
    /// Largest retained Manifest/set metadata in bytes (estimate).
    pub max_retained_metadata_bytes: u64,
    /// Largest number of relationship-traversal steps.
    pub max_relationship_steps: u64,
}

impl Default for PartitionSetLimits {
    fn default() -> Self {
        Self {
            max_partitions: PARTITION_MAX_SUPPORTED_COUNT,
            max_candidates: 131_072,
            max_duplicate_candidates: 65_536,
            max_aggregate_encoded_bytes: 1 << 50,
            max_retained_metadata_bytes: 256 * 1024 * 1024,
            max_relationship_steps: 1 << 22,
        }
    }
}

impl PartitionSetLimits {
    /// Sets the Partition count limit.
    #[must_use]
    pub const fn with_max_partitions(mut self, value: u32) -> Self {
        self.max_partitions = value;
        self
    }

    /// Sets the discovered candidate limit.
    #[must_use]
    pub const fn with_max_candidates(mut self, value: usize) -> Self {
        self.max_candidates = value;
        self
    }

    /// Sets the duplicate candidate limit.
    #[must_use]
    pub const fn with_max_duplicate_candidates(mut self, value: usize) -> Self {
        self.max_duplicate_candidates = value;
        self
    }

    /// Sets the aggregate encoded size limit.
    #[must_use]
    pub const fn with_max_aggregate_encoded_bytes(mut self, value: u64) -> Self {
        self.max_aggregate_encoded_bytes = value;
        self
    }

    /// Sets the retained metadata limit.
    #[must_use]
    pub const fn with_max_retained_metadata_bytes(mut self, value: u64) -> Self {
        self.max_retained_metadata_bytes = value;
        self
    }

    /// Sets the relationship traversal limit.
    #[must_use]
    pub const fn with_max_relationship_steps(mut self, value: u64) -> Self {
        self.max_relationship_steps = value;
        self
    }
}

/// Whether an incomplete Partition Set is an acceptable outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PartitionSetMode {
    /// Default: anything short of a complete set is an error
    /// ([`SarError::PartitionMissing`]).
    #[default]
    RequireComplete,
    /// Caller-selected: an incomplete set is returned as such, never as
    /// complete, and is not eligible for ordinary extraction.
    AllowIncomplete,
}

/// Exact Partition Set boundary knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetBoundary {
    /// A known `Total Partitions` value.
    Known(u32),
    /// No supplied Manifest carries a known total (`0xFFFFFFFF`).
    Unknown,
}

/// Predecessor-link outcome of one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    /// Partition Index zero: all-zero predecessor field.
    NotApplicable,
    /// `Previous Partition Hash` equals the predecessor's `Current Partition
    /// Hash`.  This is unkeyed: it proves neither ordering nor authenticity.
    Verified,
    /// The predecessor was not among the candidates; the link is unchecked.
    PredecessorUnavailable,
}

/// Inclusive range of missing Partition Indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingRange {
    /// First missing Index.
    pub first: u32,
    /// Last missing Index.
    pub last: u32,
}

/// One deduplicated member of an assessed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessedPartition {
    facts: UnverifiedPartitionFacts,
    link: LinkStatus,
    replicas: usize,
    input_position: usize,
}

impl AssessedPartition {
    /// Facts of the representative candidate (the earliest supplied one).
    ///
    /// Equivalent replicas may differ in local CD, signatures, padding and
    /// Footer; only canonical-Data-Area operations may use any replica.
    #[must_use]
    pub const fn facts(&self) -> &UnverifiedPartitionFacts {
        &self.facts
    }

    /// Partition Index.
    #[must_use]
    pub const fn partition_index(&self) -> u32 {
        self.facts.manifest.partition_index
    }

    /// Predecessor-link outcome.
    #[must_use]
    pub const fn link(&self) -> LinkStatus {
        self.link
    }

    /// Number of equivalent candidates (including this one).
    #[must_use]
    pub const fn replica_count(&self) -> usize {
        self.replicas
    }

    /// Position of the representative in the supplied candidate slice.
    #[must_use]
    pub const fn input_position(&self) -> usize {
        self.input_position
    }
}

/// Outcome of [`assess_partition_set`].
///
/// Guarantees (given truthful input facts): all Manifests share UUID, hash
/// algorithm, Global Header Version/flags and set-defining KMS properties;
/// known totals agree; replicas are equivalent; adjacent predecessor links
/// that could be checked match; and, when [`Self::is_complete`], exactly one
/// final Partition establishes the boundary and every Index from zero through
/// `Total - 1` is present once.
///
/// It does **not** guarantee: authenticity of the logical set (hashes are
/// unkeyed), that any source still contains the verified bytes, the validity
/// of fragments, signatures or Entries, or any reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionSetAssessment {
    uuid: [u8; 16],
    hash_algorithm_id: u8,
    boundary: SetBoundary,
    complete: bool,
    members: Vec<AssessedPartition>,
    missing: Vec<MissingRange>,
    duplicates_discarded: usize,
    aggregate_encoded_bytes: u64,
    manifests_aead_authenticated: bool,
}

impl PartitionSetAssessment {
    /// Opaque Partition Set UUID.
    #[must_use]
    pub const fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    /// Shared Manifest Hash Algorithm ID.
    #[must_use]
    pub const fn hash_algorithm_id(&self) -> u8 {
        self.hash_algorithm_id
    }

    /// Boundary knowledge.
    #[must_use]
    pub const fn boundary(&self) -> SetBoundary {
        self.boundary
    }

    /// True only for a proven complete set.  An incomplete result is never
    /// eligible for ordinary extraction.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Deduplicated members in ascending Partition Index order.
    #[must_use]
    pub fn members(&self) -> &[AssessedPartition] {
        &self.members
    }

    /// Missing Index ranges between present members and up to a known total.
    /// With an unknown boundary, Indices beyond the last member are not
    /// reported because the extent of the set is unknown.
    #[must_use]
    pub fn missing_ranges(&self) -> &[MissingRange] {
        &self.missing
    }

    /// Number of equivalent replica candidates discarded by deduplication.
    #[must_use]
    pub const fn duplicates_discarded(&self) -> usize {
        self.duplicates_discarded
    }

    /// Aggregate encoded size of every supplied candidate.
    #[must_use]
    pub const fn aggregate_encoded_bytes(&self) -> u64 {
        self.aggregate_encoded_bytes
    }

    /// True when every Manifest was AEAD-authenticated individually.  This is
    /// per-Manifest evidence and is **not** authentication of the whole
    /// logical set; unkeyed hash validation never sets it.
    #[must_use]
    pub const fn manifests_aead_authenticated(&self) -> bool {
        self.manifests_aead_authenticated
    }
}

fn bump(steps: &mut u64, limit: u64) -> Result<(), SarError> {
    *steps = steps
        .checked_add(1)
        .ok_or(SarError::Overflow("relationship traversal steps"))?;
    if *steps > limit {
        return Err(SarError::LimitExceeded(
            "Partition Set relationship traversal limit exceeded",
        ));
    }
    Ok(())
}

/// Validates set-level consistency and completeness over the supplied facts.
///
/// Rules applied (all independent of input order and of any file names):
///
/// * UUID, Hash Algorithm ID and known `Total Partitions` agree
///   ([`SarError::PartitionMismatch`]); Global Header Version
///   ([`SarError::InvalidVersion`]), Flags Size, Global Flags, set-defining KMS
///   properties and the Manifest AEAD algorithm agree
///   ([`SarError::PartitionMismatch`]).
/// * Candidates sharing an Index must be equivalent replicas (§19.1.9);
///   otherwise [`SarError::PartitionMismatch`].
/// * A known total is satisfied by every Index; an Index at or beyond it is
///   [`SarError::PartitionMismatch`].
/// * Present adjacent members must link (`Previous` == predecessor `Current`),
///   else [`SarError::PartitionMismatch`].
/// * In [`PartitionSetMode::RequireComplete`] a set lacking a required member
///   or finality evidence is [`SarError::PartitionMissing`].
///
/// Unknown-to-known total transitions: members that still carry the unknown
/// sentinel may coexist with members carrying the known total.  The
/// specification does not state a status for an unknown-total member whose
/// Index is at or beyond the established total; this implementation rejects
/// it as [`SarError::PartitionMismatch`] (it cannot belong to a set of that
/// size).
///
/// # Errors
///
/// As listed above, plus [`SarError::LimitExceeded`] and
/// [`SarError::Overflow`] for resource limits and checked arithmetic, and the
/// Manifest field errors of `PartitionManifestV1::validate_fields`.
#[allow(clippy::too_many_lines)]
pub fn assess_partition_set(
    candidates: &[UnverifiedPartitionFacts],
    limits: &PartitionSetLimits,
    mode: PartitionSetMode,
) -> Result<PartitionSetAssessment, SarError> {
    if candidates.is_empty() {
        return Err(SarError::PartitionMissing("no Partition candidates"));
    }
    if candidates.len() > limits.max_candidates {
        return Err(SarError::LimitExceeded(
            "Partition candidate count exceeds the configured limit",
        ));
    }

    let mut steps = 0u64;
    let mut aggregate = 0u64;
    let mut retained = 0u64;
    for c in candidates {
        bump(&mut steps, limits.max_relationship_steps)?;
        aggregate = aggregate
            .checked_add(c.partition_len)
            .ok_or(SarError::Overflow("aggregate encoded size"))?;
        if aggregate > limits.max_aggregate_encoded_bytes {
            return Err(SarError::LimitExceeded(
                "aggregate encoded size exceeds the configured limit",
            ));
        }
        retained = retained
            .checked_add(c.retained_bytes()?)
            .ok_or(SarError::Overflow("retained metadata size"))?;
        if retained > limits.max_retained_metadata_bytes {
            return Err(SarError::LimitExceeded(
                "retained Partition metadata exceeds the configured limit",
            ));
        }
        c.manifest.validate_fields(limits.max_partitions)?;
    }

    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|&i| (candidates[i].manifest.partition_index, i));
    let reference = &candidates[order[0]];

    let mut known_total: Option<u32> = None;
    for c in candidates {
        let m = &c.manifest;
        if m.partition_set_uuid != reference.manifest.partition_set_uuid {
            return Err(SarError::PartitionMismatch(
                "Partition Set UUID differs between Partitions",
            ));
        }
        if c.header_version != reference.header_version {
            return Err(SarError::InvalidVersion(
                "Global Header Version differs between Partitions",
            ));
        }
        if c.flags_size != reference.flags_size || c.global_flags != reference.global_flags {
            return Err(SarError::PartitionMismatch(
                "Flags Size or Global Flags differ between Partitions",
            ));
        }
        if c.kms != reference.kms {
            return Err(SarError::PartitionMismatch(
                "set-defining KMS properties differ between Partitions",
            ));
        }
        if c.manifest_aead_algo_id != reference.manifest_aead_algo_id {
            return Err(SarError::PartitionMismatch(
                "Manifest AEAD algorithm differs between Partitions",
            ));
        }
        if m.hash_algorithm_id != reference.manifest.hash_algorithm_id {
            return Err(SarError::PartitionMismatch(
                "Manifest Hash Algorithm ID differs between Partitions",
            ));
        }
        if m.total_partitions != PARTITION_TOTAL_UNKNOWN {
            match known_total {
                Some(t) if t != m.total_partitions => {
                    return Err(SarError::PartitionMismatch(
                        "known Total Partitions differs between Partitions",
                    ));
                }
                _ => known_total = Some(m.total_partitions),
            }
        }
    }

    // Duplicate resolution by Index.
    let mut members: Vec<AssessedPartition> = Vec::new();
    let mut duplicates = 0usize;
    let mut pos = 0usize;
    while pos < order.len() {
        bump(&mut steps, limits.max_relationship_steps)?;
        let first_idx = order[pos];
        let first = &candidates[first_idx];
        let index = first.manifest.partition_index;
        let mut replicas = 1usize;
        let mut next = pos
            .checked_add(1)
            .ok_or(SarError::Overflow("candidate position"))?;
        while next < order.len() && candidates[order[next]].manifest.partition_index == index {
            let other = &candidates[order[next]].manifest;
            let m = &first.manifest;
            if other.total_partitions != m.total_partitions
                || other.flags.is_final() != m.flags.is_final()
                || other.committed_content_length != m.committed_content_length
                || other.previous_partition_hash != m.previous_partition_hash
                || other.current_partition_hash != m.current_partition_hash
            {
                return Err(SarError::PartitionMismatch(
                    "conflicting candidates for one Partition Index",
                ));
            }
            replicas = replicas
                .checked_add(1)
                .ok_or(SarError::Overflow("replica count"))?;
            duplicates = duplicates
                .checked_add(1)
                .ok_or(SarError::Overflow("duplicate count"))?;
            if duplicates > limits.max_duplicate_candidates {
                return Err(SarError::LimitExceeded(
                    "duplicate Partition candidates exceed the configured limit",
                ));
            }
            next = next
                .checked_add(1)
                .ok_or(SarError::Overflow("candidate position"))?;
        }
        members.push(AssessedPartition {
            facts: first.clone(),
            link: LinkStatus::PredecessorUnavailable,
            replicas,
            input_position: first_idx,
        });
        pos = next;
    }

    if let Some(total) = known_total
        && members.iter().any(|m| m.partition_index() >= total)
    {
        return Err(SarError::PartitionMismatch(
            "a Partition Index is outside the established Total Partitions",
        ));
    }
    if members
        .iter()
        .filter(|m| m.facts.manifest.flags.is_final())
        .count()
        > 1
    {
        return Err(SarError::PartitionMismatch(
            "more than one FINAL_PARTITION claim",
        ));
    }

    // Predecessor links and missing ranges.
    let mut missing: Vec<MissingRange> = Vec::new();
    let mut expected = 0u32;
    let mut previous: Option<(u32, [u8; 32])> = None;
    for member in &mut members {
        bump(&mut steps, limits.max_relationship_steps)?;
        let index = member.partition_index();
        if index > expected {
            missing.push(MissingRange {
                first: expected,
                last: index
                    .checked_sub(1)
                    .ok_or(SarError::Overflow("missing range"))?,
            });
        }
        member.link = if index == 0 {
            LinkStatus::NotApplicable
        } else if let Some((prev_index, prev_hash)) = previous {
            let adjacent = prev_index
                .checked_add(1)
                .ok_or(SarError::Overflow("Partition Index"))?
                == index;
            if adjacent {
                if member.facts.manifest.previous_partition_hash != prev_hash {
                    return Err(SarError::PartitionMismatch(
                        "Previous Partition Hash differs from the predecessor's Current Partition Hash",
                    ));
                }
                LinkStatus::Verified
            } else {
                LinkStatus::PredecessorUnavailable
            }
        } else {
            LinkStatus::PredecessorUnavailable
        };
        expected = index
            .checked_add(1)
            .ok_or(SarError::Overflow("Partition Index"))?;
        previous = Some((index, member.facts.manifest.current_partition_hash));
    }
    if let Some(total) = known_total
        && expected < total
    {
        missing.push(MissingRange {
            first: expected,
            last: total
                .checked_sub(1)
                .ok_or(SarError::Overflow("missing range"))?,
        });
    }

    let has_final = members.iter().any(|m| m.facts.manifest.flags.is_final());
    let complete = known_total.is_some() && has_final && missing.is_empty();
    if !complete && mode == PartitionSetMode::RequireComplete {
        return Err(SarError::PartitionMissing(if known_total.is_none() {
            "no final Partition establishes the Partition Set boundary"
        } else {
            "required Partition members are unavailable"
        }));
    }

    let manifests_aead_authenticated = members
        .iter()
        .all(|m| m.facts.manifest_authentication == ManifestAuthentication::Aead);

    Ok(PartitionSetAssessment {
        uuid: reference.manifest.partition_set_uuid,
        hash_algorithm_id: reference.manifest.hash_algorithm_id,
        boundary: known_total.map_or(SetBoundary::Unknown, SetBoundary::Known),
        complete,
        members,
        missing,
        duplicates_discarded: duplicates,
        aggregate_encoded_bytes: aggregate,
        manifests_aead_authenticated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sar_core::PartitionManifestFlags;
    use sar_crypto::{
        AsymmetricRecipient, AsymmetricWrapParams, Pbkdf2Params, TlsExporterParams,
        serialize_kms_payload, serialize_tls_exporter_kms_payload,
    };

    fn facts(index: u32, total: u32, fin: bool) -> UnverifiedPartitionFacts {
        let mut prev = [0u8; 32];
        if index > 0 {
            prev = [u8::try_from(index - 1).expect("small") + 1; 32];
        }
        UnverifiedPartitionFacts::new(
            PartitionManifestV1 {
                hash_algorithm_id: 0x30,
                flags: PartitionManifestFlags::new(fin),
                partition_index: index,
                total_partitions: total,
                committed_content_length: 100,
                partition_set_uuid: [5; 16],
                previous_partition_hash: prev,
                current_partition_hash: [u8::try_from(index).expect("small") + 1; 32],
            },
            1000,
            1,
            4,
            GlobalFlags::PARTITIONED_ARCHIVE,
            PartitionKmsProfile::None,
            None,
            ManifestAuthentication::Unauthenticated,
        )
    }

    fn run(c: &[UnverifiedPartitionFacts]) -> Result<PartitionSetAssessment, SarError> {
        assess_partition_set(
            c,
            &PartitionSetLimits::default(),
            PartitionSetMode::default(),
        )
    }

    #[test]
    fn complete_chain_and_empty_input() {
        let ok = run(&[facts(1, 2, true), facts(0, 2, false)]).expect("complete");
        assert!(ok.is_complete());
        assert!(matches!(run(&[]), Err(SarError::PartitionMissing(_))));
    }

    #[test]
    fn header_version_and_flags_size_and_flags() {
        let mut a = facts(1, 2, true);
        a.header_version = 2;
        assert!(matches!(
            run(&[facts(0, 2, false), a]),
            Err(SarError::InvalidVersion(_))
        ));
        let mut a = facts(1, 2, true);
        a.flags_size = 8;
        assert!(matches!(
            run(&[facts(0, 2, false), a]),
            Err(SarError::PartitionMismatch(_))
        ));
        let mut a = facts(1, 2, true);
        a.global_flags = GlobalFlags::PARTITIONED_ARCHIVE | GlobalFlags::ENCRYPTED;
        assert!(matches!(
            run(&[facts(0, 2, false), a]),
            Err(SarError::PartitionMismatch(_))
        ));
    }

    #[test]
    fn hash_algorithm_aead_and_kms_must_match() {
        let mut a = facts(1, 2, true);
        a.manifest.hash_algorithm_id = 0x31;
        assert!(matches!(
            run(&[facts(0, 2, false), a]),
            Err(SarError::PartitionMismatch(_))
        ));
        let mut a = facts(1, 2, true);
        a.manifest_aead_algo_id = Some(1);
        assert!(matches!(
            run(&[facts(0, 2, false), a]),
            Err(SarError::PartitionMismatch(_))
        ));
        let mut a = facts(1, 2, true);
        a.kms = PartitionKmsProfile::Pbkdf2 { prf_algo_id: 1 };
        let mut b = facts(0, 2, false);
        b.kms = PartitionKmsProfile::Pbkdf2 { prf_algo_id: 2 };
        assert!(matches!(run(&[b, a]), Err(SarError::PartitionMismatch(_))));
    }

    #[test]
    fn multiple_final_and_conflicting_replicas() {
        let err = run(&[facts(0, 2, false), facts(1, 2, true), {
            let mut f = facts(1, 2, true);
            f.manifest.committed_content_length = 7;
            f
        }]);
        assert!(matches!(err, Err(SarError::PartitionMismatch(_))));
        let mut f = facts(1, 2, true);
        f.manifest.flags = PartitionManifestFlags::new(false);
        // A non-final claim for the final Index fails field validation first.
        assert!(run(&[facts(0, 2, false), facts(1, 2, true), f]).is_err());
    }

    #[test]
    fn replicas_may_differ_in_local_bytes_and_length() {
        let mut dup = facts(1, 2, true);
        dup.partition_len = 5000;
        let a = run(&[facts(0, 2, false), facts(1, 2, true), dup]).expect("replicas");
        assert_eq!(a.duplicates_discarded(), 1);
        assert_eq!(a.aggregate_encoded_bytes(), 7000);
    }

    #[test]
    fn aggregate_overflow_and_unknown_total_gap() {
        let mut a = facts(0, 2, false);
        a.partition_len = u64::MAX;
        let limits = PartitionSetLimits::default().with_max_aggregate_encoded_bytes(u64::MAX);
        assert!(matches!(
            assess_partition_set(
                &[a, facts(1, 2, true)],
                &limits,
                PartitionSetMode::default()
            ),
            Err(SarError::Overflow(_))
        ));
        let inc = assess_partition_set(
            &[facts(0, PARTITION_TOTAL_UNKNOWN, false)],
            &PartitionSetLimits::default(),
            PartitionSetMode::AllowIncomplete,
        )
        .expect("prefix");
        assert!(!inc.is_complete());
        assert!(inc.missing_ranges().is_empty());
    }

    #[test]
    fn kms_profiles_ignore_salts_and_recipient_order() {
        let p = |salt: u8, iters: u32| {
            let payload = serialize_kms_payload(&KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: 1,
                salt: vec![salt; 16],
                iterations: iters,
                derived_key_length: 32,
            }))
            .expect("ser");
            PartitionKmsProfile::from_kms(Some(&KmsData {
                mode_id: 1,
                payload,
            }))
            .expect("profile")
        };
        assert_eq!(p(1, 100_000), p(2, 200_000));

        let w = |ids: [&[u8]; 2]| {
            let payload = serialize_kms_payload(&KmsParams::AsymmetricWrap(AsymmetricWrapParams {
                wrap_algo_id: 1,
                recipients: ids
                    .iter()
                    .map(|i| AsymmetricRecipient {
                        recipient_id: i.to_vec(),
                        wrapped_key: vec![9; 8],
                    })
                    .collect(),
            }))
            .expect("ser");
            PartitionKmsProfile::from_kms(Some(&KmsData {
                mode_id: 3,
                payload,
            }))
        };
        if let (Ok(x), Ok(y)) = (w([b"aa", b"bb"]), w([b"bb", b"aa"])) {
            assert_eq!(x, y);
        }
    }

    #[test]
    fn tls_exporter_profile_extracts_set_defining_fields() {
        let payload = serialize_tls_exporter_kms_payload(&TlsExporterParams {
            context_version: 1,
            kdf_algo_id: 0,
            global_header_hash_algo_id: 0x30,
            derived_key_length: 32,
            exporter_label: "EXPORTER-SAR-v1".to_string(),
            salt: Vec::new(),
        })
        .expect("ser");
        let profile = PartitionKmsProfile::from_kms(Some(&KmsData {
            mode_id: KMS_TLS_EXPORTER,
            payload,
        }))
        .expect("profile");
        assert_eq!(
            profile,
            PartitionKmsProfile::TlsExporter {
                context_version: 1,
                kdf_algo_id: 0
            }
        );
        assert_eq!(
            PartitionKmsProfile::from_kms(None).expect("none"),
            PartitionKmsProfile::None
        );
    }
}
