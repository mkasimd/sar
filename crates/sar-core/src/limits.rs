//! Unified resource-limit model for the SAR parser/writer pipeline.
//!
//! Every archive-declared size, count, offset, length, and algorithm parameter
//! is attacker-controlled when parsing untrusted input.  This module provides a
//! single configuration point — [`ResourceLimits`] — that is threaded through
//! every resource-sensitive path: LFH parsing, TLV parsing, Central Dictionary
//! parsing, normal/compressed/encrypted/sparse/fragmented entries, FEC repair,
//! archive-level recovery, loss-tolerant reconstruction, CLI extraction, and
//! verification.
//!
//! # Effective-limit model
//!
//! ```text
//! effective_limit = min(
//!     configured per-entry limit,
//!     configured per-buffer limit,
//!     configured total pipeline limit,
//!     optional runtime memory budget  // defense-in-depth only
//! )
//! ```
//!
//! Configured limits are mandatory and primary.  Runtime memory-budget checks
//! are optional defense-in-depth only.  Do not rely solely on available system
//! memory.
//!
//! # Error
//!
//! All resource-limit violations return [`crate::error::SarError::LimitExceeded`]
//! (status code `SAR_ERR_LIMIT_EXCEEDED = 27`).

use crate::error::SarError;

/// Unified resource limits applied throughout the SAR parse/read/write pipeline.
///
/// All limits are checked **before** allocating or reading the corresponding
/// number of bytes.  Every field that originates from the archive byte stream is
/// considered attacker-controlled.
///
/// Safe defaults (see [`ResourceLimits::default`]) are conservative values
/// suitable for general-purpose extraction.  Adjust them for environments with
/// tighter memory budgets or when processing known-benign archives.
///
/// # Usage
///
/// Pass a `ResourceLimits` value inside [`crate::archive::ArchiveReaderOptions`]:
///
/// ```rust
/// use sar_core::{ArchiveReaderOptions, limits::ResourceLimits};
///
/// let opts = ArchiveReaderOptions {
///     limits: ResourceLimits {
///         max_in_memory_buffer: 64 * 1024 * 1024,
///         ..ResourceLimits::default()
///     },
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    // ── Archive-level ────────────────────────────────────────────────────────
    /// Maximum total archive byte length accepted for in-memory operations
    /// (e.g. recovery/repair, archive-level verification).  Set to 0 to
    /// disable per-archive size checks; most streaming reads do not need
    /// this.  Default: 16 GiB.
    pub max_archive_size: u64,

    /// Maximum number of file entries accepted from the Central Dictionary.
    /// Bounds the `Vec` allocation for CD offsets.  Default: 1 000 000.
    pub max_entry_count: usize,

    // ── LFH header ───────────────────────────────────────────────────────────
    /// Maximum byte length of a single LFH header blob (the 4-byte
    /// `Header Size` field value).  Bounds the per-entry header allocation.
    /// Default: 1 MiB.
    pub max_lfh_header_bytes: usize,

    /// Maximum byte length of a file path (name + optional directory path
    /// components, combined).  The on-wire `Name Length` and `Path Length`
    /// fields are 16-bit, so the wire maximum is 65 535 bytes each, but a
    /// caller may tighten this.  Default: 65 535.
    pub max_path_bytes: usize,

    /// Maximum byte length of the global flags section
    /// (`Global Flags Size` field, u16).  Default: 65 535.
    pub max_global_flags_bytes: usize,

    /// Maximum byte length of the KMS payload embedded in the global header.
    /// Default: 64 KiB.
    pub max_kms_payload_bytes: usize,

    // ── TLV ──────────────────────────────────────────────────────────────────
    /// Maximum byte length of a single TLV value field.  Default: 1 MiB.
    pub max_tlv_bytes: usize,

    /// Maximum number of TLV entries in any TLV block (global or CD metadata).
    /// Default: 1 024.
    pub max_tlv_count: usize,

    // ── Central Dictionary ────────────────────────────────────────────────────
    /// Maximum byte length of the Central Dictionary region
    /// (`file_len - 8 - cd_offset`).  Default: 256 MiB.
    pub max_cd_bytes: u64,

    // ── Entry payload ─────────────────────────────────────────────────────────
    /// Maximum decoded (uncompressed) byte count for a single entry.
    /// Applied before allocating the decompression output buffer.
    /// Default: 1 GiB.
    pub max_decoded_entry_size: u64,

    /// Maximum byte count for any single in-memory buffer (encoded payload,
    /// intermediate decompress/decrypt scratch, FEC parity, etc.).
    /// Default: 1 GiB.
    pub max_in_memory_buffer: u64,

    /// Maximum cumulative bytes held in memory across all pipeline stages at
    /// any point in time.  This is a soft cap; the reader enforces it on a
    /// best-effort basis.  Default: 2 GiB.
    pub max_total_pipeline_memory: u64,

    // ── Sparse ───────────────────────────────────────────────────────────────
    /// Maximum byte length of the sparse map blob embedded in an LFH.
    /// Default: 8 MiB (accommodates ~500 000 32-bit extents).
    pub max_sparse_map_bytes: usize,

    /// Maximum number of sparse extent descriptors derived from the sparse
    /// map.  Default: 524 288.
    pub max_sparse_descriptors: usize,

    // ── Fragments ────────────────────────────────────────────────────────────
    /// Maximum number of fragment entries accepted when reassembling a
    /// fragmented file.  Default: 65 535.
    pub max_fragment_count: usize,

    /// Maximum total byte span of a fragment group
    /// (`max(absolute_offset + fragment_size)` across all descriptors in the
    /// group).  Default: 1 GiB.
    pub max_fragment_group_span: u64,

    /// Maximum byte gap between consecutive fragments when `LOSS_TOLERANT` is
    /// set.  Default: 1 GiB.
    pub max_loss_tolerant_gap: u64,

    // ── FEC ──────────────────────────────────────────────────────────────────
    /// Maximum byte length of any FEC value field stored in an LFH.
    /// Default: 256 MiB (matches the internal `MAX_PARITY_SIZE` constant in
    /// the XOR and RS codecs).
    pub max_fec_value_bytes: usize,

    // ── Recovery / repair ─────────────────────────────────────────────────────
    /// Maximum byte length of the protected range for archive-level recovery.
    /// Default: 16 GiB.
    pub max_recovery_protected_range: u64,

    /// Maximum working-set byte size for archive-level repair operations.
    /// Default: 2 GiB.
    pub max_repair_working_set: u64,

    /// Enables optional runtime-memory-budget enforcement in addition to the
    /// configured static limits. Default: false.
    pub use_runtime_memory_budget: bool,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_archive_size: 16 * 1024 * 1024 * 1024,
            max_entry_count: 1_000_000,
            max_lfh_header_bytes: 1024 * 1024,
            max_path_bytes: 65_535,
            max_global_flags_bytes: 65_535,
            max_kms_payload_bytes: 64 * 1024,
            max_tlv_bytes: 1024 * 1024,
            max_tlv_count: 1024,
            max_cd_bytes: 256 * 1024 * 1024,
            max_decoded_entry_size: 1024 * 1024 * 1024,
            max_in_memory_buffer: 1024 * 1024 * 1024,
            max_total_pipeline_memory: 2 * 1024 * 1024 * 1024,
            max_sparse_map_bytes: 8 * 1024 * 1024,
            max_sparse_descriptors: 524_288,
            max_fragment_count: 65_535,
            max_fragment_group_span: 1024 * 1024 * 1024,
            max_loss_tolerant_gap: 1024 * 1024 * 1024,
            max_fec_value_bytes: 256 * 1024 * 1024,
            max_recovery_protected_range: 16 * 1024 * 1024 * 1024,
            max_repair_working_set: 2 * 1024 * 1024 * 1024,
            use_runtime_memory_budget: false,
        }
    }
}

impl ResourceLimits {
    /// Returns a `ResourceLimits` with every field set to `u64::MAX` or
    /// `usize::MAX`, effectively disabling all limits.
    ///
    /// **Warning**: Use only in controlled test environments.  Production code
    /// must always use a bounded [`ResourceLimits`].
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_archive_size: u64::MAX,
            max_entry_count: usize::MAX,
            max_lfh_header_bytes: usize::MAX,
            max_path_bytes: usize::MAX,
            max_global_flags_bytes: usize::MAX,
            max_kms_payload_bytes: usize::MAX,
            max_tlv_bytes: usize::MAX,
            max_tlv_count: usize::MAX,
            max_cd_bytes: u64::MAX,
            max_decoded_entry_size: u64::MAX,
            max_in_memory_buffer: u64::MAX,
            max_total_pipeline_memory: u64::MAX,
            max_sparse_map_bytes: usize::MAX,
            max_sparse_descriptors: usize::MAX,
            max_fragment_count: usize::MAX,
            max_fragment_group_span: u64::MAX,
            max_loss_tolerant_gap: u64::MAX,
            max_fec_value_bytes: usize::MAX,
            max_recovery_protected_range: u64::MAX,
            max_repair_working_set: u64::MAX,
            use_runtime_memory_budget: false,
        }
    }

    // ── Checked-limit helpers ─────────────────────────────────────────────────

    /// Checks that `value` does not exceed `max_archive_size`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `value > max_archive_size`.
    pub fn check_archive_size(&self, value: u64) -> Result<(), SarError> {
        if self.max_archive_size > 0 && value > self.max_archive_size {
            return Err(SarError::LimitExceeded(
                "archive size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that `count` does not exceed `max_entry_count`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `count > max_entry_count`.
    pub fn check_entry_count(&self, count: usize) -> Result<(), SarError> {
        if count > self.max_entry_count {
            return Err(SarError::LimitExceeded(
                "CD entry count exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that `bytes` does not exceed `max_lfh_header_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_lfh_header_bytes`.
    pub fn check_lfh_header_bytes(&self, bytes: usize) -> Result<(), SarError> {
        if bytes > self.max_lfh_header_bytes {
            return Err(SarError::LimitExceeded(
                "LFH header size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that `bytes` does not exceed `max_path_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_path_bytes`.
    pub fn check_path_bytes(&self, bytes: usize) -> Result<(), SarError> {
        if bytes > self.max_path_bytes {
            return Err(SarError::LimitExceeded(
                "path length exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that `bytes` does not exceed `max_global_flags_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_global_flags_bytes`.
    pub fn check_global_flags_bytes(&self, bytes: usize) -> Result<(), SarError> {
        if bytes > self.max_global_flags_bytes {
            return Err(SarError::LimitExceeded(
                "global flags size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that `bytes` does not exceed `max_kms_payload_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_kms_payload_bytes`.
    pub fn check_kms_payload_bytes(&self, bytes: usize) -> Result<(), SarError> {
        if bytes > self.max_kms_payload_bytes {
            return Err(SarError::LimitExceeded(
                "KMS payload size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a single TLV value length does not exceed `max_tlv_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_tlv_bytes`.
    pub fn check_tlv_bytes(&self, bytes: usize) -> Result<(), SarError> {
        if bytes > self.max_tlv_bytes {
            return Err(SarError::LimitExceeded(
                "TLV value size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a TLV count does not exceed `max_tlv_count`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `count > max_tlv_count`.
    pub fn check_tlv_count(&self, count: usize) -> Result<(), SarError> {
        if count > self.max_tlv_count {
            return Err(SarError::LimitExceeded(
                "TLV count exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that the CD region byte length does not exceed `max_cd_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_cd_bytes`.
    pub fn check_cd_bytes(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_cd_bytes {
            return Err(SarError::LimitExceeded(
                "Central Dictionary size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a decoded entry size does not exceed `max_decoded_entry_size`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_decoded_entry_size`.
    pub fn check_decoded_entry_size(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_decoded_entry_size {
            return Err(SarError::LimitExceeded(
                "decoded entry size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a single in-memory buffer size does not exceed
    /// `max_in_memory_buffer`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_in_memory_buffer`.
    pub fn check_in_memory_buffer(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_in_memory_buffer {
            return Err(SarError::LimitExceeded(
                "in-memory buffer size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that cumulative pipeline memory does not exceed
    /// `max_total_pipeline_memory`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes >
    /// max_total_pipeline_memory`.
    pub fn check_total_pipeline_memory(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_total_pipeline_memory {
            return Err(SarError::LimitExceeded(
                "total pipeline memory exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a single buffer allocation fits the configured per-buffer
    /// and pipeline-wide limits.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when the requested byte count
    /// exceeds any configured allocation limit.
    pub fn check_allocation_bytes(&self, bytes: u64) -> Result<(), SarError> {
        self.check_in_memory_buffer(bytes)?;
        self.check_total_pipeline_memory(bytes)
    }

    /// Checks that a sparse map byte length does not exceed
    /// `max_sparse_map_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_sparse_map_bytes`.
    pub fn check_sparse_map_bytes(&self, bytes: usize) -> Result<(), SarError> {
        if bytes > self.max_sparse_map_bytes {
            return Err(SarError::LimitExceeded(
                "sparse map size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a sparse descriptor count does not exceed
    /// `max_sparse_descriptors`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `count > max_sparse_descriptors`.
    pub fn check_sparse_descriptor_count(&self, count: usize) -> Result<(), SarError> {
        if count > self.max_sparse_descriptors {
            return Err(SarError::LimitExceeded(
                "sparse descriptor count exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a fragment count does not exceed `max_fragment_count`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `count > max_fragment_count`.
    pub fn check_fragment_count(&self, count: usize) -> Result<(), SarError> {
        if count > self.max_fragment_count {
            return Err(SarError::LimitExceeded(
                "fragment count exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a fragment group span does not exceed
    /// `max_fragment_group_span`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_fragment_group_span`.
    pub fn check_fragment_group_span(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_fragment_group_span {
            return Err(SarError::LimitExceeded(
                "fragment group span exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a loss-tolerant gap size does not exceed
    /// `max_loss_tolerant_gap`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_loss_tolerant_gap`.
    pub fn check_loss_tolerant_gap(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_loss_tolerant_gap {
            return Err(SarError::LimitExceeded(
                "loss-tolerant gap exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that an FEC value byte length does not exceed
    /// `max_fec_value_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_fec_value_bytes`.
    pub fn check_fec_value_bytes(&self, bytes: usize) -> Result<(), SarError> {
        if bytes > self.max_fec_value_bytes {
            return Err(SarError::LimitExceeded(
                "FEC value size exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a recovery protected range length does not exceed
    /// `max_recovery_protected_range`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_recovery_protected_range`.
    pub fn check_recovery_protected_range(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_recovery_protected_range {
            return Err(SarError::LimitExceeded(
                "recovery protected range exceeds configured limit",
            ));
        }
        Ok(())
    }

    /// Checks that a repair working set does not exceed `max_repair_working_set`.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] when `bytes > max_repair_working_set`.
    pub fn check_repair_working_set(&self, bytes: u64) -> Result<(), SarError> {
        if bytes > self.max_repair_working_set {
            return Err(SarError::LimitExceeded(
                "repair working set exceeds configured limit",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_nonzero() {
        let l = ResourceLimits::default();
        assert!(l.max_entry_count > 0);
        assert!(l.max_lfh_header_bytes > 0);
        assert!(l.max_decoded_entry_size > 0);
        assert!(l.max_fec_value_bytes > 0);
    }

    #[test]
    fn check_archive_size_pass() {
        let l = ResourceLimits::default();
        assert!(l.check_archive_size(1024).is_ok());
    }

    #[test]
    fn check_archive_size_fail() {
        let l = ResourceLimits {
            max_archive_size: 100,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            l.check_archive_size(101),
            Err(SarError::LimitExceeded(_))
        ));
    }

    #[test]
    fn check_entry_count_fail() {
        let l = ResourceLimits {
            max_entry_count: 5,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            l.check_entry_count(6),
            Err(SarError::LimitExceeded(_))
        ));
    }

    #[test]
    fn check_cd_bytes_fail() {
        let l = ResourceLimits {
            max_cd_bytes: 1000,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            l.check_cd_bytes(1001),
            Err(SarError::LimitExceeded(_))
        ));
    }

    #[test]
    fn check_fec_value_bytes_fail() {
        let l = ResourceLimits {
            max_fec_value_bytes: 512,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            l.check_fec_value_bytes(513),
            Err(SarError::LimitExceeded(_))
        ));
    }

    #[test]
    fn unlimited_passes_all_checks() {
        let l = ResourceLimits::unlimited();
        assert!(l.check_archive_size(u64::MAX).is_ok());
        assert!(l.check_entry_count(usize::MAX).is_ok());
        assert!(l.check_lfh_header_bytes(usize::MAX).is_ok());
        assert!(l.check_decoded_entry_size(u64::MAX).is_ok());
        assert!(l.check_fec_value_bytes(usize::MAX).is_ok());
    }

    #[test]
    fn check_sparse_map_bytes_fail() {
        let l = ResourceLimits {
            max_sparse_map_bytes: 100,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            l.check_sparse_map_bytes(101),
            Err(SarError::LimitExceeded(_))
        ));
    }

    #[test]
    fn check_fragment_count_fail() {
        let l = ResourceLimits {
            max_fragment_count: 3,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            l.check_fragment_count(4),
            Err(SarError::LimitExceeded(_))
        ));
    }
}
