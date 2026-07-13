// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Loss-tolerant degradation policy for SAR archives.
//!
//! This crate codifies the policy decisions for `LOSS_TOLERANT` archives:
//! when degraded output is permitted, when gaps are recoverable, and what
//! errors must never be suppressed regardless of the `LOSS_TOLERANT` flag.
//!
//! Fragment reassembly algorithm and sparse reconstruction remain in their
//! respective crates (`sar-fragmentation` and `sar-sparse`).  Archive
//! reader/writer integration and `LOSS_TOLERANT` flag parsing remain in
//! `sar-core`.

// ── Recovery status ───────────────────────────────────────────────────────────

/// Classification of a reconstruction or recovery operation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// All expected data was reconstructed without any gaps or missing parts.
    Complete,
    /// Output was produced but is incomplete due to missing fragments or data
    /// gaps permitted by `LOSS_TOLERANT`.
    Degraded,
    /// Reconstruction failed and no meaningful output could be produced.
    Failed,
}

impl RecoveryStatus {
    /// Returns `true` when any output (complete or degraded) is available.
    #[must_use]
    pub fn has_output(&self) -> bool {
        matches!(self, Self::Complete | Self::Degraded)
    }

    /// Returns `true` when the output is complete (no missing data).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Returns `true` when the output is degraded (some data is missing).
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded)
    }
}

// ── Policy helpers ────────────────────────────────────────────────────────────

/// Returns `true` when `LOSS_TOLERANT` permits degraded output for a fragment
/// group that has a gap (missing fragment indices or absent last-fragment
/// marker).
///
/// This implements the policy: degraded output is allowed only when the entry
/// has `LOSS_TOLERANT` set.
///
/// # Invariant
///
/// `LOSS_TOLERANT` **never** suppresses:
///
/// * AEAD/authentication failures;
/// * signature failures;
/// * decompression failures;
/// * patch failures;
/// * malformed structure (invalid LFH/GH/CD/Footer);
/// * invalid sparse maps;
/// * deterministic reconstruction failures.
///
/// Only missing-fragment gaps and unavailable FEC data are covered by this
/// policy.
#[must_use]
pub fn gap_degraded_output_permitted(is_loss_tolerant: bool) -> bool {
    is_loss_tolerant
}

/// Classifies a reconstruction result into a [`RecoveryStatus`].
///
/// * If `failed` is `true`, returns [`RecoveryStatus::Failed`].
/// * If `has_gap` is `true`, returns [`RecoveryStatus::Degraded`].
/// * Otherwise returns [`RecoveryStatus::Complete`].
#[must_use]
pub fn classify_recovery(has_gap: bool, failed: bool) -> RecoveryStatus {
    if failed {
        RecoveryStatus::Failed
    } else if has_gap {
        RecoveryStatus::Degraded
    } else {
        RecoveryStatus::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_not_allowed_without_loss_tolerant() {
        assert!(!gap_degraded_output_permitted(false));
    }

    #[test]
    fn gap_allowed_with_loss_tolerant() {
        assert!(gap_degraded_output_permitted(true));
    }

    #[test]
    fn classify_complete() {
        assert_eq!(classify_recovery(false, false), RecoveryStatus::Complete);
        assert!(classify_recovery(false, false).is_complete());
        assert!(classify_recovery(false, false).has_output());
    }

    #[test]
    fn classify_degraded() {
        assert_eq!(classify_recovery(true, false), RecoveryStatus::Degraded);
        assert!(classify_recovery(true, false).is_degraded());
        assert!(classify_recovery(true, false).has_output());
    }

    #[test]
    fn classify_failed() {
        assert_eq!(classify_recovery(false, true), RecoveryStatus::Failed);
        assert!(!classify_recovery(false, true).has_output());
        // failed takes precedence over gap
        assert_eq!(classify_recovery(true, true), RecoveryStatus::Failed);
    }

    #[test]
    fn aead_failure_is_not_gap_and_must_not_be_suppressed() {
        // An AEAD failure sets failed=true; LOSS_TOLERANT cannot override it.
        // This test documents the invariant: classify_recovery(_, true) is always Failed.
        assert_eq!(classify_recovery(false, true), RecoveryStatus::Failed);
        assert_eq!(classify_recovery(true, true), RecoveryStatus::Failed);
    }
}
