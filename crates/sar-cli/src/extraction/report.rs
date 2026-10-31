// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Internal description of how a failed extraction left the destination.
//!
//! Extraction is fail-fast and not transactional: when it fails after the
//! destination was changed, already published Entries and other run-created
//! objects may remain. The primary failure keeps its specific SAR status; this
//! report only adds what is known about leftovers, and never replaces or masks
//! the primary error. It is a CLI-internal type: no wire status and no
//! library API is involved.

use sar_core::SarError;

/// What a failed run is known to have left in the destination.
#[derive(Debug, Default, Clone)]
pub(crate) struct ExtractionReport {
    /// True when the destination may differ from its state before the run
    /// (created directories, published Entries, replaced objects, restored
    /// metadata, or run-owned temporary objects that could not be removed).
    pub(crate) partial_changes: bool,
    /// Run-owned temporary objects that could not be restored or removed,
    /// described without any extracted content.
    pub(crate) cleanup_failures: Vec<String>,
}

/// A failed extraction: the primary error plus the report.
#[derive(Debug)]
pub(crate) struct ExtractionFailure {
    pub(crate) error: SarError,
    pub(crate) report: ExtractionReport,
}

impl From<SarError> for ExtractionFailure {
    fn from(error: SarError) -> Self {
        Self {
            error,
            report: ExtractionReport::default(),
        }
    }
}

impl ExtractionReport {
    /// Diagnostic lines printed after the primary error line.
    pub(crate) fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.partial_changes {
            notes.push(
                "extraction is incomplete: partial changes to the destination may remain \
                 (the extraction is not transactional and nothing was rolled back)"
                    .to_string(),
            );
        }
        for failure in &self.cleanup_failures {
            notes.push(format!(
                "cleanup error (separate from the failure above): {failure}"
            ));
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use super::ExtractionReport;

    #[test]
    fn notes_distinguish_partial_changes_from_cleanup_failures() {
        assert!(ExtractionReport::default().notes().is_empty());
        let report = ExtractionReport {
            partial_changes: true,
            cleanup_failures: vec!["left '.sar-tmp-x'".to_string()],
        };
        let notes = report.notes();
        assert_eq!(notes.len(), 2);
        assert!(notes[0].contains("incomplete") && notes[0].contains("partial changes"));
        assert!(notes[1].starts_with("cleanup error") && notes[1].contains(".sar-tmp-x"));
    }
}
