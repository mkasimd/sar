use serde::Serialize;

use crate::{archive::ArchiveMetadata, flags::GlobalFlags};

/// Compliance profile selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceProfile {
    /// Minimal interoperable archive profile.
    MinimalInteroperableArchive,
    /// Standard profile roadmap target.
    Standard,
}

/// Profile validation report.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    /// Whether archive matches selected profile.
    pub compliant: bool,
    /// Human-readable findings.
    pub findings: Vec<String>,
}

/// Validates current archive metadata against a profile.
#[must_use]
pub fn validate_archive_profile(
    meta: &ArchiveMetadata,
    profile: ComplianceProfile,
) -> ProfileReport {
    let mut findings = Vec::new();
    let flags = meta.global_header.flags;

    match profile {
        ComplianceProfile::MinimalInteroperableArchive => {
            if flags.contains(GlobalFlags::ENCRYPTED) {
                findings
                    .push("ENCRYPTED is unsupported in current Milestones 1–3 core".to_string());
            }
            if flags.contains(GlobalFlags::COMPRESSED) {
                findings
                    .push("COMPRESSED must remain STORE-effective in Milestones 1–3".to_string());
            }
        }
        ComplianceProfile::Standard => {
            findings.push("Standard profile validation is not fully implemented yet".to_string());
        }
    }

    ProfileReport {
        compliant: findings.is_empty(),
        findings,
    }
}
