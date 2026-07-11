use serde::Serialize;

use crate::archive::ArchiveMetadata;
use sar_core::flags::GlobalFlags;

/// SAR v1.0 conformance profile selector.
///
/// Each variant corresponds to a named conformance profile defined in
/// `test-vectors/profiles/README.md`. Profile validation applies
/// profile-specific acceptance/rejection rules on top of base SAR parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComplianceProfile {
    /// Minimal interoperable archive profile (legacy, pre-M12a).
    ///
    /// Kept for backward compatibility. Prefer the named profiles below
    /// for new code.
    MinimalInteroperableArchive,

    /// Static archive profile.
    ///
    /// Intended for immutable, indexed archives such as software
    /// distributions and data archives. Requires indexed archives.
    /// Rejects `NO_INDEX`, `LOSS_TOLERANT`, and unsupported algorithm IDs.
    StaticArchive,

    /// Package profile.
    ///
    /// Intended for software distribution packages requiring integrity.
    /// Similar to `StaticArchive` with stricter requirements. Rejects
    /// `NO_INDEX`, `LOSS_TOLERANT`, and custom/unregistered algorithms.
    Package,

    /// Stream-package profile.
    ///
    /// Intended for SAR archives delivered sequentially over a transport.
    /// Accepts `NO_INDEX` archives. Rejects duplicate Stream IDs and
    /// unauthenticated post-binding entries when TLS_EXPORTER is active.
    StreamPackage,

    /// Backup profile.
    ///
    /// Intended for system/data backups preserving complete filesystem
    /// state. Accepts sparse files, CDC, delta, and all metadata. Rejects
    /// unsafe filesystem metadata (absolute paths, traversal).
    Backup,

    /// Telemetry profile.
    ///
    /// Intended for high-frequency, potentially lossy telemetry streams.
    /// Accepts `LOSS_TOLERANT` entries within configured gap limits.
    /// Authentication/structural failures remain fatal.
    Telemetry,

    /// Live-media profile.
    ///
    /// Intended for real-time media streaming with bounded frame loss.
    /// Accepts `LOSS_TOLERANT` fragmented entries. Authentication failures
    /// remain fatal.
    LiveMedia,

    /// Standard profile roadmap target (not yet fully implemented).
    ///
    /// Reserved for future full-conformance oracle implementation.
    Standard,
}

impl ComplianceProfile {
    /// Returns the canonical profile name as used in manifest
    /// `profile_expectations`.
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::MinimalInteroperableArchive => "minimal-interoperable-archive",
            Self::StaticArchive => "static-archive",
            Self::Package => "package",
            Self::StreamPackage => "stream-package",
            Self::Backup => "backup",
            Self::Telemetry => "telemetry",
            Self::LiveMedia => "live-media",
            Self::Standard => "standard",
        }
    }

    /// Parses a canonical profile name into a [`ComplianceProfile`].
    ///
    /// Returns `None` if the name is not recognised.
    #[must_use]
    pub fn from_canonical_name(name: &str) -> Option<Self> {
        match name {
            "minimal-interoperable-archive" => Some(Self::MinimalInteroperableArchive),
            "static-archive" => Some(Self::StaticArchive),
            "package" => Some(Self::Package),
            "stream-package" => Some(Self::StreamPackage),
            "backup" => Some(Self::Backup),
            "telemetry" => Some(Self::Telemetry),
            "live-media" => Some(Self::LiveMedia),
            "standard" => Some(Self::Standard),
            _ => None,
        }
    }
}

/// Profile validation report.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    /// Whether archive matches the selected profile.
    pub compliant: bool,
    /// Human-readable findings.  Empty when `compliant` is `true`.
    pub findings: Vec<String>,
}

/// Validates archive metadata against a conformance profile.
///
/// This check validates the **global flags** and **archive-level structure**
/// against profile-specific rules. It does not validate individual entry
/// metadata (entry-level checks require iterating entries).
///
/// ## Known limitations (M12a)
///
/// - Entry-level `LOSS_TOLERANT` check requires iterating entries; only the
///   global `ENCRYPTED` and `NO_INDEX` flags are checked here.
/// - Algorithm ID checks are not yet implemented (requires entry iteration).
/// - Unsafe filesystem metadata rejection is implemented in the CLI extraction
///   layer, not here.
/// - `Standard` profile validation is a placeholder.
///
/// These limitations are documented in `docs/CONFORMANCE.md`.
#[must_use]
pub fn validate_archive_profile(
    meta: &ArchiveMetadata,
    profile: ComplianceProfile,
) -> ProfileReport {
    let mut findings = Vec::new();
    let flags = meta.global_header.flags;

    match profile {
        ComplianceProfile::MinimalInteroperableArchive => {
            // Legacy: only check ENCRYPTED flag.
            if flags.contains(GlobalFlags::ENCRYPTED) {
                findings.push(
                    "ENCRYPTED is unsupported in the minimal interoperable archive profile"
                        .to_string(),
                );
            }
        }

        ComplianceProfile::StaticArchive => {
            // Static archives must be indexed.
            if flags.contains(GlobalFlags::NO_INDEX) {
                findings.push(
                    "NO_INDEX archives are not accepted by the static-archive profile; \
                     an indexed archive with a central dictionary is required"
                        .to_string(),
                );
            }
        }

        ComplianceProfile::Package => {
            // Packages must be indexed.
            if flags.contains(GlobalFlags::NO_INDEX) {
                findings.push(
                    "NO_INDEX archives are not accepted by the package profile; \
                     indexed archives are required for package integrity"
                        .to_string(),
                );
            }
        }

        ComplianceProfile::StreamPackage => {
            // Stream packages accept both indexed and NO_INDEX.
        }

        ComplianceProfile::Backup => {
            // Backup accepts indexed and NO_INDEX.
        }

        ComplianceProfile::Telemetry => {
            // Telemetry accepts NO_INDEX and LOSS_TOLERANT.
        }

        ComplianceProfile::LiveMedia => {
            // Live-media accepts NO_INDEX and LOSS_TOLERANT with fragmentation.
        }

        ComplianceProfile::Standard => {
            findings.push(
                "Standard profile validation is not yet fully implemented (M12a placeholder)"
                    .to_string(),
            );
        }
    }

    ProfileReport {
        compliant: findings.is_empty(),
        findings,
    }
}
