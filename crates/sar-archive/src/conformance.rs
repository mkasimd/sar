//! Conformance vector manifest types and schema validator.
//!
//! This module provides machine-readable types for SAR Protocol v1.0
//! conformance vectors and a minimal manifest schema validator.
//!
//! # Overview
//!
//! Each vector in `test-vectors/` has a `manifest.json` file following the
//! schema in `test-vectors/manifest.schema.json`. The types here map 1:1 to
//! that schema.
//!
//! # Usage
//!
//! ```rust,no_run
//! use sar_archive::conformance::{ConformanceManifest, validate_manifest_schema};
//! use std::fs;
//!
//! let raw = fs::read_to_string("test-vectors/valid/minimal/store-no-index/manifest.json").unwrap();
//! let manifest: ConformanceManifest = serde_json::from_str(&raw).unwrap();
//! let result = validate_manifest_schema(&manifest);
//! assert!(result.valid, "schema errors: {:?}", result.errors);
//! ```
//!
//! # Running all conformance checks
//!
//! ```bash
//! cargo test -p sar-archive --test conformance_tests
//! ```
//!
//! # Generating binary fixtures
//!
//! ```bash
//! cargo run --example generate_vectors -p sar-archive
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Manifest schema version supported by this validator.
pub const MANIFEST_SCHEMA_VERSION: u64 = 1;

/// A single SAR conformance vector manifest.
///
/// Maps to the JSON schema in `test-vectors/manifest.schema.json`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConformanceManifest {
    /// Manifest schema version. Must be [`MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Stable unique identifier for this vector.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// What this vector proves or exercises.
    pub description: String,
    /// Vector kind: valid, invalid, or profile.
    pub kind: VectorKind,
    /// Relative path to the binary `.sar` vector file from the manifest
    /// location. `None` for deferred/placeholder vectors.
    #[serde(default)]
    pub file: Option<String>,
    /// SAR profiles this vector is relevant to.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// SAR feature tags this vector exercises.
    #[serde(default)]
    pub features: Vec<String>,
    /// Expected parse/validation outcome.
    pub expected: ExpectedOutcome,
    /// Per-profile acceptance or rejection expectations.
    #[serde(default)]
    pub profile_expectations: HashMap<String, ProfileExpectation>,
    /// ResourceLimits overrides to apply when validating this vector.
    #[serde(default)]
    pub limits: HashMap<String, u64>,
    /// Human-readable notes.
    #[serde(default)]
    pub notes: Vec<String>,
    /// When `true`, the binary vector file has not yet been generated.
    /// The manifest documents intended behavior; see `notes` for the
    /// deferral reason.
    #[serde(default)]
    pub deferred: bool,
    /// When `true`, validating this vector requires an active key provider.
    /// Conformance checks that lack key material will skip this vector rather
    /// than report a false failure.
    #[serde(default)]
    pub requires_key_provider: bool,
    /// How the binary file was generated.
    #[serde(default)]
    pub generated_by: Option<String>,
}

/// Vector kind: valid, invalid, or profile-specific.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VectorKind {
    /// Must be accepted by any conformant implementation.
    Valid,
    /// Must be rejected by any conformant implementation.
    Invalid,
    /// Acceptance depends on the selected conformance profile.
    Profile,
}

/// Expected parse/validation outcome for a vector.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExpectedOutcome {
    /// Whether the vector is expected to parse successfully.
    pub valid: bool,
    /// Stable SAR status identifier (`SAR_OK`, `SAR_ERR_MALFORMED`, …).
    pub status: String,
    /// Optional short error class description.
    #[serde(default)]
    pub error: Option<String>,
    /// Expected warning identifiers.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Per-profile acceptance or rejection expectation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileExpectation {
    /// This profile must accept the vector.
    Accept,
    /// This profile must reject the vector.
    Reject,
    /// This vector is not applicable to this profile (skip).
    Skip,
}

/// Result of schema-level manifest validation.
#[derive(Debug, Clone)]
pub struct ManifestSchemaResult {
    /// The manifest `id` field.
    pub manifest_id: String,
    /// Whether all schema-level required fields are present and valid.
    pub valid: bool,
    /// Field-level schema errors found.
    pub errors: Vec<String>,
}

/// Validates schema-level required fields of a manifest.
///
/// This check does **not** read the binary vector file. It only validates that
/// the manifest has all required fields with acceptable values.
///
/// Returns a [`ManifestSchemaResult`] with `valid = true` if no errors were
/// found.
#[must_use]
pub fn validate_manifest_schema(manifest: &ConformanceManifest) -> ManifestSchemaResult {
    let mut errors = Vec::new();

    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        errors.push(format!(
            "unsupported schema_version {}: expected {}",
            manifest.schema_version, MANIFEST_SCHEMA_VERSION
        ));
    }
    if manifest.id.is_empty() {
        errors.push("id must not be empty".to_string());
    } else if !manifest
        .id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        errors.push(format!(
            "id '{}' must only contain ASCII letters, digits, hyphens, and underscores",
            manifest.id
        ));
    }
    if manifest.title.is_empty() {
        errors.push("title must not be empty".to_string());
    }
    if manifest.description.is_empty() {
        errors.push("description must not be empty".to_string());
    }
    if manifest.expected.status.is_empty() {
        errors.push("expected.status must not be empty".to_string());
    } else {
        let status = &manifest.expected.status;
        let known_statuses = [
            "SAR_OK",
            "SAR_ERR_GENERIC",
            "SAR_ERR_MALFORMED",
            "SAR_ERR_TRUNCATED",
            "SAR_ERR_UNSUPPORTED",
            "SAR_ERR_RESERVED_VALUE",
            "SAR_ERR_FLAG_CONFLICT",
            "SAR_ERR_INVALID_MAGIC",
            "SAR_ERR_AUTH_FAILED",
            "SAR_ERR_LIMIT_EXCEEDED",
            "SAR_ERR_BOUNDS",
            "SAR_ERR_OVERFLOW",
            "SAR_ERR_FRAGMENT_GAP",
            "SAR_ERR_INVALID_MAP",
            "SAR_ERR_INVALID_LENGTH",
            "SAR_ERR_STREAM_STATE",
            "SAR_ERR_DECRYPT_FAILED",
            "SAR_ERR_HASH_MISMATCH",
            "SAR_ERR_CRC_MISMATCH",
            "SAR_ERR_IO",
        ];
        if !known_statuses.contains(&status.as_str()) {
            errors.push(format!(
                "expected.status '{}' is not a known stable SAR status identifier; \
                 add it to the known list or use the nearest matching status",
                status
            ));
        }
    }
    if manifest.expected.valid && manifest.expected.status != "SAR_OK" {
        errors.push(format!(
            "expected.valid=true but expected.status='{}' (should be SAR_OK for valid vectors)",
            manifest.expected.status
        ));
    }
    if !manifest.expected.valid && manifest.expected.status == "SAR_OK" {
        errors.push(
            "expected.valid=false but expected.status='SAR_OK' (invalid vectors must not use SAR_OK)"
                .to_string(),
        );
    }

    ManifestSchemaResult {
        manifest_id: manifest.id.clone(),
        valid: errors.is_empty(),
        errors,
    }
}

/// Outcome of running a conformance check against a vector binary.
#[derive(Debug, Clone)]
pub struct ConformanceCheckResult {
    /// The manifest `id`.
    pub manifest_id: String,
    /// Whether the check passed (actual outcome matched expected outcome).
    pub passed: bool,
    /// Human-readable reason for the result.
    pub reason: String,
    /// Whether the vector was skipped (e.g. `deferred = true` or no file).
    pub skipped: bool,
}

/// Checks whether a SAR parse error matches the expected status identifier.
///
/// This maps `SarError` variants to the stable `SAR_ERR_*` status identifiers
/// used in manifests.
#[must_use]
pub fn sar_error_matches_expected_status(
    error: &sar_core::error::SarError,
    expected_status: &str,
) -> bool {
    use sar_core::error::SarError;
    match expected_status {
        "SAR_ERR_MALFORMED" => matches!(
            error,
            SarError::Malformed(_) | SarError::InvalidLength(_) | SarError::ReservedValue(_)
        ),
        "SAR_ERR_TRUNCATED" => matches!(
            error,
            SarError::Truncated(_) | SarError::Io(_)
        ),
        "SAR_ERR_UNSUPPORTED" => matches!(error, SarError::Unsupported(_)),
        "SAR_ERR_RESERVED_VALUE" => {
            matches!(error, SarError::ReservedValue(_) | SarError::Malformed(_))
        }
        "SAR_ERR_FLAG_CONFLICT" => matches!(error, SarError::FlagConflict(_)),
        "SAR_ERR_INVALID_MAGIC" => matches!(error, SarError::InvalidMagic),
        "SAR_ERR_AUTH_FAILED" => {
            matches!(
                error,
                SarError::AuthFailed(_) | SarError::DecryptFailed(_) | SarError::HashMismatch(_)
            )
        }
        "SAR_ERR_LIMIT_EXCEEDED" => matches!(error, SarError::LimitExceeded(_)),
        "SAR_ERR_BOUNDS" => matches!(error, SarError::Bounds(_)),
        "SAR_ERR_OVERFLOW" => matches!(error, SarError::Overflow(_)),
        "SAR_ERR_FRAGMENT_GAP" => matches!(error, SarError::FragmentGap(_)),
        "SAR_ERR_INVALID_MAP" => matches!(error, SarError::InvalidMap(_)),
        "SAR_ERR_INVALID_LENGTH" => {
            matches!(error, SarError::InvalidLength(_) | SarError::Malformed(_))
        }
        "SAR_ERR_STREAM_STATE" => matches!(error, SarError::StreamState(_)),
        "SAR_ERR_DECRYPT_FAILED" => {
            matches!(error, SarError::DecryptFailed(_) | SarError::AuthFailed(_))
        }
        "SAR_ERR_HASH_MISMATCH" => matches!(error, SarError::HashMismatch(_)),
        "SAR_ERR_CRC_MISMATCH" => matches!(error, SarError::CrcMismatch(_)),
        "SAR_ERR_IO" => matches!(error, SarError::Io(_)),
        "SAR_ERR_GENERIC" => matches!(error, SarError::Generic),
        _ => false,
    }
}

/// Runs a conformance check against a manifest and its binary vector file.
///
/// If `manifest.deferred` is `true` or `manifest.file` is `None`, the check
/// is skipped and returns a `skipped = true` result.
///
/// `base_dir` is the directory containing the manifest file. The binary
/// vector path is resolved relative to `base_dir`.
///
/// This function:
/// 1. Validates the manifest schema.
/// 2. Reads the referenced `.sar` binary.
/// 3. Attempts to open an `ArchiveReader` and read all entries.
/// 4. Compares the actual parse outcome to the expected outcome.
///
/// No filesystem side effects are performed. Resource limits may be overridden
/// via `manifest.limits` (keys: `max_payload_size`, `max_sparse_logical_size`,
/// `max_fec_value_size`, `max_tlv_count`).
pub fn run_conformance_check(
    manifest: &ConformanceManifest,
    base_dir: &std::path::Path,
) -> ConformanceCheckResult {
    // Skip deferred vectors.
    if manifest.deferred || manifest.file.is_none() {
        return ConformanceCheckResult {
            manifest_id: manifest.id.clone(),
            passed: true,
            reason: "skipped: deferred or no binary file".to_string(),
            skipped: true,
        };
    }

    // Validate schema first.
    let schema_result = validate_manifest_schema(manifest);
    if !schema_result.valid {
        return ConformanceCheckResult {
            manifest_id: manifest.id.clone(),
            passed: false,
            reason: format!("manifest schema errors: {:?}", schema_result.errors),
            skipped: false,
        };
    }

    let file_name = manifest.file.as_deref().unwrap_or("");
    let file_path = base_dir.join(file_name);

    // Read the binary.
    let bytes = match std::fs::read(&file_path) {
        Ok(b) => b,
        Err(e) => {
            return ConformanceCheckResult {
                manifest_id: manifest.id.clone(),
                passed: false,
                reason: format!("cannot read '{}': {}", file_path.display(), e),
                skipped: false,
            };
        }
    };

    // Build resource limits from manifest.limits.
    let mut limits = sar_core::limits::ResourceLimits::default();
    if let Some(&v) = manifest.limits.get("max_decoded_entry_size") {
        limits.max_decoded_entry_size = v;
    }
    if let Some(&v) = manifest.limits.get("max_payload_size") {
        // Alias used in manifests for decoded entry size.
        limits.max_decoded_entry_size = v;
    }
    if let Some(&v) = manifest.limits.get("max_sparse_logical_size") {
        // Manifest alias: maps to max_decoded_entry_size for sparse validation.
        limits.max_decoded_entry_size = v;
    }
    if let Some(&v) = manifest.limits.get("max_fec_value_size") {
        // Manifest alias: maps to max_fec_value_bytes.
        limits.max_fec_value_bytes =
            usize::try_from(v).unwrap_or(usize::MAX);
    }
    if let Some(&v) = manifest.limits.get("max_fec_value_bytes") {
        limits.max_fec_value_bytes =
            usize::try_from(v).unwrap_or(usize::MAX);
    }
    if let Some(&v) = manifest.limits.get("max_tlv_count") {
        limits.max_tlv_count =
            usize::try_from(v).unwrap_or(usize::MAX);
    }
    if let Some(&v) = manifest.limits.get("max_loss_tolerant_gap") {
        limits.max_loss_tolerant_gap = v;
    }

    // Attempt to parse the archive.
    let parse_result = attempt_full_parse(&bytes, &limits);

    // If this vector requires a key provider, a KeyMissing error is expected
    // and should be treated as a structural-level skip rather than a failure.
    // The archive can be validated structurally but full decryption requires
    // key material that is only available to tests with explicit key providers.
    if manifest.requires_key_provider {
        if let Err(ref e) = parse_result {
            if matches!(e, sar_core::error::SarError::KeyMissing(_)) {
                return ConformanceCheckResult {
                    manifest_id: manifest.id.clone(),
                    passed: true,
                    reason: "skipped: key provider required for full decryption validation"
                        .to_string(),
                    skipped: true,
                };
            }
        }
    }

    match (manifest.expected.valid, parse_result) {
        (true, Ok(())) => ConformanceCheckResult {
            manifest_id: manifest.id.clone(),
            passed: true,
            reason: "parsed successfully as expected".to_string(),
            skipped: false,
        },
        (true, Err(e)) => ConformanceCheckResult {
            manifest_id: manifest.id.clone(),
            passed: false,
            reason: format!("expected SAR_OK but got error: {}", e),
            skipped: false,
        },
        (false, Err(ref e)) => {
            let matches = sar_error_matches_expected_status(e, &manifest.expected.status);
            if matches {
                ConformanceCheckResult {
                    manifest_id: manifest.id.clone(),
                    passed: true,
                    reason: format!(
                        "correctly rejected with {} ({})",
                        manifest.expected.status, e
                    ),
                    skipped: false,
                }
            } else {
                ConformanceCheckResult {
                    manifest_id: manifest.id.clone(),
                    passed: false,
                    reason: format!(
                        "rejected with wrong error: expected {}, got: {}",
                        manifest.expected.status, e
                    ),
                    skipped: false,
                }
            }
        }
        (false, Ok(())) => ConformanceCheckResult {
            manifest_id: manifest.id.clone(),
            passed: false,
            reason: format!(
                "expected {} but parsed successfully (should have been rejected)",
                manifest.expected.status
            ),
            skipped: false,
        },
    }
}

/// Attempts to fully parse all entries in a SAR archive from bytes.
///
/// Uses an `ArchiveReader` with the given limits. Returns `Ok(())` if the
/// global header and all entries parse without error. Returns the first
/// `SarError` encountered otherwise.
fn attempt_full_parse(
    bytes: &[u8],
    limits: &sar_core::limits::ResourceLimits,
) -> Result<(), sar_core::error::SarError> {
    use std::io::Cursor;

    let cursor = Cursor::new(bytes);
    let opts = crate::archive::ArchiveReaderOptions {
        limits: *limits,
        ..Default::default()
    };
    let mut reader = crate::archive::ArchiveReader::with_options(cursor, opts)?;
    reader.read_global_header()?;

    // Drain all entries without decrypting payloads (we don't have keys for
    // test vectors; just validate structure and metadata).
    loop {
        match reader.next_entry() {
            Ok(Some(_entry)) => {
                // Entry parsed successfully; payload is available but we do
                // not try to decrypt/decompress it here unless the archive
                // is plaintext. For crypto vectors the validator may need to
                // be invoked with key material.
            }
            Ok(None) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Discovers all `manifest.json` files under a root directory.
///
/// Returns a sorted list of `(manifest_path, ConformanceManifest)` pairs.
/// Manifests that fail JSON deserialization are returned as `Err` entries.
///
/// # Errors
///
/// Returns an `io::Error` if the root directory cannot be read.
pub fn discover_manifests(
    root: &std::path::Path,
) -> std::io::Result<Vec<(std::path::PathBuf, Result<ConformanceManifest, String>)>> {
    let mut results = Vec::new();
    discover_manifests_inner(root, &mut results)?;
    results.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(results)
}

fn discover_manifests_inner(
    dir: &std::path::Path,
    out: &mut Vec<(std::path::PathBuf, Result<ConformanceManifest, String>)>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            discover_manifests_inner(&path, out)?;
        } else if path.file_name() == Some(std::ffi::OsStr::new("manifest.json")) {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let result = serde_json::from_str::<ConformanceManifest>(&raw)
                .map_err(|e| format!("JSON parse error in {}: {}", path.display(), e));
            out.push((path, result));
        }
    }
    Ok(())
}
