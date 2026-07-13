// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use sar_core::{
    GlobalFlags, SarError, SarStatus,
    format::{parse_global_header, parse_lfh},
    limits::ResourceLimits,
};
use sar_stream::{SessionEntry, SessionEvent, SessionManager, SessionManagerConfig};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum VectorKind {
    Valid,
    Invalid,
    #[allow(dead_code)]
    Profile,
}

#[derive(Debug, Clone, Deserialize)]
struct ExpectedOutcome {
    valid: bool,
    status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ConformanceManifest {
    id: String,
    kind: VectorKind,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    features: Vec<String>,
    expected: ExpectedOutcome,
    #[serde(default)]
    deferred: bool,
}

fn vectors_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    workspace.join("test-vectors")
}

fn discover_manifests(
    dir: &Path,
    out: &mut Vec<(PathBuf, ConformanceManifest)>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            discover_manifests(&path, out)?;
            continue;
        }
        if path.file_name().is_some_and(|name| name == "manifest.json") {
            let raw = fs::read_to_string(&path)?;
            let manifest: ConformanceManifest = serde_json::from_str(&raw)?;
            out.push((path, manifest));
        }
    }
    Ok(())
}

fn run_strict_stream_transcript_validation(bytes: &[u8]) -> Result<(), SarError> {
    let limits = ResourceLimits::default();
    let (header, header_len) = parse_global_header(bytes, &limits)?;
    if !header.flags.contains(GlobalFlags::NO_INDEX) {
        return Err(SarError::FlagConflict(
            "strict stream transcript validation requires NO_INDEX",
        ));
    }

    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager.observe_global_header(&header)?;

    let mut pos = header_len;
    while pos < bytes.len() {
        let (lfh, lfh_len) = parse_lfh(&bytes[pos..], &header.flags, &limits)?;
        pos += lfh_len;

        if lfh.stream_id == 0 {
            return Err(SarError::StreamState(
                "strict stream transcript validation requires nonzero Stream ID",
            ));
        }

        let payload_len =
            usize::try_from(lfh.payload_size).map_err(|_| SarError::Overflow("payload length"))?;
        if pos + payload_len > bytes.len() {
            return Err(SarError::Truncated("stream transcript payload truncated"));
        }
        let payload = bytes[pos..pos + payload_len].to_vec();
        pos += payload_len;

        let result = manager.process_entry(&SessionEntry::new(lfh, payload, false))?;
        if result
            .events
            .iter()
            .any(|event| matches!(event, SessionEvent::StatefulInactive { .. }))
        {
            return Err(SarError::StreamState(
                "strict stream transcript validation requires active stateful mode",
            ));
        }
    }

    Ok(())
}

fn stream_transcript_manifests()
-> Result<Vec<(PathBuf, ConformanceManifest)>, Box<dyn std::error::Error>> {
    let mut manifests = Vec::new();
    discover_manifests(&vectors_root(), &mut manifests)?;
    manifests.retain(|(_, manifest)| {
        !manifest.deferred
            && manifest.file.is_some()
            && manifest
                .features
                .iter()
                .any(|feature| feature == "stream:transcript")
    });
    manifests.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(manifests)
}

#[test]
fn valid_stream_transcript_vectors_pass_strict_validation() {
    let manifests = stream_transcript_manifests().expect("discover manifests");
    let mut failures = Vec::new();
    let mut checked = 0usize;

    for (manifest_path, manifest) in &manifests {
        if manifest.kind != VectorKind::Valid {
            continue;
        }
        if !manifest.expected.valid {
            failures.push(format!(
                "[{}] {}: manifest kind=valid but expected.valid=false",
                manifest.id,
                manifest_path.display()
            ));
            continue;
        }
        checked += 1;
        let fixture_path = manifest_path
            .parent()
            .expect("manifest dir")
            .join(manifest.file.as_ref().expect("file"));
        let bytes = match fs::read(&fixture_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                failures.push(format!(
                    "[{}] cannot read {}: {}",
                    manifest.id,
                    fixture_path.display(),
                    err
                ));
                continue;
            }
        };
        if let Err(err) = run_strict_stream_transcript_validation(&bytes) {
            failures.push(format!(
                "[{}] {}: expected SAR_OK but got {}",
                manifest.id,
                fixture_path.display(),
                err
            ));
        }
    }

    assert!(
        !failures.is_empty() || checked > 0,
        "no valid stream transcript vectors found"
    );
    if !failures.is_empty() {
        panic!(
            "{}/{} valid stream transcript vector(s) failed:\n{}",
            failures.len(),
            checked,
            failures.join("\n")
        );
    }
}

#[test]
fn invalid_stream_transcript_vectors_fail_with_expected_status() {
    let manifests = stream_transcript_manifests().expect("discover manifests");
    let mut failures = Vec::new();
    let mut checked = 0usize;

    for (manifest_path, manifest) in &manifests {
        if manifest.kind != VectorKind::Invalid {
            continue;
        }
        if manifest.expected.valid {
            failures.push(format!(
                "[{}] {}: manifest kind=invalid but expected.valid=true",
                manifest.id,
                manifest_path.display()
            ));
            continue;
        }
        checked += 1;
        let fixture_path = manifest_path
            .parent()
            .expect("manifest dir")
            .join(manifest.file.as_ref().expect("file"));
        let bytes = match fs::read(&fixture_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                failures.push(format!(
                    "[{}] cannot read {}: {}",
                    manifest.id,
                    fixture_path.display(),
                    err
                ));
                continue;
            }
        };
        match run_strict_stream_transcript_validation(&bytes) {
            Ok(()) => failures.push(format!(
                "[{}] {}: expected {} but parsed successfully",
                manifest.id,
                fixture_path.display(),
                manifest.expected.status
            )),
            Err(err) => {
                let actual = err.status().name();
                if actual != manifest.expected.status {
                    failures.push(format!(
                        "[{}] {}: expected {}, got {} ({})",
                        manifest.id,
                        fixture_path.display(),
                        manifest.expected.status,
                        actual,
                        err
                    ));
                }
            }
        }
    }

    assert!(
        !failures.is_empty() || checked > 0,
        "no invalid stream transcript vectors found"
    );
    if !failures.is_empty() {
        panic!(
            "{}/{} invalid stream transcript vector(s) failed:\n{}",
            failures.len(),
            checked,
            failures.join("\n")
        );
    }
}

fn manifest_by_id(
    manifests: &[(PathBuf, ConformanceManifest)],
    id: &str,
) -> (PathBuf, ConformanceManifest) {
    manifests
        .iter()
        .find(|(_, manifest)| manifest.id == id)
        .cloned()
        .unwrap_or_else(|| panic!("missing manifest id {}", id))
}

#[test]
fn strict_validation_rejects_zero_stream_id_transcript() {
    let manifests = stream_transcript_manifests().expect("discover manifests");
    let (manifest_path, manifest) =
        manifest_by_id(&manifests, "stream-transcript-invalid-zero-stream-id");
    let fixture_path = manifest_path
        .parent()
        .expect("manifest dir")
        .join(manifest.file.expect("file"));
    let bytes = fs::read(&fixture_path).expect("fixture");
    let err = run_strict_stream_transcript_validation(&bytes).expect_err("must reject");
    assert_eq!(err.status(), SarStatus::ErrStreamState);
}

#[test]
fn strict_validation_rejects_session_control_without_no_index() {
    let manifests = stream_transcript_manifests().expect("discover manifests");
    let (manifest_path, manifest) = manifest_by_id(
        &manifests,
        "stream-transcript-invalid-session-control-without-no-index",
    );
    let fixture_path = manifest_path
        .parent()
        .expect("manifest dir")
        .join(manifest.file.expect("file"));
    let bytes = fs::read(&fixture_path).expect("fixture");
    let err = run_strict_stream_transcript_validation(&bytes).expect_err("must reject");
    assert_eq!(err.status(), SarStatus::ErrFlagConflict);
}

#[test]
fn strict_stream_transcript_validation_does_not_require_sar_archive() {
    let manifests = stream_transcript_manifests().expect("discover manifests");
    let (manifest_path, manifest) =
        manifest_by_id(&manifests, "stream-transcript-valid-session-init");
    let fixture_path = manifest_path
        .parent()
        .expect("manifest dir")
        .join(manifest.file.expect("file"));
    let bytes = fs::read(&fixture_path).expect("fixture");
    run_strict_stream_transcript_validation(&bytes).expect("strict validation");
}
