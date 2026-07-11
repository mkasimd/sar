//! Additional conformance vector manifest validation tests.
//!
//! This file extends `conformance_tests.rs` with:
//! - File-reference existence checks for all non-deferred vectors.
//! - Feature-consistency checks (compression/crypto fields vs. feature tags).
//! - Profile vector file-existence checks.
//!
//! # Running
//!
//! ```bash
//! cargo test -p sar-archive --test conformance_manifest_tests
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
};

use sar_archive::{
    conformance::{TransformExpectation, VectorKind, discover_manifests, validate_manifest_schema},
    recovery::inspect_recovery_metadata,
};
use sar_core::{
    GlobalFlags, ResourceLimits,
    fec::FecSummary,
    format::{GLOBAL_HEADER_FLAGS_OFFSET, parse_global_header, parse_lfh},
};
use sar_delta::{PATCH_ALGO_BSDIFF, PATCH_ALGO_STORE_PATCH, PATCH_ALGO_VCDIFF};
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR};
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Helper: locate test-vectors root relative to CARGO_MANIFEST_DIR
// ---------------------------------------------------------------------------

fn vectors_root() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace = Path::new(manifest_dir)
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    workspace.join("test-vectors")
}

fn manifest_paths() -> Vec<PathBuf> {
    discover_manifests(&vectors_root())
        .expect("discover manifests")
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

fn raw_manifest_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("read manifest")).expect("parse manifest")
}

fn object_keys(obj: &Map<String, Value>) -> impl Iterator<Item = &str> {
    obj.keys().map(String::as_str)
}

fn value_is_string_or_null(value: &Value) -> bool {
    value.is_null() || value.is_string()
}

fn value_is_octal_permissions_or_null(value: &Value) -> bool {
    value.is_null()
        || value
            .as_str()
            .is_some_and(|s| s.len() >= 4 && s.len() <= 5 && s.starts_with('0'))
            && value
                .as_str()
                .is_some_and(|s| s.chars().all(|ch| ('0'..='7').contains(&ch)))
}

fn validate_payload_generation_shape(value: &Value, label: &str, failures: &mut Vec<String>) {
    let Some(object) = value.as_object() else {
        failures.push(format!(
            "{label}: payload_generation must be an object or null"
        ));
        return;
    };
    let allowed = ["kind", "byte_hex", "pattern_hex", "length", "path"];
    let required = ["kind"];
    for key in object_keys(object) {
        if !allowed.contains(&key) {
            failures.push(format!(
                "{label}: payload_generation has unexpected key '{key}'"
            ));
        }
    }
    for key in required {
        if !object.contains_key(key) {
            failures.push(format!(
                "{label}: payload_generation missing required key '{key}'"
            ));
        }
    }
}

fn validate_entries_shape(entries: &Value, label: &str, failures: &mut Vec<String>) {
    let Some(array) = entries.as_array() else {
        failures.push(format!("{label}: entries must be an array"));
        return;
    };
    let allowed = [
        "name",
        "kind",
        "payload_utf8",
        "payload_hex",
        "payload_sha256",
        "size",
        "logical_size",
        "payload_generation",
        "symlink_target",
        "permissions",
        "uid",
        "gid",
        "mtime",
        "atime",
        "ctime",
        "extents",
    ];
    for (index, entry) in array.iter().enumerate() {
        let Some(object) = entry.as_object() else {
            failures.push(format!("{label}[{index}]: entry must be an object"));
            continue;
        };
        for key in object_keys(object) {
            if !allowed.contains(&key) {
                failures.push(format!("{label}[{index}]: unexpected entry key '{key}'"));
            }
        }
        for key in ["name", "kind"] {
            if !object.contains_key(key) {
                failures.push(format!("{label}[{index}]: missing required key '{key}'"));
            }
        }
        if let Some(value) = object.get("payload_generation")
            && !value.is_null()
        {
            validate_payload_generation_shape(value, &format!("{label}[{index}]"), failures);
        }
        if let Some(extents) = object.get("extents") {
            let Some(extents) = extents.as_array() else {
                failures.push(format!("{label}[{index}]: extents must be an array"));
                continue;
            };
            for (extent_index, extent) in extents.iter().enumerate() {
                let Some(extent) = extent.as_object() else {
                    failures.push(format!(
                        "{label}[{index}].extents[{extent_index}]: extent must be an object"
                    ));
                    continue;
                };
                for key in object_keys(extent) {
                    if !["offset", "length"].contains(&key) {
                        failures.push(format!(
                            "{label}[{index}].extents[{extent_index}]: unexpected key '{key}'"
                        ));
                    }
                }
                for key in ["offset", "length"] {
                    if !extent.contains_key(key) {
                        failures.push(format!(
                            "{label}[{index}].extents[{extent_index}]: missing required key '{key}'"
                        ));
                    }
                }
            }
            if let Some(permissions) = object.get("permissions")
                && !value_is_octal_permissions_or_null(permissions)
            {
                failures.push(format!(
                    "{label}[{index}]: permissions must be null or an octal string with leading zero (e.g. '0644', '0755', '04755')"
                ));
            }
        }
    }
}

fn validate_base_files_shape(base_files: &Value, label: &str, failures: &mut Vec<String>) {
    let Some(array) = base_files.as_array() else {
        failures.push(format!("{label}: base_files must be an array"));
        return;
    };
    let allowed = [
        "path",
        "payload_utf8",
        "payload_hex",
        "payload_sha256",
        "size",
        "payload_generation",
    ];
    for (index, base_file) in array.iter().enumerate() {
        let Some(object) = base_file.as_object() else {
            failures.push(format!("{label}[{index}]: base file must be an object"));
            continue;
        };
        for key in object_keys(object) {
            if !allowed.contains(&key) {
                failures.push(format!(
                    "{label}[{index}]: unexpected base_files key '{key}'"
                ));
            }
        }
        if !object.contains_key("path") {
            failures.push(format!("{label}[{index}]: missing required key 'path'"));
        }
        if let Some(value) = object.get("payload_generation")
            && !value.is_null()
        {
            validate_payload_generation_shape(value, &format!("{label}[{index}]"), failures);
        }
    }
}

fn validate_transform_shape(
    value: &Value,
    label: &str,
    allow_crypto_fields: bool,
    failures: &mut Vec<String>,
) {
    if let Some(boolean) = value.as_bool() {
        if boolean {
            failures.push(format!("{label}: boolean form must be false, not true"));
        }
        return;
    }

    let Some(object) = value.as_object() else {
        failures.push(format!("{label}: must be false or an object"));
        return;
    };
    let allowed: &[&str] = if allow_crypto_fields {
        &["algorithm", "id", "password", "kms"]
    } else {
        &["algorithm", "id"]
    };
    for key in object_keys(object) {
        if !allowed.contains(&key) {
            failures.push(format!("{label}: unexpected key '{key}'"));
        }
    }
    for key in ["algorithm", "id"] {
        if !object.contains_key(key) {
            failures.push(format!("{label}: missing required key '{key}'"));
        }
    }
    if allow_crypto_fields
        && let Some(kms) = object.get("kms")
        && !kms.is_null()
    {
        let Some(kms) = kms.as_object() else {
            failures.push(format!("{label}.kms: must be an object or null"));
            return;
        };
        for key in object_keys(kms) {
            if !["mode", "salt_hex", "kdf", "iterations"].contains(&key) {
                failures.push(format!("{label}.kms: unexpected key '{key}'"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test: every non-deferred manifest with a non-null file references an
//       existing file on disk (covers profile manifests too).
// ---------------------------------------------------------------------------

#[test]
fn all_non_deferred_vector_files_exist() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue, // JSON parse errors caught elsewhere
        };

        // Deferred manifests must NOT have an existing binary file.
        if manifest.deferred {
            if let Some(ref file_name) = manifest.file {
                let base_dir = path.parent().expect("manifest dir");
                let file_path = base_dir.join(file_name);
                if file_path.exists() {
                    failures.push(format!(
                        "[{}] marked deferred but binary exists: {}",
                        manifest.id,
                        file_path.display()
                    ));
                }
            }
            continue;
        }

        // Non-deferred manifests with a non-null file must have that file.
        if let Some(ref file_name) = manifest.file {
            let base_dir = path.parent().expect("manifest dir");
            let file_path = base_dir.join(file_name);
            if !file_path.exists() {
                failures.push(format!(
                    "[{}] {} — referenced file does not exist: {}",
                    manifest.id,
                    path.display(),
                    file_path.display()
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} file-reference issue(s) found:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    let checked = manifests
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .ok()
                .is_some_and(|m| !m.deferred && m.file.is_some())
        })
        .count();
    println!("All {} non-deferred file references exist.", checked);
}

// ---------------------------------------------------------------------------
// Test: profile vectors with non-null files reference existing files.
//       (Subset check for extra visibility on profile manifest path bugs.)
// ---------------------------------------------------------------------------

#[test]
fn profile_vector_files_exist() {
    let root = vectors_root();
    let profiles_dir = root.join("profiles");
    let manifests = discover_manifests(&profiles_dir).expect("discover profile manifests");

    let mut failures = Vec::new();
    let mut checked = 0usize;

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(e) => {
                failures.push(format!("JSON parse error in {}: {}", path.display(), e));
                continue;
            }
        };

        if manifest.deferred || manifest.file.is_none() {
            continue;
        }

        let base_dir = path.parent().expect("manifest dir");
        let file_name = manifest
            .file
            .as_deref()
            .expect("non-deferred profile manifest has file");
        let file_path = base_dir.join(file_name);
        checked += 1;

        if !file_path.exists() {
            failures.push(format!(
                "[{}] {} — profile vector file does not exist: {} (resolved: {})",
                manifest.id,
                path.display(),
                file_name,
                file_path.display()
            ));
        } else {
            println!(
                "[OK] {} — profile file exists: {}",
                manifest.id,
                file_path.display()
            );
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}/{} profile vector file(s) missing:\n{}",
            failures.len(),
            checked,
            failures.join("\n")
        );
    }

    println!("{} profile vector file references all valid.", checked);
}

// ---------------------------------------------------------------------------
// Test: compression field and compression:* feature tags are consistent.
// ---------------------------------------------------------------------------

#[test]
fn compression_feature_consistency() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        // boolean true is never valid
        if let TransformExpectation::Disabled(true) = &manifest.compression {
            failures.push(format!(
                "[{}] {}: compression must be false or an object, not true",
                manifest.id,
                path.display()
            ));
            continue;
        }

        let has_compression_feature = manifest
            .features
            .iter()
            .any(|f| f.starts_with("compression:"));

        match &manifest.compression {
            TransformExpectation::Enabled(info) => {
                let expected_tag = format!("compression:{}", info.algorithm);
                if !manifest.features.iter().any(|f| f == &expected_tag) {
                    failures.push(format!(
                        "[{}] {}: compression={{algorithm: {}}} but '{}' missing from features",
                        manifest.id,
                        path.display(),
                        info.algorithm,
                        expected_tag
                    ));
                }
            }
            TransformExpectation::Disabled(false) => {
                if has_compression_feature {
                    let tags: Vec<_> = manifest
                        .features
                        .iter()
                        .filter(|f| f.starts_with("compression:"))
                        .collect();
                    failures.push(format!(
                        "[{}] {}: compression=false but features contains {:?}",
                        manifest.id,
                        path.display(),
                        tags
                    ));
                }
            }
            TransformExpectation::Disabled(_) => {}
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} compression/feature consistency failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    println!(
        "All {} manifests pass compression/feature consistency.",
        manifests.iter().filter(|(_, r)| r.is_ok()).count()
    );
}

// ---------------------------------------------------------------------------
// Test: crypto field and crypto:* feature tags are consistent.
// ---------------------------------------------------------------------------

#[test]
fn crypto_feature_consistency() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        // boolean true is never valid
        if let TransformExpectation::Disabled(true) = &manifest.crypto {
            failures.push(format!(
                "[{}] {}: crypto must be false or an object, not true",
                manifest.id,
                path.display()
            ));
            continue;
        }

        let has_crypto_feature = manifest.features.iter().any(|f| f.starts_with("crypto:"));

        match &manifest.crypto {
            TransformExpectation::Enabled(info) => {
                let expected_tag = format!("crypto:{}", info.algorithm);
                if !manifest.features.iter().any(|f| f == &expected_tag) {
                    failures.push(format!(
                        "[{}] {}: crypto={{algorithm: {}}} but '{}' missing from features",
                        manifest.id,
                        path.display(),
                        info.algorithm,
                        expected_tag
                    ));
                }
            }
            TransformExpectation::Disabled(false) => {
                if has_crypto_feature {
                    let tags: Vec<_> = manifest
                        .features
                        .iter()
                        .filter(|f| f.starts_with("crypto:"))
                        .collect();
                    failures.push(format!(
                        "[{}] {}: crypto=false but features contains {:?}",
                        manifest.id,
                        path.display(),
                        tags
                    ));
                }
            }
            TransformExpectation::Disabled(_) => {}
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} crypto/feature consistency failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    println!(
        "All {} manifests pass crypto/feature consistency.",
        manifests.iter().filter(|(_, r)| r.is_ok()).count()
    );
}

// ---------------------------------------------------------------------------
// Test: valid non-deferred vectors have non-empty entries.
// ---------------------------------------------------------------------------

#[test]
fn valid_vectors_have_entries() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut missing = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if manifest.kind != VectorKind::Valid {
            continue;
        }
        if manifest.deferred || manifest.file.is_none() {
            continue;
        }

        // Stream transcript vectors contain session frames rather than traditional
        // archive entries; the entries field is not applicable to them.
        if manifest.features.iter().any(|f| f == "stream:transcript") {
            continue;
        }

        if manifest.entries.is_empty() {
            missing.push(format!(
                "[{}] {}: valid non-deferred vector has no entries",
                manifest.id,
                path.display()
            ));
        }
    }

    if !missing.is_empty() {
        panic!(
            "{} valid vector(s) missing entries:\n{}",
            missing.len(),
            missing.join("\n")
        );
    }

    let count = manifests
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .ok()
                .is_some_and(|m| m.kind == VectorKind::Valid && !m.deferred && m.file.is_some())
        })
        .count();
    println!("All {} valid non-deferred vectors have entries.", count);
}

// ---------------------------------------------------------------------------
// Test: symlink entries must have symlink_target.
// ---------------------------------------------------------------------------

#[test]
fn symlink_entries_have_target() {
    use sar_archive::conformance::ExpectedEntryKind;

    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        for (i, entry) in manifest.entries.iter().enumerate() {
            if entry.kind == ExpectedEntryKind::Symlink && entry.symlink_target.is_none() {
                failures.push(format!(
                    "[{}] {}: entries[{}] (name='{}') is symlink but has no symlink_target",
                    manifest.id,
                    path.display(),
                    i,
                    entry.name
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} symlink entry(ies) missing symlink_target:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Test: manifest schema validation passes for all manifests.
// ---------------------------------------------------------------------------

#[test]
fn all_manifests_pass_extended_schema_validation() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(e) => {
                failures.push(format!("JSON parse error in {}: {}", path.display(), e));
                continue;
            }
        };

        let schema_result = validate_manifest_schema(manifest);
        if !schema_result.valid {
            failures.push(format!(
                "[{}] {}: schema errors: {:?}",
                manifest.id,
                path.display(),
                schema_result.errors
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} manifest(s) failed extended schema validation:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    println!(
        "All {} manifests pass extended schema validation.",
        manifests.iter().filter(|(_, r)| r.is_ok()).count()
    );
}

#[test]
fn non_deferred_valid_vectors_must_not_be_placeholders() {
    let manifests = discover_manifests(&vectors_root()).expect("discover manifests");
    let banned = [
        "deferred",
        "placeholder",
        "fallback",
        "requires more complex writer setup",
        "future work",
        "not yet generated",
        "will be added later",
    ];
    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };
        if manifest.kind != VectorKind::Valid || manifest.deferred {
            continue;
        }

        let combined = format!(
            "{}\n{}\n{}",
            manifest.title,
            manifest.description,
            manifest.notes.join("\n")
        )
        .to_ascii_lowercase();
        for phrase in banned {
            if combined.contains(phrase) {
                failures.push(format!(
                    "[{}] {}: contains placeholder language '{}'",
                    manifest.id,
                    path.display(),
                    phrase
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} canonical valid vector(s) contain placeholder language:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn non_deferred_invalid_vectors_must_not_be_placeholders() {
    let manifests = discover_manifests(&vectors_root()).expect("discover manifests");
    let banned = [
        "deferred",
        "placeholder",
        "fallback",
        "requires more complex writer setup",
        "future work",
        "not yet generated",
        "will be added later",
    ];
    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };
        if manifest.kind != VectorKind::Invalid || manifest.deferred {
            continue;
        }
        let combined = format!(
            "{}\n{}\n{}",
            manifest.title,
            manifest.description,
            manifest.notes.join("\n")
        )
        .to_ascii_lowercase();
        for phrase in banned {
            if combined.contains(phrase) {
                failures.push(format!(
                    "[{}] {}: contains placeholder language '{}'",
                    manifest.id,
                    path.display(),
                    phrase
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} non-deferred invalid vector(s) contain placeholder language:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn deferred_vectors_do_not_reference_binary_fixtures() {
    let manifests = manifest_paths();
    let mut failures = Vec::new();

    for path in manifests {
        let raw = raw_manifest_json(&path);
        let Some(object) = raw.as_object() else {
            failures.push(format!(
                "{}: manifest root must be an object",
                path.display()
            ));
            continue;
        };
        let deferred = object
            .get("deferred")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !deferred {
            continue;
        }
        match object.get("file") {
            None | Some(Value::Null) => {}
            Some(value) => failures.push(format!(
                "{}: deferred manifest must omit 'file' or set it to null, found {}",
                path.display(),
                value
            )),
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} deferred manifest(s) still reference binaries:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn known_deferred_feature_tags_are_not_canonical_unless_real() {
    let manifests = discover_manifests(&vectors_root()).expect("discover manifests");
    let deferred_tags = [
        "cdc:fastcdc",
        "cdc-map",
        "sparse+delta",
        "loss-tolerant-gap",
        "fragmentation",
        "recovery-tlv",
    ];
    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };
        if manifest.kind != VectorKind::Valid || manifest.deferred {
            continue;
        }
        let matches: Vec<_> = manifest
            .features
            .iter()
            .filter(|feature| deferred_tags.contains(&feature.as_str()))
            .cloned()
            .collect();
        if !matches.is_empty() {
            failures.push(format!(
                "[{}] {}: canonical manifest still claims deferred feature tags {:?}",
                manifest.id,
                path.display(),
                matches
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} canonical valid manifest(s) still claim deferred feature tags:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn raw_manifest_shapes_match_schema_contract() {
    let required = [
        "schema_version",
        "id",
        "title",
        "description",
        "kind",
        "expected",
        "compression",
        "crypto",
    ];
    let allowed = [
        "schema_version",
        "id",
        "title",
        "description",
        "kind",
        "file",
        "profiles",
        "features",
        "compression",
        "crypto",
        "requires_key_provider",
        "entries",
        "base_files",
        "expected",
        "profile_expectations",
        "limits",
        "notes",
        "deferred",
        "generated_by",
    ];
    let mut failures = Vec::new();

    for path in manifest_paths() {
        let raw = raw_manifest_json(&path);
        let Some(object) = raw.as_object() else {
            failures.push(format!(
                "{}: manifest root must be an object",
                path.display()
            ));
            continue;
        };
        for key in object_keys(object) {
            if !allowed.contains(&key) {
                failures.push(format!(
                    "{}: unexpected top-level key '{}'",
                    path.display(),
                    key
                ));
            }
        }
        for key in required {
            if !object.contains_key(key) {
                failures.push(format!(
                    "{}: missing required top-level key '{}'",
                    path.display(),
                    key
                ));
            }
        }
        if let Some(file) = object.get("file")
            && !value_is_string_or_null(file)
        {
            failures.push(format!("{}: file must be a string or null", path.display()));
        }
        if let Some(compression) = object.get("compression") {
            validate_transform_shape(
                compression,
                &format!("{}: compression", path.display()),
                false,
                &mut failures,
            );
        }
        if let Some(crypto) = object.get("crypto") {
            validate_transform_shape(
                crypto,
                &format!("{}: crypto", path.display()),
                true,
                &mut failures,
            );
        }
        if let Some(entries) = object.get("entries") {
            validate_entries_shape(
                entries,
                &format!("{}: entries", path.display()),
                &mut failures,
            );
        }
        if let Some(base_files) = object.get("base_files") {
            validate_base_files_shape(
                base_files,
                &format!("{}: base_files", path.display()),
                &mut failures,
            );
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} raw manifest shape error(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Promoted VCDIFF/BSDIFF vector algo-ID validation
// ---------------------------------------------------------------------------

/// Reads the `patch_algo_id` byte from the first LFH of a fixture file.
///
/// Returns `None` when the archive cannot be parsed or lacks `HAS_DELTA`.
fn read_first_entry_patch_algo_id(fixture_path: &Path) -> Option<u8> {
    let bytes = fs::read(fixture_path).ok()?;
    let limits = ResourceLimits::default();
    let (gh, after_gh) = parse_global_header(&bytes, &limits).ok()?;
    if !gh.flags.contains(GlobalFlags::HAS_DELTA) {
        return None;
    }
    let (lfh, _) = parse_lfh(&bytes[after_gh..], &gh.flags, &limits).ok()?;
    lfh.patch_algo_id
}

#[test]
fn promoted_vcdiff_vector_uses_vcdiff_algo_id() {
    let fixture = vectors_root().join("valid/delta/vcdiff/vcdiff_patch_entry.sar");
    let algo_id = read_first_entry_patch_algo_id(&fixture)
        .unwrap_or_else(|| panic!("could not read patch_algo_id from {}", fixture.display()));
    assert_eq!(
        algo_id, PATCH_ALGO_VCDIFF,
        "VCDIFF vector must use patch algorithm ID {PATCH_ALGO_VCDIFF:#04x}, got {algo_id:#04x}"
    );
    assert_ne!(
        algo_id, PATCH_ALGO_STORE_PATCH,
        "VCDIFF vector must not use STORE_PATCH"
    );
}

#[test]
fn promoted_bsdiff_vector_uses_bsdiff_algo_id() {
    let fixture = vectors_root().join("valid/delta/bsdiff/bsdiff_patch_entry.sar");
    let algo_id = read_first_entry_patch_algo_id(&fixture)
        .unwrap_or_else(|| panic!("could not read patch_algo_id from {}", fixture.display()));
    assert_eq!(
        algo_id, PATCH_ALGO_BSDIFF,
        "BSDIFF vector must use patch algorithm ID {PATCH_ALGO_BSDIFF:#04x}, got {algo_id:#04x}"
    );
    assert_ne!(
        algo_id, PATCH_ALGO_STORE_PATCH,
        "BSDIFF vector must not use STORE_PATCH"
    );
}

fn assert_real_archive_recovery_fixture(relative_fixture_path: &str, expected_algo_id: u8) {
    let fixture = vectors_root().join(relative_fixture_path);
    let bytes = fs::read(&fixture)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", fixture.display()));
    let meta = inspect_recovery_metadata(&bytes, &ResourceLimits::default())
        .unwrap_or_else(|err| panic!("failed to inspect {}: {err}", fixture.display()));
    let protected_range = meta
        .protected_range
        .unwrap_or_else(|| panic!("{} is missing a protected range", fixture.display()));

    assert!(
        meta.has_global_ec,
        "{} must set HAS_GLOBAL_EC",
        fixture.display()
    );
    assert_eq!(
        meta.recovery_tlvs.len(),
        1,
        "{} must contain exactly one RECOVERY TLV",
        fixture.display()
    );
    let algo_id = match &meta.recovery_tlvs[0] {
        FecSummary::Xor { algo_id, .. } | FecSummary::ReedSolomon { algo_id, .. } => *algo_id,
    };
    assert_eq!(
        algo_id,
        expected_algo_id,
        "{} must use expected RECOVERY algo",
        fixture.display()
    );
    assert_eq!(
        protected_range.offset,
        GLOBAL_HEADER_FLAGS_OFFSET,
        "{} must protect bytes starting at the first Global Flags byte",
        fixture.display()
    );
}

#[test]
fn promoted_archive_recovery_xor_vector_uses_real_recovery_tlv() {
    assert_real_archive_recovery_fixture(
        "valid/recovery/archive-xor/recovery_tlv_archive_xor.sar",
        FEC_ALGO_XOR,
    );
}

#[test]
fn promoted_archive_recovery_rs_vector_uses_real_recovery_tlv() {
    assert_real_archive_recovery_fixture(
        "valid/recovery/archive-rs/recovery_tlv_archive_rs.sar",
        FEC_ALGO_REED_SOLOMON,
    );
}

#[test]
fn archive_recovery_vectors_use_recovery_taxonomy_and_paths() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");
    let mut failures = Vec::new();

    for (manifest_path, result) in manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };
        if manifest.kind != VectorKind::Valid {
            continue;
        }

        let rel_manifest = manifest_path
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("{} is not under vectors root", manifest_path.display()));
        let rel_manifest_dir = rel_manifest
            .parent()
            .expect("manifest parent")
            .to_string_lossy();

        let has_archive_recovery = manifest.features.iter().any(|f| f == "recovery:archive");
        let has_fec_feature = manifest.features.iter().any(|f| f.starts_with("fec:"));
        let has_recovery_feature = manifest.features.iter().any(|f| f.starts_with("recovery:"));
        let has_recovery_algo_feature = manifest
            .features
            .iter()
            .any(|f| f == "recovery:xor" || f == "recovery:reed-solomon");
        let has_selective_fec = manifest.features.iter().any(|f| f == "selective-fec");

        if has_archive_recovery {
            if manifest.deferred {
                failures.push(format!(
                    "[{}] {}: archive-level recovery manifest must not be deferred",
                    manifest.id,
                    rel_manifest.display()
                ));
            }
            if !rel_manifest_dir.starts_with("valid/recovery/") {
                failures.push(format!(
                    "[{}] {}: archive-level recovery vectors must live under valid/recovery/",
                    manifest.id,
                    rel_manifest.display()
                ));
            }
            if has_fec_feature {
                failures.push(format!(
                    "[{}] {}: archive-level recovery vectors must not use fec:* tags",
                    manifest.id,
                    rel_manifest.display()
                ));
            }
            if !has_recovery_algo_feature {
                failures.push(format!(
                    "[{}] {}: archive-level recovery vectors must use recovery:xor or recovery:reed-solomon",
                    manifest.id, rel_manifest.display()
                ));
            }
            let Some(file_name) = manifest.file.as_ref() else {
                failures.push(format!(
                    "[{}] {}: promoted archive-level recovery manifest must reference a real .sar fixture",
                    manifest.id, rel_manifest.display()
                ));
                continue;
            };
            let fixture_path = manifest_path
                .parent()
                .expect("manifest parent")
                .join(file_name);
            if !fixture_path.exists() {
                failures.push(format!(
                    "[{}] {}: referenced fixture does not exist: {}",
                    manifest.id,
                    rel_manifest.display(),
                    fixture_path.display()
                ));
            }
        }

        if has_selective_fec || (has_fec_feature && !has_archive_recovery) {
            if !rel_manifest_dir.starts_with("valid/fec/") {
                failures.push(format!(
                    "[{}] {}: LFH Selective FEC vectors must live under valid/fec/",
                    manifest.id,
                    rel_manifest.display()
                ));
            }
            if has_recovery_feature {
                failures.push(format!(
                    "[{}] {}: LFH Selective FEC vectors must not use recovery:* tags",
                    manifest.id,
                    rel_manifest.display()
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} archive recovery taxonomy failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn invalid_recovery_vectors_are_real_and_recovery_tagged() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");
    let mut failures = Vec::new();
    let mut seen = 0usize;

    for (manifest_path, result) in manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };
        if manifest.kind != VectorKind::Invalid {
            continue;
        }
        let rel_manifest = manifest_path
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("{} is not under vectors root", manifest_path.display()));
        let rel_manifest_dir = rel_manifest
            .parent()
            .expect("manifest parent")
            .to_string_lossy();
        if !rel_manifest_dir.starts_with("invalid/recovery/") {
            continue;
        }
        seen += 1;
        if manifest.deferred {
            failures.push(format!(
                "[{}] {}: invalid recovery vectors with real fixtures must not be deferred",
                manifest.id,
                rel_manifest.display()
            ));
            continue;
        }
        let has_recovery_feature = manifest.features.iter().any(|f| f.starts_with("recovery:"));
        let has_fec_feature = manifest.features.iter().any(|f| f.starts_with("fec:"));
        if !has_recovery_feature {
            failures.push(format!(
                "[{}] {}: invalid recovery vectors must use recovery:* feature tags",
                manifest.id,
                rel_manifest.display()
            ));
        }
        if has_fec_feature {
            failures.push(format!(
                "[{}] {}: invalid recovery vectors must not use fec:* feature tags",
                manifest.id,
                rel_manifest.display()
            ));
        }
        let Some(file_name) = manifest.file.as_ref() else {
            failures.push(format!(
                "[{}] {}: non-deferred invalid recovery vector must reference a real .sar fixture",
                manifest.id,
                rel_manifest.display()
            ));
            continue;
        };
        let fixture_path = manifest_path
            .parent()
            .expect("manifest parent")
            .join(file_name);
        if !fixture_path.exists() {
            failures.push(format!(
                "[{}] {}: referenced fixture does not exist: {}",
                manifest.id,
                rel_manifest.display(),
                fixture_path.display()
            ));
        }
    }

    assert!(seen > 0, "expected at least one invalid recovery vector");
    if !failures.is_empty() {
        panic!(
            "{} invalid recovery manifest audit failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn invalid_delta_vectors_are_real_and_delta_tagged() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");
    let mut failures = Vec::new();
    let mut seen = 0usize;

    for (manifest_path, result) in manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };
        if manifest.kind != VectorKind::Invalid {
            continue;
        }
        let rel_manifest = manifest_path
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("{} is not under vectors root", manifest_path.display()));
        let rel_manifest_dir = rel_manifest
            .parent()
            .expect("manifest parent")
            .to_string_lossy();
        if !rel_manifest_dir.starts_with("invalid/delta/") {
            continue;
        }
        seen += 1;
        if manifest.deferred {
            failures.push(format!(
                "[{}] {}: invalid delta vectors with real fixtures must not be deferred",
                manifest.id,
                rel_manifest.display()
            ));
            continue;
        }
        if !manifest.features.iter().any(|f| f.starts_with("delta:")) {
            failures.push(format!(
                "[{}] {}: invalid delta vectors must use delta:* feature tags",
                manifest.id,
                rel_manifest.display()
            ));
        }
        let Some(file_name) = manifest.file.as_ref() else {
            failures.push(format!(
                "[{}] {}: non-deferred invalid delta vector must reference a real .sar fixture",
                manifest.id,
                rel_manifest.display()
            ));
            continue;
        };
        let fixture_path = manifest_path
            .parent()
            .expect("manifest parent")
            .join(file_name);
        if !fixture_path.exists() {
            failures.push(format!(
                "[{}] {}: referenced fixture does not exist: {}",
                manifest.id,
                rel_manifest.display(),
                fixture_path.display()
            ));
        }
    }

    assert!(seen > 0, "expected at least one invalid delta vector");
    if !failures.is_empty() {
        panic!(
            "{} invalid delta manifest audit failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Stream transcript manifest audit tests (M12a-stream-cp)
// ---------------------------------------------------------------------------

/// Validates that all stream transcript vectors live under the correct paths
/// and carry the required `stream:*` feature tags.
#[test]
fn stream_transcript_vectors_use_stream_tags_and_correct_paths() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");
    let mut failures = Vec::new();
    let mut seen = 0usize;

    for (manifest_path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if !manifest.features.iter().any(|f| f == "stream:transcript") {
            continue;
        }
        seen += 1;

        let rel_manifest = manifest_path
            .strip_prefix(&root)
            .unwrap_or(manifest_path.as_path());
        let rel_dir = rel_manifest
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        // Must live under valid/stream-session/, invalid/stream-session/, or profiles/
        let under_valid = rel_dir.starts_with("valid/stream-session/");
        let under_invalid = rel_dir.starts_with("invalid/stream-session/");
        let under_profiles = rel_dir.starts_with("profiles/");
        if !under_valid && !under_invalid && !under_profiles {
            failures.push(format!(
                "[{}] {}: stream:transcript vector must live under valid/stream-session/, \
                 invalid/stream-session/, or profiles/; found '{}'",
                manifest.id,
                rel_manifest.display(),
                rel_dir,
            ));
        }

        // Must also have stream:session tag
        if !manifest.features.iter().any(|f| f == "stream:session") {
            failures.push(format!(
                "[{}] {}: stream:transcript vector must include stream:session feature tag",
                manifest.id,
                rel_manifest.display(),
            ));
        }

        // Non-deferred invalid stream transcript vectors must have a stable expected status
        if manifest.kind == VectorKind::Invalid && !manifest.deferred {
            let status = &manifest.expected.status;
            if status == "SAR_OK" || status.is_empty() {
                failures.push(format!(
                    "[{}] {}: non-deferred invalid stream transcript must have a non-SAR_OK \
                     expected status; got '{}'",
                    manifest.id,
                    rel_manifest.display(),
                    status,
                ));
            }
        }

        // Non-deferred vectors must reference real files
        if !manifest.deferred {
            let Some(file_name) = manifest.file.as_ref() else {
                failures.push(format!(
                    "[{}] {}: non-deferred stream transcript vector must reference a fixture file",
                    manifest.id,
                    rel_manifest.display(),
                ));
                continue;
            };
            let fixture_path = manifest_path
                .parent()
                .expect("manifest parent")
                .join(file_name);
            if !fixture_path.exists() {
                failures.push(format!(
                    "[{}] {}: referenced fixture does not exist: {}",
                    manifest.id,
                    rel_manifest.display(),
                    fixture_path.display(),
                ));
            }
        }
    }

    assert!(
        seen > 0,
        "expected at least one stream:transcript vector; run generate_vectors first"
    );
    if !failures.is_empty() {
        panic!(
            "{} stream transcript manifest audit failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Validates that profile rejection manifests for stream transcripts do not
/// claim the bytes are structurally invalid (expected.valid must be true).
#[test]
fn stream_transcript_profile_rejection_manifests_are_not_byte_invalid() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");
    let mut failures = Vec::new();
    let mut seen = 0usize;

    for (manifest_path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if !manifest.features.iter().any(|f| f == "stream:profile-rejection") {
            continue;
        }
        seen += 1;

        let rel_manifest = manifest_path
            .strip_prefix(&root)
            .unwrap_or(manifest_path.as_path());

        // Profile rejection manifests for stream transcripts must say the bytes
        // are structurally valid SAR (expected.valid = true / status = SAR_OK).
        if !manifest.expected.valid || manifest.expected.status != "SAR_OK" {
            failures.push(format!(
                "[{}] {}: stream:profile-rejection manifest must have expected.valid=true and \
                 status=SAR_OK (the transcript is byte-valid; profile rejects it at the \
                 semantic level); got valid={}, status={}",
                manifest.id,
                rel_manifest.display(),
                manifest.expected.valid,
                manifest.expected.status,
            ));
        }
    }

    if seen == 0 {
        // Not a hard failure — profile rejection manifests may not yet exist.
        println!("No stream:profile-rejection vectors found (OK if not yet generated).");
        return;
    }
    if !failures.is_empty() {
        panic!(
            "{} stream transcript profile-rejection audit failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Validates the minimum required valid stream transcript vectors exist and
/// are not deferred.
#[test]
fn minimum_required_valid_stream_transcript_vectors_present() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    // Minimum required valid vectors by feature tag combination.
    let required_feature_sets = [
        ("session-init", vec!["stream:session-init"]),
        ("heartbeat", vec!["stream:heartbeat"]),
        ("ordered-data or sequence", vec!["stream:sequence"]),
    ];

    let valid_stream_manifests: Vec<_> = manifests
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok())
        .filter(|m| {
            m.kind == VectorKind::Valid
                && !m.deferred
                && m.features.iter().any(|f| f == "stream:transcript")
        })
        .collect();

    let mut missing = Vec::new();
    for (label, needed_tags) in &required_feature_sets {
        let found = valid_stream_manifests.iter().any(|m| {
            needed_tags
                .iter()
                .all(|tag| m.features.iter().any(|f| f == tag))
        });
        if !found {
            missing.push(format!("no valid stream transcript vector with tags {:?} ({})", needed_tags, label));
        }
    }

    if !missing.is_empty() {
        panic!(
            "minimum required valid stream transcript vectors are missing:\n{}",
            missing.join("\n")
        );
    }
}

/// Validates the minimum required invalid stream transcript vectors exist and
/// are not deferred.
#[test]
fn minimum_required_invalid_stream_transcript_vectors_present() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let invalid_stream_non_deferred: Vec<_> = manifests
        .iter()
        .filter_map(|(path, r)| r.as_ref().ok().map(|m| (path, m)))
        .filter(|(_, m)| {
            m.kind == VectorKind::Invalid
                && !m.deferred
                && m.features.iter().any(|f| f == "stream:transcript")
        })
        .collect();

    // We need at least 8 non-deferred invalid stream transcript vectors per M12a-stream-cp milestone requirements.
    if invalid_stream_non_deferred.len() < 8 {
        panic!(
            "expected at least 8 non-deferred invalid stream transcript vectors, found {}:\n{}",
            invalid_stream_non_deferred.len(),
            invalid_stream_non_deferred
                .iter()
                .map(|(p, m)| format!("  [{}] {}", m.id, p.display()))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}
