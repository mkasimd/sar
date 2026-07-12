//! Conformance vector integration tests.
//!
//! Loads every `manifest.json` under `test-vectors/`, validates the manifest
//! schema, and runs a conformance check against the referenced binary `.sar`
//! file where available (non-deferred vectors with a `file` field).
//!
//! # Running
//!
//! ```bash
//! cargo test -p sar-archive --test conformance_tests
//! ```
//!
//! # Regenerating binary fixtures
//!
//! ```bash
//! cargo run --example generate_vectors -p sar-archive
//! ```

use std::path::Path;

use sar_archive::conformance::{
    VectorKind, discover_manifests, run_conformance_check, validate_manifest_schema,
};

// ---------------------------------------------------------------------------
// Helper: locate test-vectors root relative to CARGO_MANIFEST_DIR
// ---------------------------------------------------------------------------

fn vectors_root() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // crates/sar-archive → workspace root
    let workspace = Path::new(manifest_dir)
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    workspace.join("test-vectors")
}

// ---------------------------------------------------------------------------
// Test: all manifests parse as valid JSON with correct schema fields
// ---------------------------------------------------------------------------

#[test]
fn all_manifests_parse_and_schema_validates() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    assert!(
        !manifests.is_empty(),
        "no manifests found under {}",
        root.display()
    );

    let mut failures = Vec::new();

    for (path, result) in &manifests {
        match result {
            Err(e) => {
                failures.push(format!("JSON parse error in {}: {}", path.display(), e));
            }
            Ok(manifest) => {
                let schema_result = validate_manifest_schema(manifest);
                if !schema_result.valid {
                    failures.push(format!(
                        "Schema errors in {}: {:?}",
                        path.display(),
                        schema_result.errors
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} manifest(s) failed validation:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    println!("All {} manifests validated.", manifests.len());
}

// ---------------------------------------------------------------------------
// Test: non-deferred valid vectors parse successfully
// ---------------------------------------------------------------------------

#[test]
fn valid_non_deferred_vectors_parse_ok() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();
    let mut checked = 0usize;

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue, // schema errors caught in other test
        };

        if manifest.kind != VectorKind::Valid {
            continue;
        }
        if manifest.deferred || manifest.file.is_none() {
            continue;
        }
        if manifest.features.iter().any(|f| f == "stream:transcript") {
            println!(
                "[SKIP] {} — stream transcript semantics run in sar-stream",
                manifest.id
            );
            continue;
        }

        let base_dir = path.parent().expect("manifest dir");
        let check = run_conformance_check(manifest, base_dir);
        checked += 1;

        if check.skipped {
            continue;
        }
        if !check.passed {
            failures.push(format!(
                "[{}] {}: {}",
                manifest.id,
                path.display(),
                check.reason
            ));
        } else {
            println!("[PASS] {} — {}", manifest.id, check.reason);
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}/{} valid vector(s) failed conformance check:\n{}",
            failures.len(),
            checked,
            failures.join("\n")
        );
    }

    println!("{} valid non-deferred vectors all passed.", checked);
}

// ---------------------------------------------------------------------------
// Test: non-deferred invalid vectors are rejected
// ---------------------------------------------------------------------------

#[test]
fn invalid_non_deferred_vectors_are_rejected() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();
    let mut checked = 0usize;

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if manifest.kind != VectorKind::Invalid {
            continue;
        }
        if manifest.deferred || manifest.file.is_none() {
            continue;
        }
        if manifest.features.iter().any(|f| f == "stream:transcript") {
            println!(
                "[SKIP] {} — stream transcript semantics run in sar-stream",
                manifest.id
            );
            continue;
        }

        let base_dir = path.parent().expect("manifest dir");
        let check = run_conformance_check(manifest, base_dir);
        checked += 1;

        if check.skipped {
            continue;
        }
        if !check.passed {
            failures.push(format!(
                "[{}] {}: {}",
                manifest.id,
                path.display(),
                check.reason
            ));
        } else {
            println!("[PASS] {} — {}", manifest.id, check.reason);
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}/{} invalid vector(s) failed conformance check:\n{}",
            failures.len(),
            checked,
            failures.join("\n")
        );
    }

    println!(
        "{} invalid non-deferred vectors all correctly rejected.",
        checked
    );
}

// ---------------------------------------------------------------------------
// Test: all deferred vectors are marked deferred consistently
// ---------------------------------------------------------------------------

#[test]
fn deferred_vectors_have_no_binary_file() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut inconsistencies = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if manifest.deferred {
            // Deferred vectors should not have a binary file that exists.
            if let Some(ref file_name) = manifest.file {
                let base_dir = path.parent().expect("manifest dir");
                let file_path = base_dir.join(file_name);
                if file_path.exists() {
                    inconsistencies.push(format!(
                        "[{}] marked deferred but binary exists: {}",
                        manifest.id,
                        file_path.display()
                    ));
                }
            }
        }
    }

    if !inconsistencies.is_empty() {
        panic!(
            "{} deferred vector(s) have unexpected binary files:\n{}",
            inconsistencies.len(),
            inconsistencies.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Test: profile expectations use recognised profile names
// ---------------------------------------------------------------------------

#[test]
fn profile_expectations_use_known_profile_names() {
    use sar_archive::profile::ComplianceProfile;

    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut failures = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        for profile_name in manifest.profile_expectations.keys() {
            if ComplianceProfile::from_canonical_name(profile_name).is_none() {
                failures.push(format!(
                    "[{}] {}: unknown profile name '{}'",
                    manifest.id,
                    path.display(),
                    profile_name
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} manifest(s) use unknown profile names:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Test: manifest IDs are unique across the test-vectors tree
// ---------------------------------------------------------------------------

#[test]
fn manifest_ids_are_unique() {
    use std::collections::HashMap;

    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let mut id_map: HashMap<String, String> = HashMap::new();
    let mut duplicates = Vec::new();

    for (path, result) in &manifests {
        let manifest = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if let Some(existing) = id_map.get(&manifest.id) {
            duplicates.push(format!(
                "id '{}' appears in both {} and {}",
                manifest.id,
                existing,
                path.display()
            ));
        } else {
            id_map.insert(manifest.id.clone(), path.display().to_string());
        }
    }

    if !duplicates.is_empty() {
        panic!(
            "{} duplicate manifest id(s):\n{}",
            duplicates.len(),
            duplicates.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Test: summary report
// ---------------------------------------------------------------------------

#[test]
fn conformance_summary() {
    let root = vectors_root();
    let manifests = discover_manifests(&root).expect("discover manifests");

    let total = manifests.len();
    let parse_ok = manifests.iter().filter(|(_, r)| r.is_ok()).count();
    let deferred = manifests
        .iter()
        .filter(|(_, r)| r.as_ref().ok().is_some_and(|m| m.deferred))
        .count();
    let valid_kind = manifests
        .iter()
        .filter(|(_, r)| r.as_ref().ok().is_some_and(|m| m.kind == VectorKind::Valid))
        .count();
    let invalid_kind = manifests
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .ok()
                .is_some_and(|m| m.kind == VectorKind::Invalid)
        })
        .count();
    let profile_kind = manifests
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .ok()
                .is_some_and(|m| m.kind == VectorKind::Profile)
        })
        .count();

    println!("\n=== SAR Conformance Vector Summary (M12a) ===");
    println!("Total manifests:   {}", total);
    println!("  Parsed OK:       {}", parse_ok);
    println!("  Valid vectors:   {}", valid_kind);
    println!("  Invalid vectors: {}", invalid_kind);
    println!("  Profile vectors: {}", profile_kind);
    println!("  Deferred:        {}", deferred);
    println!("  Active:          {}", total - deferred);
    println!("  Test-vectors dir: {}", root.display());
}
