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

use std::path::Path;

use sar_archive::conformance::{
    TransformExpectation, VectorKind, discover_manifests, validate_manifest_schema,
};

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
        .filter(|(_, r)| r.as_ref().ok().map_or(false, |m| !m.deferred && m.file.is_some()))
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
        let file_name = manifest.file.as_deref().unwrap();
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

        let has_crypto_feature = manifest
            .features
            .iter()
            .any(|f| f.starts_with("crypto:"));

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
            r.as_ref().ok().map_or(false, |m| {
                m.kind == VectorKind::Valid && !m.deferred && m.file.is_some()
            })
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
