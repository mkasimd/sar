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
    VectorKind, discover_manifests, run_conformance_check,
    validate_manifest_schema,
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

        let base_dir = path.parent().expect("manifest dir");
        let check = run_conformance_check(manifest, base_dir);
        checked += 1;

        if check.skipped {
            continue;
        }
        if !check.passed {
            failures.push(format!(
                "[{}] {}: {}",
                manifest.id, path.display(), check.reason
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

        let base_dir = path.parent().expect("manifest dir");
        let check = run_conformance_check(manifest, base_dir);
        checked += 1;

        if check.skipped {
            continue;
        }
        if !check.passed {
            failures.push(format!(
                "[{}] {}: {}",
                manifest.id, path.display(), check.reason
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

    println!("{} invalid non-deferred vectors all correctly rejected.", checked);
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
                        manifest.id, file_path.display()
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
                    manifest.id, path.display(), profile_name
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
                manifest.id, existing, path.display()
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
        .filter(|(_, r)| r.as_ref().ok().map_or(false, |m| m.deferred))
        .count();
    let valid_kind = manifests
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .ok()
                .map_or(false, |m| m.kind == VectorKind::Valid)
        })
        .count();
    let invalid_kind = manifests
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .ok()
                .map_or(false, |m| m.kind == VectorKind::Invalid)
        })
        .count();
    let profile_kind = manifests
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .ok()
                .map_or(false, |m| m.kind == VectorKind::Profile)
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
    println!(
        "  Test-vectors dir: {}",
        root.display()
    );
}

// ---------------------------------------------------------------------------
// Test: bad AEAD tag is rejected even with a valid key provider
// ---------------------------------------------------------------------------

/// Key provider for test-only vectors.  Returns the fixed test password used
/// by the generate_vectors example.
struct StaticTestPassword {
    password: String,
}

impl sar_crypto::provider::KeyProvider for StaticTestPassword {
    fn password_for(
        &self,
        _ctx: &sar_crypto::KmsContext,
    ) -> Result<Option<sar_crypto::SecretString>, sar_crypto::error::SarCryptoError> {
        Ok(Some(sar_crypto::SecretString::new(self.password.clone())))
    }

    fn unwrap_key(
        &self,
        _ctx: &sar_crypto::KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<sar_crypto::SecretBytes>, sar_crypto::error::SarCryptoError> {
        Ok(None)
    }

    fn external_key(
        &self,
        _ctx: &sar_crypto::KmsContext,
    ) -> Result<Option<sar_crypto::SecretBytes>, sar_crypto::error::SarCryptoError> {
        Ok(None)
    }
}

#[test]
fn bad_aead_tag_auth_failure() {
    use std::io::Cursor;
    use sar_archive::{ArchiveReader, ArchiveReaderOptions};
    use sar_core::error::SarError;

    let root = vectors_root();
    let vector_path = root
        .join("invalid/crypto/bad-aead-tag/bad_aead_tag.sar");

    let bytes = std::fs::read(&vector_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", vector_path.display(), e));

    let key_provider: Box<dyn sar_crypto::provider::KeyProvider> = Box::new(StaticTestPassword {
        password: "sar-test-password-aes".to_string(),
    });

    let opts = ArchiveReaderOptions::default();
    let mut reader = ArchiveReader::with_options(Cursor::new(&bytes), opts)
        .expect("reader init")
        .with_key_provider(key_provider);

    reader.read_global_header().expect("global header");

    // The first (and only) entry should fail with an authentication error.
    let result = reader.next_entry();
    match result {
        Err(SarError::AuthFailed(_) | SarError::DecryptFailed(_)) => {
            println!("[PASS] bad-aead-tag correctly rejected with auth failure");
        }
        Err(e) => panic!(
            "bad-aead-tag rejected with unexpected error (expected auth failure): {}",
            e
        ),
        Ok(_) => panic!("bad-aead-tag was accepted but must be rejected"),
    }
}

#[test]
fn crypto_vectors_parse_structurally_with_key_provider() {
    use std::io::Cursor;
    use sar_archive::{ArchiveReader, ArchiveReaderOptions};

    let root = vectors_root();
    let crypto_vectors = [
        (
            "valid/crypto/aes256-gcm/aes256_gcm_entry.sar",
            "sar-test-password-aes",
        ),
        (
            "valid/crypto/xchacha20-poly1305/xchacha20_poly1305_entry.sar",
            "sar-test-password-xchacha",
        ),
    ];

    let mut failures = Vec::new();

    for (rel_path, password) in &crypto_vectors {
        let path = root.join(rel_path);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("cannot read {}: {}", path.display(), e));
                continue;
            }
        };

        let key_provider: Box<dyn sar_crypto::provider::KeyProvider> =
            Box::new(StaticTestPassword {
                password: (*password).to_string(),
            });

        let opts = ArchiveReaderOptions::default();
        let mut reader = match ArchiveReader::with_options(Cursor::new(&bytes), opts) {
            Ok(r) => r.with_key_provider(key_provider),
            Err(e) => {
                failures.push(format!("{}: reader init failed: {}", rel_path, e));
                continue;
            }
        };

        if let Err(e) = reader.read_global_header() {
            failures.push(format!("{}: global header failed: {}", rel_path, e));
            continue;
        }

        loop {
            match reader.next_entry() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    failures.push(format!("{}: entry failed: {}", rel_path, e));
                    break;
                }
            }
        }

        println!("[PASS] {} — parsed successfully with key provider", rel_path);
    }

    if !failures.is_empty() {
        panic!(
            "{} crypto vector(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
