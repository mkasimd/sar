# Conformance Profile (M1–M12a)

This document describes **reference implementation coverage** and **known gaps** after M12a.

This is an **implemented profile** report, not a claim of full standard conformance.

## M12a: Conformance vector foundation

### Vector directory structure

```
test-vectors/
  README.md                    — vector layout, manifest format, how-to guide
  manifest.schema.json         — JSON Schema for all conformance manifests
  profiles/README.md           — per-profile descriptions and cold-storage status
  valid/
    minimal/                   — minimal archive vectors (store-no-index, indexed)
    no-index/                  — forward-only (NO_INDEX) archive
    indexed/                   — indexed archive
    compression/               — STORE, DEFLATE, ZSTD compression
    crypto/                    — AES-256-GCM, XChaCha20-Poly1305 (requires key provider)
    fec/                       — XOR FEC, Reed-Solomon FEC, FEC metadata
    fragmentation/             — valid fragment reassembly, loss-tolerant gap
    sparse/                    — sparse map, sparse+delta ordering
    cdc/                       — CDC literal mode, FastCDC metadata
    delta/                     — STORE_PATCH, VCDIFF, BSDIFF
    stream-session/            — (deferred: structure requires network context)
    filesystem-metadata/       — permissions, owner, timestamps, symlink, directory,
                                  combined, field-presence-inactive
  invalid/
    structure/                 — truncated GH, truncated LFH, invalid magic
    flags/                     — unknown global flag bits, flag conflicts (partial)
    algorithms/                — unsupported compression, unsupported crypto
    crypto/                    — bad AEAD tag (requires key provider)
    fec/                       — (deferred)
    fragmentation/             — (deferred: fragment gap vectors)
    sparse/                    — (deferred: sparse overlap/extent vectors)
    cdc/                       — (deferred)
    delta/                     — (deferred)
    stream-session/            — (deferred)
    filesystem-metadata/       — (deferred: unsafe path/symlink vectors)
    resource-limits/           — (deferred)
  profiles/
    static-archive/            — profile-specific acceptance/rejection
    package/                   — (partial: loss-tolerant rejection)
    stream-package/            — NO_INDEX acceptance
    backup/                    — (partial)
    telemetry/                 — (deferred)
    live-media/                — (deferred)
    cold-storage/              — placeholder (deferred, see profiles/README.md)
```

### Manifest format

Every vector has a `manifest.json` with schema version 1. Required fields:
`schema_version`, `id`, `title`, `description`, `kind`, `expected`.
Optional: `file`, `profiles`, `features`, `profile_expectations`, `limits`, `notes`,
`deferred`, `requires_key_provider`, `generated_by`.

Stable status identifiers:
`SAR_OK`, `SAR_ERR_MALFORMED`, `SAR_ERR_TRUNCATED`, `SAR_ERR_UNSUPPORTED`,
`SAR_ERR_RESERVED_VALUE`, `SAR_ERR_FLAG_CONFLICT`, `SAR_ERR_INVALID_MAGIC`,
`SAR_ERR_AUTH_FAILED`, `SAR_ERR_LIMIT_EXCEEDED`, `SAR_ERR_BOUNDS`,
`SAR_ERR_OVERFLOW`, `SAR_ERR_FRAGMENT_GAP`, `SAR_ERR_INVALID_MAP`,
`SAR_ERR_INVALID_LENGTH`, `SAR_ERR_STREAM_STATE`, `SAR_ERR_DECRYPT_FAILED`,
`SAR_ERR_HASH_MISMATCH`, `SAR_ERR_CRC_MISMATCH`, `SAR_ERR_IO`.

### Implemented profile validator

`sar_archive::conformance` module provides:
- `ConformanceManifest`: serde-deserializable manifest type matching the schema
- `validate_manifest_schema()`: schema-level field validation
- `run_conformance_check()`: end-to-end check for a manifest + binary file
- `sar_error_matches_expected_status()`: maps `SarError` variants to stable status strings
- `discover_manifests()`: recursive walker returning sorted manifest paths

`sar_archive::profile::ComplianceProfile` provides 8 profile variants with
`canonical_name()` and `from_canonical_name()` methods.

### Running conformance tests

```bash
cargo test -p sar-archive --test conformance_tests
```

9 test functions:
- `all_manifests_parse_and_schema_validates` — all manifests parse and pass schema checks
- `valid_non_deferred_vectors_parse_ok` — all valid non-deferred vectors parse successfully
- `invalid_non_deferred_vectors_are_rejected` — all invalid non-deferred vectors are rejected
- `deferred_vectors_have_no_binary_file` — deferred manifests have no unexpected binary
- `profile_expectations_use_known_profile_names` — profile names match ComplianceProfile
- `manifest_ids_are_unique` — no duplicate manifest IDs
- `conformance_summary` — summary report
- `bad_aead_tag_auth_failure` — AEAD auth failure with key provider
- `crypto_vectors_parse_structurally_with_key_provider` — crypto vectors with key material

### Regenerating binary fixtures

```bash
cargo run --example generate_vectors -p sar-archive
```

All fixtures are deterministic (fixed salts, iteration counts, payloads).

### Known gaps in M12a

- Stream/session binary vectors deferred (require network/transport context).
- Many invalid vectors deferred (fragment gaps, sparse overlaps, unsafe metadata, resource limits).
- Entry-level profile checks (per-entry algorithm gating, stream binding) not yet implemented.
- Cold-storage/tape profile vectors deferred (no SAR v1.0 interoperable mechanism yet).
- Full signature implementation/audit posture remains future work.
- No standalone conformance CLI (not in scope for M12a).
- The validator checks global-flag-level and structural correctness; entry-level profile
  enforcement gaps are documented in profile manifests.

### Relationship to M12b fuzzing

The official vectors in `test-vectors/` are the **canonical** small reproducible set.
M12b will add:
- A separate fuzzing corpus (not checked into the main tree)
- Malformed/adversarial vectors generated by fuzz targets
- cargo-fuzz / libFuzzer / AFL harnesses

The M12a manifest format and stable status identifiers are designed to be extended
by M12b fuzzing infrastructure without changing the M12a schema.

---

## Implemented profile coverage (M1–M11)

### Archive structure and indexing
- Global Header, LFH, Central Dictionary, Footer parsing/writing.
- Indexed archives and `NO_INDEX` archive flows.
- Fail-closed validation for malformed, reserved, and unsupported values.

### Transform pipeline and compression
- Transform ordering enforcement in high-level archive paths.
- Compression algorithms: `STORE`, `DEFLATE`, `ZSTD`.
- Bounded decode/transform memory via `ResourceLimits`.

### Crypto / KMS / authentication
- Hash support used by current implementation profiles (`SHA-256`, `BLAKE3`).
- AEAD support (`AES-256-GCM`, `XChaCha20-Poly1305`).
- KMS parsing/validation for implemented modes.
- Password-based encryption/decryption flows in CLI create/extract/verify.
- AEAD authentication enforced before plaintext release.

### FEC and recovery
- Selective FEC metadata handling and validation.
- XOR and Reed-Solomon file-level FEC support.
- Archive-level recovery metadata inspection/planning/repair for currently supported cases.

### Sparse, fragmentation, and loss-tolerant behavior
- Sparse map parse/write, validation, and bounded reconstruction.
- Fragment group validation and reassembly.
- `LOSS_TOLERANT` degraded-output behavior for missing-fragment cases only.
- Authentication/structural failures are never bypassed by lossy flags.

### CDC and delta
- CDC metadata/TLV structures and current CDC map handling.
- Delta metadata parsing and patch application for implemented algorithms (`STORE_PATCH`, `VCDIFF`, SAR BSDIFF v1).

### Streaming/session and transport
- Streaming parser/state model and session semantics (`sar-stream`).
- SAR-over-TCP and SAR-over-QUIC transport bindings (`sar-transport`) in current implemented profile.

### Metadata API and filesystem metadata
- LFH metadata API completeness from M11a/M11b.
- Filesystem metadata decode/encode coverage in archive APIs.
- Metadata surface includes permissions, owner, timestamps, hidden attribute, and symlink target where present.

### CLI metadata behavior (M11e)
- `sar create --preserve-permissions`
- `sar create --preserve-owner`
- `sar create --preserve-times`
- `sar create --symlinks skip|follow|archive`
- `sar extract --preserve-permissions`
- `sar extract --preserve-times`
- `sar extract --preserve-owner`
- `sar extract --allow-symlinks`
- `sar list --metadata`
- `sar inspect --json` metadata-rich output

## Known gaps

- This repository is **not yet a complete conformance suite**.
- Many invalid/negative vectors are deferred (see M12a gaps above).
- Full signature implementation/audit posture remains future work.
- Some algorithms are structurally represented but intentionally unsupported in the implemented profile.
- Delta/base-hash algorithm signaling remains limited by current spec ambiguity handling.
- Profile validation helpers are useful but are not a complete standalone conformance oracle.
- Platform-specific metadata restoration behavior remains policy-gated and best-effort where supported.
- No stable C ABI/Python/mobile binding surface is implemented in M1–M12a (future milestones).

## Milestone alignment (future)

- M12b: fuzzing and malicious corpus.
- M12c: documentation closeout.
- M13: security audit and remediation.
- M14: C ABI and Python module.
- M15: packaging and release automation.
- M16: Swift/iOS and Kotlin/Java Android packages.
