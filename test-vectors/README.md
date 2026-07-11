# SAR Conformance Test Vectors (M12a)

This directory contains the official conformance vector set for the SAR Protocol v1.0
reference implementation.

## What are conformance vectors?

Conformance vectors are small, canonical binary archives (`.sar` files) paired with
machine-readable manifests (JSON) that specify the expected parse/validation outcome.
They provide a portable, reproducible test harness for verifying correct SAR
implementation behavior across any implementation.

## Directory layout

```
test-vectors/
  README.md                  — this file
  manifest.schema.json       — JSON schema for all manifest files
  profiles/
    README.md                — profile descriptions and cold-storage/tape status
    static-archive/          — static archive profile vectors
    package/                 — package profile vectors
    stream-package/          — stream package profile vectors
    backup/                  — backup profile vectors
    telemetry/               — telemetry profile vectors
    live-media/              — live-media profile vectors
    cold-storage/            — cold-storage/tape placeholder (see profiles/README.md)
  valid/
    minimal/                 — minimal single-entry archives (STORE + NO_INDEX)
    indexed/                 — indexed archives with central dictionary
    no-index/                — NO_INDEX forward-only archives
    compression/             — STORE / DEFLATE / ZSTD compression variants
    crypto/                  — AES-256-GCM and XChaCha20-Poly1305 encrypted archives
    fec/                     — XOR FEC and Reed-Solomon FEC archives
    fragmentation/           — fragmentation reassembly vectors
    sparse/                  — sparse file reconstruction vectors
    cdc/                     — CDC metadata vectors
    delta/                   — STORE_PATCH, VCDIFF, BSDIFF delta vectors
    stream-session/          — SESSION_INIT / SESSION_CLOSE stream vectors
    filesystem-metadata/     — permissions, owner, timestamps, symlink, directory vectors
  invalid/
    structure/               — truncated GH/LFH/CD/Footer cases
    flags/                   — Global Flag and Entry Mode conflicts
    algorithms/              — unsupported/reserved compression/crypto/FEC/CDC/delta IDs
    crypto/                  — bad AEAD tag, wrong nonce, mismatched KMS
    fec/                     — malformed FEC metadata
    fragmentation/           — gap, overlap, duplicate index, missing LAST_FRAGMENT
    sparse/                  — sparse extent overlap, zero-length, excessive size
    cdc/                     — malformed CDC metadata, reserved CDC IDs
    delta/                   — malformed delta metadata, unsupported patch algorithms
    stream-session/          — invalid session sequence, duplicate stream ID
    filesystem-metadata/     — absolute path, traversal, unsafe symlink, setuid bits
    resource-limits/         — excessive declared sizes, excessive TLV count
```

## Manifest format

Each vector or vector group has a `manifest.json` file following `manifest.schema.json`.

Minimum required fields:

```json
{
  "schema_version": 1,
  "id": "unique-vector-id",
  "title": "Human-readable title",
  "description": "What this vector proves",
  "kind": "valid",
  "file": "relative/path/to/vector.sar",
  "profiles": ["static-archive"],
  "features": ["indexed", "compression:zstd"],
  "expected": {
    "valid": true,
    "status": "SAR_OK",
    "error": null,
    "warnings": []
  },
  "limits": {},
  "notes": []
}
```

For invalid vectors the `expected` block uses the relevant SAR error status:

```json
"expected": {
  "valid": false,
  "status": "SAR_ERR_MALFORMED",
  "error": "Malformed",
  "warnings": []
}
```

Stable SAR status identifiers (from `SarStatus` in `sar-core`):

| Status identifier       | Meaning                                      |
|-------------------------|----------------------------------------------|
| `SAR_OK`                | Success                                      |
| `SAR_ERR_MALFORMED`     | Malformed structure                          |
| `SAR_ERR_TRUNCATED`     | Truncated structure                          |
| `SAR_ERR_UNSUPPORTED`   | Valid but unsupported feature/algorithm      |
| `SAR_ERR_RESERVED_VALUE`| Encountered reserved value                  |
| `SAR_ERR_FLAG_CONFLICT` | Invalid flag combination                    |
| `SAR_ERR_INVALID_MAGIC` | Header magic mismatch                        |
| `SAR_ERR_AUTH_FAILED`   | Authentication failure                       |
| `SAR_ERR_LIMIT_EXCEEDED`| Implementation resource limit exceeded       |
| `SAR_ERR_BOUNDS`        | Bounds violation                             |
| `SAR_ERR_OVERFLOW`      | Arithmetic overflow                          |
| `SAR_ERR_FRAGMENT_GAP`  | Fragment gap without LOSS_TOLERANT           |
| `SAR_ERR_INVALID_MAP`   | Invalid sparse/CDC map                      |
| `SAR_ERR_INVALID_LENGTH`| Invalid declared length                      |

Do **not** over-specify exact human-readable error message strings — only stable
status/error identifiers are durable across implementation revisions.

## Profile expectations

Where a vector has profile-specific acceptance or rejection:

```json
"profile_expectations": {
  "static-archive": "accept",
  "package":        "reject",
  "backup":         "accept",
  "telemetry":      "reject"
}
```

Values: `"accept"`, `"reject"`, `"skip"`. Absent key means the vector does not
address that profile.

See `profiles/README.md` for profile descriptions.

## How to validate a vector

### Using the Rust conformance validator

The `sar-archive` crate provides a conformance module at
`sar_archive::conformance`. To run all vectors:

```bash
cargo test -p sar-archive --test conformance_tests
```

To regenerate binary fixture files:

```bash
cargo run --example generate_vectors -p sar-archive
```

### Manual validation

1. Parse `manifest.json` and verify schema fields are present.
2. Locate the binary file at the path given by `manifest.json → file`.
3. Attempt to parse the archive with `ArchiveReader`.
4. If `expected.valid == true`: parsing and full entry read must succeed.
5. If `expected.valid == false`: parsing must fail with a `SarError` matching
   the `expected.status` identifier.
6. For profile vectors: additionally verify that the archive is accepted or
   rejected by the named profiles in `profile_expectations`.

## How to add a vector

1. Create a subdirectory under the appropriate category.
2. Generate the `.sar` binary using:
   - `crates/sar-archive/examples/generate_vectors.rs` (preferred for common patterns)
   - A standalone Rust snippet using `ArchiveWriter`
   - A hand-crafted byte sequence (for truncated/malformed cases)
3. Create `manifest.json` in the same directory following `manifest.schema.json`.
4. Validate the manifest JSON: `python3 -m json.tool manifest.json > /dev/null`
5. Add the new vector to the relevant test in
   `crates/sar-archive/tests/conformance_tests.rs`.

Keep vector files **small and reviewable** (< 4 KiB for most vectors).

## Valid vs invalid vs profile-specific vectors

- **Valid**: Archives that any conformant implementation must accept.
- **Invalid**: Archives that any conformant implementation must reject.
- **Profile**: Vectors whose acceptance depends on the chosen conformance profile.
  Profile vectors may be acceptable under one profile and rejected under another.

## Stable expected-status policy

- Use stable `SAR_STATUS_*` identifiers for `expected.status`.
- Do not hard-code exact human-readable error message strings.
- Do not over-specify which sub-error variant of a status class is returned.
- Where the exact error class is ambiguous, prefer the most general stable parent
  identifier and document the ambiguity in `notes`.

## Conformance claim policy

This vector set covers the **implemented SAR v1.0 profile** as described in
`docs/CONFORMANCE.md`.

This is **not** a claim of full SAR v1.0 standard conformance. Known gaps are
documented in `docs/CONFORMANCE.md`.

## Cold-storage/tape status

Cold-storage/tape vectors are deferred. See `profiles/README.md` for details.
