# SAR Conformance Test Vectors (M12a-stream-cp)

This directory contains the official conformance vector set for the SAR Protocol v1.0
reference implementation.

## Serialized SAR stream transcripts (M12a-stream-cp)

Vectors under `valid/stream-session/` and `invalid/stream-session/` are
**serialized SAR stream transcripts** — deterministic byte sequences shaped like a primary
SAR stream:

```
Global Header (NO_INDEX flag set)
SESSION_INIT / SESSION_CAPABILITIES / SESSION_CONTROL entries
optional ordinary stream entries (sequence-numbered LFH + payload)
```

These fixtures have `.sar` extension but are **not** ordinary static archives.

Key properties:
- **No live transport required.** These bytes are parsed in-memory by `sar-stream`. They do not require TCP or QUIC connectivity.
- **Additional QUIC control streams are not covered** by this pass. Those streams don't begin with SAR magic and are transport-specific.
- **Same bytes, different profiles.** A stream transcript may be valid in stream-session context and rejected by a static-archive profile (see `profiles/static-archive/reject-session-control/`).
- **This is not M12b fuzzing.** M12a-stream-cp is a deterministic conformance-vector pass.

Stream transcript semantic conformance is executed by
`crates/sar-stream/tests/stream_transcript_conformance_tests.rs`.
`sar-archive` conformance skips `stream:transcript` semantic checks and keeps default
archive-safe behavior (reject `SESSION_CONTROL` and nonzero `OP_CODE` by default).
`sar-archive` audit mode can optionally parse these fixtures structurally in inert mode,
but stream/session semantics remain owned by `sar-stream`.

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
    fec/                     — real XOR/Reed-Solomon selective FEC archives and shared metadata fixture
    fragmentation/           — deferred/reference-only fragment fixtures until real fragment binaries exist
    sparse/                  — real sparse reconstruction fixtures plus deferred sparse+delta reference
    cdc/                     — real CDC literal-mode fixture plus deferred FASTCDC CDC_MAP reference
    delta/                   — real STORE_PATCH, VCDIFF, and SAR BSDIFF v1 fixtures
    stream-session/          — serialized SAR stream transcript fixtures (SESSION_INIT, SESSION_CAPABILITIES, ordered-data, heartbeat, sequence-wrap)
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
    delta/                   — deterministic patch-algo/base-hash/truncation/limit fixtures
    stream-session/          — invalid session sequence, duplicate stream ID, heartbeat-with-payload, reserved opcode
    filesystem-metadata/     — absolute path, traversal, unsafe symlink, setuid bits
    resource-limits/         — excessive declared sizes, excessive TLV count
```

## Manifest format

Each vector or vector group has a `manifest.json` file following `manifest.schema.json`.

### Required fields

All manifests must include:

```json
{
  "schema_version": 1,
  "id": "unique-vector-id",
  "title": "Human-readable title",
  "description": "What this vector proves",
  "kind": "valid",
  "compression": false,
  "crypto": false,
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

`file`, `profiles`, `features`, `entries`, `base_files`, `notes`, and other metadata are
optional unless the manifest specifically needs them. Deferred/reference-only vectors use
`"file": null`.

### `compression` field

Every manifest must declare its compression posture:

```json
"compression": false
```

or, when the vector specifically exercises a compression algorithm:

```json
"compression": {
  "algorithm": "deflate",
  "id": "0x01"
}
```

Allowed algorithm values: `store`, `deflate`, `zstd`, `unsupported`, `reserved`.

### `crypto` field

Every manifest must declare its crypto posture:

```json
"crypto": false
```

or, when the vector exercises encryption/authentication:

```json
"crypto": {
  "algorithm": "aes-256-gcm",
  "id": "0x01",
  "password": "test-password",
  "kms": {
    "mode": "password",
    "salt_hex": "...",
    "kdf": "pbkdf2-hmac-sha256",
    "iterations": 100000
  }
}
```

See the **Test-secret policy** section below.

### `entries` field

Valid non-deferred vectors should include an `entries` array describing the logical
content after all transforms (decrypt → decompress → patch → sparse reconstruction).
This allows auditors to verify vector intent without reverse-engineering binary
fixtures:

```json
"entries": [
  {
    "name": "hello.txt",
    "kind": "file",
    "payload_utf8": "hello world",
    "payload_sha256": "...",
    "size": 11,
    "logical_size": 11,
    "extents": []
  }
]
```

Supported `kind` values: `file`, `directory`, `symlink`.

**Directory entries** require only `name` and `kind`:
```json
{"name": "docs/", "kind": "directory"}
```

**Symlink entries** require `symlink_target`:
```json
{"name": "link", "kind": "symlink", "symlink_target": "target.txt"}
```

**Sparse entries** include `extents`:
```json
{
  "name": "sparse.bin",
  "kind": "file",
  "logical_size": 128,
  "payload_sha256": "...",
  "extents": [
    {"offset": 0, "length": 32},
    {"offset": 64, "length": 32}
  ]
}
```

**Invalid/deferred vectors** may omit `entries` or leave it empty — no logical
archive content exists or can be described for archives that are expected to fail.

### Large/generated payload exception

For file entries where `size > 60` or `logical_size > 60`, omit `payload_utf8` and
`payload_hex`. Instead, include `payload_sha256` and `payload_generation`:

```json
{
  "name": "data.bin",
  "kind": "file",
  "payload_utf8": null,
  "payload_hex": null,
  "payload_sha256": "...",
  "size": 512,
  "logical_size": 512,
  "payload_generation": {
    "kind": "repeated_pattern",
    "pattern_hex": "0001020304...",
    "length": 512
  }
}
```

Allowed `payload_generation.kind` values:
- `repeated_byte` — single byte repeated N times
- `repeated_pattern` — byte pattern repeated
- `zeroes` — all zero bytes
- `external_fixture` — load from an external fixture file
- `sparse_logical` — sparse logical layout

Do **not** commit large binary payloads. For >4 GiB behavior, use deterministic
generation or sparse logical descriptions.

### `base_files` field

Delta vectors include `base_files` describing input files required for patching:

```json
"base_files": [
  {
    "path": "base_file.bin",
    "payload_sha256": "...",
    "size": 64,
    "payload_generation": { "kind": "repeated_pattern", ... }
  }
]
```

## Real fixtures vs deferred/reference-only manifests

M12a intentionally prefers a smaller honest fixture set over inflated coverage claims.

### Real binary fixtures in this tree

- minimal, indexed, and `NO_INDEX` archives
- compression (`STORE`, `DEFLATE`, `ZSTD`)
- crypto (`AES-256-GCM`, `XChaCha20-Poly1305`) with test-only secrets
- LFH selective FEC (`fec:xor`, `fec:reed-solomon`)
- sparse reconstruction (`valid/sparse/simple`)
- CDC literal mode (`valid/cdc/literal-mode`)
- delta `STORE_PATCH`, VCDIFF, and SAR BSDIFF v1
- filesystem metadata fixtures
- 32-bit and 64-bit LFH size-layout fixtures
- archive-level Recovery TLV (`valid/recovery/archive-xor/recovery_tlv_archive_xor.sar`, `valid/recovery/archive-rs/recovery_tlv_archive_rs.sar`)
- deterministic invalid recovery fixtures under `invalid/recovery/`
- deterministic invalid delta fixtures under `invalid/delta/`
- serialized SAR stream transcript fixtures under `valid/stream-session/` and `invalid/stream-session/` (M12a-stream-cp)

### Deferred/reference-only manifests in this tree

- fragmentation reassembly
- LOSS_TOLERANT fragment-gap coverage
- sparse+delta combined ordering
- FASTCDC `CDC_MAP`

Archive-level Recovery TLV coverage is now backed by real generated fixtures:
`valid/recovery/archive-xor/recovery_tlv_archive_xor.sar` and
`valid/recovery/archive-rs/recovery_tlv_archive_rs.sar`. These archives use Central
Dictionary RECOVERY TLVs plus `HAS_GLOBAL_EC`; they are intentionally separate from
the LFH Selective FEC fixtures in `valid/fec/xor/` and `valid/fec/rs/`.

TODO: add top-level fixture digests/provenance fields in a later M12a hardening pass.

### Feature consistency rules

The `features` array and the `compression` / `crypto` fields must agree:

1. If `compression` is an object, `features` must contain `compression:<algorithm>`.
2. If `compression` is `false`, `features` must not contain any `compression:*` entry.
3. If `crypto` is an object, `features` must contain `crypto:<algorithm>`.
4. If `crypto` is `false`, `features` must not contain any `crypto:*` entry.

The conformance tests enforce this automatically.

## Test-secret policy

Crypto vectors may intentionally include test-only passwords, salts, and KMS
parameters in their `crypto` field. This is **by design** for public conformance
testing:

- Use obvious test-only values (e.g. `"sar-test-password-aes"`).
- Never use real secrets.
- Archive payloads must be non-secret test content.
- Add a note where useful: `"This vector intentionally includes unsafe test-only crypto material for public conformance testing."`

The passwords in crypto vector manifests are the same as those used by
`crates/sar-archive/examples/generate_vectors.rs` and
`crates/sar-archive/tests/conformance_tests.rs`.

## Invalid vectors

For invalid vectors the `expected` block uses the relevant SAR error status:

```json
"expected": {
  "valid": false,
  "status": "SAR_ERR_MALFORMED",
  "error": "Malformed",
  "warnings": []
}
```

`expected.status` is the authoritative machine-readable validation oracle.
`expected.error` is advisory human-readable debugging text only. Cross-implementation
validators must not require exact `expected.error` string matching.

Invalid vectors may omit `entries` — there is no valid logical archive to describe.
Non-deferred invalid vectors should reference real generated `.sar` fixtures; deferred invalid vectors may set `file` to `null`.

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
| `SAR_ERR_PATCH_FAILED`  | Delta patch application failed               |
| `SAR_ERR_BASE_MISSING`  | Required delta base identity/data missing    |
| `SAR_ERR_EC_FAILED`     | Error-correction decode failed               |
| `SAR_ERR_BOUNDS`        | Bounds violation                             |
| `SAR_ERR_OVERFLOW`      | Arithmetic overflow                          |
| `SAR_ERR_FRAGMENT_GAP`  | Fragment gap without LOSS_TOLERANT           |
| `SAR_ERR_INVALID_MAP`   | Invalid sparse/CDC map                      |
| `SAR_ERR_INVALID_LENGTH`| Invalid declared length                      |

Do **not** over-specify exact human-readable error message strings — only stable
`expected.status` identifiers are durable across implementation revisions.

## Deferred vectors

Deferred vectors have `"deferred": true` and may set `"file": null`. They document
intended behavior for features not yet implemented. Deferred vectors:

- Must not have an existing binary file on disk.
- May omit or empty `entries`.
- Must still include `compression` and `crypto` fields.

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

Profile manifest `file` paths use relative references. A profile manifest at
`test-vectors/profiles/<profile>/<case>/manifest.json` that references a shared
vector at `test-vectors/valid/...` uses:

```
../../../valid/...
```

(three levels up to reach the `test-vectors/` root).

## How to inspect vector intent

1. Read `manifest.json`: check `compression`, `crypto`, `entries`, and `base_files`.
2. Cross-check `features` is consistent with `compression`/`crypto` objects.
3. For encrypted vectors, use the `crypto.password` and `crypto.kms` details to
   decrypt the binary manually.
4. For delta vectors, use the `base_files` entries as inputs to the patch operation.
5. For sparse vectors, reconstruct the logical file from `entries[].extents`.
6. The `entries` field describes the fully-decoded logical content after all
   transforms — this is what a correct implementation must produce.

## How to validate a vector

### Using the Rust conformance validator

```bash
cargo test -p sar-archive --test conformance_tests
cargo test -p sar-archive --test conformance_manifest_tests
cargo test -p sar-stream --test stream_transcript_conformance_tests
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
   - Include `compression` and `crypto` fields.
   - For valid vectors, include `entries` with expected logical content.
   - For large payloads (> 60 bytes), use `payload_generation` instead of inline hex.
4. Validate the manifest JSON: `python3 -m json.tool manifest.json > /dev/null`
5. Run: `cargo test -p sar-archive --test conformance_manifest_tests`

Keep vector files **small and reviewable** (< 4 KiB for most vectors).

## Valid vs invalid vs profile-specific vectors

- **Valid**: Archives that any conformant implementation must accept. Should have
  non-empty `entries`.
- **Invalid**: Archives that any conformant implementation must reject. `entries` may
  be omitted or empty — no valid logical archive exists.
- **Profile**: Vectors whose acceptance depends on the chosen conformance profile.
  Profile vectors may be acceptable under one profile and rejected under another.
  Non-deferred profile vectors pointing to valid archives should have `entries`.

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
    recovery/                — archive-level Recovery TLV flag/metadata/repair-negative fixtures
