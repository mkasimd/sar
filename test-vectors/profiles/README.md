# SAR Conformance Profiles

This directory contains profile-specific conformance vectors for SAR Protocol v1.0.

## What is a conformance profile?

A conformance profile is a named set of acceptance and rejection rules that govern
which SAR archives and features are permitted in a particular deployment context.
Profiles allow implementations to apply strict rules appropriate for their use case
(e.g. reject lossy data in a static backup profile) while remaining interoperable
at the wire-format level.

## Defined profiles

### `static-archive`

**Purpose:** Long-lived, immutable, indexed archives such as software distributions
and data archives.

**Accepts:**
- Indexed archives with central dictionary
- STORE, DEFLATE, ZSTD compression
- AES-256-GCM and XChaCha20-Poly1305 encryption (where implemented)
- XOR and Reed-Solomon FEC
- Filesystem metadata (permissions, timestamps, owner, symlinks)
- Content hashes (DEDUPLICATION flag)

**Rejects:**
- NO_INDEX archives (forward-only required for static archives is disallowed)
- LOSS_TOLERANT entries
- Unsupported or custom algorithm IDs
- Unsafe filesystem metadata (absolute paths, traversal, setuid/setgid)
- Excessive resource declarations

**Implementation status:** Partially implemented. `sar_archive::profile::validate_archive_profile`
checks global-flag-level constraints (NO_INDEX rejection, LOSS_TOLERANT rejection). Entry-level
checks (per-entry algorithm gating, unsafe metadata detection) are not yet enforced at the profile
layer; they are deferred to CLI extraction guards and future M13 work.

---

### `package`

**Purpose:** Software distribution packages requiring integrity and
non-repudiation. Similar to `static-archive` with stricter requirements.

**Accepts:**
- Indexed archives
- STORE, DEFLATE, ZSTD compression
- Cryptographic authentication (hash/AEAD)

**Rejects:**
- LOSS_TOLERANT entries
- NO_INDEX archives
- Unsupported/custom algorithms
- Lossy package data
- Unsafe filesystem metadata

**Implementation status:** Partially implemented. `validate_archive_profile` rejects LOSS_TOLERANT and NO_INDEX globally. Entry-level checks (algorithm gating, lossy data, unsafe metadata) are deferred to CLI extraction guards and future M13 work.

---

### `stream-package`

**Purpose:** SAR archives streamed over a transport channel (TCP/QUIC),
where entries may arrive sequentially without an index.

**Accepts:**
- NO_INDEX archives or indexed archives
- Session semantics (SESSION_INIT, SESSION_CLOSE)
- STORE, DEFLATE, ZSTD compression
- LOSS_TOLERANT entries where explicitly permitted

**Rejects:**
- Unauthenticated post-binding entries (when TLS_EXPORTER binding is active)
- Duplicate active Stream IDs
- Invalid session sequence
- Unsupported/custom algorithms (unless profile explicitly allows them)
- Excessive resource declarations

**Implementation status:** Partially implemented. Transport bindings in
`sar-transport`; session semantics in `sar-stream`.

---

### `backup`

**Purpose:** System and data backup archives that preserve complete filesystem
state, potentially with deduplication, delta, and sparse support.

**Accepts:**
- Indexed archives
- STORE, DEFLATE, ZSTD compression
- AES-256-GCM and XChaCha20-Poly1305 encryption
- XOR and Reed-Solomon FEC
- Filesystem metadata (permissions, owner, timestamps, symlinks, directories)
- Sparse files
- CDC and delta vectors
- Content hashes

**Rejects:**
- Unsafe filesystem metadata (absolute paths, traversal)
- Excessive resource declarations
- Unsupported/custom algorithms

**Implementation status:** Partially implemented. `validate_archive_profile` enforces indexed-archive and metadata-flag-level checks. Full entry-level profile enforcement is deferred.

---

### `telemetry`

**Purpose:** High-frequency, potentially lossy telemetry data streams
where best-effort delivery is acceptable for non-critical entries.

**Accepts:**
- NO_INDEX archives
- STORE, DEFLATE, ZSTD compression
- LOSS_TOLERANT entries
- Session semantics

**Rejects:**
- Entries requiring full reconstruction (e.g. AEAD with bad tag still rejected)
- Unsafe filesystem metadata
- Authentication/structural failures (LOSS_TOLERANT never suppresses these)

**Implementation status:** Partially implemented. Profile acceptance/rejection expectations are documented in manifests. Full validator enforcement deferred.

---

### `live-media`

**Purpose:** Real-time media streaming where frame loss is acceptable but
must be bounded. Compatible with transport-level loss tolerance.

**Accepts:**
- NO_INDEX archives
- STORE, DEFLATE, ZSTD compression
- LOSS_TOLERANT entries within defined gap limits
- Session semantics
- Fragment-based streaming

**Rejects:**
- Unauthenticated post-binding entries (where TLS binding is active)
- Fragment gaps exceeding `max_loss_tolerant_gap`
- Authentication/structural failures

**Implementation status:** Partially implemented. Profile acceptance/rejection expectations are documented in manifests. Full validator enforcement deferred.

---

### `cold-storage` (deferred)

**Status: DEFERRED — no binary vectors in M12a.**

The cold-storage/tape profile is intended for archival storage on sequential media
(tape, optical disc) where the archive may be read after long periods with
potentially degraded physical media.

**Deferral reason:** The current SAR v1.0 implementation does not include a
specified sidecar, container, or profile mechanism that is specific to cold
storage/tape behavior beyond what is already covered by the general
indexed/`NO_INDEX` archive, FEC, and fragmentation features.

Until an explicit cold-storage profile mechanism is documented in the SAR
specification or an agreed profile extension is defined in this repository,
cold-storage vectors are deferred to avoid creating non-interoperable or
non-canonical fixtures.

**What to do instead:**
- General FEC vectors (XOR/RS) cover the data-recovery aspect of cold storage.
- General indexed archive vectors cover the random-access aspect.
- When a cold-storage profile spec or mechanism is agreed, add a note here and
  create vectors under `profiles/cold-storage/`.

---

## Profile rejection rules (summary)

All profiles must reject:

| Condition                                       | Reason                          |
|-------------------------------------------------|---------------------------------|
| Unsupported/custom algorithm IDs               | Fail-closed for unknown algos   |
| Absolute paths in filesystem metadata          | Path traversal hazard           |
| `..` traversal components in paths             | Path traversal hazard           |
| Setuid/setgid/sticky bits (by default)         | Privilege escalation hazard     |
| AEAD/auth failures                             | Never loss-tolerant             |
| Decompression/patch/structural failures        | Never loss-tolerant             |
| Excessive declared sizes (resource limits)     | DoS / resource exhaustion       |

Additional per-profile restrictions are documented above.

## Profile validator implementation

The Rust conformance profile validator is in `sar-archive::conformance` and
`sar-archive::profile`. See `crates/sar-archive/src/conformance.rs` and
`crates/sar-archive/src/profile.rs`.

Profile-specific vectors include `profile_expectations` in their manifests:

```json
"profile_expectations": {
  "static-archive": "accept",
  "package":        "reject",
  "backup":         "accept",
  "telemetry":      "reject"
}
```

Known validator limitations are documented in `docs/CONFORMANCE.md`.
