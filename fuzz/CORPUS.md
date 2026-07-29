<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR Malicious Corpus Taxonomy

This file documents the M12b.5 malicious corpus taxonomy for SAR fuzzing.

Each category has a seed directory under `fuzz/seeds/<category>/`. Seed
directories are tracked in git so that future fuzz targets can consume them
without requiring per-target setup.

Generated libFuzzer corpus outputs go to `fuzz/corpus/` (gitignored). Crash
artifacts go to `fuzz/artifacts/` (gitignored). Neither path is committed.

No exhaustive fuzzing coverage, production hardening, independent security
audit completion, or malicious corpus completeness is claimed.

---

## Categories

### `transform_pipeline`

**Purpose:** Exercise multi-step transform chains where an attacker controls
the pipeline composition. Targets cases such as a deeply nested pipeline,
repeated application of the same transform, incompatible transform adjacency,
or a pipeline whose composed output exceeds resource limits.

**Example input shapes:**
- LFH bytes with COMPRESS_ALGO and ENCRYPT_ALGO fields set to unusual or
  reserved combinations.
- Archives where a single entry declares a long pipeline (max-depth or
  beyond-max-depth transform chain).
- Inputs where each transform step individually validates but the composed
  result triggers an overflow or policy violation.

**Expected fail-closed behavior:** The parser or archive reader must reject
invalid or unsupported transform combinations with a deterministic error.
Resource limits must be checked before any transform allocation or expansion
step. No panic must result from deeply nested or mutually incompatible
transform chains.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR2.

---

### `transform_switching_dos`

**Purpose:** Target rapid or mid-stream transform switches designed to cause
expensive state teardown and re-initialization. An adversary may craft a
sequence of entries that repeatedly change algorithms to exhaust CPU or memory
through churn rather than a single large allocation.

**Example input shapes:**
- Archives with many small entries each declaring a distinct compression or
  encryption algorithm, forcing repeated codec initialization.
- Sequences that alternate between supported and unsupported algorithms to
  probe error-path cleanup cost.
- A single entry whose transform fields cycle through every enumerated value.

**Expected fail-closed behavior:** Each unsupported or reserved algorithm must
be rejected with a deterministic error on first encounter. Per-entry resource
limits must prevent unbounded cumulative state growth. No panic or undetected
resource leak must result.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR2.

---

### `crypto_auth_ordering`

**Purpose:** Verify that authentication checks always precede or are correctly
interleaved with decryption. Corpus covers inputs where AEAD tag bytes are
absent, truncated, or reordered relative to ciphertext to confirm that the
implementation never returns plaintext before authentication succeeds.

**Example input shapes:**
- Archives with an encrypted entry whose AEAD tag is missing or shorter than
  the required length.
- Entries where ciphertext length and authenticated-data length fields
  disagree.
- Sequences of entries that mix authenticated and unauthenticated payloads in
  the same archive to probe ordering logic.

**Expected fail-closed behavior:** Authentication failure must always produce
an error before any plaintext is returned. A truncated or absent AEAD tag must
be rejected outright. No partial plaintext must be surfaced to the caller.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR3.

---

### `tls_exporter_aad_negative`

**Purpose:** Negative corpus for TLS exporter and AAD derivation. Covers
inputs designed to supply invalid, mismatched, or absent exporter labels and
context values, and to verify that AAD derivation fails closed rather than
silently producing incorrect key material.

**Example input shapes:**
- Archives that declare a TLS-exporter key derivation path but supply a
  zero-length or reserved label.
- Inputs where the AAD context bytes are truncated mid-field.
- Archives with a KMS extension whose exporter-derived fields conflict with
  the global key identifier.

**Expected fail-closed behavior:** Any mismatch between declared and supplied
exporter material must result in a deterministic key-derivation or
authentication error. No raw exporter-derived bytes must be surfaced in errors,
logs, or debug output.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR3.

---

### `decompression_bomb`

**Purpose:** Detect cases where a small compressed input expands to a very
large output. Targets the decompression path with inputs crafted to expand
far beyond declared or permitted sizes, stressing the resource-limit
enforcement that must halt expansion before memory is exhausted.

**Example input shapes:**
- Compressed payloads (e.g., zlib or zstd streams) that decompress to output
  many times the compressed size.
- Payloads whose declared uncompressed size in the LFH is very large but whose
  compressed bytes are minimal.
- Payloads with a declared size that matches the resource limit exactly, to
  probe boundary enforcement.

**Expected fail-closed behavior:** Decompression must stop and return an error
as soon as the running output size would exceed the configured resource limit.
No allocation beyond the enforced limit must be attempted. No panic must
result.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR2.

---

### `allocator_churn`

**Purpose:** Generate high allocator pressure through a long sequence of small
or medium allocations and frees, looking for use-after-free, double-free, or
allocator exhaustion in paths that resize internal buffers repeatedly.

**Example input shapes:**
- Archives with many small entries that each trigger a separate buffer
  allocation, decoded in sequence to maximize alloc/free cycling.
- Inputs that alternate between entries requiring heap expansion and entries
  that fit in existing capacity.
- Malformed entries whose decode path allocates and then immediately returns
  an error, exercising cleanup paths.

**Expected fail-closed behavior:** Every allocation must be bounded by
resource limits. Errors returned during decode must leave no heap corruption.
Repeated alloc/free cycles must not cause allocator exhaustion or undefined
behavior.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR2.

---

### `fec_fragmentation`

**Purpose:** Target the FEC (Forward Error Correction) and packet
fragmentation paths. Inputs include crafted fragment sequences, mismatched
FEC metadata, overlapping or out-of-order fragments, and FEC repair attempts
against entries with corrupted or absent repair blocks.

**Example input shapes:**
- LFH entries with FEC TLVs declaring more repair blocks than present in the
  data.
- Fragment sequences with deliberate gaps, duplicates, or illegal fragment
  offsets.
- Archives where the FEC parity data length disagrees with the declared
  parameters.
- Inputs that trigger FEC repair on an entry with every original shard
  missing.

**Expected fail-closed behavior:** Mismatched, absent, or malformed FEC data
must produce a deterministic error. The repair path must not attempt
out-of-bounds reads or allocations when shard counts are wrong. Fragment
reassembly must reject overlapping or illegally-sized fragments without panic.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR4.

---

### `cdc_delta`

**Purpose:** Cover content-defined chunking (CDC) boundary computation and
delta-patch application paths. Malicious inputs may cause incorrect chunk
boundaries, referencing non-existent delta bases, or integer overflow in
delta offset calculations.

**Example input shapes:**
- Delta entries whose base-archive reference is absent or points outside the
  known archive set.
- Payloads with a CDC rolling-hash window that would overflow a fixed-size
  state buffer.
- Delta patches with add/copy operations that reference negative or
  out-of-bounds source offsets.
- Entries declaring a delta base whose size field overflows when combined with
  a patch length.

**Expected fail-closed behavior:** A missing or unresolvable delta base must
produce a deterministic error. Integer overflow in delta offset arithmetic must
be detected with checked arithmetic. Out-of-bounds copy operations in a patch
must be rejected without panic.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR4.

---

### `stream_session`

**Purpose:** Cover streaming and session semantics: frame ordering, session
ID collisions, transcript replay, session teardown races, and frames that
arrive outside the expected lifecycle sequence.

**Example input shapes:**
- Stream transcripts with duplicate or out-of-order frame sequence numbers.
- Session open/close frames in reversed order to probe lifecycle state checks.
- Transcripts referencing a session ID that was never opened.
- Long transcripts with frames that oscillate between valid and malformed to
  stress incremental validation.

**Expected fail-closed behavior:** Frames received outside the expected
session lifecycle must be rejected with a deterministic error. Duplicate
sequence numbers must be detected and not cause double-processing. Malformed
transcripts must return errors at the first invalid frame without undetected
state corruption.

**Current status:** seed-only. Partial overlap with the existing
`stream_transcript` fuzz target (transcript-level semantic validation). Full
session lifecycle fuzzing is planned for PR4.

---

### `metadata_edge_cases`

**Purpose:** Probe archive and entry metadata fields for edge cases: maximum
lengths, reserved field violations, conflicting flags, and non-UTF-8 path
bytes that may be accepted in some encodings but rejected in strict mode.

**Example input shapes:**
- Entry path fields at the maximum allowed length.
- Path fields containing null bytes, control characters, or non-UTF-8
  sequences.
- Global header flag combinations that are individually valid but mutually
  exclusive.
- Central Dictionary entries whose field lengths disagree with corresponding
  LFH fields.

**Expected fail-closed behavior:** Non-UTF-8 or null-containing path fields
must be rejected in strict mode and handled gracefully in permissive mode
without panic. Reserved flag bits must be rejected outright. CD/LFH
disagreements must produce a deterministic validation error.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR4.

---

### `filesystem_metadata_malformed`

**Purpose:** Target filesystem metadata extraction paths: entries with
malformed or adversarial permissions, timestamps, ownership fields, symlink
targets, or hardlink references that could cause unexpected behavior during
extraction.

**Example input shapes:**
- Entries with symlink targets pointing to absolute paths, parent-directory
  traversals (`../`), or paths beginning with `/`.
- Entries with ownership fields (uid/gid) at maximum integer values.
- Entries declaring hardlink targets that do not exist in the archive.
- Entries with timestamps far in the past or future (year 0, year 9999, or
  near integer overflow boundaries).

**Expected fail-closed behavior:** Path traversal attempts must be detected
and rejected before any filesystem operation. Overflow values in numeric
metadata fields must be caught with checked arithmetic. Unresolvable hardlink
or symlink references must produce a deterministic error.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR4.

---

### `extraction_race`

**Purpose:** Probe extraction paths for time-of-check/time-of-use (TOCTOU)
conditions and race-sensitive sequences: entries that create a directory then
overwrite it with a file, symlinks created before the target they point to,
and extraction orders that rely on implicit ordering guarantees.

**Example input shapes:**
- Archives where a directory entry is followed immediately by a file entry
  with the same path.
- Archives with symlinks whose targets are created in a later entry, requiring
  deferred resolution.
- Archives with a deeply nested directory tree where intermediate nodes are
  absent from the entry list.

**Expected fail-closed behavior:** Extraction logic must not assume that
filesystem state from a prior entry is stable when processing a later entry.
Absent intermediate directories must be created safely or the entry must be
rejected with a deterministic error. No TOCTOU window must be exposed for
path traversal escalation.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR5.

---

### `profile_rejection`

**Purpose:** Verify that archives or entries declaring unsupported, unknown,
or future-version profiles are rejected deterministically without partial
processing or silent fallback.

**Example input shapes:**
- Archives with a global profile field set to a reserved or unknown value.
- Archives whose declared profile version is higher than the implementation's
  maximum supported version.
- Entries with a profile-specific extension field whose length exceeds the
  declared profile's maximum.
- Archives that mix profile fields from incompatible profile versions in the
  same global header.

**Expected fail-closed behavior:** An unknown or reserved profile must be
rejected at header-parse time with a deterministic error. No partial
processing of profile-specific fields must occur after a profile rejection.
A higher-than-supported version number must be treated as unsupported, not
silently downgraded.

**Current status:** seed-only. No dedicated fuzz target yet. Planned for PR5.
