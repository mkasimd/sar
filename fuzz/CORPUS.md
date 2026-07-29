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

**Purpose:** Exercise archive entry decoding across supported and mutated transform
metadata. This category focuses on reader-side transform initialization,
resource-limit enforcement, and fail-closed handling when transform metadata is
malformed, unsupported, truncated, or inconsistent with the payload.

**Example input shapes:**

- Valid STORE, DEFLATE, and ZSTD archive seeds used as mutation starting points.
- Archives with multiple small compressed entries to exercise repeated
  decompressor initialization and teardown.
- Entries whose compression metadata is mutated to reserved, unsupported, or
  malformed algorithm IDs.
- Truncated or malformed compressed payloads.
- Entries whose declared decoded size or metadata exceeds configured resource
  limits.

**Expected fail-closed behavior:** Unsupported or malformed transform metadata
must be rejected with a deterministic error. Resource limits must be checked
before decompression expansion or large allocation. Malformed compressed payloads
must not panic and must not cause unbounded memory growth.

**Current status:** Seeds added in PR2 (`minimal_store.bin`,
`single_entry_deflate.bin`, `single_entry_zstd.bin`, `multi_entry_deflate.bin`,
`multi_entry_zstd.bin`, `empty_deflate.bin`, `truncated_global_header.bin`,
`empty.bin`). Covered by the `transform_pipeline_fuzz` target. Encryption,
AAD/TLS exporter behavior, and delta patch transforms are covered by separate
corpus categories.

---

### `transform_switching_dos`

**Purpose:** Target repeated transform setup and teardown patterns that could
cause excessive CPU, memory, or allocator churn through many small entries rather
than one large archive member.

**Example input shapes:**

- Archives with many small STORE entries.
- Archives with many small DEFLATE entries.
- Archives with many small ZSTD entries.
- Mutations that alternate supported, reserved, and unsupported compression
  algorithm IDs across entries.
- Truncated or malformed archives that fail during repeated entry walking.

**Expected fail-closed behavior:** Unsupported or reserved algorithms must be
rejected deterministically. Per-entry and pipeline resource limits must prevent
unbounded cumulative state growth. Repeated codec initialization, teardown, and
error-path cleanup must not panic or leak unbounded state.

**Current status:** Seeds added in PR2 (`many_store_entries.bin`,
`many_small_deflate_entries.bin`, `many_small_zstd_entries.bin`,
`magic_only.bin`, `truncated_global_header.bin`, `empty.bin`). Partially covered
by `transform_pipeline_fuzz` and existing archive reader/audit fuzz targets.
Additional dedicated state-machine or transform-switching targets may be added
later if needed, but are not part of PR3.

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

**Current status:** PR3 seeds added (`wrong_global_header_aad.bin`,
`wrong_lfh_aad.bin`, `bad_tag.bin`, `bad_ciphertext.bin`,
`generic_auth_failure.bin`) and covered by
`crypto_auth_tls_exporter_negative`.

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

**Current status:** PR3 seeds added (`wrong_session_binding.bin`,
`malformed_kms_empty_label.bin`, `malformed_kms_reserved_kdf.bin`,
`malformed_kms_reserved_flags.bin`, `malformed_kms_truncated_salt.bin`)
and covered by `crypto_auth_tls_exporter_negative`.

---

### `decompression_bomb`

**Purpose:** Detect cases where small compressed inputs could expand beyond
configured decoded-size, pipeline-memory, or archive-size limits.

**Example input shapes:**

- Compressed payloads that decompress to output much larger than their compressed
  size.
- Entries whose declared decoded size is near, equal to, or above configured
  resource limits.
- Truncated compressed streams that fail during decompression initialization or
  early output production.
- Multi-entry archives that repeatedly approach decoded-size limits.

**Expected fail-closed behavior:** Decompression must stop and return an error as
soon as the running decoded output would exceed the configured resource limit.
No allocation beyond the enforced limit must be attempted. No panic must result.

**Current status:** Partially covered by PR2 through `transform_pipeline_fuzz`
and compressed archive seeds. Dedicated high-ratio decompression-bomb seeds may
still be added later, but must remain bounded and must not require committing
large generated payloads.

---

### `allocator_churn`

**Purpose:** Generate repeated bounded allocation, resize, cleanup, and
error-path activity through many small archive entries, transform initialization
cycles, and malformed inputs that fail after bounded intermediate setup.

**Example input shapes:**

- Archives with many small entries that each trigger separate reader-side buffer
  handling.
- Archives with many small compressed entries that repeatedly initialize and
  tear down decompressor state.
- Inputs that alternate between entries fitting within existing limits and
  entries rejected by resource limits.
- Malformed entries whose decode path allocates bounded intermediate state and
  then returns an error.

**Expected fail-closed behavior:** Every allocation must remain bounded by
resource limits. Decode errors must clean up intermediate state without panic.
Repeated allocation and cleanup cycles must not cause unbounded memory growth.

**Current status:** Partially covered by PR2 through many-entry transform seeds,
`transform_pipeline_fuzz`, `archive_entry_decode`, and `archive_audit`.
Additional targeted allocator-churn fuzzing may be added later if needed.

---

### `stream_session`

**Purpose:** Cover streaming and session semantics: frame ordering, session ID
collisions, transcript replay, session teardown behavior, and frames that arrive
outside the expected lifecycle sequence.

**Example input shapes:**

- Stream transcripts with duplicate or out-of-order frame sequence numbers.
- Session open/close frames in reversed order to probe lifecycle state checks.
- Transcripts referencing a session ID that was never opened.
- Long transcripts with frames that oscillate between valid and malformed to
  stress incremental validation.
- Transport-harness operation sequences that open, feed, close, reset, and check
  inactivity across a small set of stream IDs.

**Expected fail-closed behavior:** Frames received outside the expected session
lifecycle must be rejected with a deterministic error. Duplicate sequence
numbers must be detected and must not cause double-processing. Malformed
transcripts must return errors without undetected state corruption.

**Current status:** Partially covered by existing `stream_transcript`,
`stream_transcript_declared_lengths`, and
`transport_tcp_connection_state_machine` fuzz targets. Additional stream/session
seeds or dedicated targets may be added later if new public APIs expose suitable
incremental session surfaces.

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

**Current status:** PR4 seeds added (`fragment_gap_missing_index.bin`,
`fragment_overlap_offsets.bin`, `fec_reserved_algo_nonempty.bin`,
`fec_unsupported_algo.bin`) under `fuzz/seeds/fec_fragmentation/`. Covered by
`archive_logical_files`, with additional parser/path exercise via
`archive_entry_decode`, `archive_audit`, and `parse_lfh`/`parse_lfh_wide`.

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

**Current status:** PR4 seeds added (`cdc_reserved_algo_id.bin`,
`cdc_custom_algo_unsupported.bin`, `delta_custom_patch_algo.bin`,
`delta_vcdiff_zero_base_hash.bin`, `cdc_map_malformed_short_value.bin`) under
`fuzz/seeds/cdc_delta/`. Covered by `archive_entry_decode`,
`archive_audit`, `archive_logical_files`, and `parse_tlv`/`parse_tlv_wide`.

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

**Current status:** PR4 seeds added (`invalid_utf8_name.bin`,
`invalid_utf8_path.bin`, `tlv_nonzero_padding.bin`,
`tlv_reserved_length_ffffffff.bin`) under `fuzz/seeds/metadata_edge_cases/`.
Covered by `archive_entry_decode`, `archive_audit`, and
`parse_tlv`/`parse_tlv_wide`.

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

**Current status:** PR4 seeds added (`symlink_traversal_like_metadata.bin`,
`symlink_non_utf8_target.bin`, `directory_with_payload.bin`,
`hostile_metadata_combo.bin`) under
`fuzz/seeds/filesystem_metadata_malformed/`. Covered by
`archive_entry_decode`, `archive_audit`, and `archive_logical_files`.

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
