<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# M13 Audit Findings

This file is the central tracking document for M13a audit findings and M13b
remediation.  It is updated incrementally as each M13a sub-milestone completes.

Findings in this document are based on code-level audit of the SAR Rust
reference implementation.  They are not the result of an independent external
security audit.  No claim of exhaustive coverage, production hardening
completion, certification, compliance, stable API/ABI guarantees, or
production-readiness is made.

---

## Contents

- [M13a.1 — Parser, Memory, Panic, and DoS Audit](#m13a1--parser-memory-panic-and-dos-audit)

---

## M13a.1 — Parser, Memory, Panic, and DoS Audit

**Scope:** global header, LFH, TLV, Central Dictionary, Footer, and archive
structural parsing; checked arithmetic and length/offset calculations;
`ResourceLimits` coverage; panic/DoS behavior; allocator-churn and
repeated-initialization risks; unsafe usage policy; fuzzing coverage and corpus
quality review.

**Audited files:**
- `crates/sar-core/src/format.rs`
- `crates/sar-core/src/tlv.rs`
- `crates/sar-core/src/limits.rs`
- `crates/sar-core/src/flags.rs`
- `crates/sar-core/src/io.rs`
- `crates/sar-core/src/sparse.rs`
- `crates/sar-core/src/lib.rs`
- `crates/sar-archive/src/lib.rs`
- `crates/sar-archive/src/archive.rs` (parser/resource interaction paths)
- `fuzz/fuzz_targets/parse_global_header.rs`
- `fuzz/fuzz_targets/parse_lfh.rs`
- `fuzz/fuzz_targets/parse_lfh_wide.rs`
- `fuzz/fuzz_targets/parse_tlv.rs`
- `fuzz/fuzz_targets/parse_tlv_wide.rs`
- `fuzz/fuzz_targets/parse_cd_footer.rs`
- `fuzz/fuzz_targets/archive_structural.rs`
- `fuzz/fuzz_targets/archive_audit.rs`
- `fuzz/fuzz_targets/archive_audit_wide.rs`
- `fuzz/fuzz_targets/archive_entry_decode.rs`
- `fuzz/fuzz_targets/archive_entry_decode_wide.rs`
- `fuzz/fuzz_targets/pr4_lfh_metadata_edges.rs`
- `fuzz/fuzz_targets/pr4_tlv_metadata_edges.rs`
- `fuzz/README.md`
- `fuzz/CORPUS.md`
- `fuzz/RUNS.md`

---

## M13-PARSER-001: unchecked `as u16` cast in `global_header_flags_bytes`

* Area: parser / memory
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/format.rs` — `global_header_flags_bytes()`
* Finding:
  `global_header_flags_bytes()` constructs the global-header AAD bytes for AEAD
  computation.  Line 918 uses a direct `as u16` cast to encode the flags size:
  ```rust
  let flags_size = header.flags_bytes.len() as u16;
  ```
  This is an unchecked widening cast.  The `flags_bytes.len()` field is bounded
  at parse time by `max_global_flags_bytes` (default 65 535, which is
  `u16::MAX`), so the cast is safe under the default limits.  However, when
  `ResourceLimits::unlimited()` is in effect (or `max_global_flags_bytes` is set
  above 65 535), the cast silently truncates and produces incorrect AAD bytes.
  Incorrect AAD would cause AEAD authentication to fail for all encrypted
  entries, but would do so silently rather than with a clear overflow error at
  the AAD construction point.
* Risk:
  Silent truncation at AAD construction; incorrect authentication behavior if
  `max_global_flags_bytes` is set above `u16::MAX`.  Not exploitable under
  default limits.
* Evidence:
  `crates/sar-core/src/format.rs:918` — `let flags_size = header.flags_bytes.len() as u16;`
  The same function elsewhere uses `u16::try_from(...)` for size encoding (e.g.,
  `write_global_header` at line 346–347), so the inconsistency is clear.
* Recommended remediation:
  Replace `as u16` with `u16::try_from(header.flags_bytes.len()).map_err(|_| ...)`
  and return an error rather than silently truncating.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  Under default `ResourceLimits`, `flags_bytes.len() <= 65 535 == u16::MAX`, so
  no truncation occurs in practice.  The risk only materializes with non-default
  or unlimited limits.

---

## M13-PARSER-002: `audit()` data-area scan lacks entry-count limit check

* Area: memory / DoS / ResourceLimits
* Severity: medium
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-archive/src/archive.rs` — `ArchiveReader::audit()`
* Finding:
  The `audit()` forward-scan loop (lines ~1205–1351) pushes one
  `ArchiveAuditEntryReport` struct into the `entries: Vec<_>` on each iteration
  without calling `limits.check_entry_count()`.  In contrast,
  `parse_central_dictionary()` calls `limits.check_entry_count()` before
  allocating the offset Vec.

  For indexed archives, `data_end` is set to `cd_offset`, which limits
  traversal.  But for `NO_INDEX` archives, `data_end == file_len`, and
  `max_archive_size` is the only structural bound.  An adversary supplying a
  crafted `NO_INDEX` archive with many minimal-length entries (header\_size = 4
  bytes minimum, payload\_size = 0) could force the `entries` Vec to grow
  proportional to archive size before any entry-count limit is applied.

  With the default `max_archive_size = 16 GiB` and the minimum advance of 4
  bytes per entry (header\_size only, payload\_size = 0), the theoretical
  maximum `entries` length is approximately `16 GiB / 4 B ≈ 4 × 10⁹`.  Each
  `ArchiveAuditEntryReport` struct carries multiple heap-allocated `Option<String>`
  and `Option<Vec<u8>>` fields.  Actual OOM impact depends on
  heap growth patterns but could be significant well before the theoretical
  maximum is reached.

  `next_entry()` has the same issue for direct sequential reading.
* Risk:
  Denial of service through unbounded `entries` Vec allocation against a
  `NO_INDEX` archive (or any archive whose `data_end` is large).  The attack
  requires the adversary to supply a large archive or control the archive source.
* Evidence:
  `crates/sar-archive/src/archive.rs:1205–1351` — no `check_entry_count` call
  in the loop body.
  `crates/sar-core/src/format.rs:827` — `limits.check_entry_count(file_count_usize)?;`
  is present in `parse_central_dictionary()` but not replicated in the
  data-area scan.
* Recommended remediation:
  Insert `self.options.limits.check_entry_count(entries.len())?` inside the
  `audit()` loop (and analogously in `next_entry()` or its callers) after each
  push to `entries`.  An incremental checked-add of a running count before
  pushing is preferred over checking `.len()` to avoid the checked-add
  overhead being confused with an allocator check.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  The `verify()` forward-scan builds an `offsets: Vec<u64>` with the same
  structural gap, but `verify()` then cross-checks the result against the CD
  entry count.  An attack against `verify()` via a NO_INDEX archive is not
  applicable because NO_INDEX archives have no CD.  However, the pattern should
  be made consistent.

---

## M13-PARSER-003: TLV type IDs 0x05–0x0F are silently accepted by `classify_type`

* Area: parser
* Severity: medium
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/tlv.rs` — `classify_type()` / `parse_tlvs()`
* Finding:
  The `classify_type()` function in `tlv.rs` covers specific TLV type ranges
  with explicit arms but leaves type IDs `0x05..=0x0F` (11 values) to the
  wildcard `_ => Ok(())` arm.  All explicitly covered ranges appear intentional
  (assigned, reserved-rejected, or unsupported-rejected).  The range 0x05–0x0F
  has no specification-assigned meaning and no explicit comment explaining why
  it is accepted.

  If the specification reserves these IDs for future use and requires parsers to
  reject them, the current code is fail-open for these type IDs.  TLVs carrying
  these IDs would be parsed, accumulated, and returned without error.  This could
  allow crafted archives to inject unrecognized TLV metadata that higher-level
  code does not handle, potentially bypassing TLV-dispatch safety checks.
* Risk:
  Fail-open for potentially reserved TLV type IDs.  Unknown/reserved TLVs being
  silently accepted may allow metadata injection or bypass of TLV-level security
  checks in future protocol versions.
* Evidence:
  `crates/sar-core/src/tlv.rs:28–43` — `classify_type()` match arms.
  Ranges covered:
  - 0x00 → rejected (reserved)
  - 0x01–0x04 → accepted
  - 0x10–0x1F → dispatched to FEC module
  - 0x20–0x2F → rejected (unsupported SIGNATURE TLVs)
  - 0x30–0x3F → accepted
  - 0x40, 0x41, 0x4F → accepted (CDC)
  - 0x42–0x4E → rejected (reserved CDC)
  - 0x50–0xFF → rejected (reserved)
  - `_` → accepted (covers 0x05–0x0F silently)
* Recommended remediation:
  Cross-reference the SAR wire-format specification for the assigned status of
  type IDs 0x05–0x0F.  If they are reserved, replace the wildcard arm with an
  explicit `0x05..=0x0F => Err(SarError::ReservedValue(...))` arm and update
  the wildcard to be unreachable or panic in debug.  If they are intentionally
  accepted for forward compatibility, add a comment documenting this policy and
  rename the wildcard arm clearly.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  The specification (`specification.md`) is authoritative.  The audit does not
  resolve whether 0x05–0x0F is reserved or forward-compatible; the finding is
  that the parser accepts them without explicit justification in the code.

---

## M13-PARSER-004: `GlobalFlags::from_bits_truncate` silently drops unknown flag bits

* Area: parser
* Severity: medium
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/format.rs` — `parse_global_header()`
  * `crates/sar-archive/src/archive.rs` — `ArchiveReader::read_global_header()`
* Finding:
  Both `parse_global_header()` (format.rs line 241) and
  `ArchiveReader::read_global_header()` (archive.rs line 904) call
  `GlobalFlags::from_bits_truncate()` to parse the raw 32-bit flags field.
  `from_bits_truncate` silently discards any bits that do not correspond to a
  defined flag constant.  As a result, if an archive sets bits corresponding to
  currently undefined/reserved positions (e.g., bits 6, 7, 11–15, 21–23, 31),
  the parser silently ignores them and proceeds.

  If the SAR v1.0 specification requires that reserved flag bits be zero (as is
  common in binary format specifications for forward-compatibility control), the
  parser is fail-open for reserved flag values.  A future parser version that
  assigns meaning to one of these bits would be unable to distinguish a v1.0
  archive that legitimately had those bits zero from a malformed v1.0 archive
  that had them set.

  Additionally, `validate_global_flags()` only checks a small number of specific
  flag combinations and does not enforce that reserved bits are zero.
* Risk:
  Archives with reserved flag bits set are silently accepted.  This is a
  fail-open behavior that may introduce interoperability hazards and allow
  crafted archives to probe parser behavior by setting undefined flag bits.
* Evidence:
  `crates/sar-core/src/format.rs:241`:
  ```rust
  let flags = GlobalFlags::from_bits_truncate(u32::from_le_bytes(low));
  ```
  `crates/sar-archive/src/archive.rs:904`:
  ```rust
  let flags = GlobalFlags::from_bits_truncate(u32::from_le_bytes(low));
  ```
  `crates/sar-core/src/flags.rs:175–201` — `validate_global_flags()` checks
  only specific combinations; does not reject reserved bits.
* Recommended remediation:
  Cross-reference the SAR wire-format specification to determine whether reserved
  flag bits must be zero.  If so, replace `from_bits_truncate` with
  `from_bits(...).ok_or(SarError::ReservedValue("unknown global flag bits"))` or
  compute the mask of defined bits and check that `raw_flags & !DEFINED_MASK == 0`.
  Add a `validate_global_flags` check for this invariant.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  This does not affect existing conformance tests because those tests only supply
  valid flag values.  The fuzz corpus category `profile_rejection` includes seeds
  with reserved flag combinations, but those seeds target flag-conflict logic in
  `validate_global_flags`, not the bit-truncation behavior itself.

---

## M13-PARSER-005: `parse_lfh` fuzz target covers only 8 of the relevant global flag combinations

* Area: fuzzing
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/fuzz_targets/parse_lfh.rs`
  * `fuzz/fuzz_targets/parse_lfh_wide.rs`
* Finding:
  The `parse_lfh` fuzz target uses the first byte of the fuzz input as an 8-bit
  flag selector to derive `GlobalFlags`.  The selector maps bits 0–7 to:
  SIZE\_64BIT, HAS\_PATH, SPARSE\_FILES, SELECTIVE\_FEC, HAS\_PERMS, EXT\_UID\_GID,
  EXT\_TIME, FILE\_FRAGMENTATION.

  The following global flags that affect LFH field layout are not included in the
  selector:
  - `COMPRESSED` (adds Comp Algo ID)
  - `HAS_DELTA` (adds Patch Algo ID + Delta Base Hash)
  - `ENCRYPTED` (adds Encr Algo ID + IV/Nonce)
  - `CDC_SUPPORT` (adds CDC Algo ID)
  - `PER_FILE_CRC` (adds File CRC32)
  - `DEDUPLICATION` (adds Content Hash)
  - `HAS_SYMLINKS` (affects entry-kind resolution, no LFH size change but semantic)

  These fields—particularly `ENCRYPTED` (adds 1 + 24 = 25 bytes) and `HAS_DELTA`
  (adds 1 + 32 = 33 bytes)—introduce significant additional fixed-length fields
  into the LFH.  The `parse_lfh_wide` target has the same flag-selector design
  and the same coverage gap.

  Without these flags being fuzzed, the parser paths for those optional fields
  (e.g., `iv_nonce` copy, `delta_base_hash` copy, `comp_algo_id` byte) are never
  exercised by these targets.
* Risk:
  Parser paths for ENCRYPTED, COMPRESSED, HAS\_DELTA, CDC\_SUPPORT, PER\_FILE\_CRC,
  and DEDUPLICATION LFH optional fields are not covered by `parse_lfh` or
  `parse_lfh_wide`.  Bugs in those paths would not be detected by these fuzz
  targets.  Coverage is partially compensated by `archive_entry_decode`,
  `archive_audit`, and `pr4_lfh_metadata_edges`, but the dedicated parse-layer
  targets do not exercise all optional fields.
* Evidence:
  `fuzz/fuzz_targets/parse_lfh.rs:22–51` — `lfh_flags()` function covers 8 flags
  (bits 0–7) but omits COMPRESSED, HAS\_DELTA, ENCRYPTED, CDC\_SUPPORT,
  PER\_FILE\_CRC, DEDUPLICATION, HAS\_SYMLINKS.
* Recommended remediation:
  Extend `lfh_flags()` to use a wider selector (e.g., 16-bit) covering all
  global flags that affect LFH field layout, or add a second `lfh_flags_full()`
  variant that also enables ENCRYPTED, COMPRESSED, HAS\_DELTA, CDC\_SUPPORT,
  PER\_FILE\_CRC, DEDUPLICATION.  Apply the same extension to `parse_lfh_wide`.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  `archive_entry_decode` and `archive_audit` partially compensate for this
  gap by exercising full archive parsing including encrypted/compressed entries.
  However, those targets drive higher-level code paths that do more than just
  parse an LFH, so isolated LFH parser coverage for those flag combinations
  is still valuable.

---

## M13-PARSER-006: `archive_structural` fuzz target only calls `read_global_header`

* Area: fuzzing
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/fuzz_targets/archive_structural.rs`
* Finding:
  The `archive_structural` fuzz target creates an `ArchiveReader` and calls
  `reader.read_global_header()` only.  It does not proceed to call
  `next_entry()`, `verify()`, or `audit()`.  As a result, the archive
  structural-parsing paths beyond the global header—specifically the entry-walking
  loop, payload offset arithmetic, and entry-level ResourceLimits enforcement—are
  not exercised by this target.

  These paths are covered by `archive_entry_decode` and `archive_audit`, but the
  `archive_structural` target's name implies broader structural coverage.
* Risk:
  Reduced clarity about fuzz coverage scope.  No immediate parser-safety gap
  because `archive_entry_decode` and `archive_audit` provide complementary
  coverage, but a dedicated structural target that only reads the global header
  may miss structural interactions found in the entry-walking phase.
* Evidence:
  `fuzz/fuzz_targets/archive_structural.rs:44–56` — only `reader.read_global_header()` is called.
* Recommended remediation:
  Extend `archive_structural` to also call `next_entry()` in a loop until `None`
  is returned or an error occurs, using `MetadataOnly` policy to avoid payload
  decode complexity.  Alternatively, rename the target to
  `archive_global_header` to match its actual coverage scope, and add a new
  `archive_structural` that exercises entry walking.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  `archive_audit` already covers global header + full entry walking under
  `MetadataOnly` policy with tight limits.  The remediation here is primarily
  about correctness of fuzz-coverage labeling and ensuring no structural gap
  between the two targets.

---

## M13-PARSER-007: no `unsafe` code in parser/resource paths (informational)

* Area: unsafe
* Severity: informational
* Status: accepted-risk
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/lib.rs` — `#![forbid(unsafe_code)]`
  * `crates/sar-archive/src/lib.rs` — `#![forbid(unsafe_code)]`
* Finding:
  Both `sar-core` and `sar-archive` use `#![forbid(unsafe_code)]` at the crate
  level.  A search of all `.rs` files in `crates/sar-core/src/` and
  `crates/sar-archive/src/` found no `unsafe` blocks, `from_raw_parts`,
  `MaybeUninit`, raw pointer dereferences, or FFI assumptions in any parser or
  resource path.  All memory access is bounds-checked through the `ParseCursor`
  abstraction and standard Rust slice indexing.
* Risk:
  None.  This is an audit observation confirming the policy is enforced.
* Evidence:
  `crates/sar-core/src/lib.rs:3` — `#![forbid(unsafe_code)]`
  `crates/sar-archive/src/lib.rs:4` — `#![forbid(unsafe_code)]`
  Grep for `unsafe|from_raw_parts|MaybeUninit` across both crates: zero results
  in parser/resource paths.
* Recommended remediation: none
* Regression test needed: no
* Suggested remediation milestone: N/A
* Notes:
  Future crates that introduce FFI (C ABI, Python bindings, mobile) must not
  relax this policy for `sar-core` or `sar-archive`.  Any unsafe code introduced
  for FFI purposes must be confined to a dedicated FFI crate layer.

---

## M13-PARSER-008: `ResourceLimits::unlimited()` is public with no `#[cfg(test)]` guard

* Area: ResourceLimits / DoS
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/limits.rs` — `ResourceLimits::unlimited()`
* Finding:
  `ResourceLimits::unlimited()` is a public `#[must_use]` function that returns a
  `ResourceLimits` with every field set to `u64::MAX` or `usize::MAX`, effectively
  disabling all parser, allocation, and structural limits.  The doc comment warns
  "Use only in controlled test environments", but the function is publicly
  accessible from production code without any compile-time barrier.

  If a caller accidentally uses `ResourceLimits::unlimited()` in production (e.g.,
  copy-pasting from a test helper), all resource limits are silently disabled,
  enabling unbounded allocation, unlimited TLV counts, unlimited entry counts, and
  other unchecked paths on malformed input.
* Risk:
  Accidental production use disables all resource-limit protections, potentially
  enabling any DoS path that limits would otherwise prevent.  No exploit is
  possible in correctly configured callers, but the public API surface is
  error-prone.
* Evidence:
  `crates/sar-core/src/limits.rs:274–312` — `ResourceLimits::unlimited()` function
  is fully public and has no `#[cfg(test)]` or `#[doc(hidden)]` attribute.
* Recommended remediation:
  Either add `#[cfg(any(test, fuzzing))]` to `ResourceLimits::unlimited()` to
  restrict it to test/fuzz contexts, or add a prominent naming convention such as
  `unlimited_for_testing_only()` and apply `#[doc(hidden)]` to reduce API
  discoverability in production use.  If the function is needed for benchmarking
  or performance testing outside of unit tests, document this explicitly and add
  a safety note to the function signature.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  All fuzz targets currently use `ResourceLimits::default()` or explicitly
  bounded limits, not `ResourceLimits::unlimited()`.  The risk is accidental
  misuse rather than a fuzz-target coverage gap.

---

## M13-PARSER-009: cumulative TLV allocation not explicitly bounded as a single ceiling

* Area: memory / ResourceLimits / DoS
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/tlv.rs` — `parse_tlvs()`
  * `crates/sar-core/src/limits.rs` — `ResourceLimits`
* Finding:
  `parse_tlvs()` enforces per-TLV limits (`max_tlv_bytes` per value, `max_tlv_count`
  total count) but there is no single cumulative limit on the total bytes
  allocated across all TLV values in one `parse_tlvs()` call.

  With default limits (`max_tlv_count = 1024`, `max_tlv_bytes = 1 MiB`), a
  crafted archive may allocate up to `1024 × 1 MiB = 1 GiB` per `parse_tlvs()`
  invocation before the count limit is hit.  This allocation happens for any
  block that includes global-metadata TLVs (CD metadata) and is bounded by the
  CD region size (`max_cd_bytes`), but the interaction between the CD limit and
  the TLV allocation total is not explicit.

  Note: The `check_allocation_bytes` call in `parse_central_dictionary()` (line
  816) gates the raw metadata blob size (total `meta_size` bytes), not individual
  TLV parsed values.  Within that blob, TLV count and per-value limits apply.
  The chain of checks is: `check_allocation_bytes(meta_size)` then
  `parse_tlvs(meta_bytes, limits)` — this is correct, but the interaction between
  `max_in_memory_buffer` (CD blob) and cumulative TLV value allocations
  (potentially 1 GiB under defaults) is not documented.
* Risk:
  Under default limits, a single archive with a maximum-allowed CD metadata blob
  may trigger up to ~1 GiB of TLV value allocations.  This is intentional
  (limits are configurable), but the multiplicative interaction of
  `max_tlv_count` × `max_tlv_bytes` is not documented in either `ResourceLimits`
  or `parse_tlvs()`.
* Evidence:
  `crates/sar-core/src/tlv.rs:46–89` — `parse_tlvs()` does not maintain a
  running cumulative allocation counter.
  `crates/sar-core/src/limits.rs:92–98` — `max_tlv_bytes` and `max_tlv_count`
  are separate fields with no documented interaction.
* Recommended remediation:
  Document in `ResourceLimits` that the effective maximum TLV allocation per
  `parse_tlvs()` invocation is `max_tlv_count × max_tlv_bytes`.  Optionally, add
  a `max_total_tlv_bytes` field or a runtime check within `parse_tlvs()` that
  tracks cumulative value bytes allocated and enforces a separate ceiling.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  The default ceiling of 1 GiB total TLV allocation per block is intentional and
  calibrated.  The finding is about documentation and explicitness of the
  interaction, not an immediate safety risk.

---

## M13-PARSER-010: `archive_global_header_read` allocates header buffer without upper bound on combined optional field sizes

* Area: memory / parser
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-archive/src/archive.rs` — `ArchiveReader::read_global_header()`
* Finding:
  `ArchiveReader::read_global_header()` builds a `header_bytes: Vec<u8>` by
  appending slices from multiple reads (fixed prefix, flags buf, optional
  partition descriptor, optional KMS payload).  The initial `Vec::with_capacity`
  on line 896 is:
  ```rust
  Vec::with_capacity(8 + flags_size + 96 + 5)
  ```
  This capacity hint does not include the KMS payload length (up to
  `max_kms_payload_bytes`).  Although `Vec` automatically resizes, the initial
  capacity hint may be significantly smaller than the actual header for large KMS
  payloads.  This is not a safety issue (the Vec grows correctly), but the
  inconsistency suggests the capacity hint was written without accounting for the
  KMS extension.

  More importantly, when both `PARTITIONED_ARCHIVE` and `ENCRYPTED` are set, the
  combined header_bytes vector contains 4 bytes magic + 1 version + 1 reserved +
  2 flags_size + flags_bytes + 96 partition descriptor + 1 KMS mode + 4 KMS
  payload_len + payload.  The entire buffer is then passed to
  `parse_global_header()` for a second parse.  There is no explicit upper-bound
  check on the total header bytes before the second parse call.  The individual
  field limits (`max_global_flags_bytes`, `max_kms_payload_bytes`) bound the
  components, so the total is implicitly bounded, but no single limit guards
  `header_bytes.len()` as a whole.
* Risk:
  Minor: no unchecked allocation path exists because each component is guarded
  by its own limit.  The implicit total is bounded by the sum of component
  limits, which under defaults is at most ~65 535 + 96 + 5 + 65 536 ≈ 131 KB.
  The finding is a clarity/documentation gap rather than a safety gap.
* Evidence:
  `crates/sar-archive/src/archive.rs:896` — capacity hint omits KMS payload.
  `crates/sar-archive/src/archive.rs:930` — `parse_global_header(&header_bytes, ...)`
  parses the combined buffer.
* Recommended remediation:
  Update the capacity hint to include the KMS payload length.  Optionally, add a
  comment that the total header bytes are bounded by the sum of component limits.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  This is a low-priority clarity issue.  No memory safety risk is present.

---

## M13-PARSER-011: dead defensive KMS/partition-descriptor conflict checks in `parse_global_header`

* Area: parser
* Severity: informational
* Status: accepted-risk
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/format.rs` — `parse_global_header()`
* Finding:
  `parse_global_header()` contains two defensive conflict checks (lines 288–296):
  ```rust
  if !flags.contains(GlobalFlags::ENCRYPTED) && kms.is_some() {
      return Err(SarError::FlagConflict(...));
  }
  if !flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) && partition_descriptor.is_some() {
      return Err(SarError::FlagConflict(...));
  }
  ```
  These checks are structurally unreachable because `kms` is only assigned
  `Some(...)` when `flags.contains(GlobalFlags::ENCRYPTED)` is true (line 272),
  and `partition_descriptor` is only assigned `Some(...)` when
  `flags.contains(GlobalFlags::PARTITIONED_ARCHIVE)` is true (line 244).  The
  inverse conditions cannot be true given the control flow above.
* Risk:
  None.  Dead defensive code does not affect security or correctness.  A future
  refactor that changes the control flow could silently remove protection without
  noticing the dead checks.
* Evidence:
  `crates/sar-core/src/format.rs:244–286` — conditional field parsing.
  `crates/sar-core/src/format.rs:288–296` — dead defensive checks.
* Recommended remediation:
  Either remove the dead checks and rely on the structural impossibility, or add
  `debug_assert!` variants that fire in test builds but are elided in release.
  Adding a comment explaining that these checks are defensive-in-depth against
  future refactoring is also acceptable.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  This is informational only.  No remediation urgency.

---

## M13-PARSER-012: `archive_structural` and entry-decode fuzz targets use narrow `max_entry_count`

* Area: fuzzing / ResourceLimits
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/fuzz_targets/archive_structural.rs`
  * `fuzz/fuzz_targets/archive_audit.rs`
  * `fuzz/fuzz_targets/archive_entry_decode.rs`
* Finding:
  The `archive_entry_decode` and `archive_audit` fuzz targets configure
  `max_entry_count: 16`.  This is appropriate for performance during fuzzing, but
  it limits coverage of the entry-walking limit enforcement paths themselves.
  Specifically, the path where `check_entry_count` triggers a `LimitExceeded`
  error during CD parsing is not exercised at higher counts, and interactions
  between a large declared CD entry count and the `entries` Vec growth (see
  M13-PARSER-002) are not exposed with this limit.

  Wide targets (`archive_audit_wide`, `archive_entry_decode_wide`) do use wider
  resource limits, but their `max_entry_count` configurations have not been
  verified to be meaningfully wider than the standard targets in the audited
  sources.
* Risk:
  Reduced fuzzer exploration of entry-count boundary conditions.  The M13-PARSER-002
  audit finding (missing `check_entry_count` in audit loop) would not be
  triggered by existing fuzz targets operating within `max_entry_count: 16`.
* Evidence:
  `fuzz/fuzz_targets/archive_audit.rs:26` — `max_entry_count: 16`
  `fuzz/fuzz_targets/archive_entry_decode.rs` — same config structure.
* Recommended remediation:
  Once M13-PARSER-002 is remediated, add a fuzz target variant (or use the wide
  target) with a higher `max_entry_count` (e.g., 10 000) and verify the limit
  enforcement path is covered.  Alternatively, add a regression test that
  verifies `audit()` returns `LimitExceeded` when entry count exceeds the
  configured limit.
* Regression test needed: yes (after M13-PARSER-002 fix)
* Suggested remediation milestone: M13b.1
* Notes:
  This finding is dependent on M13-PARSER-002.  Addressing M13-PARSER-002 first
  will determine the exact regression test shape.

---

## M13-PARSER-013: `parse_lfh` trailing-field end check may produce misleading error for flag/size mismatches

* Area: parser
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/format.rs` — `parse_lfh()`
* Finding:
  `parse_lfh()` performs two cross-checks against the declared `header_size`:
  1. Line 614: checks that the computed trailing-field end equals `header_size`.
  2. Lines 675–677: calls `compute_lfh_size()` and compares the result to
     `header_size_u32`.

  Check 1 uses the accumulated position of the header cursor after reading
  all variable-length fields (name, path, sparse map, FEC value) and verifies
  that they exactly fill the declared header size.  Check 2 re-derives the
  expected size from flags and parsed field lengths.  Both checks serve the same
  structural invariant but from different directions.

  If an LFH is malformed such that the declared `header_size` is larger than the
  sum of required fields (e.g., padding bytes injected between fields), check 1
  (line 614) would fail with `InvalidLength("computed LFH trailing field size
  does not match Header Size")` — which is correct.  However, if the flags are
  correct and the payload bytes are present but `header_size` is declared too
  small to accommodate them (triggering a `Truncated` from `hdr_cursor` reads),
  the error message may be less diagnostic than ideal.

  This is a minor diagnostic clarity issue, not a safety issue.
* Risk:
  Diagnostic only.  Parser is fail-closed on malformed input; the specific error
  variant returned in mismatched flag/size combinations may be less informative
  for debugging.
* Evidence:
  `crates/sar-core/src/format.rs:606–618` — trailing-end check.
  `crates/sar-core/src/format.rs:675–678` — `compute_lfh_size` cross-check.
* Recommended remediation:
  Consider adding the parsed `flags` bitmask to the `InvalidLength` error
  context, or a separate `ParseCursor::require_empty()` check that asserts no
  unread bytes remain at the end of `hdr_cursor`.  Lower priority than structural
  findings.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  The double cross-check pattern (lines 614 and 675–677) provides redundant
  structural validation.  The redundancy is intentional and valuable.

---

## M13-PARSER-014: no `archive_entry_decode` fuzz seed for maximum-size sparse map entries

* Area: fuzzing / ResourceLimits
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/CORPUS.md`
  * `fuzz/fuzz_targets/archive_entry_decode.rs`
  * `fuzz/fuzz_targets/pr4_lfh_metadata_edges.rs`
* Finding:
  The malicious corpus categories documented in `CORPUS.md` include
  `fec_fragmentation` and `metadata_edge_cases` categories, but no dedicated
  corpus category or seed specifically targets maximum-size sparse maps combined
  with the `check_sparse_map_bytes` and `check_sparse_descriptor_count` resource
  limits.  The `pr4_lfh_metadata_edges` target exercises LFH metadata edge cases
  (including sparse) but sparse-map seeds with near-limit byte counts and
  descriptor counts are not explicitly documented.

  The `max_sparse_map_bytes` default is 8 MiB (≈ 500 000 extents) and
  `max_sparse_descriptors` default is 524 288.  Archives with sparse maps near
  these limits are high-value regression test candidates.
* Risk:
  Sparse-map parsing paths near configured limits are not explicitly covered
  by fuzz seeds.  The `parse_sparse_map` function (in `crates/sar-core/src/sparse.rs`)
  includes a guard against unsafe allocation sizes, but boundary conditions
  near `max_sparse_descriptors` may not be hit by existing corpus inputs.
* Evidence:
  `fuzz/CORPUS.md` — no dedicated sparse-map corpus category.
  `fuzz/fuzz_targets/parse_lfh.rs:9–19` — limits: `max_sparse_map_bytes: 512`.
  `crates/sar-core/src/sparse.rs:52` — guard: `count > isize::MAX as usize / std::mem::size_of::<SparseExtent>()`.
* Recommended remediation:
  Add seeds to the `fec_fragmentation` or `metadata_edge_cases` corpus category
  (or a new `sparse_map_edges` category) with sparse maps at:
  - 0 extents (empty map)
  - 1 extent (minimum)
  - near `max_sparse_descriptors` (boundary test)
  - exactly `max_sparse_map_bytes` (size limit boundary)
  Add a regression test verifying `check_sparse_descriptor_count` fires at
  the configured limit.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  The `pr4_lfh_metadata_edges` target provides partial coverage for this area.
  This finding specifically addresses seed corpus completeness near the
  resource-limit boundary values.

---

## M13-PARSER-015: fuzzing campaign gap — `archive_logical_files` and `pr4_*` targets never run against `ResourceLimits::default()` at near-limit values

* Area: fuzzing / ResourceLimits
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/RUNS.md`
  * `fuzz/fuzz_targets/archive_logical_files.rs`
  * `fuzz/fuzz_targets/pr4_lfh_metadata_edges.rs`
  * `fuzz/fuzz_targets/pr4_tlv_metadata_edges.rs`
* Finding:
  The M12b.5 PR3/PR4 overnight fuzzing campaign ran `pr4_lfh_metadata_edges`,
  `pr4_tlv_metadata_edges`, and `archive_logical_files` with custom low limits
  (as appropriate for fuzz performance).  However, these targets have not been
  run with limits close to `ResourceLimits::default()` values (e.g.,
  `max_path_bytes: 65535`, `max_tlv_bytes: 1 MiB`), which would expose
  off-by-one and large-allocation boundary conditions at realistic production
  configurations.

  Wide fuzz targets (`parse_lfh_wide`, `parse_tlv_wide`) use larger limits but
  their specific limit values are not documented in `RUNS.md`, making it
  difficult to determine what range they actually cover.
* Risk:
  Bugs that only manifest near production-scale resource limits (e.g., a
  1 MiB TLV value, a 65 535-byte path) are not exercised.  Such bugs could
  include off-by-one errors in limit checks, unexpected allocation patterns,
  or errors that trigger only at large values.
* Evidence:
  `fuzz/RUNS.md` — no campaign records for near-default-limit fuzzing of
  parser/resource targets.
  `fuzz/fuzz_targets/parse_lfh_wide.rs`, `parse_tlv_wide.rs` — limits are wider
  but exact values are not in RUNS.md.
* Recommended remediation:
  Run at least one short fuzzing campaign for `parse_lfh_wide`, `parse_tlv_wide`,
  `archive_audit_wide`, and `archive_entry_decode_wide` with limits set close to
  `ResourceLimits::default()` values, and document the campaign in `RUNS.md`.
  This would cover production-scale boundary conditions not reached by tight-limit
  targets.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  The M12b.4 overnight campaign ran `parse_lfh_wide` for 2.4 B executions and
  `parse_tlv_wide` for 307 M executions.  Their exact limit configurations are
  not in `RUNS.md`, so whether they represent near-default coverage is unknown
  from the audit record.

---

## Summary table

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| M13-PARSER-001 | Unchecked `as u16` cast in `global_header_flags_bytes` | low | open |
| M13-PARSER-002 | `audit()` data-area scan lacks entry-count limit check | medium | open |
| M13-PARSER-003 | TLV type IDs 0x05–0x0F silently accepted | medium | open |
| M13-PARSER-004 | `GlobalFlags::from_bits_truncate` silently drops unknown flag bits | medium | open |
| M13-PARSER-005 | `parse_lfh` fuzz target covers only 8 global flag combinations | low | open |
| M13-PARSER-006 | `archive_structural` fuzz target only calls `read_global_header` | low | open |
| M13-PARSER-007 | No `unsafe` code in parser/resource paths (informational) | informational | accepted-risk |
| M13-PARSER-008 | `ResourceLimits::unlimited()` lacks test-only guard | low | open |
| M13-PARSER-009 | Cumulative TLV allocation not explicitly bounded as single ceiling | low | open |
| M13-PARSER-010 | Header-buffer capacity hint omits KMS payload length | low | open |
| M13-PARSER-011 | Dead defensive KMS/partition conflict checks in `parse_global_header` | informational | accepted-risk |
| M13-PARSER-012 | Fuzz targets use narrow `max_entry_count` (16) | low | open |
| M13-PARSER-013 | `parse_lfh` trailing-field check produces imprecise error diagnostics | low | open |
| M13-PARSER-014 | No sparse-map seeds at near-limit byte and descriptor counts | low | open |
| M13-PARSER-015 | No near-default-limits fuzzing campaign record for wide targets | low | open |

**Counts by severity:**
- blocker: 0
- high: 0
- medium: 3 (M13-PARSER-002, M13-PARSER-003, M13-PARSER-004)
- low: 10 (M13-PARSER-001, M13-PARSER-005 through M13-PARSER-010, M13-PARSER-012 through M13-PARSER-015)
- informational: 2 (M13-PARSER-007, M13-PARSER-011)

---

## Audit scope notes

The following areas were reviewed and found well-handled with no specific findings
beyond those above:

**Checked arithmetic:** All length/offset arithmetic in `parse_global_header`,
`parse_lfh`, `parse_tlvs`, `parse_central_dictionary`, `parse_footer`, and
`ArchiveReader` uses `checked_add`, `checked_sub`, `checked_mul`, or
`u*::try_from(...)` throughout.  Direct `as` casts are used only in the case
documented in M13-PARSER-001 and in test-only code.  The `ParseCursor`
abstraction gates all byte-slice reads with checked index arithmetic.

**`ResourceLimits` enforcement:** `check_lfh_header_bytes`, `check_path_bytes`,
`check_global_flags_bytes`, `check_kms_payload_bytes`, `check_tlv_bytes`,
`check_tlv_count`, `check_cd_bytes`, `check_allocation_bytes`, `check_entry_count`
(in CD parsing), `check_sparse_map_bytes`, `check_sparse_descriptor_count`,
`check_fec_value_bytes`, and `allocation_len` are all called before the
corresponding allocations in the parser paths audited.  No allocation was found
to occur before its limit check, except as documented in M13-PARSER-002 for
the audit/next\_entry entry-count gap.

**Footer parsing:** `parse_footer()` is minimal (8 bytes, single u64 read) and
has no arithmetic risk.  The offset bounds are checked in the `ArchiveReader`
against `file_len` and `header_len` before CD parsing proceeds.

**CD/LFH disagreement:** CD offset and file-count mismatches are explicitly
checked in `verify()` and structurally guarded at read time.  The `data_end`
boundary for indexed archives is set to `cd_offset`, preventing entry-walking
from reading into the CD region.

**Panic resistance:** No `unwrap()`, `expect(...)`, `panic!()`, `todo!()`, or
`unreachable!()` macros were found in the `sar-core` or `sar-archive` parser
paths (excluding test code and dead-code unreachable patterns in transform.rs
test helpers).  All error paths return `Err(SarError::...)`.

**Allocator churn:** `parse_tlvs`, `parse_lfh`, and `parse_central_dictionary`
allocate `Vec<u8>` per call bounded by per-field limits.  No O(n²) or O(n×m)
allocation patterns were identified in the parser hot paths.  Repeated
initialization/teardown churn is bounded by per-entry and per-archive limits.

**Fuzzing coverage (well-covered areas):**
- Global header magic/version/flags: covered by `parse_global_header` (M12b.4:
  > 12 B executions, overnight campaign).
- LFH field layout (8 flag combinations): covered by `parse_lfh` / `parse_lfh_wide`
  (M12b.4: > 21 B executions combined).
- TLV type/length/count/padding: covered by `parse_tlv` / `parse_tlv_wide`
  (M12b.4: > 16 B executions combined).
- CD + Footer: covered by `parse_cd_footer` (M12b.4: > 13 B executions).
- Archive audit entry walking: covered by `archive_audit` / `archive_audit_wide`
  (M12b.4/M12b.5: > 3.6 B executions).
- LFH metadata edges (FEC, fragmentation, CDC, delta): covered by
  `pr4_lfh_metadata_edges` (M12b.5: > 18 B executions).
- TLV metadata edges: covered by `pr4_tlv_metadata_edges` (M12b.5: > 8 B executions).

---

*Document last updated: M13a.1 audit completion.*
*This document does not claim exhaustive audit coverage, production hardening completion,
independent external audit completion, certification, compliance, or stable API/ABI guarantees.*
