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

- [M13a.1 - Parser, Memory, Panic, and DoS Audit](#m13a1---parser-memory-panic-and-dos-audit)

---

## M13a.1 - Parser, Memory, Panic, and DoS Audit

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
- `crates/sar-core/src/fec.rs` (recovery TLV classification and limit-checked paths)
- `crates/sar-core/src/metadata.rs` (LFH metadata types; no allocation paths; reviewed and out of scope for parser findings)
- `crates/sar-archive/src/lib.rs`
- `crates/sar-archive/src/archive.rs` (parser/resource interaction paths)
- `crates/sar-archive/src/stream.rs` (StreamArchiveParser push-parse state machine; parser/resource behavior; reviewed, no additional findings beyond those below)
- `crates/sar-archive/src/recovery.rs` (parser-facing interface paths only; repair algorithm internals reserved for M13a.3)
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
- `fuzz/fuzz_targets/archive_logical_files.rs`
- `fuzz/fuzz_targets/stream_archive_parser_state_machine.rs`
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
  * `crates/sar-core/src/format.rs` - `global_header_flags_bytes()`
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
  `crates/sar-core/src/format.rs:918` - `let flags_size = header.flags_bytes.len() as u16;`
  The same function elsewhere uses `u16::try_from(...)` for size encoding (e.g.,
  `write_global_header` at line 346-347), so the inconsistency is clear.
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
  * `crates/sar-archive/src/archive.rs` - `ArchiveReader::audit()`
* Finding:
  The `audit()` forward-scan loop (lines ~1205-1351) pushes one
  `ArchiveAuditEntryReport` struct into the `entries: Vec<_>` on each iteration
  without first calling `limits.check_entry_count()`.  In contrast,
  `parse_central_dictionary()` calls `limits.check_entry_count()` before
  allocating the offset Vec.

  For indexed archives, `data_end` is set to `cd_offset`, which limits
  traversal.  For `NO_INDEX` archives, `data_end == file_len`, and
  `max_archive_size` is the only structural bound.  An adversary supplying a
  crafted `NO_INDEX` archive with many minimal-length entries could force the
  `entries` Vec to grow proportional to archive size before any entry-count limit
  is applied.

  The minimum parseable LFH with no optional global flags set consists of the
  always-present fixed fields: Header Size (4 B) + Entry Mode (2 B) + Stream ID
  (2 B) + Sequence No (2 B) + Uncompressed Size (4 B) + Payload Size (4 B) +
  Name Length (2 B) = 20 bytes.  With payload_size = 0 and name_length = 0, the
  minimum archive advance per entry is 20 bytes.  With the default
  `max_archive_size = 16 GiB`, the theoretical maximum number of entries before
  the entry-count check would apply is approximately `16 GiB / 20 B ~ 858
  million`.  Each `ArchiveAuditEntryReport` carries several heap-allocated
  `Option<String>` and `Option<Vec<u8>>` fields; actual OOM impact depends on
  heap growth patterns but could be significant well below the theoretical
  maximum.

  These paths must be analyzed separately:

  * `audit()` retains one `ArchiveAuditEntryReport` per scanned entry in the
    `entries: Vec<_>` without any pre-push entry-count check.  This is the
    primary concern.
  * `verify()` accumulates `offsets: Vec<u64>` (8 bytes per offset) by calling
    `next_entry()` in a loop.  `verify()` is applicable only to indexed archives,
    where `data_end = cd_offset`, so the traversal is bounded by the CD offset
    rather than the full archive size.  The missing `check_entry_count` pre-push
    call is a policy inconsistency but the structural exposure is smaller.
  * `next_entry()` advances by one entry per call and does not accumulate a
    retained collection of prior entries.  Its callers are responsible for
    bounding iteration.  The missing entry-count check in `next_entry()` means
    callers that loop without their own counter are not protected by the limit.
* Risk:
  Denial of service through unbounded `entries` Vec growth against a `NO_INDEX`
  archive.  The attack requires the adversary to control the archive source.
* Evidence:
  `crates/sar-archive/src/archive.rs:1205-1351` - no `check_entry_count` call
  in the `audit()` loop body before `entries.push(...)`.
  `crates/sar-core/src/format.rs:827` - `limits.check_entry_count(file_count_usize)?;`
  is present in `parse_central_dictionary()` but not replicated in the
  data-area scan paths.
* Recommended remediation:
  In the `audit()` loop, maintain a checked running count and call
  `self.options.limits.check_entry_count(entry_count)?` before each
  `entries.push(...)`.  A running counter incremented with `checked_add` before
  the push is preferred so the check fires before memory is allocated.
  Apply the same pre-push limit check in `verify()` for consistency.
  For `next_entry()`, consider whether a per-call count check (via a stored
  counter on the reader) is appropriate for callers that do not maintain their
  own limit.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  The `verify()` exposure is smaller than `audit()` because `verify()` only
  applies to indexed archives (bounded by `cd_offset`) and stores only 8-byte
  offsets rather than full report structs.  The primary remediation target is
  `audit()`.

---

## M13-PARSER-003: TLV type IDs 0x05-0x0F are accepted in violation of the specification

* Area: parser
* Severity: medium
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/tlv.rs` - `classify_type()` / `parse_tlvs()`
* Finding:
  The specification (`specification.md` section on TLV type registry, line 1074)
  explicitly reserves TLV type IDs in the range `0x05..=0x0F`:
  ```
  | 0x05 - 0x0F | RESERVED | Reserved for future use. |
  ```
  The specification requires that reserved values produce `SAR_ERR_RESERVED_VALUE`.

  The `classify_type()` function in `tlv.rs` covers all other ranges with
  explicit arms (0x00 rejected, 0x01-0x04 accepted, 0x10-0x1F FEC dispatch,
  0x20-0x2F unsupported, 0x30-0x3F accepted, 0x40/0x41/0x4F CDC accepted,
  0x42-0x4E reserved CDC rejected, 0x50-0xFF reserved rejected) but leaves
  IDs `0x05..=0x0F` to the wildcard `_ => Ok(())` arm.  As a result, TLVs
  carrying these reserved IDs are parsed, accumulated, and returned without error.
* Risk:
  The parser is fail-open for reserved TLV type IDs 0x05-0x0F, in direct
  violation of the specification.  Archives supplying these IDs pass TLV
  validation silently.  Higher-level code that does not enumerate or validate
  TLV type IDs may accept metadata it was not designed to handle.
* Evidence:
  `specification.md:1074` - explicit RESERVED designation for 0x05-0x0F.
  `crates/sar-core/src/tlv.rs:28-43` - `classify_type()` wildcard arm accepts
  0x05-0x0F without error.
  Ranges covered:
  - 0x00 -> rejected (reserved)
  - 0x01-0x04 -> accepted
  - 0x10-0x1F -> dispatched to FEC module
  - 0x20-0x2F -> rejected (unsupported SIGNATURE TLVs)
  - 0x30-0x3F -> accepted
  - 0x40, 0x41, 0x4F -> accepted (CDC)
  - 0x42-0x4E -> rejected (reserved CDC)
  - 0x50-0xFF -> rejected (reserved)
  - `_` -> accepted (covers 0x05-0x0F in violation of the specification)
* Recommended remediation:
  Add an explicit arm `0x05..=0x0F => Err(SarError::ReservedValue("TLV type
  IDs 0x05-0x0F are reserved"))` before the wildcard, and change the wildcard
  to `unreachable!()` or an explicit exhaustive pattern covering any remaining
  unhandled bytes.  Do not use `panic!()` or debug-only assertions as the sole
  rejection mechanism in an input-controlled parser path.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  The specification is authoritative.  The fix is straightforward: add the
  missing reserved-range arm.  The wildcard should become unreachable once all
  byte values are explicitly handled.

---

## M13-PARSER-004: `GlobalFlags::from_bits_truncate` silently drops unknown bits in the first 32 flag bits

* Area: parser
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/format.rs` - `parse_global_header()`
  * `crates/sar-archive/src/archive.rs` - `ArchiveReader::read_global_header()`
* Finding:
  Both `parse_global_header()` (format.rs line 241) and
  `ArchiveReader::read_global_header()` (archive.rs line 904) call
  `GlobalFlags::from_bits_truncate()` to parse the raw 32-bit flags word.
  `from_bits_truncate` silently discards any bits that do not correspond to a
  defined flag constant.  The defined bits are 0-5, 8-10, 16-20, and 24-30.
  Bits 6, 7, 11-15, 21-23, and 31 are currently undefined and are silently
  cleared.

  The specification (section 5.2) does not contain an explicit "reserved bits
  MUST be zero" requirement for the 32-bit global flags word, unlike the
  session-layer flags (section 10.x) which carry an explicit MUST requirement.
  However, `from_bits_truncate` is fail-open: archives setting unrecognized bits
  in the first 32 bits are accepted without any warning or error.  The project's
  general conformance posture is fail-closed for reserved and unsupported values.

  There is a second related issue: the global flags field is variable-length
  (at least 4 bytes, governed by the `Flags Size` field).  Bytes 5 and beyond
  in `flags_bytes` are stored but their content is not validated.  The
  specification does not define semantics for bytes beyond the first 4, so
  whether nonzero extension bytes should be accepted or rejected is not resolved
  by the specification.

  `validate_global_flags()` checks specific flag-combination conflicts but does
  not reject unrecognized bits in either the first 32 bits or in extension bytes.
* Risk:
  Archives with unrecognized bits set in the first 32 global flag bits are
  silently accepted, which is inconsistent with the general fail-closed posture
  of the implementation.  Extension bytes beyond byte 4 are not validated.
  Neither issue has a confirmed MUST violation in the current specification, but
  both create interoperability and forward-compatibility ambiguity.
* Evidence:
  `crates/sar-core/src/format.rs:241`:
  ```rust
  let flags = GlobalFlags::from_bits_truncate(u32::from_le_bytes(low));
  ```
  `crates/sar-archive/src/archive.rs:904`:
  ```rust
  let flags = GlobalFlags::from_bits_truncate(u32::from_le_bytes(low));
  ```
  `crates/sar-core/src/flags.rs:175-201` - `validate_global_flags()` checks
  only specific flag combinations; does not reject unrecognized bits.
* Recommended remediation:
  For the first 32-bit word: replace `from_bits_truncate` with a check that
  `raw_flags & !DEFINED_BITS_MASK == 0` and return `SarError::ReservedValue` on
  nonzero undefined bits.  This aligns with the implementation's general policy
  of fail-closed behavior.  Add the check to `validate_global_flags`.
  For extension bytes: add a check that all bytes beyond byte 3 are zero, or
  document explicitly why nonzero extension bytes are intentionally preserved.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  Replacing `from_bits_truncate` alone does not address extension bytes beyond
  byte 4, since `from_bits_truncate` only operates on the first 4 bytes.
  Both the reserved-bit and extension-byte behaviors require separate targeted
  fixes in `parse_global_header` and `read_global_header`.  Severity is low
  because the specification does not explicitly require rejection of unknown bits
  in global flags (unlike session flags), but fail-open acceptance is
  inconsistent with project conformance posture.

---

## M13-PARSER-005: `parse_lfh` fuzz targets omit several LFH-layout-affecting global flags

* Area: fuzzing
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/fuzz_targets/parse_lfh.rs`
  * `fuzz/fuzz_targets/parse_lfh_wide.rs`
* Finding:
  The `parse_lfh` fuzz target uses the first byte of the fuzz input as an 8-bit
  flag selector.  The selector maps bits 0-7 to 8 individual `GlobalFlags`
  constants (SIZE_64BIT, HAS_PATH, SPARSE_FILES, SELECTIVE_FEC, HAS_PERMS,
  EXT_UID_GID, EXT_TIME, FILE_FRAGMENTATION), which means the target can
  exercise all 256 combinations of those 8 flags.

  The following global flags that add fixed-length fields to the physical LFH
  layout are not included in the selector and are never set:
  - `COMPRESSED` (adds 1 B: Comp Algo ID)
  - `HAS_DELTA` (adds 1 B Patch Algo ID + 32 B Delta Base Hash = 33 B total)
  - `ENCRYPTED` (adds 1 B Encr Algo ID + 24 B IV/Nonce = 25 B total)
  - `CDC_SUPPORT` (adds 1 B: CDC Algo ID)
  - `PER_FILE_CRC` (adds 4 B: File CRC32)
  - `DEDUPLICATION` (adds 32 B: Content Hash)

  `HAS_SYMLINKS` (bit 26) does not add any field to the LFH physical layout
  (it is absent from `compute_lfh_size`) and affects only per-entry semantic
  interpretation.  It is correctly omitted from the layout-affecting list.

  Without these flags in the selector, the parser paths for the corresponding
  optional fields (iv_nonce copy, delta_base_hash copy, comp_algo_id byte, etc.)
  are never exercised by `parse_lfh` or `parse_lfh_wide`.
* Risk:
  Parser paths for ENCRYPTED, HAS_DELTA, COMPRESSED, CDC_SUPPORT, PER_FILE_CRC,
  and DEDUPLICATION LFH optional fields are not covered by the dedicated
  `parse_lfh` or `parse_lfh_wide` targets.  Bugs in those paths would not be
  detected by these targets.  Coverage is partially compensated by
  `archive_entry_decode`, `archive_audit`, and `pr4_lfh_metadata_edges`, but
  the dedicated parse-layer targets do not exercise all optional fields.
* Evidence:
  `fuzz/fuzz_targets/parse_lfh.rs:22-51` - `lfh_flags()` function covers 8
  flags (bits 0-7 of selector) but omits COMPRESSED, HAS_DELTA, ENCRYPTED,
  CDC_SUPPORT, PER_FILE_CRC, DEDUPLICATION.
  `fuzz/fuzz_targets/parse_lfh_wide.rs:22-51` - same `lfh_flags()` design.
* Recommended remediation:
  Extend `lfh_flags()` to use a wider selector (e.g., a `u16`) covering all
  global flags that add physical fields to the LFH layout, or add a separate
  variant that also enables ENCRYPTED, COMPRESSED, HAS_DELTA, CDC_SUPPORT,
  PER_FILE_CRC, and DEDUPLICATION.  Apply the same extension to `parse_lfh_wide`.
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
  structural-parsing paths beyond the global header - specifically the entry-walking
  loop, payload offset arithmetic, and entry-level ResourceLimits enforcement -
  are not exercised by this target.

  These paths are covered by `archive_entry_decode` and `archive_audit`, but the
  `archive_structural` target name implies broader structural coverage.
* Risk:
  Reduced clarity about fuzz coverage scope.  No immediate parser-safety gap
  because `archive_entry_decode` and `archive_audit` provide complementary
  coverage, but a dedicated structural target that only reads the global header
  may miss structural interactions found in the entry-walking phase.
* Evidence:
  `fuzz/fuzz_targets/archive_structural.rs:44-56` - only `reader.read_global_header()` is called.
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

## M13-PARSER-007: no `unsafe` code in parser/resource paths

* Area: unsafe
* Severity: informational
* Status: verified
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/lib.rs` - `#![forbid(unsafe_code)]`
  * `crates/sar-archive/src/lib.rs` - `#![forbid(unsafe_code)]`
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
  `crates/sar-core/src/lib.rs:3` - `#![forbid(unsafe_code)]`
  `crates/sar-archive/src/lib.rs:4` - `#![forbid(unsafe_code)]`
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

## M13-PARSER-008: `ResourceLimits::unlimited()` public without documentation of production-use risk

* Area: ResourceLimits / API design
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/limits.rs` - `ResourceLimits::unlimited()`
* Finding:
  `ResourceLimits::unlimited()` is a public `#[must_use]` function that returns a
  `ResourceLimits` with every field set to `u64::MAX` or `usize::MAX`, effectively
  disabling all parser, allocation, and structural limits.  The doc comment warns
  "Use only in controlled test environments", but the warning is in prose and is
  not enforced structurally.

  If a caller accidentally uses `ResourceLimits::unlimited()` in production (e.g.,
  copy-pasting from a test helper), all resource limits are silently disabled,
  enabling unbounded allocation, unlimited TLV counts, and unlimited entry counts
  on malformed input.

  Note: restricting this function to `#[cfg(test)]` would not be sufficient to
  protect downstream crates.  Dependency crates are compiled with their own
  `cfg(test)` attribute context, which does not propagate to integration tests or
  external tools compiled against the crate.  A `#[cfg(test)]` restriction in
  `sar-core` would not prevent an external integration test from calling
  `ResourceLimits::unlimited()` using a release build of the crate.  Any naming
  or visibility change to this function would constitute a public API change.
* Risk:
  Accidental production use disables all resource-limit protections.  No exploit
  is possible in correctly configured callers, but the public API surface
  increases the risk of misuse.  This is an API discoverability and documentation
  risk rather than a confirmed vulnerability in the current codebase.
* Evidence:
  `crates/sar-core/src/limits.rs:274-312` - `ResourceLimits::unlimited()` is
  fully public with only a prose warning in the doc comment.
* Recommended remediation:
  Strengthen the documentation to prominently describe the risk, expected use
  cases (benchmarks, offline testing, fuzzing), and the consequences of
  production use.  Consider adding a naming convention (e.g., a companion
  `unlimited_unsecured()` with a stronger warning) or `#[doc(hidden)]` to reduce
  discoverability in generated API documentation.  Any renaming is a public API
  change and must be treated as such.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  All fuzz targets currently use `ResourceLimits::default()` or explicitly
  bounded limits, not `ResourceLimits::unlimited()`.  The risk is accidental
  misuse rather than a gap in the current fuzz-target configuration.

---

## M13-PARSER-009: TLV allocation duplication factor not documented in `ResourceLimits`

* Area: memory / ResourceLimits / documentation
* Severity: informational
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/tlv.rs` - `parse_tlvs()`
  * `crates/sar-core/src/limits.rs` - `ResourceLimits`
* Finding:
  `parse_tlvs()` enforces per-TLV limits (`max_tlv_bytes` per value,
  `max_tlv_count` total count) and is always called inside
  `parse_central_dictionary()` after a `check_allocation_bytes(meta_size)` call
  that bounds the total CD metadata blob.  The TLV value bytes in the parsed
  output are copies from the input `meta_bytes` slice, so the sum of all TLV
  value lengths cannot exceed `meta_size`.

  The effective ceiling on TLV value allocation is therefore bounded by the
  enclosing `check_allocation_bytes` and `max_cd_bytes` (default 256 MiB), not
  by `max_tlv_count * max_tlv_bytes` in isolation.  Under default limits:
  - CD metadata blob: bounded by `min(meta_size, max_in_memory_buffer)` = at
    most 1 GiB, further constrained by `max_cd_bytes` = 256 MiB.
  - TLV value copies: sum <= meta_size, because values are copied from the blob.
  - Peak memory: raw metadata buffer + cloned TLV value buffers <= 2 * meta_size
    <= 2 * 256 MiB = 512 MiB under default limits.

  This interaction is not documented in `ResourceLimits`, making it non-obvious
  that the per-TLV limits are secondary to the enclosing CD allocation limit.
* Risk:
  The memory behavior is already bounded by existing limits; no safety gap
  exists.  The finding is a documentation clarity observation about how the
  limits interact and about the 2x duplication factor during parsing.
* Evidence:
  `crates/sar-core/src/format.rs:813-820` - `check_allocation_bytes(meta_size)`
  called before `parse_tlvs(meta_bytes, limits)`.
  `crates/sar-core/src/limits.rs:92-98` - `max_tlv_bytes` and `max_tlv_count`
  documented without mentioning the enclosing CD limit interaction.
* Recommended remediation:
  Add a comment or doc update to `ResourceLimits` explaining that the effective
  maximum TLV allocation per `parse_tlvs()` call is bounded by the enclosing
  `check_allocation_bytes` / `max_cd_bytes` limit, and that peak memory during
  CD parsing is at most 2x the CD metadata blob size due to the raw buffer and
  cloned TLV value copies coexisting briefly.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  No new limit field is needed.  The clarification is documentation-only.

---

## M13-PARSER-012: `archive_entry_decode` and `archive_audit` fuzz targets use narrow `max_entry_count`

* Area: fuzzing / ResourceLimits
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/fuzz_targets/archive_audit.rs`
  * `fuzz/fuzz_targets/archive_audit_wide.rs`
  * `fuzz/fuzz_targets/archive_entry_decode.rs`
  * `fuzz/fuzz_targets/archive_entry_decode_wide.rs`
* Finding:
  The `archive_audit` and `archive_entry_decode` fuzz targets configure
  `max_entry_count: 16`.  This is appropriate for fuzzing performance, but it
  limits coverage of entry-walking limit enforcement paths.  Specifically, the
  path where `check_entry_count` triggers a `LimitExceeded` error during CD
  parsing is not exercised at higher counts, and the M13-PARSER-002 missing
  entry-count check in `audit()` would not be triggered by existing targets
  operating within `max_entry_count: 16`.

  The wide targets do use larger values: `archive_audit_wide` configures
  `max_entry_count: 64`, and `archive_entry_decode_wide` configures
  `max_entry_count: 128`.  These widen the entry-count boundary but remain well
  below the default `max_entry_count: 1 000 000`, so the limit enforcement path
  at realistic production values is not exercised.

  Note: `archive_structural` does not call `next_entry()` or `audit()` and its
  `max_entry_count: 16` setting is not relevant to entry-walking coverage.
* Risk:
  Reduced fuzzer exploration of entry-count boundary conditions.  The
  M13-PARSER-002 finding (missing `check_entry_count` in `audit()` loop) would
  not be triggered by fuzz targets operating within their configured limit.
* Evidence:
  `fuzz/fuzz_targets/archive_audit.rs:25` - `max_entry_count: 16`
  `fuzz/fuzz_targets/archive_audit_wide.rs:25` - `max_entry_count: 64`
  `fuzz/fuzz_targets/archive_entry_decode.rs:25` - `max_entry_count: 16`
  `fuzz/fuzz_targets/archive_entry_decode_wide.rs:25` - `max_entry_count: 128`
* Recommended remediation:
  After M13-PARSER-002 is remediated, add a deterministic regression test that
  verifies `audit()` returns `LimitExceeded` when entry count exceeds the
  configured limit.  Consider a wide target variant with a higher
  `max_entry_count` (e.g., 10 000) to exercise the limit enforcement path.
* Regression test needed: yes (after M13-PARSER-002 fix)
* Suggested remediation milestone: M13b.1
* Notes:
  This finding is dependent on M13-PARSER-002.  Addressing M13-PARSER-002 first
  will determine the exact regression test shape.

---

## M13-PARSER-014: no sparse-map seeds at near-limit byte and descriptor counts

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
  corpus category or seed specifically targets the `check_sparse_map_bytes` and
  `check_sparse_descriptor_count` resource limits near their default values.
  The `pr4_lfh_metadata_edges` target exercises LFH metadata edge cases
  (including sparse) but sparse-map seeds with near-limit byte counts and
  descriptor counts are not explicitly documented.

  The `max_sparse_map_bytes` default is 8 MiB and `max_sparse_descriptors`
  default is 524 288.  Archives with sparse maps near these limits are high-value
  deterministic regression test candidates, but the appropriate seed size for
  fuzzing should be small (using deliberately reduced fuzz-target limits such as
  `max_sparse_map_bytes: 512` as configured in `parse_lfh.rs`), not multi-megabyte
  production-scale files.
* Risk:
  Sparse-map parsing paths near configured limits are not explicitly covered
  by fuzz seeds or deterministic regression tests.  The `parse_sparse_map`
  function (in `crates/sar-core/src/sparse.rs`) includes a guard against unsafe
  allocation sizes, but boundary conditions near `max_sparse_descriptors` are
  not hit by existing corpus inputs or regression tests.
* Evidence:
  `fuzz/CORPUS.md` - no dedicated sparse-map corpus category.
  `fuzz/fuzz_targets/parse_lfh.rs:9-19` - limits: `max_sparse_map_bytes: 512`.
  `crates/sar-core/src/sparse.rs:52` - guard: `count > isize::MAX as usize / std::mem::size_of::<SparseExtent>()`.
* Recommended remediation:
  Add small seed files for the `pr4_lfh_metadata_edges` or `parse_lfh` targets
  using reduced limits (e.g., `max_sparse_descriptors: 4`) with sparse maps at:
  - 0 extents (empty map)
  - 1 extent (minimum)
  - exactly at the fuzz-target configured limit (boundary test)
  Add a deterministic regression test verifying `check_sparse_descriptor_count`
  fires at the configured limit using production/default boundary values in a
  unit test (not as an oversized corpus seed).  Do not use multi-megabyte seed
  files for boundary testing; use reduced-limit deterministic tests instead.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  The `pr4_lfh_metadata_edges` target provides partial coverage for this area.
  This finding specifically addresses seed corpus completeness and the need for
  deterministic regression tests at resource-limit boundary values.

---

## M13-PARSER-015: wide fuzz targets not run with documented near-default limits; exact limits absent from RUNS.md

* Area: fuzzing / ResourceLimits / documentation
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/RUNS.md`
  * `fuzz/fuzz_targets/archive_logical_files.rs`
  * `fuzz/fuzz_targets/parse_lfh_wide.rs`
  * `fuzz/fuzz_targets/parse_tlv_wide.rs`
  * `fuzz/fuzz_targets/archive_audit_wide.rs`
  * `fuzz/fuzz_targets/archive_entry_decode_wide.rs`
* Finding:
  The wide fuzz targets are configured in source as follows (from direct source
  inspection):
  - `parse_lfh_wide`: `max_lfh_header_bytes: 1 MiB`, `max_path_bytes: 64 KiB`,
    `max_sparse_map_bytes: 256 KiB`, `max_fec_value_bytes: 256 KiB`
  - `parse_tlv_wide`: `max_tlv_bytes: 1 MiB` (= default), `max_tlv_count: 4 096`
    (4x default)
  - `archive_audit_wide`: `max_archive_size: 1 MiB`, `max_entry_count: 64`,
    `max_tlv_bytes: 64 KiB`
  - `archive_entry_decode_wide`: `max_archive_size: 1 MiB`,
    `max_entry_count: 128`, `max_tlv_bytes: 64 KiB`
  - `archive_logical_files`: `max_archive_size: 64 KiB`,
    `max_entry_count: 32`, `max_tlv_bytes: 4 KiB`

  `RUNS.md` records execution counts for `parse_lfh_wide` (M12b.4: > 21 B
  executions combined), `parse_tlv_wide` (M12b.4: > 16 B combined), and
  `archive_audit_wide` (M12b.4/M12b.5: > 3.6 B), but does not state the
  configured limit values for these campaigns.

  `archive_logical_files` is referenced in the M12b.5 campaign but its limits
  are not documented in `RUNS.md`.

  As a result:
  - The configured limits for past campaigns are known from source but are not
    in the campaign record.
  - For `parse_lfh_wide` and `parse_tlv_wide`, the wide limits are close to or
    equal to production defaults for some fields but not for others (e.g.,
    `max_path_bytes: 64 KiB` vs. default 65 535; `max_entry_count: 64` vs.
    default 1 000 000).
  - No campaign record exists for any target at `max_entry_count` close to the
    production default of 1 000 000.
  - Exact off-by-one and large-allocation conditions at true production-default
    boundary values remain untested by documented campaigns.
* Risk:
  Bugs that only manifest near production-scale resource limits (e.g., near
  1 000 000 entry count, 65 535-byte path) are not covered by documented
  fuzzing campaigns.  The primary issue is that past campaign limit
  configurations are not in `RUNS.md`, making audit trail incomplete.
* Evidence:
  `fuzz/RUNS.md` - no limit configuration documented for wide-target campaigns.
  `fuzz/fuzz_targets/parse_lfh_wide.rs` - limits confirmed from source.
  `fuzz/fuzz_targets/parse_tlv_wide.rs` - limits confirmed from source.
  `fuzz/fuzz_targets/archive_audit_wide.rs` - limits confirmed from source.
  `fuzz/fuzz_targets/archive_entry_decode_wide.rs` - limits confirmed from source.
  `fuzz/fuzz_targets/archive_logical_files.rs` - limits confirmed from source.
* Recommended remediation:
  Update `RUNS.md` to document the configured limit values for each past
  campaign.  Run at least one short deterministic test (not a fuzzing campaign)
  for each major parser with limits set to exact `ResourceLimits::default()`
  values, using boundary-value inputs generated to hit each limit exactly.
  Document these tests separately from fuzz campaigns.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  The M12b.4 overnight campaign ran `parse_lfh_wide` for > 21 B executions and
  `parse_tlv_wide` for > 16 B executions combined.  Their exact limit
  configurations are known from source but are not in `RUNS.md`, so whether
  they represent near-default coverage cannot be determined from the campaign
  record alone.

---

## Summary table

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| M13-PARSER-001 | Unchecked `as u16` cast in `global_header_flags_bytes` | low | open |
| M13-PARSER-002 | `audit()` data-area scan lacks entry-count limit check | medium | open |
| M13-PARSER-003 | TLV type IDs 0x05-0x0F accepted in violation of specification | medium | open |
| M13-PARSER-004 | `GlobalFlags::from_bits_truncate` silently drops unknown flag bits | low | open |
| M13-PARSER-005 | `parse_lfh` fuzz targets omit several LFH-layout-affecting global flags | low | open |
| M13-PARSER-006 | `archive_structural` fuzz target only calls `read_global_header` | low | open |
| M13-PARSER-007 | No `unsafe` code in parser/resource paths | informational | verified |
| M13-PARSER-008 | `ResourceLimits::unlimited()` lacks documentation of production-use risk | low | open |
| M13-PARSER-009 | TLV allocation duplication factor not documented in `ResourceLimits` | informational | open |
| M13-PARSER-012 | `archive_audit` fuzz targets use narrow `max_entry_count` | low | open |
| M13-PARSER-014 | No sparse-map seeds at near-limit byte and descriptor counts | low | open |
| M13-PARSER-015 | Wide target limits not documented in RUNS.md; no near-default-limit campaign record | low | open |

**Counts by severity:**
- blocker: 0
- high: 0
- medium: 2 (M13-PARSER-002, M13-PARSER-003)
- low: 8 (M13-PARSER-001, M13-PARSER-004, M13-PARSER-005, M13-PARSER-006, M13-PARSER-008, M13-PARSER-012, M13-PARSER-014, M13-PARSER-015)
- informational: 2 (M13-PARSER-007, M13-PARSER-009)

---

## Informational observations

The following items were reviewed but do not rise to the level of tracked security
findings.  They are retained here for completeness.

### IO-001: dead defensive conflict checks in `parse_global_header`

`parse_global_header()` contains two defensive conflict checks (lines 288-296)
that are structurally unreachable given the control flow immediately above them:
`kms` is only assigned `Some(...)` when `ENCRYPTED` is set, and
`partition_descriptor` is only assigned `Some(...)` when `PARTITIONED_ARCHIVE`
is set.  The inverse conditions cannot be true.  The checks do not affect
correctness and would catch future refactoring regressions, but they may cause
confusion because they appear to guard conditions that cannot arise in the current
code.  No action needed; a comment clarifying their defensive-in-depth purpose
would be sufficient.

### IO-002: `read_global_header` capacity hint omits KMS payload length

The `Vec::with_capacity(8 + flags_size + 96 + 5)` hint in
`ArchiveReader::read_global_header()` (line 896) does not include the KMS
payload length.  The `Vec` grows correctly when the KMS payload is appended, so
this is a minor clarity issue with no memory or safety consequence.  Under
default limits the total header is at most approximately 131 KB.  No action
needed beyond optionally updating the hint to include the KMS payload length.

---

## Audit scope notes

The following areas were reviewed and found well-handled with no specific findings
beyond those above:

**Checked arithmetic:** In the audited functions and paths -
`parse_global_header`, `parse_lfh`, `parse_tlvs`, `parse_central_dictionary`,
`parse_footer`, `ArchiveReader`, and `StreamArchiveParser` - length and offset
arithmetic uses `checked_add`, `checked_sub`, `checked_mul`, or
`u*::try_from(...)` throughout.  No additional input-derived narrowing conversion
requiring a finding was identified in the reviewed parser paths.  The `ParseCursor`
abstraction gates all byte-slice reads with checked index arithmetic.  The only
unchecked `as` cast identified in parser paths is documented in M13-PARSER-001.

**`ResourceLimits` enforcement:** In the audited parser paths,
`check_lfh_header_bytes`, `check_path_bytes`, `check_global_flags_bytes`,
`check_kms_payload_bytes`, `check_tlv_bytes`, `check_tlv_count`, `check_cd_bytes`,
`check_allocation_bytes`, `check_entry_count` (in CD parsing),
`check_sparse_map_bytes`, `check_sparse_descriptor_count`,
`check_fec_value_bytes`, and `allocation_len` are called before the corresponding
allocations.  No additional allocation-before-limit issue was identified in the
reviewed parser paths, except as documented in M13-PARSER-002 for the
`audit()` entry-count gap.

**Footer parsing:** `parse_footer()` is minimal (8 bytes, single u64 read) and
has no arithmetic risk.  The offset bounds are checked in the `ArchiveReader`
against `file_len` and `header_len` before CD parsing proceeds.

**CD/LFH disagreement:** CD offset and file-count mismatches are explicitly
checked in `verify()` and structurally guarded at read time.  The `data_end`
boundary for indexed archives is set to `cd_offset`, preventing entry-walking
from reading into the CD region.

**Panic resistance:** In the `sar-core` and `sar-archive` parser paths reviewed,
no `unwrap()`, `expect(...)`, `panic!()`, `todo!()`, or `unreachable!()` macros
were found outside of test code and dead-code patterns in transform.rs test
helpers.  All error paths return `Err(SarError::...)`.

**Allocator churn:** In the audited parser hot paths, `parse_tlvs`, `parse_lfh`,
and `parse_central_dictionary` allocate `Vec<u8>` per call bounded by per-field
limits.  No additional O(n^2) or O(n*m) allocation pattern was identified in
the reviewed parser paths.  Repeated initialization/teardown churn is bounded by
per-entry and per-archive limits.

**StreamArchiveParser:** The `StreamArchiveParser` push-parse state machine
(`crates/sar-archive/src/stream.rs`) was reviewed for parser-facing length,
count, allocation, panic, and structural behavior.  It delegates to the same
`parse_global_header` and `parse_lfh` functions reviewed above.  No additional
parser-safety issues were identified beyond those already covered by existing
findings.  It is exercised by `stream_archive_parser_state_machine.rs`.

**Fuzzing coverage (well-covered areas):**
- Global header magic/version/flags: covered by `parse_global_header` (M12b.4:
  > 12 B executions, overnight campaign).
- LFH field layout (8 flag combinations from selector): covered by `parse_lfh` /
  `parse_lfh_wide` (M12b.4: > 21 B executions combined).
- TLV type/length/count/padding: covered by `parse_tlv` / `parse_tlv_wide`
  (M12b.4: > 16 B executions combined).
- CD + Footer: covered by `parse_cd_footer` (M12b.4: > 13 B executions).
- Archive audit entry walking: covered by `archive_audit` / `archive_audit_wide`
  (M12b.4/M12b.5: > 3.6 B executions).
- LFH metadata edges (FEC, fragmentation, CDC, delta): covered by
  `pr4_lfh_metadata_edges` (M12b.5: > 18 B executions).
- TLV metadata edges: covered by `pr4_tlv_metadata_edges` (M12b.5: > 8 B executions).

---

*Document last updated during M13a.1 audit review.*
*This document does not claim exhaustive audit coverage, production hardening completion,
independent external audit completion, certification, compliance, or stable API/ABI guarantees.*
