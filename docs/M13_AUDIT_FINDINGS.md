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
  This is an unchecked narrowing conversion.  The `flags_bytes.len()` field is bounded
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
  million`.  The `entries: Vec<ArchiveAuditEntryReport>` grows by one element
  per scanned entry.  Each `ArchiveAuditEntryReport` has a nontrivial inline
  size.  Additional heap allocations per entry depend on whether `String` and
  `Vec` fields are populated and on the active audit options; an empty
  `Option` or an empty `Vec` does not necessarily cause a separate additional
  allocation.  Actual memory impact depends on entry content and audit
  configuration but could be significant well below the theoretical maximum.

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
  Reserved TLV type IDs `0x05..=0x0F` must be rejected with a reserved-value
  status before any accumulate or accept path.  The `classify_type()` dispatch
  must be exhaustive and fail closed for every possible input byte; no input
  byte may reach an accept arm via a wildcard.
* Regression test needed: yes
* Suggested remediation milestone: M13b.1

---

## M13-PARSER-004: `GlobalFlags` undefined bits and extension bytes - normative behavior undefined

* Finding type: specification_gap
* Area: parser
* Severity: not_applicable
* Status: pending_normative_resolution
* Source milestone: M13a.1
* Resolution owner: M13a.7
* Affected files/APIs:
  * `crates/sar-core/src/format.rs` - `parse_global_header()`
  * `crates/sar-archive/src/archive.rs` - `ArchiveReader::read_global_header()`
  * `crates/sar-core/src/flags.rs` - `validate_global_flags()`
* Current behavior:
  Both `parse_global_header()` (format.rs line 241) and
  `ArchiveReader::read_global_header()` (archive.rs line 904) call
  `GlobalFlags::from_bits_truncate()` to parse the raw 32-bit flags word.
  `from_bits_truncate` silently discards any bits that do not correspond to a
  defined flag constant.  The defined bits are 0-5, 8-10, 16-20, and 24-30.
  Bits 6, 7, 11-15, 21-23, and 31 are currently undefined and are silently
  cleared.  Archives setting those bits are silently accepted.

  The global flags field is variable-length (at least 4 bytes, governed by the
  Flags Size field).  Bytes 5 and beyond in `flags_bytes` are stored but their
  content is not validated.  The specification does not define semantics for
  bytes beyond the first 4.

  `validate_global_flags()` checks specific flag-combination conflicts but does
  not reject unrecognized bits in either the first 32 bits or in extension bytes.

* Normative questions:
  1. Must undefined bits in the first 32-bit Global Flags word be zero?
  2. Are additional Global Flags bytes an extensibility mechanism?
  3. If additional bytes are allowed, how must unknown nonzero bits in those
     bytes be handled by a SAR v1.0 implementation?
  4. Which SAR status applies when unsupported or reserved global-flag bits
     are encountered?
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
* Compatibility impact: unknown pending normative resolution; resolution may
  require previously accepted archives to be rejected.
* Regression test needed: pending normative resolution

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
  exercise up to 256 combinations of those 8 selected flags.

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

## M13-PARSER-006: `archive_structural` fuzz target name overstates coverage scope

* Finding type: documentation_gap
* Area: fuzzing
* Severity: informational
* Status: closed_no_action
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/fuzz_targets/archive_structural.rs`
* Finding:
  The `archive_structural` fuzz target creates an `ArchiveReader` and calls
  `reader.read_global_header()` only.  It does not proceed to call
  `next_entry()`, `verify()`, or `audit()`.  The target name implies broader
  structural coverage than it provides.

  Entry-walking coverage is provided by `archive_entry_decode` and
  `archive_audit`.  No immediate parser-safety gap was demonstrated from
  the target-name mismatch alone.
* Evidence:
  `fuzz/fuzz_targets/archive_structural.rs:44-56` - only `reader.read_global_header()` is called.
  `archive_entry_decode` and `archive_audit` provide entry-walking coverage.
* Impact:
  Reduced clarity about fuzz coverage scope.  No confirmed parser-safety gap.
* Resolution: no action required. The coverage gap is addressed by other
  existing targets. The target name is an informational labeling observation.

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

## M13-PARSER-008: `ResourceLimits::unlimited()` documentation of production-use risk

* Finding type: documentation_gap
* Area: resource_limits / documentation
* Severity: informational
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/limits.rs` - `ResourceLimits::unlimited()`
* Finding:
  `ResourceLimits::unlimited()` is a public `#[must_use]` function that returns a
  `ResourceLimits` with every field set to `u64::MAX` or `usize::MAX`, effectively
  disabling all parser, allocation, and structural limits.  The doc comment warns
  "Use only in controlled test environments", but the warning is in prose and may
  not be prominent enough for callers encountering the function in generated API
  documentation.

  The existing public documentation already warns that this constructor is
  intended for controlled test environments.  No confirmed misuse in SAR has
  been identified.
* Evidence:
  `crates/sar-core/src/limits.rs:274-312` - `ResourceLimits::unlimited()` is
  fully public with a prose warning in the doc comment.
* Impact:
  This is a documentation discoverability observation.  Accidental production
  use would disable all resource-limit protections, but no confirmed
  vulnerability from such misuse exists in the current codebase.
* Recommended remediation:
  Strengthen the documentation to prominently describe the risk, expected use
  cases (benchmarks, offline testing, fuzzing), and the consequences of
  production use.
* Regression test needed: no
* Suggested remediation milestone: M13b.1
* Notes:
  All fuzz targets currently use `ResourceLimits::default()` or explicitly
  bounded limits, not `ResourceLimits::unlimited()`.

---

## M13-PARSER-009: TLV allocation limit interaction and path-specific duplication not documented

* Finding type: documentation_gap
* Area: memory / resource_limits / documentation
* Severity: informational
* Status: closed_no_action
* Source milestone: M13a.1
* Affected files/APIs:
  * `crates/sar-core/src/tlv.rs` - `parse_tlvs()`
  * `crates/sar-core/src/limits.rs` - `ResourceLimits`
* Finding:
  `parse_tlvs()` enforces per-TLV limits (`max_tlv_bytes` per value,
  `max_tlv_count` total count).  It can be called from different contexts:

  * From `parse_central_dictionary()`, after a `check_allocation_bytes(meta_size)`
    call that bounds the total CD metadata blob.  In this path, TLV value bytes
    are copies from the input `meta_bytes` slice, so the sum of all TLV value
    lengths cannot exceed `meta_size`.  Peak memory is bounded by the raw
    metadata buffer plus cloned TLV values, which may briefly coexist.  Under
    default limits the CD metadata blob is bounded by `max_cd_bytes` (default
    256 MiB), so 512 MiB is an upper bound for this specific path under default
    limits.
  * Direct callers over caller-provided slices, `ArchiveReader` paths where an
    owned raw metadata buffer may coexist with cloned TLV values, and fuzz and
    test callers may have different peak-memory shapes.  A universal 512 MiB
    maximum does not apply to all call paths.

  This limit interaction and path-specific temporary duplication are not
  currently documented in `ResourceLimits`.  No safety gap exists; the memory
  behavior is already bounded by existing limits.
* Evidence:
  `crates/sar-core/src/format.rs:813-820` - `check_allocation_bytes(meta_size)`
  called before `parse_tlvs(meta_bytes, limits)` in `parse_central_dictionary`.
  `crates/sar-core/src/limits.rs:92-98` - `max_tlv_bytes` and `max_tlv_count`
  documented without mentioning the enclosing CD limit interaction.
* Impact:
  Documentation clarity observation.  No memory safety gap exists in the
  audited functions and paths.
* Resolution: no action required at this time. Limit interaction documentation
  may be added opportunistically.

---

## M13-PARSER-012: no deterministic regression test for `audit()` entry-count limit enforcement

* Finding type: test_gap
* Area: testing / resource_limits
* Severity: informational
* Status: open
* Source milestone: M13a.1
* Related finding: M13-PARSER-002
* Affected files/APIs:
  * `fuzz/fuzz_targets/archive_audit.rs`
  * `fuzz/fuzz_targets/archive_audit_wide.rs`
* Finding:
  The `archive_audit` and `archive_entry_decode` fuzz targets configure
  `max_entry_count: 16` and `max_entry_count: 64/128` respectively.  These
  limits constrain what the fuzzer will accept, but they do not cause the fuzzer
  to exercise the M13-PARSER-002 missing limit check: because `audit()` does not
  enforce `max_entry_count` itself, supplying more than 16 entries simply grows
  the `entries` Vec beyond the nominal limit without error.  Setting
  `max_entry_count` to 10 000 in a fuzz target does not make the missing check
  easier for coverage-guided fuzzing to reach.

  The correct future regression strategy for M13-PARSER-002 is a deterministic
  test: a small explicit limit (for example, 2 allowed entries) combined with a
  valid archive containing more entries than the limit, verifying that `audit()`
  returns a limit-exceeded error.
* Evidence:
  `fuzz/fuzz_targets/archive_audit.rs:25` - `max_entry_count: 16`
  `fuzz/fuzz_targets/archive_audit_wide.rs:25` - `max_entry_count: 64`
* Impact:
  No deterministic regression test yet exists for the entry-count limit
  enforcement gap identified in M13-PARSER-002.  This test gap will be
  addressed after M13-PARSER-002 is remediated.
* Recommended remediation:
  After M13-PARSER-002 is remediated in M13b.1, add a deterministic regression
  test verifying that `audit()` returns a limit-exceeded error when entry count
  exceeds a small explicitly configured limit (for example, 2 allowed entries
  and 3 valid entries in the archive).  Do not rely on production-scale entry
  counts or fuzz-only coverage for this regression check.
* Regression test needed: yes (after M13-PARSER-002 fix)
* Suggested remediation milestone: M13b.1

---

## M13-PARSER-014: no sparse-map seeds or deterministic tests at near-limit byte and descriptor counts

* Area: fuzzing / testing / resource_limits
* Severity: low
* Status: open
* Source milestone: M13a.1
* Affected files/APIs:
  * `fuzz/CORPUS.md`
  * `fuzz/fuzz_targets/archive_entry_decode.rs`
  * `fuzz/fuzz_targets/pr4_lfh_metadata_edges.rs`
* Finding:
  No dedicated corpus category or seed specifically targets the
  `check_sparse_map_bytes` and `check_sparse_descriptor_count` resource limits
  near their configured values.  The `pr4_lfh_metadata_edges` target exercises
  LFH metadata edge cases including sparse, but sparse-map seeds at near-limit
  byte counts and descriptor counts are not explicitly documented.

  The `max_sparse_map_bytes` default is 8 MiB and `max_sparse_descriptors`
  default is 524 288.  Future boundary coverage should use reduced fuzz-target
  limits (such as `max_sparse_map_bytes: 512` as configured in `parse_lfh.rs`)
  to avoid multi-megabyte corpus seeds.

  Boundary coverage should be provided for:
  - one descriptor below the configured maximum;
  - exactly equal to the configured maximum;
  - one descriptor above the configured maximum.

  Do not require multi-megabyte corpus seeds or exact production-default
  allocations to test limit logic; use reduced custom limits for both
  deterministic and fuzz-target tests.
* Evidence:
  `fuzz/CORPUS.md` - no dedicated sparse-map corpus category.
  `fuzz/fuzz_targets/parse_lfh.rs:9-19` - limits: `max_sparse_map_bytes: 512`.
  `crates/sar-core/src/sparse.rs:52` - guard: `count > isize::MAX as usize / std::mem::size_of::<SparseExtent>()`.
* Impact:
  Sparse-map parsing paths near configured limits are not explicitly covered
  by fuzz seeds or deterministic regression tests.  The `parse_sparse_map`
  function includes a guard against unsafe allocation sizes, but boundary
  conditions near `max_sparse_descriptors` are not hit by existing corpus inputs
  or regression tests.
* Recommended remediation:
  Add small seed files for `pr4_lfh_metadata_edges` or `parse_lfh` targets using
  reduced limits with sparse maps at: 0 extents, 1 extent, one below the
  fuzz-target configured limit, exactly at the limit, and one above the limit.
  Add a deterministic regression test verifying `check_sparse_descriptor_count`
  fires correctly using reduced limits in a unit test (not as an oversized corpus
  seed).
* Regression test needed: yes
* Suggested remediation milestone: M13b.1
* Notes:
  The `pr4_lfh_metadata_edges` target provides partial coverage for this area.
  This finding specifically addresses seed corpus completeness and the need for
  deterministic regression tests at resource-limit boundary values using reduced
  custom limits.

---

## M13-PARSER-015: wide target limit configurations not recorded in RUNS.md

* Finding type: documentation_gap
* Area: fuzzing / documentation
* Severity: informational
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

  `RUNS.md` records execution counts for past campaigns but does not document
  the configured limit values used for those runs.  The absence of limit
  configurations in the campaign record means the audit trail is incomplete:
  it is not possible to determine from the campaign record alone whether
  near-default limits were used for any past campaign.

  The primary issue is reproducibility and audit-trail quality.  The absence
  of this documentation does not demonstrate a parser-safety gap.
* Evidence:
  `fuzz/RUNS.md` - no limit configuration documented for wide-target campaigns.
  Wide-target limit values confirmed from source inspection.
* Impact:
  Past campaign limit configurations are known from source but are not in the
  campaign record.  This affects reproducibility and audit-trail completeness,
  not parser safety.
* Recommended remediation:
  Update `RUNS.md` to document the configured limit values for each past
  campaign.  Selected production-default constants may be checked with
  deterministic boundary-value tests rather than production-scale fuzz campaigns.
* Regression test needed: no
* Suggested remediation milestone: M13b.1

---

## Summary table

| ID | Title | Type | Severity | Status |
|----|-------|------|----------|--------|
| M13-PARSER-001 | Unchecked `as u16` narrowing conversion in `global_header_flags_bytes` | implementation_defect | low | open |
| M13-PARSER-002 | `audit()` data-area scan lacks entry-count limit check | resource_risk | medium | open |
| M13-PARSER-003 | TLV type IDs 0x05-0x0F accepted in violation of specification | implementation_spec_mismatch | medium | confirmed |
| M13-PARSER-004 | `GlobalFlags` undefined bits and extension bytes - normative behavior undefined | specification_gap | not_applicable | pending_normative_resolution |
| M13-PARSER-005 | `parse_lfh` fuzz targets omit several LFH-layout-affecting global flags | fuzzing_gap | low | open |
| M13-PARSER-006 | `archive_structural` fuzz target name overstates coverage scope | documentation_gap | informational | closed_no_action |
| M13-PARSER-007 | No `unsafe` code in parser/resource paths | positive_observation | informational | verified |
| M13-PARSER-008 | `ResourceLimits::unlimited()` documentation of production-use risk | documentation_gap | informational | open |
| M13-PARSER-009 | TLV allocation limit interaction and path-specific duplication not documented | documentation_gap | informational | closed_no_action |
| M13-PARSER-012 | No deterministic regression test for `audit()` entry-count limit enforcement | test_gap | informational | open |
| M13-PARSER-014 | No sparse-map seeds or deterministic tests at near-limit byte and descriptor counts | test_gap | low | open |
| M13-PARSER-015 | Wide target limit configurations not recorded in RUNS.md | documentation_gap | informational | open |

**Counts by severity:**
- blocker: 0
- high: 0
- medium: 2 (M13-PARSER-002, M13-PARSER-003)
- low: 3 (M13-PARSER-001, M13-PARSER-005, M13-PARSER-014)
- informational: 6 (M13-PARSER-006, M13-PARSER-007, M13-PARSER-008, M13-PARSER-009, M13-PARSER-012, M13-PARSER-015)
- not_applicable: 1 (M13-PARSER-004)

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
- LFH layouts formed from up to 256 combinations of the 8 selected flags: covered by `parse_lfh` /
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
