<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# M13 Audit Findings

**Authoritative source:** `docs/M13_AUDIT_FINDINGS.json` (schema version 2)

This file is the human-readable rendering of the machine-readable audit registry
at `docs/M13_AUDIT_FINDINGS.json`.  That JSON file is authoritative for finding
content, classifications, statuses, ownership, verification requirements,
resolutions, audit objectives, and scope.  If this Markdown and the JSON
disagree, the JSON is correct.

Findings in this document are based on code-level audit of the SAR Rust
reference implementation.  They are not the result of an independent external
security audit.  No claim of exhaustive coverage, production hardening
completion, certification, compliance, stable API/ABI guarantees, or
production-readiness is made.

---

## Contents

- [Registry Metadata](#registry-metadata)
- [M13a.1 - Parser, Memory, Panic, and DoS Audit](#m13a1---parser-memory-panic-and-dos-audit)
  - [Scope and Artifacts](#scope-and-artifacts)
  - [Audit Objectives](#audit-objectives)
  - [Open Remediation Findings](#open-remediation-findings)
  - [Pending Normative Findings](#pending-normative-findings)
  - [Closed Observations](#closed-observations)
  - [Superseded Records](#superseded-records)
  - [Verified Controls](#verified-controls)
  - [M13a.1 Completion Summary](#m13a1-completion-summary)
- [Summary Table](#summary-table)
- [Audit Scope Well-Reviewed Areas](#audit-scope-well-reviewed-areas)

---

## Registry Metadata

- **Schema version:** 2
- **Project:** SAR
- **Milestone:** M13
- **Registry status:** in_progress
- **Source:** mixed audit
- **Generated markdown:** docs/M13_AUDIT_FINDINGS.md
- **Last updated:** 2026-08-01
- **Branch:** copilot/m13a1-audit-milestone
- **Source commit:** c0f4d6d7ea6a60d8372b5fb2c80c05e0f041c8bf

**Notes:**
- M13a.1 findings were structurally migrated from schema v1 and then reviewed
  under schema v2.
- JSON is the authoritative structured representation; Markdown synchronization
  is handled separately.
- Open implementation, resource, fuzzing, and test findings are remediation
  inputs for the applicable M13b milestone.
- Specification gaps remain pending normative resolution in M13a.7.

The overall registry status remains `in_progress` because M13a.2 through
M13a.7 audit scopes and the M13b remediation milestones are not yet complete.

---

## M13a.1 - Parser, Memory, Panic, and DoS Audit

### Scope and Artifacts

- **Status:** complete
- **Completed date:** 2026-08-01
- **Reviewed commit:** c0f4d6d7ea6a60d8372b5fb2c80c05e0f041c8bf

**Scope:** Global Header, LFH, TLV, Central Dictionary, Footer, and archive
structural parsing; checked arithmetic and length/offset calculations;
`ResourceLimits` coverage; panic/DoS behavior; allocator-churn and
repeated-initialization risks; unsafe usage policy; fuzzing coverage and corpus
quality review.

**Scope notes:**
- All M13a.1 audit objectives are complete.
- Conclusions are bounded to the audited functions, files, and paths listed
  in this scope.

**Included artifacts:**
- `crates/sar-core/src/format.rs`
- `crates/sar-core/src/tlv.rs`
- `crates/sar-core/src/limits.rs`
- `crates/sar-core/src/flags.rs`
- `crates/sar-core/src/io.rs`
- `crates/sar-core/src/sparse.rs`
- `crates/sar-core/src/lib.rs`
- `crates/sar-core/src/fec.rs`
- `crates/sar-core/src/metadata.rs`
- `crates/sar-archive/src/lib.rs`
- `crates/sar-archive/src/archive.rs`
- `crates/sar-archive/src/stream.rs`
- `crates/sar-archive/src/recovery.rs`
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

**Excluded topics:**
- cryptographic dependency usage and AEAD internals (M13a.2)
- transform and recovery resource accounting (M13a.3)
- filesystem metadata and extraction safety (M13a.4)
- crate-boundary and profile-boundary attack surface (M13a.5)
- cold-storage and tape resilience (M13a.6)
- recovery algorithm internals beyond parser-facing interface paths
- CLI extraction behavior
- session/transport semantics

---

### Audit Objectives

All 8 M13a.1 audit objectives were completed.  Open remediation findings
(owned by M13b.1) and the pending normative question (owned by M13a.7) do not
prevent M13a.1 completion.

| ID | Title | Status | Outcome | Related Findings |
|----|-------|--------|---------|-----------------|
| M13a.1-OBJ-01 | Audit structural parser paths | complete | findings_recorded | M13-PARSER-001, M13-PARSER-002, M13-PARSER-003, M13-PARSER-004 |
| M13a.1-OBJ-02 | Audit checked arithmetic and length or offset calculations | complete | findings_recorded | M13-PARSER-001 |
| M13a.1-OBJ-03 | Audit ResourceLimits coverage | complete | mixed | M13-PARSER-002, M13-PARSER-008, M13-PARSER-009, M13-PARSER-014 |
| M13a.1-OBJ-04 | Audit panic and denial-of-service behavior | complete | findings_recorded | M13-PARSER-002 |
| M13a.1-OBJ-05 | Audit allocator churn and repeated initialization | complete | mixed | M13-PARSER-002, M13-PARSER-009 |
| M13a.1-OBJ-06 | Audit unsafe usage policy | complete | observations_only | M13-PARSER-007 |
| M13a.1-OBJ-07 | Review parser and resource fuzzing coverage and corpus quality | complete | findings_recorded | M13-PARSER-005, M13-PARSER-006, M13-PARSER-014, M13-PARSER-015 |
| M13a.1-OBJ-08 | Record and classify remediation inputs | complete | mixed | (all findings) |

**Objective summaries:**

- **M13a.1-OBJ-01:** Global Header, LFH, TLV, Central Dictionary, Footer,
  ArchiveReader, and StreamArchiveParser structural paths were reviewed within
  the stated audit boundary.
- **M13a.1-OBJ-02:** Input-derived length, size, and offset calculations in
  the audited parser paths were reviewed; the unchecked narrowing conversion is
  tracked separately.
- **M13a.1-OBJ-03:** Resource-limit checks and allocation boundaries were
  reviewed in the audited parser paths; the audit entry-count gap and related
  test coverage are tracked.
- **M13a.1-OBJ-04:** Panic-prone constructs and attacker-controlled iteration
  or retained-allocation behavior were reviewed in the audited paths; the
  concrete retained-entry risk is tracked.
- **M13a.1-OBJ-05:** Allocator behavior and repeated parser initialization
  were reviewed within the audited paths.  No additional actionable issue was
  identified beyond the tracked retained-report resource risk and the closed
  TLV allocation observation.
- **M13a.1-OBJ-06:** The crate-level unsafe-code prohibition and parser or
  resource paths were reviewed and recorded as a verified positive control.
- **M13a.1-OBJ-07:** Dedicated parser, archive, state-machine, metadata-edge,
  and corpus evidence was reviewed.  Open target and boundary-test gaps and a
  closed campaign-record reproducibility observation are recorded.
- **M13a.1-OBJ-08:** Findings were assigned stable IDs and classified as
  implementation defects, specification gaps, resource risks, test or fuzzing
  gaps, documentation observations, or verified controls.

---

### Open Remediation Findings

The following findings remain open and are assigned to M13b.1 for remediation.
None of these prevent M13a.1 audit milestone completion.  M13-PARSER-003 has
status `confirmed` rather than `open` because the specification basis is fully
established; remediation is still assigned to M13b.1.

---

## M13-PARSER-001

**Title:** Unchecked `as u16` narrowing conversion in `global_header_flags_bytes`

- **Type:** implementation_defect
- **Areas:** parser, memory
- **Severity:** low
- **Priority:** medium
- **Confidence:** confirmed
- **Status:** open
- **Source milestone:** M13a.1
- **Remediation owner:** M13b.1
- **Compatibility impact:** preserves_compliant_inputs

**Summary:**
`global_header_flags_bytes()` uses an unchecked `as u16` narrowing conversion
for the flags size.  Under default limits the cast is safe, but with
non-default or unlimited limits the cast silently truncates, producing
incorrect AEAD AAD bytes.

**Current behavior:**
Line 918 of `format.rs` casts `header.flags_bytes.len()` (a usize) to u16
using `as u16` without a checked conversion.  When `max_global_flags_bytes`
is set above `u16::MAX` or `ResourceLimits::unlimited()` is in effect, the
cast silently truncates, producing incorrect AAD bytes for AEAD computation.

**Expected behavior:**
The flags size must be encoded into the AAD bytes using a checked conversion
that returns an error on overflow rather than silently truncating.

**Impact:**
Silent truncation at AAD construction would cause AEAD authentication to fail
for all encrypted entries when the flags buffer exceeds 65535 bytes, without a
clear overflow error at the point of failure.  Not exploitable under default
limits.

**Evidence:**
- `crates/sar-core/src/format.rs` line 918 -
  `let flags_size = header.flags_bytes.len() as u16;` - unchecked narrowing
  conversion from usize to u16.
- `crates/sar-core/src/format.rs` lines 346-347 - `write_global_header` uses
  `u16::try_from(...)` for size encoding at the same location; the
  inconsistency is clear.

**Remediation requirements (M13b.1):**
- Use a checked conversion when encoding the Global Flags byte length into the
  u16 AAD field and return the appropriate existing error on overflow.

**Verification (required, M13b.1):**
- Test that `global_header_flags_bytes` returns an error when flags buffer
  length exceeds `u16::MAX` under non-default limits.

**Notes:**
Under default `ResourceLimits`, `flags_bytes.len() <= 65535 == u16::MAX`, so
no truncation occurs in practice.  The risk only materializes with non-default
or unlimited limits.

---

## M13-PARSER-002

**Title:** `audit()` data-area scan lacks entry-count limit check

- **Type:** resource_risk
- **Areas:** memory, dos, resource_limits
- **Severity:** medium
- **Priority:** high
- **Confidence:** confirmed
- **Status:** open
- **Source milestone:** M13a.1
- **Remediation owner:** M13b.1
- **Compatibility impact:** preserves_compliant_inputs

**Summary:**
`ArchiveReader::audit()` retains one `ArchiveAuditEntryReport` per scanned
entry without enforcing the configured maximum entry count before retaining the
report.

**Current behavior:**
The `audit()` data-area scan advances through parseable entries and pushes one
`ArchiveAuditEntryReport` into its retained `entries` vector for each entry.
The loop does not call `ResourceLimits::check_entry_count` before the push, so
`max_entry_count` does not bound the number of retained reports.  `verify()`
retains offsets in a separate vector and `next_entry()` does not itself retain
prior reports; those paths must not be conflated with the primary `audit()`
allocation behavior.

**Impact:**
For attacker-controlled archives, retained report memory and scan CPU can grow
linearly with the number of parseable entries inside the permitted archive
region rather than stopping at `max_entry_count`.  The report vector has
nontrivial inline storage per entry, and populated owned fields may add
per-entry allocations.  Archive size still provides an outer bound, but the
default archive-size ceiling permits far more entries than the default
entry-count limit and can cause memory exhaustion or prolonged processing
before the scan ends.

**Evidence:**
- `crates/sar-archive/src/archive.rs` lines 1205-1351 - no
  `check_entry_count` call in the `audit()` loop body before
  `entries.push(...)`.
- `crates/sar-core/src/format.rs` line 827 -
  `limits.check_entry_count(file_count_usize)?;` is present in
  `parse_central_dictionary()` but not replicated in the data-area scan paths.

**Detail:**

The following paths must be analyzed separately:

- `audit()` retains one `ArchiveAuditEntryReport` per scanned entry in the
  `entries: Vec<_>` without any pre-push entry-count check.  This is the
  primary concern.
- `verify()` accumulates `offsets: Vec<u64>` (8 bytes per offset) by calling
  `next_entry()` in a loop.  `verify()` is applicable only to indexed archives,
  where `data_end = cd_offset`, so the traversal is bounded by the CD offset
  rather than the full archive size.  The missing `check_entry_count` pre-push
  call is a policy inconsistency but the structural exposure is smaller.
- `next_entry()` advances by one entry per call and does not accumulate a
  retained collection of prior entries.  Its callers are responsible for
  bounding iteration.  The missing entry-count check in `next_entry()` means
  callers that loop without their own counter are not protected by the limit.

For indexed archives, `data_end` is set to `cd_offset`, which limits
traversal.  For `NO_INDEX` archives, `data_end == file_len`, and
`max_archive_size` is the only structural bound.  An adversary supplying a
crafted `NO_INDEX` archive with many minimal-length entries could force the
`entries` Vec to grow proportional to archive size before any entry-count limit
is applied.

The minimum parseable LFH estimate in the audit record is 20 bytes with no
optional fields, zero payload, and a zero-length name; the estimate is
illustrative rather than a practical allocation forecast.

**Remediation requirements (M13b.1):**
- Maintain a checked running entry count in `audit()` and enforce
  `max_entry_count` before retaining another `ArchiveAuditEntryReport`.
- Return the existing limit-exceeded status without changing unrelated archive
  parsing or wire-format behavior.

**Remediation constraints:**
- Use a deterministic regression test with a deliberately small configured
  limit.

**Verification (required, M13b.1):**
- Deterministic test verifying `audit()` returns LimitExceeded when entry
  count exceeds the configured limit.  Use a small explicit limit (e.g., 2
  allowed entries) and a valid archive containing more entries than the limit.

**Notes:**
The `verify()` exposure is smaller than `audit()` because `verify()` only
applies to indexed archives (bounded by `cd_offset`) and stores only 8-byte
offsets rather than full report structs.  The primary remediation target is
`audit()`.

---

## M13-PARSER-003

**Title:** TLV type IDs 0x05-0x0F accepted in violation of specification

- **Type:** implementation_spec_mismatch
- **Areas:** parser, wire_format
- **Severity:** low
- **Priority:** high
- **Confidence:** confirmed
- **Status:** confirmed
- **Source milestone:** M13a.1
- **Remediation owner:** M13b.1
- **Normative basis:** specification.md line 1074 - TLV type IDs 0x05-0x0F are
  RESERVED.  Reserved values must produce SAR_ERR_RESERVED_VALUE.
- **Compatibility impact:** rejects_previously_accepted_nonconforming_input

**Summary:**
The `classify_type()` function in `tlv.rs` leaves TLV type IDs 0x05..=0x0F
to a wildcard accept arm.  The specification explicitly reserves these IDs and
requires a reserved-value error.  The parser is fail-open for these IDs.

**Current behavior:**
`classify_type()` covers 0x00 (rejected), 0x01-0x04 (accepted), 0x10-0x1F
(FEC dispatch), 0x20-0x2F (rejected), 0x30-0x3F (accepted),
0x40/0x41/0x4F (CDC accepted), 0x42-0x4E (rejected), 0x50-0xFF (rejected),
and `_` wildcard (accepted).  IDs 0x05..=0x0F fall to the wildcard and are
parsed, accumulated, and returned without error.

**Expected behavior:**
Reserved TLV type IDs 0x05..=0x0F must be rejected with a reserved-value
status before any accumulate or accept path.  The dispatch must be exhaustive
and fail closed for every possible input byte.

**Impact:**
The parser accepts values that the specification designates as reserved and
maps to a reserved-value error.  This is a confirmed conformance and
interoperability defect.  No independent security bypass is demonstrated by the
audit evidence, so severity is low while remediation priority remains high.

**Evidence:**
- `specification.md` line 1074, TLV type registry - explicit RESERVED
  designation for TLV type IDs 0x05-0x0F.  The specification requires reserved
  values produce SAR_ERR_RESERVED_VALUE.
- `crates/sar-core/src/tlv.rs` lines 28-43 - `classify_type()` wildcard arm
  accepts 0x05-0x0F without error; gap in explicit range coverage.

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

**Remediation requirements (M13b.1):**
- Reject every reserved TLV type ID in 0x05..=0x0F with the specified
  reserved-value status before any accumulation or acceptance path.
- Keep TLV type classification exhaustive and fail closed for every possible
  input byte.

**Verification (required, M13b.1):**
- Test that each TLV type ID in 0x05..=0x0F is rejected with a reserved-value
  error by `parse_tlvs`.

---

## M13-PARSER-005

**Title:** `parse_lfh` fuzz targets omit several LFH-layout-affecting global flags

- **Type:** fuzzing_gap
- **Areas:** fuzzing
- **Severity:** low
- **Priority:** low
- **Confidence:** confirmed
- **Status:** open
- **Source milestone:** M13a.1
- **Remediation owner:** M13b.1
- **Compatibility impact:** none

**Summary:**
The `parse_lfh` and `parse_lfh_wide` fuzz targets use an 8-bit selector that
maps to 8 GlobalFlags constants, producing up to 256 combinations of those 8
selected flags.  Six flags that add physical fields to the LFH layout
(COMPRESSED, HAS_DELTA, ENCRYPTED, CDC_SUPPORT, PER_FILE_CRC, DEDUPLICATION)
are not included in the selector and are never set.

**Impact:**
Parser paths for ENCRYPTED, HAS_DELTA, COMPRESSED, CDC_SUPPORT, PER_FILE_CRC,
and DEDUPLICATION LFH optional fields are not covered by the dedicated
`parse_lfh` or `parse_lfh_wide` targets.  Coverage is partially compensated
by `archive_entry_decode`, `archive_audit`, and `pr4_lfh_metadata_edges`, but
isolated LFH parser coverage for those flag combinations is absent from the
dedicated targets.

**Evidence:**
- `fuzz/fuzz_targets/parse_lfh.rs` lines 22-51 - `lfh_flags()` function
  covers 8 flags (bits 0-7 of selector) but omits COMPRESSED, HAS_DELTA,
  ENCRYPTED, CDC_SUPPORT, PER_FILE_CRC, DEDUPLICATION.
- `fuzz/fuzz_targets/parse_lfh_wide.rs` lines 22-51 - same `lfh_flags()`
  design as `parse_lfh.rs`; same omissions.

The following global flags add fixed-length fields to the physical LFH layout
and are missing from the selector:
- `COMPRESSED` (adds 1 B: Comp Algo ID)
- `HAS_DELTA` (adds 1 B Patch Algo ID + 32 B Delta Base Hash = 33 B total)
- `ENCRYPTED` (adds 1 B Encr Algo ID + 24 B IV/Nonce = 25 B total)
- `CDC_SUPPORT` (adds 1 B: CDC Algo ID)
- `PER_FILE_CRC` (adds 4 B: File CRC32)
- `DEDUPLICATION` (adds 32 B: Content Hash)

`HAS_SYMLINKS` (bit 26) does not add any field to the LFH physical layout
and is correctly omitted from the layout-affecting list.

**Remediation requirements (M13b.1):**
- Extend the dedicated LFH fuzzing inputs so every Global Flags value that
  changes the physical LFH layout is independently and combinatorially
  reachable.
- Apply equivalent coverage to both the standard and wide LFH fuzz targets.

**Verification:**
- Not required (test_requirement: not_required).

**Notes:**
`archive_entry_decode` and `archive_audit` partially compensate by exercising
full archive parsing including encrypted/compressed entries, but those targets
drive higher-level code paths.  Isolated LFH parser coverage for these flag
combinations is still valuable.

---

## M13-PARSER-014

**Title:** No sparse-map seeds or deterministic tests at near-limit byte and
descriptor counts

- **Type:** test_gap
- **Areas:** fuzzing, testing, resource_limits
- **Severity:** informational
- **Priority:** low
- **Confidence:** confirmed
- **Status:** open
- **Source milestone:** M13a.1
- **Remediation owner:** M13b.1
- **Compatibility impact:** none

**Summary:**
Deterministic sparse-map boundary coverage is absent for reduced custom byte
and descriptor limits.  Compact fuzz seeds may complement these tests, but
production-scale corpus files are not required to validate limit logic.

**Impact:**
Without deterministic boundary tests, off-by-one behavior in sparse-map byte
and descriptor limits is not explicitly locked down.  No parser defect is
currently demonstrated.

**Evidence:**
- `fuzz/CORPUS.md` corpus categories - no dedicated sparse-map corpus category
  for near-limit byte and descriptor counts.
- `fuzz/fuzz_targets/parse_lfh.rs` lines 9-19 - limits include
  `max_sparse_map_bytes: 512` - appropriate reduced limit for fuzz targets.
- `crates/sar-core/src/sparse.rs` line 52 - guard:
  `count > isize::MAX as usize / std::mem::size_of::<SparseExtent>()`
  prevents unsafe allocations.

**Detail:**

No dedicated corpus category or seed specifically targets the
`check_sparse_map_bytes` and `check_sparse_descriptor_count` resource limits
near their configured values.  The `pr4_lfh_metadata_edges` target exercises
LFH metadata edge cases including sparse, but sparse-map seeds at near-limit
byte counts and descriptor counts are not explicitly documented.

The `max_sparse_map_bytes` default is 8 MiB and `max_sparse_descriptors`
default is 524288.  Future boundary coverage should use reduced fuzz-target
limits (such as `max_sparse_map_bytes: 512` as configured in `parse_lfh.rs`)
to avoid multi-megabyte corpus seeds.

Boundary coverage should be provided for:
- one descriptor below the configured maximum;
- exactly equal to the configured maximum;
- one descriptor above the configured maximum.

Do not require multi-megabyte corpus seeds or exact production-default
allocations to test limit logic; use reduced custom limits for both
deterministic and fuzz-target tests.

**Remediation requirements (M13b.1):**
- Add deterministic tests using reduced custom limits that accept one below
  and exactly equal to each maximum and reject one above with the expected
  limit error.
- Add only compact, structurally useful sparse-map fuzz seeds; do not require
  multi-megabyte or production-scale corpus inputs for exact boundary
  verification.

**Verification (required, M13b.1):**
- For sparse descriptor count: one below and exactly equal to the configured
  maximum are accepted, and one above returns the expected limit error.
- For sparse-map byte length: one below and exactly equal to the configured
  maximum are accepted, and one above returns the expected limit error.
- Boundary tests use reduced custom limits and do not require
  production-scale allocations.

**Notes:**
The `pr4_lfh_metadata_edges` target provides partial coverage for this area.
This finding specifically addresses seed corpus completeness and the need for
deterministic regression tests at resource-limit boundary values using reduced
custom limits.

---

### Pending Normative Findings

The following finding is pending normative resolution.  Implementation behavior
cannot be assessed or changed until the specification gap is resolved.
Resolution is owned by M13a.7 and does not prevent M13a.1 completion.

---

## M13-PARSER-004

**Title:** `GlobalFlags` undefined bits and extension bytes - normative behavior
undefined

- **Type:** specification_gap
- **Areas:** parser, wire_format, interoperability
- **Severity:** not_applicable
- **Priority:** medium
- **Confidence:** confirmed
- **Status:** pending_normative_resolution
- **Source milestone:** M13a.1
- **Resolution owner:** M13a.7
- **Compatibility impact:** unknown_pending_resolution

**Summary:**
The specification does not explicitly define how SAR v1.0 readers must handle
undefined bits in the first 32 Global Flags bits or nonzero extension bytes
beyond the first four bytes.  Current implementation behavior is recorded, but
normative resolution is required before that behavior can be assessed or
changed.

**Current behavior:**
Both `parse_global_header()` and `ArchiveReader::read_global_header()` call
`GlobalFlags::from_bits_truncate()` to parse the 32-bit flags word, silently
discarding bits 6, 7, 11-15, 21-23, and 31.  Extension bytes beyond the first
4 bytes are stored but not semantically validated.  `validate_global_flags()`
does not reject unrecognized bits.

**Evidence:**
- `crates/sar-core/src/format.rs` line 241 -
  `GlobalFlags::from_bits_truncate(u32::from_le_bytes(low))` silently drops
  undefined bits.
- `crates/sar-archive/src/archive.rs` line 904 -
  `GlobalFlags::from_bits_truncate(u32::from_le_bytes(low))` - same pattern
  in reader path.
- `crates/sar-core/src/flags.rs` lines 175-201 - `validate_global_flags()`
  checks only specific flag combinations; does not reject unrecognized bits.
- `specification.md` section 5.2 - no explicit MUST-be-zero requirement for
  undefined bits in the 32-bit Global Flags word.

**Normative questions (pending M13a.7):**
1. Must undefined bits in the first 32-bit Global Flags word be zero?
2. Are additional Global Flags bytes an extensibility mechanism?
3. If additional bytes are allowed, how must unknown nonzero bits in those
   bytes be handled by a SAR v1.0 implementation?
4. Which SAR status applies when unsupported or reserved global-flag bits are
   encountered?

**Verification:**
- Pending normative resolution.

**Notes:**
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

---

### Closed Observations

The following findings were reviewed and closed with no action during M13a.1.
They are retained as audit-evidence records only.

---

## M13-PARSER-006

**Title:** `archive_structural` fuzz target name overstates coverage scope

- **Type:** documentation_gap
- **Areas:** fuzzing, documentation
- **Severity:** informational
- **Priority:** deferred
- **Confidence:** confirmed
- **Status:** closed_no_action
- **Source milestone:** M13a.1
- **Resolution owner:** none
- **Compatibility impact:** documentation_only

**Summary:**
The `archive_structural` fuzz target calls only `read_global_header()` and
does not exercise entry-walking paths.  The target name implies broader
structural coverage.  Entry-walking coverage is provided by
`archive_entry_decode` and `archive_audit`.  No parser-safety gap was
demonstrated.

**Impact:**
Reduced clarity about fuzz coverage scope.  No confirmed parser-safety gap:
entry-walking coverage is provided by other existing targets.

**Evidence:**
- `fuzz/fuzz_targets/archive_structural.rs` lines 44-56 - only
  `reader.read_global_header()` is called; no `next_entry()`, `verify()`, or
  `audit()` calls.

**Resolution (M13a.1, 2026-08-01):**
- Decision: closed_no_action
- Summary: No action required.  Entry-walking coverage is provided by
  `archive_entry_decode` and `archive_audit`.  The target name is an
  informational labeling observation only.

**Verification:**
- Not required.

---

## M13-PARSER-008

**Title:** `ResourceLimits::unlimited()` documentation of production-use risk

- **Type:** documentation_gap
- **Areas:** resource_limits, documentation, public_api
- **Severity:** informational
- **Priority:** deferred
- **Confidence:** confirmed
- **Status:** closed_no_action
- **Source milestone:** M13a.1
- **Resolution owner:** none
- **Compatibility impact:** documentation_only

**Summary:**
`ResourceLimits::unlimited()` is public and disables all configured limits,
but its existing documentation already restricts intended use to controlled
test environments.  No misuse was identified in the audited code.

**Impact:**
Accidental use on untrusted input would remove resource protections, but the
audit identified neither an implementation defect nor an objective
documentation failure beyond the existing warning.

**Evidence:**
- `crates/sar-core/src/limits.rs` lines 274-312 - `ResourceLimits::unlimited()`
  is fully public with a prose warning in the doc comment.

**Resolution (M13a.1, 2026-08-01):**
- Decision: closed_no_action
- Summary: Closed with no action in M13a.1.  The API already warns that
  unlimited limits are for controlled testing, and no misuse was found in the
  audited code.

**Verification:**
- Not required.

**Notes:**
All fuzz targets currently use `ResourceLimits::default()` or explicitly
bounded limits, not `ResourceLimits::unlimited()`.

---

## M13-PARSER-009

**Title:** TLV allocation limit interaction and path-specific duplication not
documented

- **Type:** documentation_gap
- **Areas:** memory, resource_limits, documentation
- **Severity:** informational
- **Priority:** deferred
- **Confidence:** confirmed
- **Status:** closed_no_action
- **Source milestone:** M13a.1
- **Resolution owner:** none
- **Compatibility impact:** documentation_only

**Summary:**
`parse_tlvs()` can be called from multiple contexts with different peak-memory
shapes.  The interaction between per-TLV limits and the enclosing CD allocation
limit, and the path-specific temporary duplication factor, are not currently
documented in `ResourceLimits`.  No safety gap exists in the audited functions
and paths.

**Impact:**
Documentation clarity observation about how limits interact across call paths.
No memory safety gap exists in the audited functions and paths.

**Evidence:**
- `crates/sar-core/src/format.rs` lines 813-820 -
  `check_allocation_bytes(meta_size)` called before
  `parse_tlvs(meta_bytes, limits)` in `parse_central_dictionary`.
- `crates/sar-core/src/limits.rs` lines 92-98 - `max_tlv_bytes` and
  `max_tlv_count` documented without mentioning the enclosing CD limit
  interaction.

**Detail:**

`parse_tlvs()` enforces per-TLV limits (`max_tlv_bytes` per value,
`max_tlv_count` total count).  It can be called from different contexts:

- From `parse_central_dictionary()`, after a
  `check_allocation_bytes(meta_size)` call that bounds the total CD metadata
  blob.  In this path, TLV value bytes are copies from the input `meta_bytes`
  slice, so the sum of all TLV value lengths cannot exceed `meta_size`.  Peak
  memory is bounded by the raw metadata buffer plus cloned TLV values, which
  may briefly coexist.  Under default limits the CD metadata blob is bounded by
  `max_cd_bytes` (default 256 MiB), so 512 MiB is an upper bound for this
  specific path under default limits.
- Direct callers over caller-provided slices, `ArchiveReader` paths where an
  owned raw metadata buffer may coexist with cloned TLV values, and fuzz and
  test callers may have different peak-memory shapes.  A universal 512 MiB
  maximum does not apply to all call paths.

**Resolution (M13a.1, 2026-08-01):**
- Decision: closed_no_action
- Summary: Closed with no action in M13a.1.  The audited paths remain bounded
  by existing limits, and the observation does not establish a safety defect.

**Verification:**
- Not required.

**Notes:**
- In the Central Dictionary path, the raw metadata bytes and cloned TLV value
  bytes may together approach twice the metadata size while both coexist,
  excluding TLV container storage, Vec spare capacity, allocator overhead, and
  other parsed structures.
- Direct callers over caller-provided slices and fuzz or test callers can have
  different peak-memory shapes; no universal process-memory ceiling is asserted.

---

## M13-PARSER-015

**Title:** Fuzz campaign records do not preserve sufficient configuration
metadata

- **Type:** documentation_gap
- **Areas:** fuzzing, documentation
- **Severity:** informational
- **Priority:** deferred
- **Confidence:** confirmed
- **Status:** closed_no_action
- **Source milestone:** M13a.1
- **Resolution owner:** none
- **Compatibility impact:** documentation_only

**Summary:**
`fuzz/RUNS.md` records execution results but does not consistently preserve
the commit and relevant target configuration needed to reconstruct historical
campaigns.  Current target source does not by itself prove which limits were
used by an earlier run.

**Impact:**
The gap affects reproducibility and audit-trail quality only.  It does not
demonstrate a parser-safety defect or prove that production-scale limits were
not exercised.

**Evidence:**
- `fuzz/RUNS.md` historical campaign records - campaign records do not
  consistently include the tested commit and relevant ResourceLimits
  configuration needed to reconstruct a run.

**Resolution (M13a.1, 2026-08-01):**
- Decision: closed_no_action
- Summary: Closed with no action in M13a.1.  The record is retained only as
  an audit-evidence limitation; no modification to historical fuzz campaign
  records is assigned within M13.

**Verification:**
- Not required.

---

### Superseded Records

The following finding was superseded during M13a.1.  It is retained as a
historical audit record only.

---

## M13-PARSER-012

**Title:** No deterministic regression test for `audit()` entry-count limit
enforcement

- **Type:** test_gap
- **Areas:** testing, resource_limits
- **Severity:** informational
- **Priority:** deferred
- **Confidence:** confirmed
- **Status:** superseded
- **Source milestone:** M13a.1
- **Resolution owner:** none
- **Compatibility impact:** none

**Summary:**
The missing deterministic regression test is part of remediating M13-PARSER-002
and does not require an independent lifecycle record.

**Impact:**
Tracking the same future regression test in two findings would duplicate
ownership, verification, and closure work.

**Evidence:**
- `fuzz/fuzz_targets/archive_audit.rs` line 25 - `max_entry_count: 16` - does
  not cause limit enforcement in `audit()` because the check is missing.
- `fuzz/fuzz_targets/archive_audit_wide.rs` line 25 - `max_entry_count: 64` -
  wider limit but same structural issue.

**Relationships:**
- Related finding: M13-PARSER-002
- Superseded by: M13-PARSER-002

**Resolution (M13a.1, 2026-08-01):**
- Decision: superseded
- Summary: Superseded by M13-PARSER-002, which owns both the entry-count
  enforcement change and its deterministic regression test.

**Verification:**
- Not required.

---

### Verified Controls

The following finding is a verified positive control, confirmed during M13a.1.

---

## M13-PARSER-007

**Title:** No `unsafe` code in parser/resource paths

- **Type:** positive_observation
- **Areas:** unsafe
- **Severity:** informational
- **Priority:** low
- **Confidence:** confirmed
- **Status:** verified
- **Source milestone:** M13a.1
- **Resolution owner:** none
- **Compatibility impact:** none

**Summary:**
Both `sar-core` and `sar-archive` use `#![forbid(unsafe_code)]` at the crate
level.  No `unsafe` blocks, `from_raw_parts`, `MaybeUninit`, raw pointer
dereferences, or FFI assumptions were found in any parser or resource path.
All memory access is bounds-checked through the `ParseCursor` abstraction and
standard Rust slice indexing.

**Evidence:**
- `crates/sar-core/src/lib.rs` line 3 - `#![forbid(unsafe_code)]` at crate
  level.
- `crates/sar-archive/src/lib.rs` line 4 - `#![forbid(unsafe_code)]` at
  crate level.
- Grep for `unsafe|from_raw_parts|MaybeUninit` across both crates: zero
  results in parser/resource paths.

**Resolution (M13a.1, 2026-08-01):**
- Decision: verified_control
- Summary: Verified during M13a.1.  Both `sar-core` and `sar-archive` use
  `#![forbid(unsafe_code)]` at the crate level.  No `unsafe` blocks,
  `from_raw_parts`, `MaybeUninit`, raw pointer dereferences, or FFI
  assumptions were found in any parser or resource path.  All memory access
  is bounds-checked through the `ParseCursor` abstraction and standard Rust
  slice indexing.

**Verification:**
- Not required.

**Notes:**
Future crates that introduce FFI (C ABI, Python bindings, mobile) must not
relax this policy for `sar-core` or `sar-archive`.  Any unsafe code introduced
for FFI purposes must be confined to a dedicated FFI crate layer.

---

### M13a.1 Completion Summary

**M13a.1 audit scope status: complete (completed 2026-08-01)**

All 8 audit objectives were completed at commit
`c0f4d6d7ea6a60d8372b5fb2c80c05e0f041c8bf`.

**Finding counts by status:**
- open: 4 (M13-PARSER-001, M13-PARSER-002, M13-PARSER-005, M13-PARSER-014)
- confirmed (awaiting remediation): 1 (M13-PARSER-003)
- pending_normative_resolution: 1 (M13-PARSER-004)
- closed_no_action: 4 (M13-PARSER-006, M13-PARSER-008, M13-PARSER-009, M13-PARSER-015)
- superseded: 1 (M13-PARSER-012, superseded by M13-PARSER-002)
- verified: 1 (M13-PARSER-007)

**Remediation assignments:**
- M13b.1 owns remediation for M13-PARSER-001, M13-PARSER-002, M13-PARSER-003,
  M13-PARSER-005, and M13-PARSER-014.
- M13a.7 owns normative resolution for M13-PARSER-004.
- Open remediation findings do not prevent M13a.1 audit milestone completion.

**What this audit established:**
- The audited parser paths consistently use checked arithmetic, with one
  confirmed unchecked narrowing conversion in AAD construction (M13-PARSER-001).
- `ResourceLimits` enforcement is present in most audited parser paths; the
  `audit()` data-area scan lacks entry-count enforcement before retained-report
  allocation (M13-PARSER-002).
- TLV type IDs 0x05-0x0F are accepted in violation of the specification
  (M13-PARSER-003); normative behavior for undefined Global Flags bits is not
  specified (M13-PARSER-004).
- Fuzz coverage has gaps for LFH layout-affecting flags (M13-PARSER-005) and
  sparse-map boundary values (M13-PARSER-014).
- Both `sar-core` and `sar-archive` enforce `#![forbid(unsafe_code)]` at the
  crate level across all audited paths (M13-PARSER-007, verified).
- Four informational documentation and audit-trail observations were closed with
  no action.

---

## Summary Table

| ID | Title | Type | Severity | Status |
|----|-------|------|----------|--------|
| M13-PARSER-001 | Unchecked `as u16` narrowing conversion in `global_header_flags_bytes` | implementation_defect | low | open |
| M13-PARSER-002 | `audit()` data-area scan lacks entry-count limit check | resource_risk | medium | open |
| M13-PARSER-003 | TLV type IDs 0x05-0x0F accepted in violation of specification | implementation_spec_mismatch | low | confirmed |
| M13-PARSER-004 | `GlobalFlags` undefined bits and extension bytes - normative behavior undefined | specification_gap | not_applicable | pending_normative_resolution |
| M13-PARSER-005 | `parse_lfh` fuzz targets omit several LFH-layout-affecting global flags | fuzzing_gap | low | open |
| M13-PARSER-006 | `archive_structural` fuzz target name overstates coverage scope | documentation_gap | informational | closed_no_action |
| M13-PARSER-007 | No `unsafe` code in parser/resource paths | positive_observation | informational | verified |
| M13-PARSER-008 | `ResourceLimits::unlimited()` documentation of production-use risk | documentation_gap | informational | closed_no_action |
| M13-PARSER-009 | TLV allocation limit interaction and path-specific duplication not documented | documentation_gap | informational | closed_no_action |
| M13-PARSER-012 | No deterministic regression test for `audit()` entry-count limit enforcement | test_gap | informational | superseded |
| M13-PARSER-014 | No sparse-map seeds or deterministic tests at near-limit byte and descriptor counts | test_gap | informational | open |
| M13-PARSER-015 | Fuzz campaign records do not preserve sufficient configuration metadata | documentation_gap | informational | closed_no_action |

**Counts by severity:**
- blocker: 0
- high: 0
- medium: 1 (M13-PARSER-002)
- low: 3 (M13-PARSER-001, M13-PARSER-003, M13-PARSER-005)
- informational: 7 (M13-PARSER-006, M13-PARSER-007, M13-PARSER-008, M13-PARSER-009, M13-PARSER-012, M13-PARSER-014, M13-PARSER-015)
- not_applicable: 1 (M13-PARSER-004)

**Counts by status:**
- open: 4 (M13-PARSER-001, M13-PARSER-002, M13-PARSER-005, M13-PARSER-014)
- confirmed: 1 (M13-PARSER-003)
- pending_normative_resolution: 1 (M13-PARSER-004)
- closed_no_action: 4 (M13-PARSER-006, M13-PARSER-008, M13-PARSER-009, M13-PARSER-015)
- superseded: 1 (M13-PARSER-012)
- verified: 1 (M13-PARSER-007)

---

## Audit Scope Well-Reviewed Areas

The following areas were reviewed and found well-handled with no specific
findings beyond those above:

**Checked arithmetic:** In the audited functions and paths -
`parse_global_header`, `parse_lfh`, `parse_tlvs`, `parse_central_dictionary`,
`parse_footer`, `ArchiveReader`, and `StreamArchiveParser` - length and offset
arithmetic uses `checked_add`, `checked_sub`, `checked_mul`, or
`u*::try_from(...)` throughout.  No additional input-derived narrowing
conversion requiring a finding was identified in the reviewed parser paths.
The `ParseCursor` abstraction gates all byte-slice reads with checked index
arithmetic.  The only unchecked `as` cast identified in parser paths is
documented in M13-PARSER-001.

**`ResourceLimits` enforcement:** In the audited parser paths,
`check_lfh_header_bytes`, `check_path_bytes`, `check_global_flags_bytes`,
`check_kms_payload_bytes`, `check_tlv_bytes`, `check_tlv_count`,
`check_cd_bytes`, `check_allocation_bytes`, `check_entry_count` (in CD
parsing), `check_sparse_map_bytes`, `check_sparse_descriptor_count`,
`check_fec_value_bytes`, and `allocation_len` are called before the
corresponding allocations.  No additional allocation-before-limit issue was
identified in the reviewed parser paths, except as documented in M13-PARSER-002
for the `audit()` entry-count gap.

**Footer parsing:** `parse_footer()` is minimal (8 bytes, single u64 read)
and has no arithmetic risk.  The offset bounds are checked in the
`ArchiveReader` against `file_len` and `header_len` before CD parsing proceeds.

**CD/LFH disagreement:** CD offset and file-count mismatches are explicitly
checked in `verify()` and structurally guarded at read time.  The `data_end`
boundary for indexed archives is set to `cd_offset`, preventing entry-walking
from reading into the CD region.

**Panic resistance:** In the `sar-core` and `sar-archive` parser paths
reviewed, no `unwrap()`, `expect(...)`, `panic!()`, `todo!()`, or
`unreachable!()` macros were found outside of test code and dead-code patterns
in `transform.rs` test helpers.  All error paths return `Err(SarError::...)`.

**Allocator churn:** In the audited parser hot paths, `parse_tlvs`,
`parse_lfh`, and `parse_central_dictionary` allocate `Vec<u8>` per call
bounded by per-field limits.  No additional O(n^2) or O(n*m) allocation
pattern was identified in the reviewed parser paths.  Repeated
initialization/teardown churn is bounded by per-entry and per-archive limits.

**StreamArchiveParser:** The `StreamArchiveParser` push-parse state machine
(`crates/sar-archive/src/stream.rs`) was reviewed for parser-facing length,
count, allocation, panic, and structural behavior.  It delegates to the same
`parse_global_header` and `parse_lfh` functions reviewed above.  No additional
parser-safety issues were identified beyond those already covered by existing
findings.  It is exercised by `stream_archive_parser_state_machine.rs`.

**Fuzzing coverage (well-covered areas):**
- Global header magic/version/flags: covered by `parse_global_header` (M12b.4:
  > 12 B executions, overnight campaign).
- LFH layouts formed from up to 256 combinations of the 8 selected flags:
  covered by `parse_lfh` / `parse_lfh_wide` (M12b.4: > 21 B executions
  combined).
- TLV type/length/count/padding: covered by `parse_tlv` / `parse_tlv_wide`
  (M12b.4: > 16 B executions combined).
- CD + Footer: covered by `parse_cd_footer` (M12b.4: > 13 B executions).
- Archive audit entry walking: covered by `archive_audit` /
  `archive_audit_wide` (M12b.4/M12b.5: > 3.6 B executions).
- LFH metadata edges (FEC, fragmentation, CDC, delta): covered by
  `pr4_lfh_metadata_edges` (M12b.5: > 18 B executions).
- TLV metadata edges: covered by `pr4_tlv_metadata_edges`
  (M12b.5: > 8 B executions).

---

*This document is generated from `docs/M13_AUDIT_FINDINGS.json` and must not
be edited by hand.  All corrections must be made in the JSON registry.*

*This document does not claim exhaustive audit coverage, production hardening
completion, independent external audit completion, certification, compliance,
or stable API/ABI guarantees.*
