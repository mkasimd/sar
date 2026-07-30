<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR fuzzing run log

This file records bounded local fuzzing passes for the SAR Rust reference
implementation.

These runs are development-time hardening activity. They do not claim exhaustive
fuzzing, production hardening, independent security audit completion, or
malicious corpus completeness.

## M12b.4 initial local fuzzing pass

Date: 2026-07-27 through 2026-07-28  
Scope: initial local fuzzing execution, crash triage, post-fix regression
validation, and extended local boundary fuzzing for M12b.4  
Status: completed

### Purpose

This pass establishes initial local fuzzing execution for the current fuzz
target set.

It covers:

- short smoke fuzzing;
- bounded exploratory fuzzing on higher-risk parser, archive, and stream targets;
- triage and minimization of discovered crash inputs;
- promotion of a useful minimized crash input into a normal regression test;
- post-fix validation of the affected target;
- an extended local follow-up pass with wider and boundary-focused fuzz targets.

Extended malicious corpus work and longer scheduled fuzzing campaigns remain
deferred to M12b.5 and ongoing security hardening.

### Initial higher-risk target selection

The following higher-risk targets were selected for the initial local
exploratory pass:

```text
archive_entry_decode
archive_audit
stream_transcript
parse_lfh
parse_cd_footer
parse_tlv
````

Rationale:

* `archive_entry_decode` exercises archive entry walking and payload decoding
  under limits.
* `archive_audit` exercises archive audit metadata walking and policy handling.
* `stream_transcript` exercises stream transcript semantic validation.
* `parse_lfh` exercises dense LFH parsing with flag-dependent optional fields.
* `parse_cd_footer` exercises central dictionary and footer parsing.
* `parse_tlv` exercises metadata length, count, and padding parsing.

### Crash finding: `stream_transcript` overflow

Status: fixed
Target: `stream_transcript`
Owner: `sar-stream`
Result before fix: panic on malformed input
Expected behavior: fail closed with `Err`, not panic

#### Summary

The `stream_transcript` fuzz target found a reproducible integer overflow panic
in stream transcript validation.

The panic occurred in:

```text
crates/sar-stream/src/transcript.rs:126:12
```

Observed panic:

```text
attempt to add with overflow
```

Backtrace excerpt:

```text
validate_stream_transcript_internal
  at ./crates/sar-stream/src/transcript.rs:126:12

validate_stream_transcript_with_options
  at ./crates/sar-stream/src/transcript.rs:84:5

__libfuzzer_sys_run
  at ./fuzz/fuzz_targets/stream_transcript.rs:25:13
```

#### Reproducer

Original local crash artifact:

```text
fuzz/artifacts/stream_transcript/crash-d558a30f12a7ec3a299d2969ad260c33a06be432
```

Artifact size:

```text
62 bytes
```

Base64 form reported by libFuzzer:

```text
U0FSIQEABAATAAACMgAAACAABAD/AAAAAAAAAAAA9v////////8AAAAAAAAAAAAAU0FSAACACAACADAAAAA=
```

Reproduction command used during triage:

```bash
RUST_BACKTRACE=1 cargo +nightly fuzz run stream_transcript \
  fuzz/artifacts/stream_transcript/crash-d558a30f12a7ec3a299d2969ad260c33a06be432
```

#### Minimization

Minimization command:

```bash
cargo +nightly fuzz tmin stream_transcript \
  fuzz/artifacts/stream_transcript/crash-d558a30f12a7ec3a299d2969ad260c33a06be432
```

Result:

```text
cargo-fuzz confirmed the crash is reproducible but could not minimize it below
the original 62-byte input.
```

The original 62-byte artifact is therefore the minimized reproducer.

#### Fix

This finding was fixed in PR #36.

The fix replaced unchecked transcript payload-span arithmetic with checked
conversion and checked addition. Malformed input that previously panicked now
returns `SAR_ERR_OVERFLOW`.

A normal `sar-stream` regression test was added for the 62-byte reproducer.

### Local overnight exploratory rerun

After preserving and minimizing the known `stream_transcript` crash, an
overnight exploratory pass was run without `stream_transcript`.

Run ID:

```text
M12b4-overnight-20260727-015202
```

Configuration:

```text
Start: 2026-07-27T01:52:02+0200
End: 2026-07-27T07:52:32+0200
Max total time per target: 21600 seconds
Max generated input length: 65536 bytes
Target count: 5
```

Selected targets:

```text
archive_entry_decode
archive_audit
parse_lfh
parse_cd_footer
parse_tlv
```

Results:

| Target                 |           Runs | Exit | Artifacts | Result                            |
| ---------------------- | -------------: | ---: | --------: | --------------------------------- |
| `archive_entry_decode` |    770,684,193 |    0 |         0 | no obvious crash/error indicators |
| `archive_audit`        |  3,335,103,406 |    0 |         0 | no obvious crash/error indicators |
| `parse_lfh`            | 16,883,974,423 |    0 |         0 | no obvious crash/error indicators |
| `parse_cd_footer`      | 12,310,690,890 |    0 |         0 | no obvious crash/error indicators |
| `parse_tlv`            | 14,946,930,775 |    0 |         0 | no obvious crash/error indicators |

Generated corpus entries and fuzz artifacts remained ignored and were not
committed.

### Post-fix `stream_transcript` validation

After PR #36, the exact reproducer was validated again.

A temporary reproducer file can be recreated with:

```bash
printf '%s' 'U0FSIQEABAATAAACMgAAACAABAD/AAAAAAAAAAAA9v////////8AAAAAAAAAAAAAU0FSAACACAACADAAAAA=' \
  | base64 -d > /tmp/sar-m12b4-stream-transcript-overflow-62b.bin
```

Post-fix reproduction command:

```bash
RUST_BACKTRACE=1 cargo +nightly fuzz run stream_transcript \
  /tmp/sar-m12b4-stream-transcript-overflow-62b.bin
```

Expected post-fix result:

```text
The reproducer returns SAR_ERR_OVERFLOW instead of panicking.
```

A focused one-hour post-fix fuzzing pass was then run for
`stream_transcript`:

```bash
cargo +nightly fuzz run stream_transcript -- -max_total_time=3600 -max_len=65536
```

Result:

```text
Done 330845161 runs in 3601 second(s)
```

No panic or crash was observed after the fix.

### Extended local boundary fuzz target additions

Additional local fuzz targets were added for wider and boundary-focused
exploratory fuzzing:

```text
archive_entry_decode_wide
archive_audit_wide
parse_lfh_wide
parse_tlv_wide
stream_transcript_declared_lengths
```

Purpose:

* `archive_entry_decode_wide` exercises archive entry walking and payload
  decoding with wider resource limits.
* `archive_audit_wide` exercises archive audit metadata walking with wider
  resource limits while retaining metadata-only payload policy.
* `parse_lfh_wide` exercises LFH parsing with larger LFH, path, sparse, FEC,
  and decoded-size limits.
* `parse_tlv_wide` exercises TLV parsing with larger TLV, FEC, and CDC metadata
  limits.
* `stream_transcript_declared_lengths` exercises large declared stream
  transcript lengths, overflow-adjacent values, truncation states, and
  fail-closed behavior using compact fuzz inputs rather than multi-gigabyte
  input files.

### Extended declared-length stream transcript run

Run directory:

```text
/tmp/sar-fuzz-runs/sar-fuzz-20260728-042612
```

Configuration:

```text
Started: 2026-07-28T04:26:12+0200
Ended: 2026-07-28T05:26:15+0200
Target: stream_transcript_declared_lengths
Max total time: 3600 seconds
Max generated input length: 4096 bytes
Build before run: yes
```

Result:

| Target                               |        Runs | Exit | Result              |
| ------------------------------------ | ----------: | ---: | ------------------- |
| `stream_transcript_declared_lengths` | 687,516,528 |    0 | no crash indicators |

Log indicators:

```text
DONE: yes
ERROR: no
panicked at: no
libFuzzer: deadly signal: no
crash artifact marker: no
```

### Extended archive/parser/stream fuzzing campaign

Run directory:

```text
/tmp/sar-fuzz-runs/sar-fuzz-20260728-042757
```

Configuration:

```text
Started: 2026-07-28T04:27:57+0200
Ended: 2026-07-28T05:28:04+0200
Max total time per target: 3600 seconds
Max generated input length: 1048576 bytes
Target count: 10
Build before run: yes
```

Targets:

```text
archive_entry_decode
archive_audit
parse_lfh
parse_cd_footer
parse_tlv
stream_transcript
archive_entry_decode_wide
archive_audit_wide
parse_lfh_wide
parse_tlv_wide
```

Results:

| Target                      |          Runs | Exit | Result              |
| --------------------------- | ------------: | ---: | ------------------- |
| `archive_entry_decode`      |    88,088,598 |    0 | no crash indicators |
| `archive_audit`             |   313,589,475 |    0 | no crash indicators |
| `parse_lfh`                 | 2,431,126,452 |    0 | no crash indicators |
| `parse_cd_footer`           | 1,583,936,157 |    0 | no crash indicators |
| `parse_tlv`                 | 1,116,512,282 |    0 | no crash indicators |
| `stream_transcript`         |   127,634,612 |    0 | no crash indicators |
| `archive_entry_decode_wide` |   131,391,752 |    0 | no crash indicators |
| `archive_audit_wide`        |   297,189,237 |    0 | no crash indicators |
| `parse_lfh_wide`            | 2,399,821,661 |    0 | no crash indicators |
| `parse_tlv_wide`            |   307,015,109 |    0 | no crash indicators |

Total main campaign executions:

```text
8,796,305,335
```

Combined with the declared-length boundary target:

```text
9,483,821,863
```

All targets exited successfully. No run reported `ERROR:`, `panicked at`,
`libFuzzer: deadly signal`, or a crash artifact marker.

### Stateful writer/parser/transport fuzzing campaign

After adding stateful operation-sequence fuzz targets, a six-hour local
overnight campaign was run against the new stateful targets.

This campaign complements the earlier byte-oriented parser, archive, and stream
fuzzing with public-API lifecycle fuzzing for:

* archive writer state transitions;
* forward-only incremental archive parsing;
* in-memory transport/session-facing stream lifecycle behavior.

Run directory:

```text
/tmp/sar-fuzz-runs/sar-fuzz-20260729-000956
```

Configuration:

```text
Started: 2026-07-29T00:09:56+0200
Ended: 2026-07-29T06:09:59+0200
Max total time per target: 21600 seconds
Max generated input length: 1048576 bytes
Target count: 3
Build before run: yes
```

Targets:

```text
archive_writer_state_machine
stream_archive_parser_state_machine
transport_tcp_connection_state_machine
```

Results:

| Target                                  |        Runs | Exit | Result              |
| --------------------------------------- | ----------: | ---: | ------------------- |
| `archive_writer_state_machine`          |  58,325,290 |    0 | no crash indicators |
| `stream_archive_parser_state_machine`   | 905,415,385 |    0 | no crash indicators |
| `transport_tcp_connection_state_machine` | 756,790,652 |    0 | no crash indicators |

Total stateful campaign executions:

```text
1,720,531,327
```

All three targets built successfully and exited successfully. No run reported
`ERROR:`, `panicked at`, `libFuzzer: deadly signal`, or a crash artifact marker.

The stateful fuzz targets exercise:

* `ArchiveWriter` lifecycle behavior using bounded regular-file and sparse-file
  write operations, `stream_state()`, and `finish()`;
* `StreamArchiveParser` push/step/finalize/state transitions with unusual chunk
  boundaries and bounded resource limits;
* `TransportHarness` TCP-policy in-memory open/feed/close/reset/inactivity
  transitions without real sockets, networking, async runtime, or QUIC features.

Direct `SessionManager` fuzzing was not added in this campaign. Session behavior
is exercised indirectly through `sar-transport`'s public `TransportHarness`,
which drives the in-memory transport/session state layer.

### Final M12b.4 result

M12b.4 produced one confirmed fuzz finding:

```text
stream_transcript integer overflow panic
```

The finding was:

* reproduced;
* minimized to the original 62-byte input;
* fixed with checked arithmetic;
* promoted into a normal regression test;
* validated with direct reproduction;
* fuzzed again after the fix;
* followed by extended local boundary, wide-target, and stateful
  operation-sequence fuzzing.

No additional crash indicators were observed in the post-fix M12b.4 fuzzing
passes recorded above.

Recorded post-fix extended campaign executions:

```text
11,204,353,190
```

This total consists of:

* `9,483,821,863` executions from the extended local boundary and
  archive/parser/stream campaigns; and
* `1,720,531,327` executions from the stateful writer/parser/transport campaign.

These numbers are local fuzzing execution counts only. They do not imply
exhaustive coverage, production hardening completion, independent security audit
completion, or malicious corpus completeness.

### Unresolved / deferred work

* Extended malicious corpus work remains deferred to M12b.5.
* Longer scheduled or dedicated fuzzing campaigns remain ongoing
  security-hardening work.
* Additional targeted stateful fuzzing may still be added later for specialized
  profiles, invalid sparse-map generation, transport feature variants, or direct
  session APIs if suitable public APIs are exposed.
* These results do not claim exhaustive parser coverage, production hardening
  completion, independent security audit completion, or malicious corpus
  completeness.
  
## M12b.5 extended malicious corpus and long-running fuzzing

Date: 2026-07-29 through 2026-07-30  
Scope: malicious corpus expansion and targeted local fuzzing for M12b.5  
Status: completed

### PR2 transform pipeline and transform-switching corpus run

After adding the `transform_pipeline_fuzz` target and PR2 transform pipeline /
transform-switching seed archives, a one-hour local campaign was run against the
new target and two existing archive-reader targets.

Run directory:

```text
/tmp/sar-fuzz-runs/sar-fuzz-20260729-205624
```

Configuration:

```text
Started: 2026-07-29T20:56:24+0200
Ended: 2026-07-29T21:56:27+0200
Max total time per target: 3600 seconds
Max generated input length: 1048576 bytes
Target count: 3
Build before run: yes
```

Targets:

```text
transform_pipeline_fuzz
archive_entry_decode
archive_audit
```

Results:

| Target                   |        Runs | Exit | Result              |
| ------------------------ | ----------: | ---: | ------------------- |
| `transform_pipeline_fuzz` | 129,383,564 |    0 | no crash indicators |
| `archive_entry_decode`   | 144,756,628 |    0 | no crash indicators |
| `archive_audit`          | 267,364,313 |    0 | no crash indicators |

Total PR2 campaign executions:

```text
541,504,505
```

All three targets built successfully and exited successfully. No run reported
`ERROR:`, `panicked at`, `libFuzzer: deadly signal`, or a crash artifact marker.

This run covers bounded transform-pipeline and transform-switching corpus
expansion only. It does not claim exhaustive transform coverage, complete
decompression-bomb coverage, production hardening completion, independent
security audit completion, or malicious corpus completeness.

### PR5 extraction-race and profile-rejection corpus status

Date: 2026-07-29  
Scope: M12b.5 PR5 seed additions for `extraction_race` and `profile_rejection`
categories.

PR5 adds hand-authored seed archives covering:

- `extraction_race`: multi-entry path ordering, directory/file collisions,
  duplicate paths, `..` traversal, absolute-path entries, symlink-before-target,
  symlink traversal targets, and unsafe permission ordering.
- `profile_rejection`: global-header version values above the supported maximum,
  reserved-byte violations, and flag conflicts (`NO_INDEX+OPT_PRESENT`,
  `NO_INDEX+HAS_GLOBAL_CRC32`, `HAS_GLOBAL_EC` without `OPT_PRESENT`, `SIGNED`
  without `OPT_PRESENT`, reserved KMS mode IDs, flags_size below minimum).

Seeds were added to `fuzz/seeds/extraction_race/` and
`fuzz/seeds/profile_rejection/`.  Seed shapes were verified to be correctly
structured via the existing `parse_global_header` and `parse_lfh` parsers.

No long-running campaign was run for the PR5 extraction-race/profile-rejection
seed categories in this PR. Longer M12b.5 campaigns covering these categories
remain maintainer-run ongoing hardening work.

These results do not claim exhaustive coverage, production hardening completion,
independent security audit completion, or malicious corpus completeness..

### PR3/PR4 targeted overnight fuzzing campaign

A six-hour parallel local campaign was run against the PR3 and PR4 M12b.5
targets.

Run root:

```text
$HOME/sar-fuzz-runs/m12b5-overnight-20260730-010837
```

Configuration:

```text
Started: 2026-07-30T01:08:37+0200
Ended: 2026-07-30T07:08:40+0200
Max total time per target: 21600 seconds
Targets were run in parallel
Build before run: yes
```

Targets:

| Target | Max generated input length | Runs | Exit | Result |
| --- | ---: | ---: | ---: | --- |
| `archive_logical_files` | 262144 | 327,646,141 | 0 | no crash indicators |
| `crypto_auth_tls_exporter_negative` | 4096 | 201,819,214 | 0 | no crash indicators |
| `pr4_lfh_metadata_edges` | 32768 | 18,522,999,206 | 0 | no crash indicators |
| `pr4_tlv_metadata_edges` | 65536 | 8,600,871,757 | 0 | no crash indicators |

Total campaign executions:

```text
27,653,336,318
```

All four targets built successfully and exited successfully. No run reported
`ERROR:`, `panicked at`, `libFuzzer: deadly signal`, or a crash artifact marker.

This campaign covers targeted PR3/PR4 M12b.5 fuzzing only:

* `crypto_auth_tls_exporter_negative` covers bounded crypto/auth ordering and
  TLS_EXPORTER/AAD negative cases;
* `archive_logical_files` covers bounded logical-file reconstruction and
  lossy/non-lossy archive-reader paths;
* `pr4_lfh_metadata_edges` covers PR4 LFH metadata edge parsing;
* `pr4_tlv_metadata_edges` covers PR4 TLV metadata edge parsing.

This campaign does not claim exhaustive fuzzing, complete malicious corpus
coverage, production hardening completion, independent security audit completion,
certification, compliance, or stable API/ABI guarantees.

### M12b.5 milestone result

M12b.5 is complete as a milestone: the planned malicious corpus taxonomy,
seed-backed corpus categories, PR2 transform-pipeline coverage, PR3
crypto/auth-negative coverage, PR4 metadata/FEC/fragmentation/CDC/delta coverage,
PR5 extraction-race/profile-rejection seed coverage, seed-copy tooling, and
bounded local fuzzing records have been added.

Longer fuzzing remains ongoing security-hardening work and may continue in
parallel with later milestones. Future local, scheduled, or dedicated campaigns
may extend coverage, add new seeds, or promote newly discovered crash inputs into
ordinary regression tests.

This milestone completion does not claim exhaustive fuzzing, complete malicious
corpus coverage, production hardening completion, independent security audit
completion, certification, compliance, or stable API/ABI guarantees.