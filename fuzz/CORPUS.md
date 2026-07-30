<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Fuzz corpus coverage and limitations (M12c.1)

This file summarizes current corpus scope for SAR fuzzing and documents explicit limits.

For execution logs and run counts, see [`RUNS.md`](RUNS.md).  
For harness coverage and local workflow details, see [`README.md`](README.md).

## Current high-level coverage

Current committed harnesses and seed inputs cover:

* parser targets (`parse_global_header`, `parse_lfh`, `parse_tlv`, `parse_cd_footer`);
* archive reader/audit targets (`archive_structural`, `archive_entry_decode`, `archive_audit`, and wide variants);
* stream transcript/stateful targets (`stream_transcript`, `stream_transcript_declared_lengths`, `archive_writer_state_machine`, `stream_archive_parser_state_machine`, `transport_tcp_connection_state_machine`).

## M12b.5 malicious corpus category tracking

The M12b.5 category list tracked in `docs/MILESTONES.md` includes expansion areas such as:

* transform pipeline and transform-switching DoS inputs;
* crypto/auth ordering and TLS_EXPORTER/AAD negative inputs;
* decompression bomb and allocator-churn inputs;
* FEC/fragmentation, CDC/delta, stream/session, metadata edge-case, and malformed filesystem metadata inputs;
* extraction-race and profile-specific rejection inputs.

These categories are tracking targets for ongoing hardening work and must not be interpreted as exhaustively complete.

## Campaign references

* PR3/PR4 targeted overnight campaigns are represented by the recorded overnight/extended local campaigns in `RUNS.md` and should be read as bounded development-time runs, not exhaustive proof.
* PR5 seed-backed extraction/profile-rejection categories are tracked as malicious-corpus expansion areas; they are not a claim that every extraction/profile-rejection class is fully fuzzed.

## Limitations and non-claims

* Fuzzing is not exhaustive.
* No independent security audit completion is claimed.
* Future campaigns may continue in parallel with development.
* Generated corpora/artifacts (`fuzz/corpus/**`, `fuzz/artifacts/**`, `fuzz/target/**`) are not committed.
