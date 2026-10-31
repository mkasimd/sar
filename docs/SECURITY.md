<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Security Notes

This document reflects the current security posture of the SAR Rust reference implementation.

SAR is experimental and pre-stable. The implementation has not completed:

* independent external security audit
* production-hardening completion
* certification/compliance activities
* multi-implementation interoperability validation

Bounded local fuzzing campaigns were completed during M12b. Exhaustive fuzzing is not claimed.

Do not use this implementation in environments requiring production-grade security, regulatory assurance, long-term archival guarantees, or security certification.

Related documents:

* `docs/CRATE_RESPONSIBILITIES.md` (implementation policy vs wire-format behavior)
* `docs/COMPATIBILITY.md` (pre-stable compatibility and non-claims)
* `docs/SPEC_QUESTIONS.md` (open questions, including recovery mapping/alignment context)
* `fuzz/README.md`, `fuzz/CORPUS.md`, `fuzz/RUNS.md` (fuzzing coverage and limits)

## Core security posture

The implementation is designed around fail-closed behavior, bounded parsing, and explicit transform ordering.

Trust boundaries: unless the caller has out-of-band trust, all of the following are treated as untrusted/attacker-controlled:

* archive bytes and stream transcript bytes
* LFH/TLV metadata, transform metadata (compression/FEC/CDC/delta/sparse), and recovery erasure descriptions
* filesystem metadata carried in archive entries
* extraction destination filesystem state (existing files, symlinks, permissions, ownership)

Malformed untrusted input must fail closed. A panic on malformed untrusted input is treated as a bug.

Current defensive assumptions include attackers attempting to:

* trigger parser confusion via malformed, reserved, ambiguous, or unsupported values
* force oversized allocation or expansion via compressed payloads, sparse/fragment metadata, or repair metadata
* trigger transform-ordering mistakes around recovery/FEC/decrypt/decompress/patch/sparse phases
* bypass authentication or integrity checks to obtain plaintext or accepted corrupted output
* exploit extraction path traversal or metadata restoration hazards during CLI extraction

Current implemented protections include:

* parsing/listing/inspection APIs remain side-effect-free
* filesystem mutation is limited to explicit CLI extraction paths
* input validation fails closed for malformed, reserved, unsupported, ambiguous, or conflicting values
* resource limits are enforced before dangerous allocation or expansion paths
* checked arithmetic and checked conversions are used in parser and reconstruction paths
* AEAD authentication failures do not release plaintext
* loss-tolerant behavior does not bypass authentication, decompression, patch, sparse, fragment, or structural validation
* archive repair works on explicit erasure descriptions and does not guess missing ranges
* secret-buffer and key-provider APIs remain in `sar-crypto`
* raw keying material is not exposed through public documentation/API contracts

## CLI extraction policy and filesystem mutation boundaries

Library parsing/listing/verification/audit paths remain side-effect-free. Filesystem mutation is CLI/application policy, not SAR wire-format behavior.

Safe extraction defaults are enabled for current CLI extraction paths.

Extraction lexically rejects:

* absolute paths
* `..` traversal components
* empty path components
* `.` components
* Windows drive-prefix forms
* UNC/verbatim-style forms
* backslash usage in archive paths
* NUL-byte usage in archive paths

Extraction rejects per-component symlink traversal while resolving destination paths. On Unix this is enforced with descriptor-relative `O_NOFOLLOW` traversal rather than lexical checks; escapes and unconfinable paths report `SAR_ERR_PATH_ESCAPE`.

Symlink extraction is disabled unless `--allow-symlinks` is provided. Even when enabled, a relative symlink target is evaluated lexically from the link directory and must not escape the extraction root, an absolute or platform-specific target outside the root is refused with `SAR_ERR_PATH_ESCAPE`, and stored targets are never rewritten.

Hardlink/device/FIFO/socket extraction behavior is not provided as a general CLI restore path in the current implementation.

## Extraction staging and mutation safety

Extraction creates directories with restrictive staging permissions (mode `0700`, never group- or world-accessible while created).

Final directory permissions are applied only after child entries are extracted.

Regular/sparse extraction uses temporary files with exclusive creation and atomic-style finalization behavior.

Metadata is applied through open directory or file descriptors; paths are not re-resolved.

Extraction is fail-fast and not all-or-nothing, and there is no crash-recovery journal; see `docs/CONFORMANCE.md` for the failure and cleanup contract.

Targets without `cfg(unix)` (including Windows) have no secure extraction backend and refuse `sar extract` with `SAR_ERR_PATH_ESCAPE` before any filesystem access. Native runtime evidence exists for Linux (and the Package A backend on FreeBSD 15.1); macOS is unverified.

## Filesystem metadata policy

Metadata restoration is explicit, opt-in, and implementation-policy-gated.

* `--preserve-permissions`, `--preserve-owner`, and `--preserve-times` are opt-in.
* UID/GID restoration is disabled by default.
* Setuid/setgid/sticky bits are stripped even when permissions are preserved.
* Timestamp restoration is disabled by default.
* Platform-specific metadata restoration is best-effort and explicitly policy-gated.

Risk notes when metadata restoration is opted in:

* permission restoration may reintroduce broad file modes if operators opt in
* UID/GID restoration can map differently across hosts and privilege models
* timestamp restoration can affect forensic or ordering assumptions in downstream workflows
* symlink restoration can create follow-on risk if extracted trees are later consumed by privileged tooling
* platform-specific metadata behavior is best-effort and may differ by host OS/filesystem

## Archive audit mode

`sar-archive` exposes archive audit APIs for deterministic structural reporting and payload verification status.

Default archive parsing remains strict. Entries with `SESSION_CONTROL` set or nonzero `OP_CODE` are rejected by default.

Explicit inert audit mode can structurally report such entries, but it does not execute stream/session/opcode semantics and does not extract inert payloads as archive files.

Stream transcript semantic validation belongs to `sar-stream`, not `sar-archive`.

## Recovery API and repair limitations

Current archive-level recovery APIs are bounded in-memory APIs over complete archive byte slices.

Current limitations and policy boundaries:

* callers provide `ResourceLimits`; limits are enforced before repair working-set expansion
* streaming repair and external-storage-backed repair remain future work
* explicit block-aligned erasure requirements are current implementation policy tied to open spec questions, not a universal SAR v1.0 wire-format rule
* repair output should be written to a temporary file and renamed only after structural verification
* recovery availability does not imply authenticity; verification/authentication must still succeed

See `docs/API.md`, `docs/CRATE_RESPONSIBILITIES.md`, and `docs/SPEC_QUESTIONS.md` for current API and policy details.

## Current limitations and threat-model notes

* no independent external security audit has completed
* production-hardening completion is planned in M13 and is not yet complete
* M12b bounded local fuzzing is complete, but exhaustive fuzzing and malicious corpus completeness are not claimed
* CLI extraction on Unix uses a descriptor-relative confinement backend; it is runtime-tested on Linux (FreeBSD 15.1 for the Package A backend), macOS is unverified, and non-Unix targets refuse extraction. staging symlink identities are pinned with a path-only descriptor (Linux, Android, FreeBSD) because an unpinned identity can be reused by a substituted object on inode-recycling filesystems (PR #104), and where a symlink cannot be pinned its temporary name is left unresolved and reported rather than removed; POSIX check/use races remain where atomic identity operations are unavailable
* the `repair` command on Unix stages its output exclusively under a random name in the output's parent directory (descriptor-relative, no symlink following), verifies it through the staged descriptor and publishes it by rename; a narrow POSIX check/use window remains between the staging identity check and the rename or cleanup unlink, there is no crash recovery, and non-Unix targets refuse the repair output operation (`M13-EXTRACT-007`, resolved; staging and permissions-probe cleanup are identity-checked through held descriptors, the original error is preserved and unresolved cleanup is reported separately, there is no transactional guarantee, and native macOS/Windows and targeted FreeBSD runtime are unverified)
* extraction into attacker-writable directories is not recommended
* metadata restoration can create platform-dependent risk; see the Filesystem metadata policy section above
* the implementation has not demonstrated multi-implementation interoperability

## Reporting security issues

Do not open public issues containing exploit details or sensitive vulnerability information.

If the repository has private vulnerability reporting enabled, use that mechanism. Otherwise, open a minimal public issue asking for a private security contact without including exploit details.

Please include, privately where possible:

* affected component
* reproduction steps
* expected impact
* whether the issue affects parsing, extraction, crypto/authentication, transport/session behavior, or resource exhaustion
* whether the issue requires malicious input, malformed archives, hostile filesystem state, or network interaction

## M13 audit findings

The M13a.1 parser, memory, panic, and DoS audit is complete. The authoritative
machine-readable findings registry is
`docs/machine-readable/M13_AUDIT_FINDINGS.json`. The generated human-readable
report is `docs/M13_AUDIT_FINDINGS.md`.

## Future security work

Planned future work includes:

* M13 internal security audit and remediation work (parser/memory/DoS, crypto/secret handling, transform/resource accounting, extraction/metadata safety, crate/profile boundaries)
* M14+ profile and binding security-policy work may define default-deny unsupported/custom feature handling, privileged/unprivileged extraction policies, helper-process isolation expectations, and binding-specific security expectations (C ABI, Python, mobile); no stable profile/API/ABI contract is claimed today
* continued fuzzing and negative testing as ongoing hardening work
