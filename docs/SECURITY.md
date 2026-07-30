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

* `docs/SECURITY_MODEL.md` (threat model and scope boundaries)
* `docs/CLI_SECURITY.md` (CLI extraction and metadata restoration policy)
* `docs/CRATE_RESPONSIBILITIES.md` (implementation policy vs wire-format behavior)
* `docs/COMPATIBILITY.md` (pre-stable compatibility and non-claims)
* `docs/SPEC_QUESTIONS.md` (open questions, including recovery mapping/alignment context)
* `fuzz/README.md`, `fuzz/CORPUS.md`, `fuzz/RUNS.md` (fuzzing coverage and limits)

## Core security posture

The implementation is designed around fail-closed behavior, bounded parsing, and explicit transform ordering.

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

See `docs/SECURITY_MODEL.md` for trusted/untrusted input boundaries, attacker model, parser panic expectations, authentication handling, and ordering constraints.

## CLI extraction policy and filesystem mutation boundaries

Library parsing/listing/verification/audit paths remain side-effect-free. Filesystem mutation is CLI/application policy, not SAR wire-format behavior.

Safe extraction defaults are enabled for current CLI extraction paths.

Extraction lexically rejects:

* absolute paths
* parent-directory traversal (`..`)
* empty/current-directory components
* Windows drive prefixes
* UNC/verbatim-style paths

Extraction rejects per-component symlink traversal while resolving destination paths.

Symlink extraction is disabled unless `--allow-symlinks` is provided. Even when enabled, symlink targets must be relative and non-traversing.

Hardlink/device/FIFO/socket extraction behavior is not provided as a general CLI restore path in the current implementation.

See `docs/CLI_SECURITY.md` for extraction-path policy details, platform-specific behavior notes, and known limitations.

## Extraction staging and mutation safety

Extraction creates directories with restrictive staging permissions.

Final directory permissions are applied only after child entries are extracted.

Regular/sparse extraction uses temporary files with exclusive creation and atomic-style finalization behavior.

Metadata application re-checks final path type before applying filesystem metadata.

## Filesystem metadata policy

Metadata restoration is explicit, opt-in, and implementation-policy-gated.

* `--preserve-permissions`, `--preserve-owner`, and `--preserve-times` are opt-in.
* UID/GID restoration is disabled by default.
* Setuid/setgid/sticky bits are stripped even when permissions are preserved.
* Timestamp restoration is disabled by default.
* Platform-specific metadata restoration is best-effort and explicitly policy-gated.

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
* CLI extraction currently uses lexical/per-component validation and symlink checks, but is not yet a full `openat`/directory-fd confinement engine on every platform
* extraction into attacker-writable directories is not recommended
* metadata restoration can create platform-dependent risk; see `docs/CLI_SECURITY.md`
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

## Future security work

Planned future work includes:

* M13 internal security audit and remediation work (parser/memory/DoS, crypto/secret handling, transform/resource accounting, extraction/metadata safety, crate/profile boundaries)
* M14+ profile and binding security-policy design (C ABI, Python, mobile) without claiming stable API/ABI/profile contracts yet
* continued fuzzing and negative testing as ongoing hardening work
