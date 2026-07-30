<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Security Notes

This document reflects the current security posture of the SAR Rust reference implementation.

SAR is experimental and pre-stable. The implementation has not yet completed long-term fuzzing, independent security audit, production hardening, or multi-implementation interoperability validation.

Do not use this implementation in environments requiring production-grade security, regulatory assurance, long-term archival guarantees, or security certification.

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

## Safe extraction defaults and path safety

Safe extraction defaults are enabled for CLI extraction paths.

Extraction lexically rejects:

* absolute paths
* parent-directory traversal (`..`)
* empty/current-directory components
* Windows drive prefixes
* UNC/verbatim-style paths

Extraction rejects per-component symlink traversal while resolving destination paths.

Symlink extraction is disabled unless `--allow-symlinks` is provided. Even when enabled, symlink targets must be relative and non-traversing.

## Extraction staging and mutation safety

Extraction creates directories with restrictive staging permissions.

Final directory permissions are applied only after child entries are extracted.

Regular/sparse extraction uses temporary files with exclusive creation and atomic-style finalization behavior.

Metadata application re-checks final path type before applying filesystem metadata.

## Filesystem metadata policy

Metadata restoration is explicit and policy-gated.

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

## Current limitations and threat-model notes

The implementation is not yet independently audited.

M12b fuzzing passes are documented in `fuzz/README.md`, `fuzz/CORPUS.md`, and
`fuzz/RUNS.md`, but fuzzing remains non-exhaustive and ongoing.

CLI extraction currently uses stable lexical/per-component validation and symlink checks. It is not yet a fully `openat`/directory-fd confinement engine on every platform.

Extraction into attacker-writable directories is not recommended.

The implementation has not demonstrated multi-implementation interoperability.

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

* M12b fuzzing and malicious-corpus expansion
* M12c documentation/API/security posture hardening
* M13 security audit and remediation
* M14 C ABI / Python binding security profile work
* M15/M16 packaging and mobile binding hardening
