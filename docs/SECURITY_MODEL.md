<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR Security Model (Current Implementation)

This document describes the current security model for the SAR Rust reference implementation. It documents current behavior and limits; it does not define new SAR wire-format rules.

`specification.md` remains authoritative for SAR v1.0 wire-format behavior, validation rules, transform ordering, streaming/session semantics, and transport bindings.

## Scope and trust boundaries

### Trusted inputs/components

Trusted behavior is assumed only for:

* this implementation's compiled code paths
* explicit caller configuration such as `ResourceLimits`
* local policy choices made by the operator/application

### Untrusted inputs

Treat all of the following as attacker-controlled unless the caller has out-of-band trust:

* archive bytes
* stream transcript bytes
* LFH/TLV metadata fields
* compression/FEC/CDC/delta/sparse metadata values
* recovery erasure descriptions
* filesystem metadata carried in archive entries
* extraction destination filesystem state (existing files, symlinks, permissions, ownership)

## Attacker model (malformed archive focus)

Current defensive assumptions include attackers attempting to:

* trigger parser confusion through malformed, reserved, ambiguous, or unsupported values
* force oversized allocation/expansion via compressed payloads, sparse/fragment metadata, or repair metadata
* trigger transform-ordering mistakes around recovery/FEC/decrypt/decompress/patch/sparse phases
* bypass authentication/integrity checks to obtain plaintext or accepted corrupted output
* exploit extraction path traversal or metadata restoration hazards during CLI extraction

## Current security expectations

### Fail-closed parsing and validation

Current parsing behavior is expected to fail closed for malformed, reserved, unsupported, conflicting, overflowing, or ambiguous input.

A panic on malformed untrusted input is treated as a bug.

### Authentication and integrity handling

AEAD/tag validation must succeed before plaintext is released to callers. Authentication failure is fatal for the affected entry/path and is not bypassed by loss-tolerant controls.

Recovery/repair APIs and CLI `repair` can reconstruct bytes structurally, but authenticity still depends on successful verification/authentication after reconstruction.

### Transform ordering constraints (current behavior)

Current implementation and documentation enforce explicit ordering constraints. Security-relevant points include:

* authentication failure blocks plaintext release
* decompression/patch/sparse reconstruction do not bypass authentication outcomes
* recovery/FEC handling is bounded by limits and remains subject to structural/authentication verification rules

For normative protocol behavior, follow `specification.md`.

### Resource-limit model

`ResourceLimits` is the primary control plane for resource exhaustion defense in parsing, transform handling, sparse/fragment reconstruction, and recovery planning/execution.

Limits are enforced before dangerous allocation or expansion paths. Limit values are implementation policy, not universal SAR v1.0 wire-format requirements.

## Library vs CLI behavior

Library parsing/listing/inspection/verification/audit APIs are designed to remain side-effect-free.

Filesystem mutation is an explicit CLI/application policy surface (for example, extraction and repaired-output file writes). See `docs/CLI_SECURITY.md` for extraction policy and metadata restoration limits.

## Out of scope today

This implementation does not currently claim:

* independent external security audit completion
* production-readiness or production-hardening completion
* certification/compliance status
* stable API/ABI/profile contract guarantees
* demonstrated multi-implementation interoperability

## Planned work and deferred areas

* M13: internal audit and remediation work (parser/memory/DoS, crypto/secret handling, resource accounting, extraction/metadata safety, crate/profile boundaries)
* M14+: profile-policy and binding-security design (C ABI, Python, mobile), including security-profile behavior documentation

Open design/spec questions remain tracked in `docs/SPEC_QUESTIONS.md`; this document does not resolve them.
