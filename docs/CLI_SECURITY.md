<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# CLI Security Behavior (Current Implementation)

This document describes current `sar-cli` security-relevant behavior. These behaviors are implementation policy and must not be interpreted as universal SAR v1.0 wire-format requirements.

## Extraction path policy

Current extraction validates archive paths before filesystem mutation and rejects:

* absolute paths
* `..` traversal components
* empty path components
* `.` components
* Windows drive-prefix forms
* UNC/verbatim-style forms
* backslash and NUL-byte usage in archive paths

Current extraction path resolution also rejects traversal through existing symlink path components while building destination parent directories.

## Entry-kind handling and default safety posture

Current extraction behavior:

* regular files: extracted through temporary-file staging and final rename
* directories: created with restrictive staging permissions before final metadata application
* symlinks: rejected unless `--allow-symlinks` is explicitly set

When symlink extraction is enabled, symlink target metadata is validated as a safe relative path (no absolute or `..` traversal target).

No general hardlink restoration path is currently exposed in `sar-cli` extraction behavior.

## Metadata restoration policy and risks

Metadata restoration is opt-in and policy-gated:

* `--preserve-permissions`
* `--preserve-owner`
* `--preserve-times`

Current risk notes:

* permission restoration may reintroduce overly broad file modes if operators opt in
* owner restoration (`uid/gid`) can map differently across hosts and privilege models
* timestamp restoration can affect forensic/ordering assumptions in downstream workflows
* symlink restoration can create follow-on risk if extracted trees are later consumed by privileged tooling
* platform-specific metadata behavior is best-effort and may differ by host OS/filesystem

Current safeguards:

* owner restoration is disabled by default
* timestamps are disabled by default
* setuid/setgid/sticky bits are stripped even when permissions are preserved
* metadata application re-checks path type and avoids applying file metadata through symlink paths

Metadata restoration remains CLI/profile policy, not a base SAR wire-format requirement.

## Replacement and ordering hazards

Current extraction refuses replacement of existing directories with file/symlink output at target paths and applies final directory metadata after child extraction to reduce unsafe ordering effects.

Extraction into attacker-writable directories remains a known risk and is not recommended.

## Repair command behavior

`sar repair` currently:

* operates over in-memory archive bytes read with configured `ResourceLimits`
* requires explicit erasure descriptions
* writes repaired output to a temporary file
* verifies structure/authentication via normal archive verification flow before rename

Recovery availability alone does not imply trustworthy output; verification/authentication must still succeed.

## Known limitations

* current path-safety implementation is lexical/per-component plus symlink checks, not a full cross-platform directory-fd/openat confinement engine
* platform-specific metadata and symlink behavior can vary
* streaming repair and external-storage-backed repair are future work

See also:

* `docs/SECURITY.md`
* `docs/SECURITY_MODEL.md`
* `docs/CRATE_RESPONSIBILITIES.md`
* `docs/API.md`
* `docs/SPEC_QUESTIONS.md`
