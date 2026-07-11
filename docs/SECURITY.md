# Security Notes (post-M11e)

This document reflects current implemented behavior only.

## Core security posture
- Parsing/listing/inspection APIs remain side-effect-free.
- Filesystem mutation is limited to explicit CLI extraction paths.
- Input validation is fail-closed for malformed, reserved, unsupported, or ambiguous values.
- Resource limits are enforced before dangerous allocation/expansion.

## Safe extraction defaults and path safety
- Safe extraction defaults are on; metadata restoration and symlink extraction are opt-in.
- Extraction lexically rejects:
  - absolute paths,
  - parent-directory traversal (`..`),
  - empty/current-directory components,
  - Windows drive prefixes,
  - UNC/verbatim-style paths.
- Extraction rejects per-component symlink traversal while resolving destination paths.
- Symlink extraction is disabled unless `--allow-symlinks` is provided.
- Even when enabled, symlink targets must be relative and non-traversing.

## Extraction staging and mutation safety
- Extraction creates directories with restrictive staging permissions.
- Final directory permissions are applied only after children are extracted.
- Regular/sparse extraction uses temp files with exclusive creation and atomic-style finalization behavior.
- Metadata application re-checks final path type before applying filesystem metadata.

## Filesystem metadata policy (M11e)
- `--preserve-permissions`, `--preserve-owner`, and `--preserve-times` are opt-in.
- UID/GID restoration is disabled by default.
- Setuid/setgid/sticky bits are stripped even when permissions are preserved.
- Timestamp restoration is disabled by default.
- Platform-specific metadata restoration is best-effort and explicitly policy-gated.

## Current limitation and threat-model note
- CLI extraction currently uses stable lexical/per-component validation and symlink checks.
- It is not yet a fully `openat`/directory-fd confinement engine on every platform.
- Extraction into attacker-writable directories is not recommended.

## Additional implemented protections
- AEAD authentication failures do not release plaintext.
- Loss-tolerant behavior does not bypass authentication or structural validation.
- Secret-buffer/key-provider APIs remain in `sar-crypto`; raw keying material is not surfaced through docs/API contracts.

## Future milestones
- M12: conformance vectors, fuzzing/malicious corpus, docs/security posture hardening.
- M13: security audit and remediation.
- M14: stable C ABI and Python module security profile work.
