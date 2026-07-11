# Conformance Profile (M1–M11)

This document describes **reference implementation coverage** and **known gaps** after M11e.

This is an **implemented profile** report, not a claim of full standard conformance.

## Implemented profile coverage

### Archive structure and indexing
- Global Header, LFH, Central Dictionary, Footer parsing/writing.
- Indexed archives and `NO_INDEX` archive flows.
- Fail-closed validation for malformed, reserved, and unsupported values.

### Transform pipeline and compression
- Transform ordering enforcement in high-level archive paths.
- Compression algorithms: `STORE`, `DEFLATE`, `ZSTD`.
- Bounded decode/transform memory via `ResourceLimits`.

### Crypto / KMS / authentication
- Hash support used by current implementation profiles (`SHA-256`, `BLAKE3`).
- AEAD support (`AES-256-GCM`, `XChaCha20-Poly1305`).
- KMS parsing/validation for implemented modes.
- Password-based encryption/decryption flows in CLI create/extract/verify.
- AEAD authentication enforced before plaintext release.

### FEC and recovery
- Selective FEC metadata handling and validation.
- XOR and Reed-Solomon file-level FEC support.
- Archive-level recovery metadata inspection/planning/repair for currently supported cases.

### Sparse, fragmentation, and loss-tolerant behavior
- Sparse map parse/write, validation, and bounded reconstruction.
- Fragment group validation and reassembly.
- `LOSS_TOLERANT` degraded-output behavior for missing-fragment cases only.
- Authentication/structural failures are never bypassed by lossy flags.

### CDC and delta
- CDC metadata/TLV structures and current CDC map handling.
- Delta metadata parsing and patch application for implemented algorithms (`STORE_PATCH`, `VCDIFF`, SAR BSDIFF v1).

### Streaming/session and transport
- Streaming parser/state model and session semantics (`sar-stream`).
- SAR-over-TCP and SAR-over-QUIC transport bindings (`sar-transport`) in current implemented profile.

### Metadata API and filesystem metadata
- LFH metadata API completeness from M11a/M11b.
- Filesystem metadata decode/encode coverage in archive APIs.
- Metadata surface includes permissions, owner, timestamps, hidden attribute, and symlink target where present.

### CLI metadata behavior (M11e)
- `sar create --preserve-permissions`
- `sar create --preserve-owner`
- `sar create --preserve-times`
- `sar create --symlinks skip|follow|archive`
- `sar extract --preserve-permissions`
- `sar extract --preserve-times`
- `sar extract --preserve-owner`
- `sar extract --allow-symlinks`
- `sar list --metadata`
- `sar inspect --json` metadata-rich output

## Known gaps

- This repository is **not yet a complete conformance suite**.
- Cross-implementation official vectors and full malicious corpus are not yet complete (M12 scope).
- Full signature implementation/audit posture remains future work.
- Some algorithms are structurally represented but intentionally unsupported in the implemented profile.
- Delta/base-hash algorithm signaling remains limited by current spec ambiguity handling.
- Profile validation helpers are useful but are not a complete standalone conformance oracle.
- Platform-specific metadata restoration behavior remains policy-gated and best-effort where supported.
- No stable C ABI/Python/mobile binding surface is implemented in M1–M11 (future milestones).

## Milestone alignment (future)

- M12: conformance vectors, fuzzing/malicious corpus, docs/security posture hardening.
- M13: security audit and remediation.
- M14: C ABI and Python module.
- M15: packaging and release automation.
- M16: Swift/iOS and Kotlin/Java Android packages.
