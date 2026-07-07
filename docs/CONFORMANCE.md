# Conformance Statement

## Implemented now

- Global header parsing/writing with required fields and flag validation.
- Partition descriptor structural parsing/writing.
- LFH deterministic parsing/writing based on global flags.
- Header-size and bounds validation logic.
- Central Dictionary + Footer parsing/writing for minimal indexed archives.
- TLV parsing/writing with 8-byte alignment and zero-padding checks.
- Archive reader/writer with compression support for `NO_INDEX` and indexed modes.
  - STORE (`0x00`)
  - DEFLATE (`0x01`)
  - ZSTD (`0x02`)
- Archive reader/writer with AEAD encryption support.
  - AES-256-GCM (`0x01`)
  - XChaCha20-Poly1305 (`0x04`)
- KMS parsing and CEK resolution support.
  - PBKDF2-HMAC-SHA256 (`0x01`)
  - Argon2id (`0x02`)
  - ASYMMETRIC_WRAP structural parsing and external unwrap hooks (`0x03`)
- Hashing support.
  - SHA-256 (`0x30`)
  - BLAKE3 (`0x31`)
- CLI create/extract/verify flows with password-based encryption.
- Full Section 10 status/error/warning registry values in `sar-core`.
- PR-only CI workflow (`on: pull_request`) for fmt/clippy/tests.

## Partial

- Signed-archive anchor validation checks (`SIGNED` requires metadata and `DATA_HASH` presence during verify), but no signature cryptography.
- ASYMMETRIC_WRAP depends on application-provided unwrap logic; no built-in RSA-OAEP/ECIES implementation yet.
- CD metadata TLV parsing for accepted implemented type ranges only.

## Unsupported (explicitly rejected)

- SHA3-256 hashing.
- Assigned but unimplemented encryption IDs such as ChaCha20, AES-CBC, and ChaCha20-Poly1305.
- FEC decode/repair, CDC resolution, delta patch execution.
- Sparse reconstruction, fragmentation reassembly, lossy modes.
- Streaming session protocol and transport layers.

## Planned

Milestones 6–11 per roadmap in `specification.md`.
