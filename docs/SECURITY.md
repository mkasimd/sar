# Security Notes

This document reflects current implemented behavior only.

## Unsafe code policy

- All currently audited SAR crates use `#![forbid(unsafe_code)]`.
- Public parsing and validation paths fail closed on malformed, reserved, and unsupported values.

## Resource bounds and allocation limits

- `ArchiveReaderOptions.max_decoded_entry_size` defaults to `1 GiB` and bounds decompression output.
- `sar-compression` enforces a caller-provided maximum decoded size to reduce decompression-bomb risk.
- `sar-fec` bounds parity allocations to `256 MiB` for both XOR and Reed-Solomon helpers.
- KMS parsing enforces conservative limits, including PBKDF2 and Argon2 DoS ceilings.

## Crypto and secret handling

- `SecretBytes` and `SecretString` use zeroizing containers.
- Archives store KMS metadata and wrapped/derived-key parameters, **not** plaintext CEKs.
- `sar-cli` currently writes password-based archives using PBKDF2-HMAC-SHA256 with a random 32-byte salt and 100,000 iterations.
- `ArchiveWriter` tracks nonces per writer instance and fails if it cannot obtain a unique nonce.
- AEAD decryption zeroizes its working plaintext buffer on authentication failure before returning an error.

## Password handling

- `sar-cli create`, `extract`, and `verify` accept `--password`.
- If `--password` is absent where needed, the CLI falls back to `SAR_PASSWORD` and then a terminal prompt.
- `list` and `inspect` do not accept passwords today, so encrypted archives are not fully supported by those commands.

## Authentication, AAD, and release ordering

- Encrypted entry payloads are authenticated before plaintext is released.
- Current AAD binding uses the global-header flag section plus LFH bytes prepared for AEAD.
- When Selective FEC is enabled for an encrypted entry, the AEAD AAD excludes only the FEC size/value region so that ciphertext repair metadata can vary without invalidating the authenticated header contract.
- Wrong passwords fail during AEAD verification before decompression runs.

## FEC and AEAD ordering

Current implemented order is:

```text
stored payload -> FEC repair over ciphertext bytes (if applicable)
               -> AEAD verify/decrypt
               -> decompression / STORE decode
               -> logical payload
```

Notes:

- current writer-side integration computes Selective FEC over ciphertext bytes when encryption is enabled
- archive-level/global EC is validated structurally; `repair_archive` applies XOR/RS repair for block-aligned erasures
- LOSS_TOLERANT flag never bypasses AEAD authentication — if AEAD verification fails, the entry is rejected regardless of the LOSS_TOLERANT setting
- archive-level repair applies FEC repair to ciphertext bytes within the protected range; AEAD tags within that range are repaired before authentication

## Fragmentation and loss-tolerant semantics

- `reconstruct_fragments` fills gap regions in the logical output buffer with zero bytes when LOSS_TOLERANT is set, and sets `is_degraded = true`
- without LOSS_TOLERANT, any missing fragment index returns `FragmentGap` error and no data is released
- AEAD authentication of individual fragment payloads must succeed before plaintext is released, regardless of LOSS_TOLERANT
- LOSS_TOLERANT permits degraded logical file output only for *missing* fragments, not for *corrupted* (authentication-failed) fragments

## Filesystem and parsing safety

- Extraction rejects absolute paths.
- Extraction rejects `..` traversal.
- Parsing uses checked arithmetic for offsets, lengths, header sizes, and region boundaries.
- Unknown assigned-but-unsupported algorithms return SAR unsupported/reserved errors rather than silent fallback.

## Known security limitations

- No signature implementation is present.
- No built-in asymmetric-wrap cryptography is present; application code must provide unwrap behavior.
- `sar-core::profile` is not a complete security/compliance oracle.
- The current CLI has no dedicated encrypted `list` or encrypted `inspect` path because those commands do not accept passwords.
- There is no stable FFI/C ABI yet, so no cross-language ownership guarantees exist.

## Future FFI / C ABI security concerns (Milestone 12)

When a stable ABI is introduced later, security design should explicitly cover:

- ownership across language boundaries
- allocator mismatch and explicit free functions
- zeroization rules for secret buffers returned to or accepted from foreign callers
- avoiding secret leakage in error strings or debug output
- callback safety for key-provider / KMS integration
- thread-safety guarantees for archive and crypto handles
- version negotiation so new ABI fields do not get misinterpreted by older clients

## Future work

- signature support
- fuller interoperability and adversarial corpus testing
- complete archive-level repair orchestration for non-block-aligned erasures (pending spec clarification)
- automatic end-to-end loss-tolerant extraction integration in `ArchiveReader`
- stable FFI/C ABI with explicit status codes, opaque handles, and secret-handling rules
