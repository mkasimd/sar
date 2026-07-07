# Security Notes (Milestones 1–5)

## Core guarantees

- `unsafe` is forbidden across SAR crates (`#![forbid(unsafe_code)]`).
- Parsers fail closed on malformed, reserved, or unsupported values.
- Checked arithmetic guards offsets, lengths, sizes, and archive-region boundaries.
- Extraction rejects absolute paths and `..` traversal.
- Decompression is bounded by `ArchiveReaderOptions.max_decoded_entry_size`.
- AEAD authentication happens **before** decompression for encrypted entries.

## Crypto scope in Milestone 5

Implemented in `sar-crypto` and integrated into `sar-core`/`sar-cli`:

- Hashing:
  - SHA-256 (`0x30`)
  - BLAKE3 (`0x31`)
- AEAD:
  - AES-256-GCM (`0x01`)
  - XChaCha20-Poly1305 (`0x04`)
- KMS/password modes:
  - PBKDF2-HMAC-SHA256 (`0x01`)
  - Argon2id (`0x02`)
  - ASYMMETRIC_WRAP structural model/hooks (`0x03`)

Assigned-but-unimplemented algorithms return SAR unsupported/reserved errors.

## Key handling

- Content-encryption keys use `SecretBytes = Zeroizing<Vec<u8>>` and are cleared on drop.
- Passwords use `SecretString = Zeroizing<String>`.
- Archives never store plaintext CEKs.
- CEKs are resolved externally through the `KeyProvider` trait.
- `sar-cli` currently writes password-protected archives with PBKDF2-HMAC-SHA256 and a random 32-byte salt.

## KDF policy

Conservative minimums are enforced while parsing and deriving keys:

- PBKDF2 salt length >= 16 bytes
- PBKDF2 iterations >= 100,000
- Argon2id salt length >= 16 bytes
- Argon2id memory >= 64 MiB
- Argon2id output length = 32 bytes

DoS ceilings are also enforced for PBKDF2 iterations and Argon2 memory/time/parallelism values.

## AEAD / nonce policy

- AES-256-GCM uses the first 12 bytes of the on-wire 24-byte nonce field; bytes `12..24` must be zero.
- XChaCha20-Poly1305 uses all 24 bytes.
- `ArchiveWriter` tracks nonces per session and fails on detected reuse.
- Authentication failures map to `SAR_ERR_AUTH_FAILED`.

## Operational notes

- Listing/inspection of encrypted archives may require keys if entry decoding is attempted.
- Wrong passwords fail during AEAD verification before any plaintext reaches the decompressor.
- Future milestones will extend signatures, asymmetric wrapping implementations, and recovery features; unsupported modes fail closed today.
