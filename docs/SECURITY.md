# Security Notes

This document reflects current implemented behavior only.

## Unsafe code policy

- All currently audited SAR crates use `#![forbid(unsafe_code)]`.
- Public parsing and validation paths fail closed on malformed, reserved, and unsupported values.

## Resource bounds and allocation limits

- `ArchiveReaderOptions` now carries a unified `ResourceLimits` struct; configured limits are the primary safety mechanism for parsing untrusted archives.
- `ResourceLimits::default()` applies conservative caps to archive size, entry count, LFH header bytes, path bytes, TLV bytes/count, Central Dictionary bytes, sparse maps, fragment groups, FEC value bytes, recovery protected ranges, and repair working buffers.
- `ArchiveReaderOptions.limits.max_decoded_entry_size` defaults to `1 GiB` and bounds decompression output.
- `sar-compression` enforces a caller-provided maximum decoded size to reduce decompression-bomb risk.
- `sar-fec` bounds parity allocations to `256 MiB` for both XOR and Reed-Solomon helpers.
- Parsing rejects configured-limit violations before dangerous allocation and returns `SAR_ERR_LIMIT_EXCEEDED`.
- `sar-cli extract`, `verify`, and `repair` use the same `ResourceLimits` model as the library and expose override flags for the relevant limits.
- CLI resource-limit failures are reported explicitly as `resource-limit error (SAR_ERR_LIMIT_EXCEEDED)`.
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
- archive-level/global EC is validated structurally; `repair_archive` applies XOR/RS repair for block-aligned erasures while enforcing `max_recovery_protected_range` and `max_repair_working_set`
- LOSS_TOLERANT flag never bypasses AEAD authentication — if AEAD verification fails, the entry is rejected regardless of the LOSS_TOLERANT setting
- archive-level repair applies FEC repair to ciphertext bytes within the protected range; AEAD tags within that range are repaired before authentication

## Fragmentation and loss-tolerant semantics

- `reconstruct_fragments` fills gap regions in the logical output buffer with zero bytes when LOSS_TOLERANT is set, and sets `is_degraded = true`
- loss-tolerant fragment gaps are bounded by `ResourceLimits.max_loss_tolerant_gap`
- without LOSS_TOLERANT, any missing fragment index returns `FragmentGap` error and no data is released
- AEAD authentication of individual fragment payloads must succeed before plaintext is released, regardless of LOSS_TOLERANT
- LOSS_TOLERANT permits degraded logical file output only for *missing* fragments, not for *corrupted* (authentication-failed) fragments

## Pipeline memory accounting and expansion-bomb protection (Stage 3)

In-memory reconstruction and transformation pipelines enforce `ResourceLimits`
**before** allocating any intermediate buffer.  The effective limit is:

```text
effective_limit = min(
    max_decoded_entry_size,
    max_in_memory_buffer,
    max_total_pipeline_memory
)
```

Configured limits are the primary and deterministic protection mechanism.

**Runtime memory budget is not implemented by design**; configured
`ResourceLimits` are the deterministic protection.

### Sparse expansion-bomb protection

The attack shape is:

```text
tiny stored payload  +  huge Uncompressed Size  +  sparse extent near end
```

For example:
- `Uncompressed Size = 1025`, `max_decoded_entry_size = 1024`
- Sparse Map: `{offset = 1024, length = 1}`
- Stored Payload: one byte

In-memory APIs (`ArchiveReader::read_all_logical_files`,
`apply_sparse_reconstruction`) **reject this before allocation**.  They do not
attempt `vec![0u8; Uncompressed Size]`.  The error is `SAR_ERR_LIMIT_EXCEEDED`
(`SarError::LimitExceeded`), not `SAR_ERR_INVALID_MAP` (the sparse map is
structurally valid).

The same protection applies to:
- fragmented sparse entries (logical size from fragment-0's `Uncompressed Size`)
- non-sparse entries (raw payload size, decompressed output size)
- fragment group span (`max_fragment_group_span`)
- loss-tolerant gap fills (`max_loss_tolerant_gap`)
- FEC / recovery working sets (`max_repair_working_set`)

### Pipeline buffers accounted before allocation

Before allocating intermediate buffers the implementation checks:
- raw payload buffer
- decrypted payload buffer (if encrypted)
- decompressed payload buffer (if compressed)
- fragment reassembly buffer
- sparse reconstructed output buffer
- FEC parity / recovery working buffer

Each buffer is checked individually and no `u64 → usize` conversion occurs
without a checked path through `ResourceLimits::allocation_len`.

## Sparse file reconstruction security

- Sparse reconstruction occurs **after** fragment reassembly, AEAD authentication (decryption), and decompression. It never runs on unauthenticated or still-encrypted bytes.
- Sparse descriptor arithmetic uses checked arithmetic; overflow in `offset + length` or an extent exceeding `Uncompressed Size` returns `SarError::InvalidMap`.
- Overlapping descriptors are rejected before reconstruction begins.
- Sparse payload length is validated: it must exactly equal the sum of all extent lengths. Excess bytes (possible padding forgery) and short payload (truncated payload) both return an error.
- The zero-filled reconstruction buffer is bounded by `ArchiveReaderOptions.limits.max_decoded_entry_size` and the general in-memory allocation limits to prevent denial-of-service via large `Uncompressed Size` values.  **The implementation never allocates `vec![0u8; Uncompressed Size]` without first verifying the size is within all configured limits.**
- `sar-cli extract` does **not** finalize sparse outputs by reconstructing the apparent file size in memory. It validates the apparent size against `max_decoded_entry_size`, creates a temp file, sets the final file length, seeks to each sparse extent, writes only gathered payload bytes, and renames the temp file only after successful completion.
- Sparse holes are left as filesystem holes when supported by the host filesystem. The CLI does not allocate large zero buffers for holes; CRC32 accounting for sparse holes uses bounded zero chunks.
- Fragmented sparse extraction still enforces `max_fragment_group_span`, `max_fragment_count`, and `max_loss_tolerant_gap` before fragment-group reconstruction.
- **CRC32 verification** is now active in `read_all_logical_files`. CRC32 is computed over the fully reconstructed sparse file including zero-filled holes; it is not computed over the stored sparse payload bytes alone. A CRC mismatch returns `SarError::CrcMismatch`. This ensures that tampering with sparse map offsets (changing where data lands in the logical file without changing the stored payload) is detected when the LFH carries a CRC32.
- **Content Hash is not verified** because the archive format does not encode the hash algorithm identifier. The 32-byte `content_hash` field is parsed and preserved in `EntryMetadata`, but no verification is performed. See `docs/CONFORMANCE.md` Known Gaps.
- **Sparse Map placement**: in a fragmented archive, a Sparse Map on any non-zero fragment index returns `SarError::InvalidMap` immediately and is never suppressed by `allow_lossy`, preventing a malformed archive from triggering undefined reconstruction ordering.



- Extraction rejects absolute paths.
- Extraction rejects `..` traversal.
- Failed CLI extraction and failed CLI repair do not leave finalized output files behind after a resource-limit error.
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

---

## Milestone 9a — CDC security properties

### CDC does not bypass AEAD authentication

CDC metadata (CDC_MAP TLVs, recipe payloads) is parsed from the Central Dictionary and the decrypted/decompressed payload. The CDC parsing layer never operates on raw encrypted bytes. AEAD authentication is enforced before any CDC validation occurs.

### CDC resource limits prevent denial-of-service

All CDC parse paths enforce `ResourceLimits`:

| Limit field              | Default   | Protected paths                                |
|--------------------------|-----------|------------------------------------------------|
| `max_cdc_chunk_count`    | 1,000,000 | `validate_recipe_payload`, `parse_cdc_map`, `parse_entry_cdc_map` |
| `max_cdc_metadata_bytes` | 50 MiB    | `validate_recipe_payload`, `parse_entry_cdc_map`, `make_cdc_map_tlv` |

A malformed archive with an excessively large CDC_MAP TLV or Recipe payload will fail with `SarError::LimitExceeded` before any allocation proportional to the claimed record count occurs.

`Vec::with_capacity` is never called with an unchecked chunk count; all capacity allocations are guarded by `max_cdc_chunk_count`.

### No unchecked u64→usize casts in CDC paths

All `u64` to `usize` conversions in CDC code use `usize::try_from(...).ok()` or are guarded by resource-limit checks that ensure the value fits in a `usize` on the target platform.

### CDC_MAP record alignment checked before iteration

`parse_cdc_map` validates that the byte slice length is a multiple of `CDC_MAP_RECORD_LEN = 50` before iterating. Non-aligned lengths return `SarError::Malformed` without reading out-of-bounds.

### FASTCDC algorithm has no unbounded allocation

The FASTCDC chunker operates on a bounded input slice. Chunk count is bounded by `max_cdc_chunk_count`; a `LimitExceeded` error is returned if this limit is exceeded. No in-place allocation is proportional to the entire input; the gear hash is a rolling scalar.

### Reserved and unsupported CDC algorithm IDs fail closed

- Reserved IDs (0x04–0xEF) → `SarError::ReservedValue`
- Unsupported optional IDs (0x01 Rabin, 0x03 BuzHash) → `SarError::Unsupported`
- Custom IDs (0xF0–0xFF) → `SarError::Unsupported`

No fallback behavior is attempted for unknown CDC algorithms.

### Recipe hashes are not verified against file content in M9a

Recipe payloads are validated for structure (32-byte alignment, resource limits) but the SHA-256 hashes within them are not verified against the logical file bytes. This is a known limitation. Verification cannot be performed portably until the spec normatively names the hash algorithm for recipe hashes.
