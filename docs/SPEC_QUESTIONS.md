# Spec Questions / Conservative Choices

1. **Global flags beyond first 32 bits**: currently parsed from the first 4 bytes (required minimum) with raw bytes retained.
2. **NO_INDEX footer-forbidden detection**: no heuristic scan is used; parser treats remaining bytes as data area in NO_INDEX mode.
3. **KMS custom mode handling**: custom range (`0xF0..=0xFF`) returns `SAR_ERR_UNSUPPORTED` unless future policy enables it.
4. **Reserved CD bytes**: enforced as zero for fail-closed behavior.
5. **TLV processing scope**: milestone-limited parser supports structural parsing and strict reserved/unsupported mapping.
6. **Compression override behavior**: when global `COMPRESSED` is set but `IS_COMPRESSED` is unset, implementation treats effective algorithm as STORE.
7. **Compression level mapping**: CLI accepts levels `0..9` and passes them as hints to codec backends.
8. **AEAD AAD scope**: current implementation authenticates `global_header_flags_section || raw_lfh_bytes` plus ciphertext/tag. This matches the Milestone 5 conservative choice but should be confirmed against the final spec wording.
9. **Global ENCRYPTED with plaintext entries**: the implementation permits `GlobalFlags::ENCRYPTED` archives to contain entries without `IS_ENCRYPTED`; such entries pass through as plaintext while still carrying the global KMS extension.
10. **AES-GCM nonce field layout**: the implementation treats the 24-byte LFH nonce field as `nonce[0..12] || 12 zero bytes` for AES-GCM and validates the zero suffix strictly.

## Milestones 6–7: FEC Questions & Conservative Choices

11. **RS symbol size range**: Spec requires support for at least 1024, 4096, and 16384 bytes. Implementation supports any `symbol_size ≥ 1` up to the implementation bound (`1 << 24` = 16 MiB), enforced by allocation limit. Any value exceeding `MAX_PARITY_SIZE` returns `SAR_ERR_LIMIT_EXCEEDED`.

12. **RS parity count limit**: Spec allows `n-k` up to 255 by format. The minimal interoperable profile cap of 32 parity symbols is documented. Values 33–255 return `SAR_ERR_LIMIT_EXCEEDED`; format remains parseable so future implementations can raise the cap without a format change.

13. **XOR block size index 0x07/0x08**: Indices 0x07 (32 KB) and 0x08 (64 KB) are assigned by the spec but exceed the "minimal implementation support" range (0x00..=0x06). Implementation supports all nine assigned block sizes (0x00..=0x08). No values return `SAR_ERR_LIMIT_EXCEEDED` for the block size index.

14. **XOR stripe size**: Spec marks 0x00 as reserved and 0x01..=0xFF as valid by format. Implementation enforces 0x01..=32 for the minimal support profile and returns `SAR_ERR_LIMIT_EXCEEDED` for 33..=255. This is conservative; a future implementation may raise the cap.

15. **Erasure index semantics for XOR**: Erasure `index` is the zero-based block index in the full data stream (`block_idx = byte_offset / block_size`). The erasure index is absolute, not relative to a stripe. The codec derives `(stripe_idx, in_stripe)` from `block_idx`.

16. **Erasure index semantics for RS**: Erasure `index` is the zero-based data symbol index in the full data stream (`sym_idx = byte_offset / symbol_size`). The codec derives `(group_idx, in_group)` from `sym_idx / k`. Recovery silently skips erasures with `in_group >= k` (which would be out-of-bounds for the data symbol count).

17. **AEAD + Selective FEC pipeline**: FEC protects only the ciphertext bytes (not the AEAD tag) when AEAD is active. Recovery order is: `stored_payload → FEC repair over ciphertext → AEAD verify/decrypt → decompress`. This matches the spec's pipeline ordering requirements. The AEAD tag is always validated before plaintext is released.

18. **Data Recovery TLV disabled case**: The spec defines `0x00` as disabled/none for the FEC algorithm ID field. For Data Recovery TLVs, `validate_recovery_tlv(0x00, &[])` returns `Ok(FecSummary::None)` (no error, no metadata). A TLV with type `0x00` would not appear in the RECOVERY range `0x10..=0x1F` so this case only applies to LFH FEC.

19. **RS Vandermonde generator matrix**: The generator uses `G[r][c] = α^((r+1)×c)` where r is the zero-based parity row and c is the zero-based data column. The primitive element α=0x02 with polynomial 0x11D is used. This is exactly as specified in Section 9.2.1.

20. **Archive-level FEC recovery scope**: Before Milestone 8 (fragmentation), archive-level FEC recovery is limited to metadata validation and codec-level APIs over explicit byte slices. Full archive repair over fragmented or partial data requires fragmentation-aware address translation not yet available. Attempting archive repair without explicit erasure positions returns `SAR_ERR_RECOVERY_UNAVAILABLE`.

