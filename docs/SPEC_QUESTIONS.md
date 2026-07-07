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
