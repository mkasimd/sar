# Spec Questions / Conservative Choices

The items below are derived from the current code audit. They document places where the implementation intentionally makes a conservative choice or where the spec text still leaves important integration questions open.

- **Spec section:** Global flags / header layout
  - **Issue:** The implementation parses the low 32 bits of global flags into `GlobalFlags` and retains the raw flag bytes separately. The spec allows a variable-length flag field.
  - **Current conservative implementation:** only the first 4 bytes drive semantic flag decisions today; additional bytes are preserved but not interpreted by `GlobalFlags`.
  - **Interoperability risk:** future extensions beyond the low 32 bits may be silently retained but not acted on.
  - **Follow-up needed:** define how higher-order flag bytes are surfaced in conformance and FFI-facing APIs.

- **Spec section:** `NO_INDEX` archives
  - **Issue:** The spec forbids CD/Footer in `NO_INDEX` mode, but it does not require heuristic detection of stray trailing bytes.
  - **Current conservative implementation:** the reader treats the remaining bytes as data area when `NO_INDEX` is set and does not scan for a footer signature.
  - **Interoperability risk:** malformed files with unexpected trailing structures may be interpreted differently by other implementations.
  - **Follow-up needed:** decide whether conformance should require stronger `NO_INDEX` trailer rejection.

- **Spec section:** KMS custom mode range (`0xF0..=0xFF`)
  - **Issue:** Custom KMS values are reserved for implementation-defined behavior.
  - **Current conservative implementation:** custom KMS mode IDs return unsupported unless the application provides future policy around them.
  - **Interoperability risk:** two implementations can assign different meanings to the same custom ID.
  - **Follow-up needed:** document whether any custom KMS policy is ever allowed in the reference implementation.

- **Spec section:** Central Dictionary reserved bytes and padding
  - **Issue:** The spec leaves little room for tolerant parsing of non-zero reserved bytes.
  - **Current conservative implementation:** reserved bytes and alignment padding are required to be zero.
  - **Interoperability risk:** tolerant encoders/decoders elsewhere may accept archives this implementation rejects.
  - **Follow-up needed:** confirm whether fail-closed zero enforcement is the intended interoperability baseline.

- **Spec section:** TLV handling
  - **Issue:** The spec defines more TLV families than the current code implements.
  - **Current conservative implementation:** implemented TLV ranges parse structurally; unsupported signature/CDC ranges return unsupported or reserved errors.
  - **Interoperability risk:** archives carrying future TLVs may fail earlier than some implementations expect.
  - **Follow-up needed:** define extension-policy expectations for unknown-but-assigned TLVs.

- **Spec section:** Compression semantics
  - **Issue:** The spec allows `COMPRESSED` globally while per-entry mode controls whether a given entry is actually compressed.
  - **Current conservative implementation:** if global `COMPRESSED` is set but `IS_COMPRESSED` is clear for an entry, the effective algorithm is STORE for that entry.
  - **Interoperability risk:** other implementations may reject such entries or require the LFH compression field to be interpreted differently.
  - **Follow-up needed:** clarify whether this mixed-mode behavior is intended.

- **Spec section:** Compression level mapping
  - **Issue:** The spec names algorithms but not exact CLI level semantics.
  - **Current conservative implementation:** the CLI accepts `0..9` and forwards them as backend-specific hints.
  - **Interoperability risk:** encoded output may differ across implementations even when algorithm IDs match.
  - **Follow-up needed:** decide whether level values are purely local encoder hints or should be normalized further.

- **Spec section:** AEAD AAD construction
  - **Issue:** The spec requires authenticated binding of structural metadata, including special treatment when Selective FEC is present.
  - **Current conservative implementation:** AEAD AAD is built from the global-header flag section plus LFH bytes; when Selective FEC is active for an encrypted entry, the FEC size/value region is excluded from AAD.
  - **Interoperability risk:** independent implementations must make the exact same byte-level AAD choice or encrypted interoperability fails.
  - **Follow-up needed:** pin down the normative byte-level AAD recipe in an interoperability appendix.

- **Spec section:** Global `ENCRYPTED` vs plaintext entries
  - **Issue:** The spec can be read as archive-wide encryption capability versus per-entry encryption state.
  - **Current conservative implementation:** `GlobalFlags::ENCRYPTED` may be present while some entries leave `IS_ENCRYPTED` clear.
  - **Interoperability risk:** implementations that assume all entries are encrypted may reject otherwise valid archives.
  - **Follow-up needed:** clarify whether mixed encrypted/plaintext entries are intentional.

- **Spec section:** AES-GCM nonce field layout
  - **Issue:** The format reserves a 24-byte nonce field while AES-GCM uses 12-byte nonces.
  - **Current conservative implementation:** bytes `0..12` carry the nonce and bytes `12..24` must be zero.
  - **Interoperability risk:** looser implementations may accept non-zero suffix bytes that this implementation rejects.
  - **Follow-up needed:** explicitly specify the 24-byte field mapping for AES-GCM.

- **Spec section:** Reed-Solomon symbol size range
  - **Issue:** The spec names required interoperability sizes but leaves room for larger values.
  - **Current conservative implementation:** symbol sizes greater than zero parse, but practical behavior is still bounded by implementation allocation limits.
  - **Interoperability risk:** very large symbol sizes may be format-valid but operationally unacceptable.
  - **Follow-up needed:** state whether a tighter interoperable upper bound is desirable.

- **Spec section:** Reed-Solomon parity count
  - **Issue:** Format space allows larger parity counts than the current implementation supports.
  - **Current conservative implementation:** parity count must be non-zero and no greater than 32.
  - **Interoperability risk:** another implementation may generate archives this implementation rejects even though the on-wire format could encode them.
  - **Follow-up needed:** document whether 32 is only a reference-implementation limit or part of the interoperability profile.

- **Spec section:** XOR block-size index and stripe size
  - **Issue:** The spec distinguishes assigned values from minimal implementation support.
  - **Current conservative implementation:** all assigned block-size indices `0x00..=0x08` are supported; stripe size `0x00` is reserved and non-zero values are accepted subject to codec/resource checks.
  - **Interoperability risk:** implementations may disagree on which values are merely assigned versus required.
  - **Follow-up needed:** define the minimum interoperable XOR parameter set more explicitly.

- **Spec section:** Erasure index semantics
  - **Issue:** Erasure positions must map consistently between format-level metadata and codec-level recovery.
  - **Current conservative implementation:** XOR erasure indices are absolute block indices; Reed-Solomon erasure indices are absolute data-symbol indices.
  - **Interoperability risk:** mismatched index semantics produce unrecoverable repair attempts.
  - **Follow-up needed:** make the absolute-index rule explicit in the spec text.

- **Spec section:** AEAD + Selective FEC pipeline
  - **Issue:** The spec constrains ordering between repair, authentication, and decompression.
  - **Current conservative implementation:** FEC protects ciphertext bytes when encryption is enabled; recovery order is repair -> authenticate/decrypt -> decompress.
  - **Interoperability risk:** different ordering breaks authenticated repair compatibility.
  - **Follow-up needed:** preserve one normative ordering for all implementations.

- **Spec section:** Archive-level/global EC
  - **Issue:** The format can carry archive-level recovery TLVs before the repository has a full archive-repair workflow.
  - **Current conservative implementation:** the reader validates recovery TLV structure during verify; archive-wide repair orchestration is not implemented.
  - **Interoperability risk:** archives may look FEC-enabled while only metadata validation is available.
  - **Follow-up needed:** specify the minimum archive-level recovery behavior expected before claiming that milestone complete.

- **Spec section:** Compliance profiles
  - **Issue:** The current `sar-core::profile` API is not aligned with the full post–Milestones 6–7 feature set.
  - **Current conservative implementation:** profile validation is treated as advisory and incomplete.
  - **Interoperability risk:** consumers may incorrectly treat `validate_archive_profile()` as a definitive conformance oracle.
  - **Follow-up needed:** refresh profile rules after milestone stabilization.

---

## Milestone 8 additions

- **Spec section:** Archive-level repair orchestration (spec section 9.2)
  - **Issue:** The spec defines the protected byte range (global_flags_offset to the final byte before the Central Dictionary) and the FEC TLV wire format (type IDs 0x10–0x1F), but does not specify how to map arbitrary byte erasures to FEC block positions for a complete end-to-end archive repair workflow.
  - **Current conservative implementation:** `inspect_recovery_metadata` fully parses recovery TLVs and computes the protected range. `plan_archive_repair` validates that erasures are within the protected range and returns `RecoveryUnavailable` with the message "archive-level repair orchestration requires explicit block-aligned erasure mapping; see docs/SPEC_QUESTIONS.md" when erasures are not aligned to FEC block boundaries. `repair_archive` applies XOR or Reed-Solomon erasure recovery when erasures can be properly mapped to block indices.
  - **Interoperability risk:** archives with recovery TLVs will report `repair_possible: false` for unaligned erasures, even if another implementation could repair them with a different block-mapping heuristic.
  - **Follow-up needed:** the spec needs to normatively define the mapping from arbitrary byte offsets to FEC block positions — specifically the byte offset of the first FEC block within the protected range, the block stride, and how partial trailing blocks are padded.

- **Spec section:** Fragment reconstruction ordering (spec section 19)
  - **Issue:** Spec section 19 is primarily streaming-oriented; it describes fragment groups in terms of sequential delivery rather than random-access archival reconstruction.
  - **Current conservative implementation:** archival fragment reconstruction uses the Fragment Descriptor (`abs_offset` + `frag_size`) to scatter-gather each fragment's payload at its absolute offset within a logical-size buffer. Fragments are sorted by `fragment_index` before placement; this matches streaming delivery order but is driven by absolute offsets, not arrival order.
  - **Interoperability risk:** implementations that reconstruct by concatenation (ignoring Fragment Descriptor offsets) will produce the same output only if fragments are contiguous and monotonically laid out. Non-contiguous or sparse fragment groups will diverge.
  - **Follow-up needed:** spec should state whether Fragment Descriptor `abs_offset` is normative for archival reconstruction or only a hint for streaming delivery.

- **Spec section:** Loss-tolerant extraction in archival mode (spec sections 6.2.2 and 19.4.5)
  - **Issue:** Spec sections 6.2.2 and 19.4.5 describe LOSS_TOLERANT in a streaming context. The archival interpretation — accepting degraded output with gaps filled with zero bytes — is a reasonable extension but not explicitly specified.
  - **Current conservative implementation:** when LOSS_TOLERANT is set and fragments are missing, reconstruction fills gap regions with zero bytes and returns `is_degraded = true`, signaling `WarnIncomplete` to the caller. AEAD authentication failures are **never** overridden by LOSS_TOLERANT; this is enforced by the spec constraint that loss-tolerant semantics apply only to missing/unrecoverable fragments, not to authentication errors.
  - **Interoperability risk:** implementations that interpret LOSS_TOLERANT as bypassing all error categories would be non-conformant; this implementation is strict.
  - **Follow-up needed:** spec should explicitly state that LOSS_TOLERANT applies only to missing fragment data, not to authentication or format errors.

- **Spec section:** Future Milestone 12 FFI / C ABI
  - **Issue:** Future cross-language bindings will affect API shape, ownership rules, and interoperability claims.
  - **Current conservative implementation:** no FFI/C ABI is implemented in this pass.
  - **Interoperability risk:** later ABI choices could freeze semantics that do not map cleanly from the current generic Rust APIs.
  - **Follow-up needed:** decide first on opaque handles, `sar_status_t`, buffer ownership rules, and version negotiation, then finalize key-provider callback rules and other callback-heavy contracts before Milestone 12 begins.

- **Spec section:** Sparse file logical size — **RESOLVED**
  - **Resolution:** The spec defines `Uncompressed Size` as the "fully reconstructed logical file after all applicable transformations have been reversed during decoding." For sparse files this means the full logical file size including all holes, not the sum of sparse extent data lengths. Truncation to `Uncompressed Size` after writing sparse extents is explicitly required by the spec and is critical when the file ends with a hole.
  - **Implementation updated:** `ArchiveReader::read_all_logical_files` now uses LFH `Uncompressed Size` directly as the logical file size for sparse reconstruction. The `next_entry` size validation check is skipped for sparse entries because the decoded payload (sparse data bytes) is smaller than `Uncompressed Size` by design. Trailing holes after the final extent are filled with `0x00` bytes.
  - **No remaining ambiguity:** This question is closed. Trailing sparse holes are not a spec gap.

- **Spec section:** Content Hash algorithm identifier encoding
  - **Issue:** The archive format stores a 32-byte `content_hash` field in the LFH when the `DEDUPLICATION` flag is set. The spec refers to "e.g., BLAKE3" as the hash algorithm, but does not normatively define a hash algorithm identifier field in the LFH, Global Header, or any other fixed-format location.
  - **Current conservative implementation:** the 32-byte field is parsed and preserved in `EntryMetadata.content_hash`, but no verification is performed because the algorithm cannot be determined from the archive.
  - **Interoperability risk:** high. Two implementations that store content hashes with different algorithms would both claim conformance but produce incompatible archives.
  - **Follow-up needed:** spec must normatively define how the hash algorithm is signaled (e.g., a 1-byte algo ID prepended to the 32-byte value, or a Global Header field, or a fixed "BLAKE3-only" mandate). Until this is resolved, content hash verification cannot be implemented portably.

---

## Milestone 9a — Content-Defined Chunking (CDC) spec ambiguities

- **Spec section:** CDC_MAP TLV record field widths (spec section 21.1)
  - **Status: RESOLVED in M9a (CDC_MAP v1 header format)**
  - Section 21.1 now defines a `CDC_MAP_Header v1` with normative field widths. The record layout for v1 is `[Hash: 32 B][Partition_ID: 4 B u32 LE][Absolute_Offset: 8 B u64 LE][Compressed_Size: 4 B u32 LE]` = 48 bytes per record. The header carries `Hash_Algorithm_ID` so parsers do not need to guess the hash algorithm. `CDC_MAP_RECORD_LEN = 48`. The pre-M9a implementation used a provisional 50-byte assumed layout (`Partition_ID: u16 2B, Compressed_Size: u64 8B`) which was replaced by this normative header-based format.

- **Spec section:** CDC_MAP Hash_Algorithm_ID (spec section 21.1)
  - **Status: RESOLVED in M9a (CDC_MAP v1 header format)**
  - `Hash_Algorithm_ID` in the v1 header identifies the SAR hash algorithm used for all record hashes. BLAKE3 (`0x31`) is required; SHA-256 (`0x30`) is supported. The LFH `CDC Algo ID` is the chunking algorithm; `Hash_Algorithm_ID` is the record hash algorithm. These are independent fields.

- **Spec section:** Recipe Mode hash algorithm (spec sections 8.5 and 20)
  - **Issue:** Section 8.5 states that when `cdc_algo_id > 0` the payload (after decryption/decompression) is an ordered array of 32-byte chunk hashes, and that the hash is "determined by DEDUPLICATION (Bit 29)". Section 20 does not name the hash algorithm.
  - **Current conservative implementation:** assumed SHA-256 for all recipe chunk hashes (length 32 bytes). This is consistent with the `content_hash` field which is also 32 bytes.
  - **Interoperability risk:** medium. If DEDUPLICATION Bit 29 selects BLAKE3 in some profiles, SHA-256 chunk hashes would not match.
  - **Follow-up needed:** spec must normatively name the hash algorithm for Recipe Mode chunk hashes, or reference an algorithm registry. This should be resolved when the DEDUPLICATION feature is specified in full.

- **Spec section:** FastCDC parameters — minimum, average, maximum chunk size (spec section 8.5)
  - **Issue:** Section 8.5 names FASTCDC as a required CDC algorithm (algorithm ID 0x02) but does not specify the minimum, average, or maximum chunk sizes, normalization/masking level, gear hash table or seed, cut-point condition, fingerprint width, or EOF handling.
  - **Current conservative implementation:** implemented two-level FASTCDC with `min_size=2 KiB`, `avg_size=8 KiB`, `max_size=64 KiB`. Gear table generated via `xorshift64*` PRNG seeded at `0x9e3779b97f4a7c15`. Two-level masking: `mask_s = mask_for(avg/2)`, `mask_l = mask_for(avg)`.
  - **Interoperability risk:** high for cross-writer deterministic chunking or regenerated-boundary verification. Any difference in chunk sizes or gear table produces different chunk boundaries, but that must not be treated as a parsing failure when the stored CDC metadata is self-consistent.
  - **Follow-up needed:** spec must normatively specify FastCDC parameters (min/avg/max chunk sizes), normalization/masking strategy, gear table/seed, cut-point condition, and EOF behavior. These values must be embedded in the archive or specified as mandatory defaults before portable boundary-regeneration verification or cross-writer deterministic chunking can be claimed.

- **Spec section:** CDC chunking transformation domain (spec sections 8.5 and 21)
  - **Issue:** The spec does not explicitly state which byte domain CDC chunking operates on. Options include: logical file bytes, pre-compression bytes, post-compression bytes, pre-encryption bytes, or post-encryption bytes.
  - **Current conservative implementation:** CDC metadata records chunk boundaries over logical reconstructed file bytes (i.e., after fragment reassembly, sparse reconstruction, decryption, and decompression). Recipe Mode hashes are computed over these logical bytes. This follows the conservative expectation: `fragment reassembly → sparse reconstruction → logical file bytes → CDC metadata`.
  - **Interoperability risk:** medium. If the spec intends CDC over compressed or encrypted bytes, all chunk boundaries and recipe hashes would differ from this implementation.
  - **Follow-up needed:** spec must normatively state the transformation domain for CDC chunking (which byte sequence is chunked and which byte sequence the recipe hashes cover). Without that, boundary regeneration and external provider recipe reconstruction are not portable.

- **Spec section:** CDC interaction with LOSS_TOLERANT and FEC (spec sections 6.2.2, 19.4.5, and 21)
  - **Issue:** Section 21 does not describe how CDC metadata should be handled when LOSS_TOLERANT is active or when FEC recovery replaces erased data. Should CDC validation be skipped for degraded entries? Should partial recipe hashes be verified?
  - **Current conservative implementation:** CDC_MAP TLVs in the Central Dictionary are always validated structurally. Recipe payloads are validated against resource limits. For loss-tolerant entries, CDC validation is not enforced beyond structural checks because the logical bytes may be degraded.
  - **Interoperability risk:** low for structural validation; medium for recipe hash verification in degraded mode.
  - **Follow-up needed:** spec should state whether CDC recipe hash verification is required when LOSS_TOLERANT is active or when FEC repair has been applied.
- **Spec section:** External provider / CAS recipe resolution contract (spec sections 20.3 and 21.2)
  - **Issue:** The spec allows recipe chunks to be fetched from an external CAS via `CDC_EXT_PROVIDER`, but it does not define the provider protocol, record layout contract, or how the provider and archive agree on the CDC transformation domain.
  - **Current conservative implementation:** parses `CDC_EXT_PROVIDER` only as inert UTF-8 URI metadata. No provider resolution or recipe reconstruction is attempted.
  - **Interoperability risk:** high. Even if two implementations parse the same metadata, they may be unable to reconstruct the same recipe from an external provider without a shared protocol and profile.
  - **Follow-up needed:** specify the provider protocol, recipe hash algorithm, record layout, and CDC transformation domain required for portable external-CAS recipe resolution.


---

## Milestone 9b — Delta spec gaps

- **Spec section:** Delta Base Hash algorithm (spec §6.1)
  - **Issue:** The LFH `Delta Base Hash` field is 32 bytes. The spec does not include a hash algorithm identifier in the LFH or any other header field to identify which algorithm produced this value.
  - **Current conservative implementation:** the 32-byte field is parsed and preserved in `EntryMetadata.delta_base_hash`, but no verification is performed because the algorithm cannot be determined from the archive. The field is treated as opaque bytes and exposed in JSON output as a lowercase hex string. An all-zero value is treated as "no base recorded" for BSDIFF and VCDIFF (returns `SAR_ERR_BASE_MISSING`). BLAKE3, SHA-256, or any other algorithm is not assumed.
  - **Interoperability risk:** high. Without a known algorithm, implementations cannot verify base identity, detect tampered base objects, or perform portable base lookup.
  - **Follow-up needed:** spec must normatively define how the hash algorithm is signaled for `Delta Base Hash` (e.g., a 1-byte algo ID prepended to the 32-byte field, a Global Header field, or a fixed "BLAKE3-only" mandate).

- **Spec section:** Base object resolution model (spec §8.4)
  - **Issue:** Section 8.4 references a "Delta Base Hash" for identifying the base archive or object, but does not define how a reader locates the base object given a hash. The spec does not specify whether the base is a prior entry in the same archive, a separate archive, a URI, or an external repository.
  - **Current conservative implementation:** automatic base resolution is not implemented. No lookup, no file access, and no URI resolution is attempted. `EntryMetadata.delta_base_hash` is exposed as an opaque field. Callers supply base bytes explicitly via `ArchiveReaderOptions.delta_base`.
  - **Interoperability risk:** high. Without a normative resolution model, two implementations cannot independently reconstruct the same target from the same archive.
  - **Follow-up needed:** spec must define a normative base object resolution model (same-archive by hash, external file, URI, CAS, or other mechanism).

- **Spec section:** Per-entry `IS_DELTA` opt-out bit (spec §6.1 and §8.4)
  - **Issue:** The spec defines `HAS_DELTA` as a global flag that governs the presence of `Patch Algo ID` and `Delta Base Hash` in every LFH. There is no per-entry bit defined to indicate that a specific entry is not a delta (i.e., is a full copy even within a delta archive). If any entry in a delta archive stores a full copy rather than a patch, the reader has no way to distinguish it from a delta entry without applying the patch.
  - **Current conservative implementation:** the spec defines no IS_DELTA per-entry bit; this implementation does not invent one. All entries in a `HAS_DELTA` archive are treated as having delta LFH fields present.
  - **Interoperability risk:** medium. Mixed archives (some entries delta, some full) cannot be expressed without a per-entry opt-out.
  - **Follow-up needed:** spec should define a per-entry indicator (e.g., `IS_DELTA` entry flag or a sentinel `Patch Algo ID` value) for mixed-mode archives.

- **Spec section:** ZSTD_PATCH dictionary/protocol (spec §8.4)
  - **Issue:** Section 8.4 assigns `0x03` to ZSTD_PATCH but does not define the patch protocol: whether the payload is a raw ZSTD-compressed delta, a ZSTD dictionary-based frame, or a higher-level format that uses ZSTD compression internally.
  - **Current conservative implementation:** ZSTD_PATCH is an assigned, optional algorithm. The ID is recognized; application is not implemented; attempting to apply returns `SarError::Unsupported`.
  - **Interoperability risk:** high if ZSTD_PATCH is ever implemented without a normative protocol definition.
  - **Follow-up needed:** spec must define the ZSTD_PATCH protocol (compression format, dictionary negotiation, and delta structure).

- **Spec section:** BSDIFF legacy compatibility (spec §8.4.4)
  - **Issue:** The spec allows optional legacy `BSDIFF40` decode support.
  - **Current conservative implementation:** only SAR BSDIFF v1 (`SARBSD01`) is supported; legacy `BSDIFF40` decoding is not implemented; `BSDIFF40` magic returns `SarError::PatchFailed`.
  - **Interoperability risk:** archives that use legacy `BSDIFF40` payloads are intentionally rejected by this implementation profile.
  - **Follow-up needed:** none for current profile unless legacy compatibility is explicitly required.
