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

- **Spec section:** Future Milestone 12 FFI / C ABI
  - **Issue:** Future cross-language bindings will affect API shape, ownership rules, and interoperability claims.
  - **Current conservative implementation:** no FFI/C ABI is implemented in this pass.
  - **Interoperability risk:** later ABI choices could freeze semantics that do not map cleanly from the current generic Rust APIs.
  - **Follow-up needed:** decide on opaque handles, `sar_status_t`, buffer ownership rules, key-provider callback rules, and version negotiation before Milestone 12 begins.
