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
- `StreamArchiveParser` preserves the same ordering: AEAD verification/decrypt occurs before decompression and before any patch/sparse/fragment reconstruction output is released.

## M10a forward-only stream parser security notes

- M10a implements the **stateless** SAR Byte Stream model only.
- The parser is forward-only and does not require backward seek for supported streaming paths (`NO_INDEX` archives).
- Partial input is handled deterministically via `NeedMore`; truncated errors are emitted only after `finalize_input()` declares end-of-stream.
- Entry Mode does not remove physical LFH fields: Global Flags remain authoritative for on-wire field presence.
- Session control opcodes are parsed structurally only in M10a; no session lifecycle state is established.

## M10b in-memory session-layer security notes

- `sar-stream` implements only the in-memory session semantics layer; it performs no network I/O, transport framing, socket access, or background activity.
- Stateful activation is fail-closed: `NO_INDEX`, non-zero `Stream ID`, and a valid `SESSION_INIT` are all required before any filesystem opcode is exposed as an action.
- Reserved entry-mode bit 12, reserved filesystem/session opcodes, reserved session flags, reserved capability bits, and reserved ACK bits all fail closed with SAR reserved/flag/state errors.
- Sequence continuity is enforced for every accepted entry, including `SESSION_HEARTBEAT`; wraparound from `0xFFFF` to `0x0000` is accepted.
- Session-layer limits bound active streams, status message size, metadata size, fragment/session buffers, and cumulative session memory before allocations grow.
- `LOSS_TOLERANT` warnings are emitted only for degraded authenticated data; auth failures, decompression failures, patch failures, and structural corruption remain hard errors.
- `ATOMIC_WRITE` and `FORCE_SYNC` are surfaced as inert action flags only; the crate does not mutate filesystems or expose unauthenticated plaintext.

## M10c in-memory transport-layer security notes

- `sar-transport` implements transport abstraction and deterministic in-memory policy/harness behavior only; it performs no production network I/O.
- `sar-transport` does not implement real TCP sockets, real QUIC sockets, async runtime integration, TLS, retransmission, congestion control, or handshake logic.
- transport policy does not authenticate SAR data by itself and does not weaken SAR AEAD/integrity invariants enforced by `sar-core`/`sar-stream`.
- Session UUID values are not authentication credentials; they remain bound only as session identifiers.
- rejected/invalid stream states fail closed and rejected Stream IDs remain unbound.
- heartbeat/watchdog hooks use explicit timestamp input only; no background timers/tasks are spawned.
- status/ack behavior is represented as abstract in-memory transport actions only; no real send path is performed.
- for untrusted future transports, AEAD-capable SAR encryption is strongly recommended to authenticate `SESSION_INIT` / `SESSION_RESUME` and reduce hijack risk.
- without SAR AEAD, session protection relies on future transport security or network isolation.

## M10d SAR-over-TCP binding security notes

- `TcpSarConnection<S>` wraps an existing TCP stream; it does **not** implement TLS or any transport-layer encryption.
- The M10d TCP binding is **plaintext SAR-over-TCP only**.  TCP+TLS is **not** implemented.  STARTTLS is **not** implemented.  No in-band upgrade path exists.
- **For connections over untrusted networks, SAR AEAD encryption and/or external transport security (e.g., WireGuard, IPsec, SSH tunneling) is required.**  M10d does not provide confidentiality or integrity of the TCP byte stream itself.
- TCP clients that send TLS handshake bytes, HTTP requests, random garbage, or any non-SAR bytes before a valid SAR Global Header are rejected and the connection is immediately closed; no further data is accepted.
- TCP clients that send valid SAR magic (`SAR!`) followed by a malformed SAR body (e.g., wrong version byte, invalid flags length) are rejected with a structural SAR parse error (not `InvalidMagic`); no SAR session is bound, no payload is exposed, no panic occurs.
- KMS Mode `0x04 TLS_EXPORTER` is spec-defined but **must not** be used over a plaintext TCP stream.  If a plaintext TCP stream encounters this KMS mode, the connection is rejected with `SAR_ERR_UNSUPPORTED`.  There is no TLS session and no TLS exporter material available on this binding.
- The TCP binding does **not** advertise `CAP_TLS_EXPORTER_AEAD`.  Any local capability set used by the TCP binding must not include this bit.
- The `process_available` path never exposes raw payload bytes to callers; all payload processing occurs inside `sar-core`/`sar-stream` behind AEAD and session semantics before any filesystem actions are surfaced.
- Invalid/unskippable byte sequences trigger `CloseConnection` before any further data is accepted; the connection is then permanently closed.
- `read_buffer_size` caps bytes accepted per `process_available` call; `write_buffer_size` caps bytes per `write_all_sar_bytes` call — both enforced before any allocation from network input.
- Idle TCP connections are subject to the inactivity watchdog: callers pass explicit `now_ms` timestamps to `process_available`; the watchdog fires and returns `SAR_ERR_TIMEOUT` when the configured `inactivity_timeout_ms` elapses without valid activity.  No background threads or timers are used.
- `std::net` blocking I/O is used; no async runtime, no `tokio`, no `mio`, no background tasks.
- `thread::spawn` appears only in tests and is always joined deterministically.
- No `unsafe` code is present.  All `unwrap` / `expect` calls in production code have been replaced with `?`-based error propagation.

## M10e SAR-over-QUIC binding security notes

- The M10e QUIC binding uses **quinn 0.11 + rustls 0.23** (ring provider) for all TLS and QUIC cryptography.  No custom TLS handshake, no custom QUIC crypto, no custom congestion logic is implemented.
- QUIC/TLS protects transport bytes end-to-end.  SAR-layer AEAD provides an additional independent authentication and confidentiality layer.
- **Server identity is explicit**: `QuicServerIdentity` requires a DER-encoded certificate chain and DER-encoded private key.  Private keys are never logged and never transmitted.
- **Client trust is explicit**: `QuicClientTrust` requires either a custom CA DER or the clearly-named `InsecureSkipVerifyForTestsOnly` variant.  Insecure verification is never the default.
- `InsecureSkipVerifyForTestsOnly` is a test-only helper intended only for tests and local diagnostics.  Production code must never use it.  The variant name explicitly warns against production use.  It must not be the default and must not be used in trusted production deployments.
- Certificate chain DER and private key DER buffers are validated before being accepted into QUIC server configuration; validation occurs on construction of `QuicServerIdentity`, before any connection is accepted.
- All connection and stream limits are enforced before allocation: `max_connections`, `max_quic_streams_per_connection`, `max_active_sar_streams_per_connection`, `max_control_streams_per_sar_session`, `max_buffered_bytes`, `max_read_chunk`, `max_outbound_buffer_bytes`.
- A malformed QUIC stream is rejected stream-locally; it does not close the entire QUIC connection or corrupt other active SAR sessions unless the error is connection-fatal.
- A QUIC stream that starts with valid SAR magic but has a malformed SAR body (e.g., wrong version, invalid flags) is rejected stream-locally with a structural SAR parse error; it does not affect other streams on the same connection.
- Rejected SAR Stream IDs remain unbound; no partial session state is retained.
- `SESSION_CLOSE` unbinds a SAR Stream ID and disassociates all QUIC streams attached to that session; the Stream ID may be reused for a new session on the same QUIC connection afterward.
- Duplicate `SESSION_INIT` for an already-bound SAR Stream ID on the same QUIC connection fails closed with `SAR_ERR_STREAM_STATE`; the incoming stream is rejected.
- Additional QUIC control streams are accepted only when they begin directly with LFH-encoded `SESSION_CONTROL` traffic for an active Stream ID on the same QUIC connection.  Additional control streams do not establish new SAR sessions.  Unknown Stream ID, closed session, malformed LFH, filesystem entries, `SESSION_INIT`, and private magic prefixes such as `CTL!` cause stream-local rejection.
- Same numeric SAR Stream ID on different QUIC connections are independent sessions; uniqueness is scoped per connection.
- No plaintext SAR payload is exposed before AEAD authentication succeeds, when AEAD is active.
- `LOSS_TOLERANT` does not suppress AEAD authentication failures, structural errors, decompression errors, or patch failures in QUIC mode.
- **TLS_EXPORTER key material is never transmitted in SAR frames, never logged, and never placed in KMS Data.**  The TLS exporter API is called internally to derive keying material used only as SAR AEAD input.
- TLS_EXPORTER exporter output is used directly as SAR AEAD keying material; it is not re-encrypted or wrapped before use; it must not leave the process.
- `CLIENT_TO_SERVER_ENTRY` and `SERVER_TO_CLIENT_ENTRY` key usages are bound to TLS endpoint roles (initiator vs. acceptor), not to SAR Sender/Receiver roles.  Receivers use only the single selected key usage; they do not retry with alternate key usages on AEAD failure.
- AEAD authentication failure is a hard failure in QUIC mode; no retry, no fallback, no alternate key usage attempt.
- Sequence Number wrap `0xFFFF → 0x0000` is handled correctly; wrap is not treated as an error.  Monotonic progression is still enforced modulo the sequence space.
- Nonzero KDF Algo IDs, unsupported context versions, reserved flags, and reserved/unsupported AEAD/hash/key-usage IDs fail closed.
- No `unsafe` code is present.  No production `unwrap`/`expect`/`panic`/`todo`/`unimplemented` is used.
- **TCP+TLS is not implemented.  STARTTLS is not implemented.  TLS_EXPORTER over plaintext TCP is not implemented.**  Plain TCP remains plaintext SAR-over-TCP only.

## M10g TLS PQ/hybrid key agreement policy (Section 18.6.7)

- `TlsPqPolicy` variants: `ClassicalAllowed`, `PreferPq`, `RequirePqOrHybrid`, `RequirePqOnly`.
- The bundled `ring` TLS provider does **not** support PQ-safe or hybrid key agreement groups.  The default policy is therefore `ClassicalAllowed`.
- `RequirePqOrHybrid` and `RequirePqOnly` **fail closed** with `SAR_ERR_UNSUPPORTED` at `QuicSarListener::bind` or `connect_quic` time when `ring` is the TLS provider.  No classical connection is established when a PQ/hybrid requirement cannot be satisfied.
- `PreferPq` may fall back to classical with `ring`.  A connection using `PreferPq` with classical-only negotiation **MUST NOT** be described as providing PQ-safe or HNDL-resistant protection for TLS_EXPORTER SAR AEAD keying material.
- Negotiated-group verification is not available with the `ring` provider and `quinn` in the current configuration.  Required-PQ modes therefore fail closed before TLS exporter material is used.  If a TLS provider that does expose negotiated group information is configured, negotiated-group verification SHOULD be implemented and used for `RequirePqOrHybrid` and `RequirePqOnly`.
- TLS_EXPORTER SAR AEAD inherits HNDL properties from the negotiated TLS session key agreement.  Classical-only negotiation yields no HNDL protection regardless of `TlsPqPolicy` setting.
- No TLS secrets, exporter outputs, derived SAR AEAD keys, or private keys are logged, placed in KMS Data, or transmitted in any SAR frame.

## M10h additional QUIC control-stream security notes

- Additional QUIC control streams start directly with the LFH bytes physically present on that stream; they do not use `CTL!`, UUID preheaders, private envelopes, or extra association metadata.
- Association is by QUIC connection + LFH `Stream ID` only.  The referenced Stream ID must already be active on that QUIC connection.
- Additional control streams do not establish new SAR sessions and are not permitted to carry `SESSION_INIT`.
- Additional control-stream errors are stream-local and do not corrupt or close unrelated QUIC streams.

## M10i TLS_EXPORTER post-binding enforcement

- **Post-binding enforcement**: for KMS Mode `0x04 TLS_EXPORTER`, `SESSION_INIT` is the only permitted plaintext bootstrap entry.  After `SESSION_INIT` activates the session, every subsequent SAR entry on the primary stream and on all attached additional QUIC control streams MUST carry `EntryMode::ENCRYPTED`.
- Any unencrypted SAR entry received after binding is active is rejected with `SAR_ERR_AUTH_FAILED`.  The transport never falls back to plaintext and never silently downgrades from required TLS_EXPORTER SAR-AEAD mode.

### Additional QUIC control-stream AEAD decryption (wired in `run_additional_control_stream_loop`)

For LFH-direct additional QUIC control streams after TLS_EXPORTER SAR-AEAD binding is active, the implementation **authenticates and decrypts** the payload before passing it to `SessionManager::process_entry`.  Only decrypted plaintext bytes are forwarded; ciphertext bytes are never forwarded.

- **AAD construction**: `global_header_flags_bytes(active_session_global_header) || wire_lfh_bytes`.  The global-flags section is derived from the canonical Global Header of the SAR session identified by the LFH Stream ID (KMS payload excluded from the flags section, consistent with `build_aead_aad`).  The LFH bytes are those physically present on the additional control stream.
- **Key derivation**: the CEK is resolved from the `KeyProvider` supplied to `InMemoryTransport::with_key_provider` via `resolve_cek`.  For TLS_EXPORTER sessions this is expected to be a pre-derived key supplied by the transport binding.
- **Algorithm**: determined by `encr_algo_id` in the LFH (set by the sender).
- **Rejection policy** — all failure modes map to the single `SAR_ERR_AUTH_FAILED` status to prevent error-oracle attacks; callers cannot distinguish the failure sub-type:
  - Plaintext entries (no `EntryMode::ENCRYPTED` bit) → `SAR_ERR_AUTH_FAILED`.
  - `EntryMode::ENCRYPTED` set but tag verification fails (wrong key, wrong AAD, tampered ciphertext, tampered LFH bytes, wrong Global Header bytes, random payload) → `SAR_ERR_AUTH_FAILED`.
  - Missing `encr_algo_id` or `iv_nonce` in a marked-encrypted LFH → `SAR_ERR_AUTH_FAILED`.
  - No key provider present when decryption is required → `SAR_ERR_AUTH_FAILED`.
- `LOSS_TOLERANT` does not suppress post-binding plaintext enforcement.  AEAD failures are never treated as acceptable degraded output.
- AEAD failure on one additional QUIC control stream is stream-local; the QUIC policy resets only the affected stream and does not close the connection or affect other sessions.
- Plaintext is never exposed on AEAD authentication failure: `aead_decrypt` zeroizes the output buffer before returning `SAR_ERR_AUTH_FAILED`.
- The implementation never tries multiple key usages after authentication failure.
- `CTL!` remains rejected with `SAR_ERR_INVALID_MAGIC` regardless of KMS mode.
- `InMemoryTransport::with_key_provider` allows production and test code to inject a `KeyProvider` that supplies the TLS-exporter-derived CEK for both `StreamArchiveParser` AEAD decryption (primary stream) and the additional-control-stream manual AEAD path; no key material is stored in SAR frames or logs.

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



- Extraction lexically rejects absolute paths, `..`, empty/current-directory components, Windows drive prefixes, and UNC/verbatim-style paths before archive-controlled filesystem writes begin.
- Extraction validates each path component under the destination root and refuses to traverse an existing symlink component.
- Symlink extraction is disabled by default; `--allow-symlinks` is required before a symlink entry may be created on the host filesystem.
- Even when symlink extraction is enabled, absolute or parent-traversing symlink targets are rejected, and later entries cannot use an extracted symlink as a traversal primitive because parent-component symlinks are rejected.
- Newly-created extraction directories are staged with restrictive permissions before any optional final metadata application.
- Final directory permissions are applied only after entry extraction completes.
- Permission restoration is disabled by default and strips setuid/setgid/sticky bits even when `--preserve-permissions` is requested.
- UID/GID restoration is disabled by default and remains Unix-only / privilege-dependent when `--preserve-owner` is requested.
- Timestamp restoration is disabled by default and currently restores atime/mtime only; archive `ctime` remains inspection metadata rather than a directly restorable host field.
- Failed CLI extraction and failed CLI repair do not leave finalized output files behind after a resource-limit error.
- Parsing uses checked arithmetic for offsets, lengths, header sizes, and region boundaries.
- Unknown assigned-but-unsupported algorithms return SAR unsupported/reserved errors rather than silent fallback.

## Known security limitations

- No signature implementation is present.
- No built-in asymmetric-wrap cryptography is present; application code must provide unwrap behavior.
- `sar-core::profile` is not a complete security/compliance oracle.
- The current CLI has no dedicated encrypted `list` or encrypted `inspect` path because those commands do not accept passwords.
- Metadata-preserving create/extract behavior is currently strongest on Unix-like platforms; unsupported platforms fail clearly instead of claiming owner/group or symlink-restoration behavior they cannot provide safely.
- CLI extraction uses a stable per-component validation approach rather than an `openat`/directory-fd extraction engine on every platform, so confinement guarantees are strongest when the host filesystem reports symlink state accurately for each component.
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

CDC metadata (`CDC_MAP` at `0x40`, inert `CDC_EXT_PROVIDER` at `0x41`, `CDC_CUSTOM` at `0x4F`, and recipe payloads) is parsed from the Central Dictionary and the decrypted/decompressed payload. The CDC parsing layer never operates on raw encrypted bytes. AEAD authentication is enforced before any CDC validation occurs.

### CDC resource limits prevent denial-of-service

All CDC parse paths enforce `ResourceLimits`:

| Limit field              | Default   | Protected paths                                |
|--------------------------|-----------|------------------------------------------------|
| `max_cdc_chunk_count`    | 1,000,000 | `validate_recipe_payload`, `parse_cdc_map`, `parse_entry_cdc_map` |
| `max_cdc_metadata_bytes` | 50 MiB    | `validate_recipe_payload`, `parse_entry_cdc_map`, `make_cdc_map_tlv` |

A malformed archive with an excessively large CDC_MAP TLV or Recipe payload will fail with `SarError::LimitExceeded` before any allocation proportional to the claimed record count occurs.

`Vec::with_capacity` is never called with an unchecked chunk count; all capacity allocations are guarded by `max_cdc_chunk_count`.

### No unchecked u64→usize casts in CDC paths

All `u64` to `usize` conversions in CDC code use `usize::try_from(...)` or are guarded by resource-limit checks that ensure the value fits in a `usize` on the target platform.

### CDC TLV registry fails closed

- `0x31` remains `DATA_HASH/BLAKE3` and is not interpreted as CDC metadata.
- `0x42–0x4E` are rejected with `SarError::ReservedValue`.
- `0x41` (`CDC_EXT_PROVIDER`) is parsed as a UTF-8 URI string only; invalid UTF-8 fails closed with `SarError::Malformed`.
- `0x4F` (`CDC_CUSTOM`) is treated as opaque implementation-defined metadata and is parsed/preserved only.

### CDC_MAP v1 header validation

`parse_cdc_map` validates the 16-byte v1 header before processing any records:

* TLV length ≥ 16 (minimum header size);
* `Map_Version` MUST be `0x01`; other versions return `CdcError::Unsupported`;
* `Hash_Algorithm_ID` MUST be in the SAR hash registry (0x30 or 0x31); others return `Unsupported` or `ReservedValue`;
* `Flags` MUST be zero; non-zero flags return `CdcError::Malformed`;
* `Reserved` bytes MUST be zero; non-zero bytes return `CdcError::Malformed`;
* `Record_Size` MUST be 48; other values return `CdcError::Malformed`;
* TLV Length MUST equal `16 + Record_Count × 48` (checked multiplication and addition); overflow or mismatch returns `Overflow` or `Malformed`.

Non-aligned or oversized payloads return `CdcError::Malformed` or `CdcError::Overflow` without any out-of-bounds reads.

### CDC_MAP hash algorithm ID must not be guessed

The `Hash_Algorithm_ID` field in the CDC_MAP header MUST be read to determine which algorithm was used for record hashes. Implementations MUST NOT hard-code an unnamed hash algorithm or assume SHA-256 without reading the header. Treating the LFH `CDC Algo ID` (chunking algorithm) as the hash algorithm is incorrect; they are independent fields.

### CDC_MAP record hash verification uses checked arithmetic

`verify_cdc_map_record_hash` verifies that `Absolute_Offset + Compressed_Size` does not overflow before indexing into archive bytes. Both `Absolute_Offset` and the computed end offset are validated against archive bounds.

### FASTCDC algorithm has no unbounded allocation

The FASTCDC chunker operates on a bounded input slice. Chunk count is bounded by `max_cdc_chunk_count`; a `LimitExceeded` error is returned if this limit is exceeded. No in-place allocation is proportional to the entire input; the gear hash is a rolling scalar.

### Reserved and unsupported CDC algorithm IDs fail closed

- Reserved IDs (0x04–0xEF) → `SarError::ReservedValue`
- Unsupported optional IDs (0x01 Rabin, 0x03 BuzHash) → `SarError::Unsupported`
- Custom IDs (0xF0–0xFF) → `SarError::Unsupported`

No fallback behavior is attempted for unknown CDC algorithms.

### CDC_MAP hash verification is distinct from FASTCDC boundary-regeneration

CDC_MAP hash verification (`verify_cdc_map_record_hash`) checks that the hash stored in a record matches the bytes at `[Absolute_Offset, Absolute_Offset + Compressed_Size)` in the archive. It does **not** regenerate FASTCDC boundaries from file content. These two operations are independent. Do not claim FASTCDC boundary-regeneration verification from CDC_MAP hash verification.

### CDC_EXT_PROVIDER is inert in M9a

`CDC_EXT_PROVIDER` values are exposed as inert parsed metadata only. The implementation does not perform network access, does not contact external CAS providers, and does not attempt provider-driven recipe resolution in M9a.

### Delta Base Hash is opaque — do not assume a hash algorithm (M9b)

The LFH `Delta Base Hash` field is a 32-byte opaque value. The spec does not define a hash algorithm identifier for this field. This implementation:

- preserves the 32 bytes without interpretation;
- does **not** assume BLAKE3, SHA-256, or any other algorithm;
- does **not** verify the base object against this field;
- treats an all-zero `Delta Base Hash` as "no base recorded" for BSDIFF and VCDIFF (returns `SAR_ERR_BASE_MISSING`);
- accepts any `Delta Base Hash` value for `STORE_PATCH` (base not required).

Implementations MUST NOT hard-code a hash algorithm for `Delta Base Hash` verification until the spec normatively defines the algorithm encoding for this field.

### STORE_PATCH application security properties

`STORE_PATCH` (`0x00`) is implemented with the following security properties:

- **No unchecked allocation:** `Uncompressed Size` is checked against `ResourceLimits.max_decoded_entry_size` before any allocation. Oversized payloads return `SAR_ERR_LIMIT_EXCEEDED` without allocating.
- **No unchecked arithmetic:** all length comparisons use `u64` checked equality; no cast-narrowing.
- **No panic on malformed input:** length mismatch returns `SAR_ERR_PATCH_FAILED`; allocation failure is not possible due to the pre-allocation limit check.
- **No base object access:** `STORE_PATCH` requires no base object; no file access, URI resolution, or external lookup is performed.
- **`LOSS_TOLERANT` does not suppress errors:** `SAR_ERR_PATCH_FAILED` is always propagated regardless of `LOSS_TOLERANT` semantics.

### BSDIFF and VCDIFF patch application security properties

`BSDIFF` (`0x02`, SAR BSDIFF v1 `SARBSD01`) and `VCDIFF` (`0x01`, RFC 3284) are implemented with the following security properties:

- **All operations are bounded by `ResourceLimits`:** BSDIFF block sizes, VCDIFF instruction counts, VCDIFF window counts, and output size are capped. `SAR_ERR_LIMIT_EXCEEDED` is returned before any oversized allocation.
- **No automatic base discovery:** the caller must supply base bytes explicitly via `ArchiveReaderOptions.delta_base`. No file access, network access, CAS lookup, or URI resolution is performed.
- **All-zero `Delta Base Hash` → `SAR_ERR_BASE_MISSING`:** prevents silent use of a wrong base when no base was recorded.
- **Missing base → `SAR_ERR_BASE_MISSING`:** if `delta_base` is not supplied, the error is immediate, not a silent corrupt reconstruction.
- **Negative field rejection (BSDIFF):** negative `Control_Block_Length`, `Diff_Block_Length`, `New_File_Size`, `diff_len`, or `extra_len` values → `SAR_ERR_PATCH_FAILED`.
- **Seek-before-zero rejection (BSDIFF):** `old_pos < 0` after seek → `SAR_ERR_PATCH_FAILED`.
- **Block overread protection (BSDIFF):** diff and extra block reads are bounds-checked against decoded payload block sizes.
- **Trailing-byte rejection (BSDIFF):** trailing unused Diff/Extra bytes return `SAR_ERR_PATCH_FAILED`.
- **Output size mismatch rejection:** `New_File_Size` (BSDIFF) or reconstructed output (VCDIFF) must exactly equal LFH `Uncompressed Size`; any mismatch → `SAR_ERR_PATCH_FAILED`.
- **No use of C FFI in VCDIFF:** VCDIFF decoding is pure Rust.
- **Unsupported VCDIFF secondary compression:** VCDIFF streams requiring secondary compressors return `SAR_ERR_UNSUPPORTED`.
- **No hidden BSDIFF decompression layer:** SAR BSDIFF v1 uses uncompressed Control/Diff/Extra blocks; archive compression remains solely in the SAR compression layer.
- **Legacy `BSDIFF40` decode path:** not implemented; `BSDIFF40` magic is rejected as `SAR_ERR_PATCH_FAILED`.
- **`LOSS_TOLERANT` does not suppress `SAR_ERR_PATCH_FAILED`.**

### Reserved and unsupported patch algorithm IDs fail closed

- Reserved IDs (`0x04–0xEF`) → `SarError::ReservedValue`
- Custom IDs (`0xF0–0xFF`) → `SarError::Unsupported`
- `ZSTD_PATCH` (`0x03`) → `SarError::Unsupported` (dictionary protocol not specified)

No fallback behavior is attempted for unknown patch algorithms.
