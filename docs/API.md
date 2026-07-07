# API (Milestones 1–5)

## `sar-core`

Primary archive APIs:

- `ArchiveReader<R: Read + Seek>`
  - `new(reader)`
  - `with_options(reader, options)`
  - `with_key_provider(provider)`
  - `read_global_header()`
  - `next_entry()`
  - `verify()`
- `ArchiveWriter<W: Write>`
  - `new(writer, options)`
  - `new_with_compression(writer, options, compression)`
  - `new_with_compression_and_key_provider(writer, options, compression, provider)`
  - `add_entry(entry)`
  - `finish()`

Writer configuration:

- `ArchiveWriterOptions`
  - `no_index`
  - `encryption: Option<EncryptionSettings>`
- `CompressionSettings`
- `EncryptionSettings`
  - `algo_id`
  - `kms_params`

Transform APIs:

- `EncoderTransform` / `DecoderTransform`
- `CompressionEncoderTransform` / `CompressionDecoderTransform`
- `encode_payload` / `decode_payload`
- `encode_payload_v2` / `decode_payload_v2`
- `EntryCryptoContext`
- `EncodingPlanV2` / `DecodingPlanV2`

Format/parser helpers:

- `parse_global_header`, `write_global_header`
- `parse_lfh`, `write_lfh`, `compute_lfh_size`
- `global_header_flags_bytes`, `lfh_to_bytes`
- `parse_central_dictionary`, `write_central_dictionary`
- `parse_footer`, `write_footer`
- `parse_tlvs`, `write_tlvs`

## `sar-crypto`

Public building blocks:

- `SarCryptoError`
- Algorithm constants and validators
- `aead::{aead_encrypt, aead_decrypt, generate_nonce, validate_nonce_field}`
- `aad::{global_header_aad_bytes, build_aead_aad}`
- `hash::{sha256, blake3_hash, new_hasher, hash_data, ct_eq}`
- `kms::{Pbkdf2Params, Argon2Params, AsymmetricWrapParams, KmsParams}`
- `parse_kms_payload`, `serialize_kms_payload`
- `KeyProvider`, `resolve_cek`
- `SecretBytes`, `SecretString`

### `KeyProvider`

`KeyProvider` is the integration point for applications that need to supply:

- passwords for PBKDF2/Argon2 derivation;
- externally wrapped-key unwrap logic;
- pre-derived/external CEKs.

`sar-cli` provides a simple password-based implementation (`CliKeyProvider`). Applications embedding `sar-core` can implement their own provider for HSM/KMS-backed key resolution.

## `sar-cli`

Commands:

- `sar create <input> <output.sar> [--indexed|--no-index] [--compression ...] [--compression-level ...] [--encrypt aes256-gcm|xchacha20-poly] [--password ...]`
- `sar extract <archive.sar> <output-dir> [--password ...]`
- `sar list <archive.sar>`
- `sar verify <archive.sar> [--password ...]`
- `sar inspect <archive.sar> --json`
- `sar version`

If `--password` is omitted for encrypted create/extract/verify flows, the CLI falls back to `SAR_PASSWORD` and then to a terminal prompt.
