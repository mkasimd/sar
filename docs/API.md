# API (Milestones 1–4)

## `sar-core`

Primary APIs:

- `ArchiveReader<R: Read + Seek>`
  - `new(reader)`
  - `with_options(reader, ArchiveReaderOptions)`
  - `read_global_header()`
  - `next_entry()`
  - `verify()`
- `ArchiveWriter<W: Write>`
  - `new(writer, options)`
  - `new_with_compression(writer, options, CompressionSettings)`
  - `add_entry(entry)`
  - `finish()`

Transform APIs:

- `EncoderTransform` / `DecoderTransform`
- `CompressionEncoderTransform` / `CompressionDecoderTransform`
- `encode_payload` / `decode_payload`

Format/parser APIs:

- `parse_global_header`, `write_global_header`
- `parse_lfh`, `write_lfh`, `compute_lfh_size`
- `parse_central_dictionary`, `write_central_dictionary`
- `parse_footer`, `write_footer`
- `parse_tlvs`, `write_tlvs`

Validation APIs:

- `validate_global_flags`
- `validate_entry_mode_against_global`
- `validate_archive_profile`

Section 10 registry APIs:

- `SarStatus` (full status/error/warning registry mapping with stable numeric codes)
- `SarError::status()`
- `TryFrom<i32> for SarStatus`

## `sar-cli`

Thin CLI wrapper over `sar-core` archive APIs for create/extract/list/verify/inspect/version and shorthand aliases, including compression options:

- `--compression store|deflate|zstd`
- `-S` / `-z` / `-Z`
- `--compression-level 0..9` or `-0..-9`
