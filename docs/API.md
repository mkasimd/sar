# API (Milestones 1–3)

## `sar-core`

Primary APIs:

- `ArchiveReader<R: Read + Seek>`
  - `new(reader)`
  - `read_global_header()`
  - `next_entry()`
  - `verify()`
- `ArchiveWriter<W: Write>`
  - `new(writer, options)`
  - `add_entry(entry)`
  - `finish()`

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

## `sar-cli`

Thin CLI wrapper over `sar-core` archive APIs for create/extract/list/verify/inspect/version and shorthand aliases.
