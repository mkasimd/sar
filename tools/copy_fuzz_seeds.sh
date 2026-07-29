#!/usr/bin/env bash
set -euo pipefail

copy_seeds() {
  local target="$1"
  shift

  mkdir -p "fuzz/corpus/${target}"

  for seed_dir in "$@"; do
    if compgen -G "fuzz/seeds/${seed_dir}/*.bin" > /dev/null; then
      cp "fuzz/seeds/${seed_dir}"/*.bin "fuzz/corpus/${target}/"
    fi
  done
}

# M12b.2 / parser targets
copy_seeds parse_global_header \
  parse_global_header \
  archive_structural \
  metadata_edge_cases

copy_seeds parse_lfh \
  parse_lfh \
  fec_fragmentation \
  metadata_edge_cases \
  filesystem_metadata_malformed

copy_seeds parse_tlv \
  parse_tlv \
  cdc_delta \
  metadata_edge_cases \
  fec_fragmentation

copy_seeds parse_cd_footer \
  parse_cd_footer \
  archive_audit \
  metadata_edge_cases

# M12b.3 / archive targets
copy_seeds archive_structural \
  archive_structural \
  archive_entry_decode \
  archive_audit \
  transform_pipeline \
  transform_switching_dos \
  fec_fragmentation \
  cdc_delta \
  metadata_edge_cases \
  filesystem_metadata_malformed

copy_seeds archive_entry_decode \
  archive_entry_decode \
  transform_pipeline \
  transform_switching_dos \
  fec_fragmentation \
  cdc_delta \
  metadata_edge_cases \
  filesystem_metadata_malformed

copy_seeds archive_audit \
  archive_audit \
  transform_switching_dos \
  cdc_delta \
  metadata_edge_cases \
  filesystem_metadata_malformed \
  fec_fragmentation

# M12b.3 / stream target
copy_seeds stream_transcript \
  stream_transcript \
  stream_session

# M12b.5 PR2
copy_seeds transform_pipeline_fuzz \
  transform_pipeline \
  transform_switching_dos \
  decompression_bomb \
  allocator_churn

# M12b.5 PR3
copy_seeds crypto_auth_tls_exporter_negative \
  crypto_auth_ordering \
  tls_exporter_aad_negative

# M12b.5 PR4
copy_seeds archive_logical_files \
  fec_fragmentation \
  cdc_delta \
  filesystem_metadata_malformed \
  metadata_edge_cases

copy_seeds pr4_lfh_metadata_edges \
  parse_lfh \
  fec_fragmentation \
  metadata_edge_cases \
  filesystem_metadata_malformed \
  cdc_delta

copy_seeds pr4_tlv_metadata_edges \
  parse_tlv \
  cdc_delta \
  metadata_edge_cases \
  fec_fragmentation

# M12b.5 PR5
# extraction_race seeds: multi-entry, path-ordering, traversal, and symlink shapes.
# Consumed by archive entry-walking and audit targets.
copy_seeds archive_entry_decode \
  extraction_race

copy_seeds archive_audit \
  extraction_race

copy_seeds archive_logical_files \
  extraction_race

# profile_rejection seeds: header-level version, reserved-byte, and flag-conflict shapes.
# Consumed by global-header and high-level structural targets.
copy_seeds parse_global_header \
  profile_rejection

copy_seeds archive_structural \
  profile_rejection

echo "Copied curated seeds into fuzz/corpus/"
