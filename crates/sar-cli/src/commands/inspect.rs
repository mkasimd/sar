// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::{fs::File, io::BufReader, path::PathBuf};

use serde_json::json;

use sar_archive::ArchiveReader;
use sar_core::{GlobalFlags, ResourceLimits, SarError, fec::validate_recovery_tlv};
use sar_delta::{PATCH_ALGO_STORE_PATCH, patch_algo_name};

use crate::commands::entry_kind_label;

struct CdcMetadataInspectRow {
    type_id: u8,
    value_len: usize,
    kind: &'static str,
    record_count: Option<usize>,
    uri: Option<String>,
}

pub(crate) fn inspect_archive(archive: PathBuf, as_json: bool) -> Result<(), SarError> {
    let limits = ResourceLimits::default();
    let mut reader = ArchiveReader::new(BufReader::new(File::open(&archive)?))?;
    let header = reader.read_global_header()?;

    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        entries.push(entry.metadata);
    }

    let metadata = reader.metadata();
    let has_global_ec = header.flags.contains(GlobalFlags::HAS_GLOBAL_EC);
    let cdc_support = header.flags.contains(GlobalFlags::CDC_SUPPORT);
    let has_delta = header.flags.contains(GlobalFlags::HAS_DELTA);

    let recovery_tlvs_raw: Vec<_> = metadata
        .as_ref()
        .and_then(|m| m.central_dictionary.as_ref())
        .map(|cd| {
            cd.metadata
                .iter()
                .filter(|tlv| (0x10..=0x1F).contains(&tlv.type_id))
                .map(|tlv| {
                    let summary = validate_recovery_tlv(tlv.type_id, &tlv.value, &limits).ok();
                    (tlv.type_id, tlv.value.len(), summary)
                })
                .collect()
        })
        .unwrap_or_default();

    let cdc_metadata_tlvs_raw: Vec<CdcMetadataInspectRow> = if let Some(cd) = metadata
        .as_ref()
        .and_then(|m| m.central_dictionary.as_ref())
    {
        let mut out = Vec::new();
        for tlv in &cd.metadata {
            if !sar_core::is_cdc_metadata_tlv_type(tlv.type_id) {
                continue;
            }

            match tlv.type_id {
                sar_core::TLV_CDC_MAP => {
                    let record_count =
                        sar_core::parse_entry_cdc_map(std::slice::from_ref(tlv), &limits)?
                            .map_or(0, |map| map.records.len());
                    out.push(CdcMetadataInspectRow {
                        type_id: tlv.type_id,
                        value_len: tlv.value.len(),
                        kind: "cdc_map",
                        record_count: Some(record_count),
                        uri: None,
                    });
                }
                sar_core::TLV_CDC_EXT_PROVIDER => {
                    let provider = sar_core::parse_cdc_ext_provider_tlv(tlv, &limits)?;
                    out.push(CdcMetadataInspectRow {
                        type_id: tlv.type_id,
                        value_len: tlv.value.len(),
                        kind: "cdc_ext_provider",
                        record_count: None,
                        uri: Some(provider.uri),
                    });
                }
                sar_core::TLV_CDC_CUSTOM => {
                    sar_core::validate_cdc_metadata_tlv(tlv, &limits)?;
                    out.push(CdcMetadataInspectRow {
                        type_id: tlv.type_id,
                        value_len: tlv.value.len(),
                        kind: "cdc_custom",
                        record_count: None,
                        uri: None,
                    });
                }
                _ => unreachable!("non-CDC TLV filtered earlier"),
            }
        }
        out
    } else {
        Vec::new()
    };

    let repair_possible = has_global_ec && !recovery_tlvs_raw.is_empty();

    if as_json {
        let recovery_tlvs_json: Vec<serde_json::Value> = recovery_tlvs_raw
            .iter()
            .map(|(type_id, value_len, summary)| {
                json!({
                    "type_id": format!("0x{type_id:02X}"),
                    "value_len": value_len,
                    "summary": summary,
                })
            })
            .collect();

        let cdc_metadata_tlvs_json: Vec<serde_json::Value> = cdc_metadata_tlvs_raw
            .iter()
            .map(|row| {
                let mut value = json!({
                    "type_id": format!("0x{:02X}", row.type_id),
                    "kind": row.kind,
                    "value_len": row.value_len,
                });
                if let Some(record_count) = row.record_count {
                    value["record_count"] = json!(record_count);
                    value["portability"] = json!("implementation-defined");
                }
                if let Some(uri) = &row.uri {
                    value["uri"] = json!(uri);
                    value["resolution"] = json!("not_implemented");
                }
                if row.kind == "cdc_custom" {
                    value["handling"] = json!("parsed_preserved_only");
                }
                value
            })
            .collect();
        let cdc_map_tlvs_json: Vec<_> = cdc_metadata_tlvs_json
            .iter()
            .filter(|value| value["kind"] == "cdc_map")
            .cloned()
            .collect();

        let entries_json: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| {
                let sparse_extent_count = entry.sparse_extents.as_ref().map_or(0, Vec::len);
                let mut val = serde_json::to_value(entry).unwrap_or(json!({}));
                if let Some(obj) = val.as_object_mut() {
                    obj.insert(
                        "kind".to_string(),
                        json!(entry_kind_label(entry.entry_kind)),
                    );
                    obj.insert(
                        "sparse_extent_count".to_string(),
                        json!(sparse_extent_count),
                    );
                    if let Some(owner) = entry.owner {
                        obj.insert("uid".to_string(), json!(owner.uid()));
                        obj.insert("gid".to_string(), json!(owner.gid()));
                    }
                    if let Some(algo_id) = entry.patch_algo_id {
                        obj.insert(
                            "patch_algorithm".to_string(),
                            json!(patch_algo_name(algo_id)),
                        );
                    }
                }
                val
            })
            .collect();

        let output = json!({
            "global_version": header.version,
            "flags": header.flags.bits(),
            "flags_size": header.flags_bytes.len(),
            "indexed": !header.flags.contains(GlobalFlags::NO_INDEX),
            "selective_fec": header.flags.contains(GlobalFlags::SELECTIVE_FEC),
            "global_ec": has_global_ec,
            "fragmentation": header.flags.contains(GlobalFlags::FILE_FRAGMENTATION),
            "sparse_files": header.flags.contains(GlobalFlags::SPARSE_FILES),
            "cdc_support": cdc_support,
            "has_delta": has_delta,
            "entry_count": entries.len(),
            "recovery_tlvs": recovery_tlvs_json,
            "cdc_metadata_tlvs": cdc_metadata_tlvs_json,
            "cdc_map_tlvs": cdc_map_tlvs_json,
            "repair_possible": repair_possible,
            "entries": entries_json,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| SarError::Generic)?
        );
    } else {
        println!("global_version={}", header.version);
        println!("flags=0x{:08X}", header.flags.bits());
        println!(
            "selective_fec={}",
            header.flags.contains(GlobalFlags::SELECTIVE_FEC)
        );
        println!("global_ec={has_global_ec}");
        println!("cdc_support={cdc_support}");
        println!("has_delta={has_delta}");
        println!(
            "fragmentation={}",
            header.flags.contains(GlobalFlags::FILE_FRAGMENTATION)
        );
        println!(
            "sparse_files={}",
            header.flags.contains(GlobalFlags::SPARSE_FILES)
        );
        println!("entries={}", entries.len());
        println!("repair_possible={repair_possible}");
        if !cdc_metadata_tlvs_raw.is_empty() {
            println!("cdc_metadata_tlvs={}", cdc_metadata_tlvs_raw.len());
            for row in &cdc_metadata_tlvs_raw {
                match (row.kind, row.record_count, row.uri.as_deref()) {
                    ("cdc_map", Some(record_count), _) => println!(
                        "  cdc_map: type_id=0x{:02X} value_len={} record_count={record_count} portability=implementation-defined",
                        row.type_id, row.value_len
                    ),
                    ("cdc_ext_provider", _, Some(uri)) => println!(
                        "  cdc_ext_provider: type_id=0x{:02X} value_len={} uri={uri} resolution=not_implemented",
                        row.type_id, row.value_len
                    ),
                    ("cdc_custom", _, _) => println!(
                        "  cdc_custom: type_id=0x{:02X} value_len={} handling=parsed_preserved_only",
                        row.type_id, row.value_len
                    ),
                    _ => {}
                }
            }
        }
        for entry in &entries {
            if let Some(fec) = &entry.fec {
                let fec_line = match fec {
                    sar_core::fec::FecSummary::Xor {
                        stripe_size,
                        block_size,
                        parity_data_len,
                        ..
                    } => format!(
                        "algo=xor stripe_size={stripe_size} block_size={block_size} parity_bytes={parity_data_len}"
                    ),
                    sar_core::fec::FecSummary::ReedSolomon {
                        k,
                        parity_count,
                        symbol_size,
                        parity_data_len,
                        ..
                    } => format!(
                        "algo=reed-solomon k={k} parity_count={parity_count} symbol_size={symbol_size} parity_bytes={parity_data_len}"
                    ),
                };
                println!("  entry={} fec={}", entry.name, fec_line);
            }
            if entry.is_fragment {
                println!(
                    "  entry={} fragment_id={:?} fragment_index={:?} last={} loss_tolerant={}",
                    entry.name,
                    entry.fragment_id,
                    entry.fragment_index,
                    entry.is_last_fragment,
                    entry.is_loss_tolerant
                );
            }
            if let Some(extents) = &entry.sparse_extents {
                println!(
                    "  entry={} sparse_extent_count={}",
                    entry.name,
                    extents.len()
                );
            }
            if let Some(algo_id) = entry.cdc_algo_id {
                let name = sar_cdc::algo_name(algo_id);
                println!(
                    "  entry={} cdc_algo_id=0x{algo_id:02X} ({name})",
                    entry.name
                );
            }
            if let Some(algo_id) = entry.patch_algo_id {
                let name = patch_algo_name(algo_id);
                let status = if algo_id == PATCH_ALGO_STORE_PATCH {
                    "applied"
                } else {
                    "not_implemented"
                };
                println!(
                    "  entry={} patch_algo_id=0x{algo_id:02X} ({name}) application={status}",
                    entry.name
                );
            }
        }
        if !recovery_tlvs_raw.is_empty() {
            println!("recovery_tlvs={}", recovery_tlvs_raw.len());
        }
    }

    Ok(())
}
