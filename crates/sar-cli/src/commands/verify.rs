use std::{fs::File, io::BufReader, path::PathBuf};

use sar_archive::{ArchiveReader, ArchiveReaderOptions, inspect_recovery_metadata};
use sar_core::{ResourceLimits, SarError, fec::validate_recovery_tlv, sparse::validate_sparse_extents};
use sar_fragmentation::{FragmentDescriptor, FragmentEntry, validate_fragment_group};

use crate::{commands::read_file_with_archive_limit, password::{CliKeyProvider, load_password}};

pub(crate) fn verify_archive(
    archive: PathBuf,
    password: Option<String>,
    recovery: bool,
    cdc: bool,
    limits: ResourceLimits,
) -> Result<(), SarError> {
    let mut reader = ArchiveReader::with_options(
        BufReader::new(File::open(&archive)?),
        ArchiveReaderOptions {
            limits,
            delta_base: None,
        },
    )?;
    let header = reader.read_global_header()?;
    let password = if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        Some(load_password(password)?)
    } else {
        None
    };
    if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        reader = reader.with_key_provider(Box::new(CliKeyProvider::new(password.clone())));
    }
    let report = reader.verify()?;
    println!(
        "verify: valid={} entries={} indexed={}",
        report.valid, report.entry_count, report.indexed
    );

    if cdc || report.cdc_support {
        println!(
            "verify: cdc_support={} cdc_entries={}",
            report.cdc_support, report.cdc_entry_count
        );
        if report.cdc_support && cdc {
            println!("verify: cdc_metadata_validation=pass");
            println!(
                "verify: recipe_hash_verification=unavailable (spec does not name the recipe hash algorithm)"
            );
        } else if cdc && !report.cdc_support {
            println!("verify: cdc_support=false (CDC_SUPPORT flag not set in archive)");
        }
    }

    if recovery {
        let mut re_reader = ArchiveReader::with_options(
            BufReader::new(File::open(&archive)?),
            ArchiveReaderOptions {
                limits,
                delta_base: None,
            },
        )?;
        let _ = re_reader.read_global_header()?;
        if password.is_some() {
            re_reader = re_reader.with_key_provider(Box::new(CliKeyProvider::new(password)));
        }
        let mut entries = Vec::new();
        while let Some(entry) = re_reader.next_entry()? {
            entries.push(entry.metadata);
        }

        let mut sparse_errors = 0u32;
        for entry in &entries {
            if entry.sparse_extents.as_ref().is_some_and(|ext| {
                validate_sparse_extents(ext, entry.uncompressed_size, &limits.sparse_limits())
                    .is_err()
            }) {
                eprintln!("recovery verify: sparse extent error in '{}'", entry.name);
                sparse_errors += 1;
            }
        }

        let mut frag_groups: std::collections::HashMap<u32, Vec<&sar_archive::EntryMetadata>> =
            std::collections::HashMap::new();
        for entry in &entries {
            if let (true, Some(fid)) = (entry.is_fragment, entry.fragment_id) {
                frag_groups.entry(fid).or_default().push(entry);
            }
        }

        let mut frag_errors = 0u32;
        for (fid, group) in &frag_groups {
            let frag_entries: Vec<FragmentEntry> = group
                .iter()
                .filter_map(|entry| {
                    let desc = entry.fragment_descriptor.as_ref()?;
                    Some(FragmentEntry {
                        fragment_index: entry.fragment_index.unwrap_or(0),
                        is_last_fragment: entry.is_last_fragment,
                        is_loss_tolerant: entry.is_loss_tolerant,
                        descriptor: FragmentDescriptor {
                            absolute_offset: desc.absolute_offset,
                            fragment_size: desc.fragment_size,
                        },
                        payload: Vec::new(),
                    })
                })
                .collect();

            let max_offset = frag_entries.iter().try_fold(0u64, |max_end, f| {
                let end = f
                    .descriptor
                    .absolute_offset
                    .checked_add(u64::from(f.descriptor.fragment_size))
                    .ok_or(SarError::Overflow("fragment descriptor end"))?;
                Ok::<u64, SarError>(max_end.max(end))
            })?;

            if let Err(err) = validate_fragment_group(&frag_entries, max_offset, &limits.fragment_limits()) {
                eprintln!("recovery verify: fragment group {fid} error: {err}");
                frag_errors += 1;
            }
        }

        let archive_bytes = read_file_with_archive_limit(&archive, &limits)?;
        let rec_meta = inspect_recovery_metadata(&archive_bytes, &limits)?;

        println!(
            "recovery verify: sparse_errors={sparse_errors} fragment_group_errors={frag_errors}"
        );
        println!(
            "recovery verify: has_global_ec={} recovery_tlv_count={} repair_possible={}",
            rec_meta.has_global_ec,
            rec_meta.recovery_tlvs.len(),
            rec_meta.repair_possible
        );
        if let Some(reason) = rec_meta.repair_unavailable_reason {
            println!("recovery verify: repair_unavailable_reason={reason}");
        }

        if sparse_errors > 0 || frag_errors > 0 {
            return Err(SarError::Malformed(
                "recovery metadata validation found errors",
            ));
        }

        for tlv in rec_meta.recovery_tlvs {
            let _ = validate_recovery_tlv(tlv.type_id, &tlv.value, &limits)?;
        }
    }

    Ok(())
}
