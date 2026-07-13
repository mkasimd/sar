// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::{fs::File, io::BufReader, path::PathBuf};

use sar_archive::ArchiveReader;
use sar_core::SarError;

use crate::commands::entry_kind_label;

pub(crate) fn list_archive(archive: PathBuf, show_metadata: bool) -> Result<(), SarError> {
    let mut reader = ArchiveReader::new(BufReader::new(File::open(archive)?))?;
    let _ = reader.read_global_header()?;
    while let Some(entry) = reader.next_entry()? {
        if show_metadata {
            let mut extras = Vec::new();
            if let Some(permissions) = entry.metadata.permissions {
                extras.push(format!("mode={:o}", permissions.mode));
            }
            if let Some(owner) = entry.metadata.owner {
                extras.push(format!("uid={} gid={}", owner.uid(), owner.gid()));
            }
            if let Some(timestamps) = entry.metadata.timestamps {
                extras.push(format!(
                    "mtime={} atime={} ctime={}",
                    timestamps.mtime, timestamps.atime, timestamps.ctime
                ));
            }
            if entry.metadata.is_hidden {
                extras.push("hidden=true".to_string());
            }
            if let Some(target) = entry.metadata.symlink_target.as_deref() {
                extras.push(format!("target={target}"));
            }
            println!(
                "{}\tkind={}\t{}\tencoded={}\tuncompressed={}{}",
                entry.metadata.name,
                entry_kind_label(entry.metadata.entry_kind),
                entry.metadata.compression_algorithm,
                entry.metadata.payload_size,
                entry.metadata.uncompressed_size,
                if extras.is_empty() {
                    String::new()
                } else {
                    format!("\t{}", extras.join("\t"))
                }
            );
        } else {
            let suffix = entry
                .metadata
                .symlink_target
                .as_deref()
                .map(|target| format!("\t-> {target}"))
                .unwrap_or_default();
            println!(
                "{}\tkind={}\t{}\tencoded={}\tuncompressed={}{}",
                entry.metadata.name,
                entry_kind_label(entry.metadata.entry_kind),
                entry.metadata.compression_algorithm,
                entry.metadata.payload_size,
                entry.metadata.uncompressed_size,
                suffix
            );
        }
    }
    Ok(())
}
