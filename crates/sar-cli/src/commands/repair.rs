// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::{fs, fs::File, io::BufReader, path::PathBuf};

use sar_archive::{
    ArchiveReader, ErasureInput, inspect_recovery_metadata, plan_archive_repair, repair_archive,
};
use sar_core::{ResourceLimits, SarError};

#[cfg(not(unix))]
use crate::commands::repair_output::require_secure_output_backend;
use crate::commands::{read_file_with_archive_limit, repair_output::write_verified_output};

pub(crate) fn repair_cmd(
    archive: PathBuf,
    output: PathBuf,
    fec: bool,
    erasures_path: Option<PathBuf>,
    limits: ResourceLimits,
) -> Result<(), SarError> {
    if !fec {
        return Err(SarError::Malformed("repair requires --fec"));
    }

    let erasures_file =
        erasures_path.ok_or(SarError::Malformed("repair requires --erasures <file>"))?;

    #[cfg(not(unix))]
    require_secure_output_backend()?;

    let erasures_bytes = fs::read(&erasures_file)?;
    let erasures: ErasureInput = serde_json::from_slice(&erasures_bytes)
        .map_err(|_| SarError::Malformed("failed to parse erasures JSON"))?;

    let archive_bytes = read_file_with_archive_limit(&archive, &limits)?;

    let rec_meta = inspect_recovery_metadata(&archive_bytes, &limits)?;
    if !rec_meta.repair_possible {
        let reason = rec_meta
            .repair_unavailable_reason
            .unwrap_or("repair unavailable");
        eprintln!("repair: recovery unavailable — {reason}");
        return Err(SarError::RecoveryUnavailable(
            "archive-level repair is unavailable for this archive",
        ));
    }

    let plan = match plan_archive_repair(&archive_bytes, erasures, &limits) {
        Ok(plan) => plan,
        Err(SarError::RecoveryUnavailable(msg)) => {
            eprintln!("repair: planning failed — {msg}");
            return Err(SarError::RecoveryUnavailable(msg));
        }
        Err(err) => return Err(err),
    };

    let (repaired_bytes, report) = match repair_archive(&archive_bytes, &plan, &limits) {
        Ok(pair) => pair,
        Err(SarError::EcFailed(msg)) => {
            eprintln!("repair: FEC repair failed (too many erasures) — {msg}");
            return Err(SarError::EcFailed(msg));
        }
        Err(SarError::RecoveryUnavailable(msg)) => {
            eprintln!("repair: recovery unavailable — {msg}");
            return Err(SarError::RecoveryUnavailable(msg));
        }
        Err(err) => return Err(err),
    };

    let mut verify = |staged: &File| -> Result<(), SarError> {
        let mut re_reader = ArchiveReader::new(BufReader::new(staged.try_clone()?))?;
        let _ = re_reader.read_global_header()?;
        re_reader.verify()?;
        Ok(())
    };
    if let Err(err) = write_verified_output(&output, &repaired_bytes, &mut verify) {
        eprintln!("repair: output not published: {err}");
        return Err(err);
    }

    println!(
        "repair: success repaired_ranges={} degraded={}",
        report.repaired_ranges.len(),
        report.degraded
    );
    Ok(())
}
