use std::{fs, fs::File, io::BufReader, path::PathBuf};

use sar_archive::{ArchiveReader, ErasureInput, inspect_recovery_metadata, plan_archive_repair, repair_archive};
use sar_core::{ResourceLimits, SarError};

use crate::commands::read_file_with_archive_limit;

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

    let tmp_path = PathBuf::from(format!("{}.tmp", output.display()));
    if let Err(err) = fs::write(&tmp_path, &repaired_bytes) {
        eprintln!("repair: failed to write temp file: {err}");
        return Err(SarError::Io(err));
    }

    let verify_result = (|| -> Result<(), SarError> {
        let mut re_reader = ArchiveReader::new(BufReader::new(File::open(&tmp_path)?))?;
        let _ = re_reader.read_global_header()?;
        re_reader.verify()?;
        Ok(())
    })();

    if let Err(err) = verify_result {
        eprintln!("repair: temp file verification failed: {err}");
        if let Err(rm_err) = fs::remove_file(&tmp_path) {
            eprintln!(
                "repair: warning: could not remove temp file {}: {rm_err}",
                tmp_path.display()
            );
        }
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, &output) {
        if let Err(rm_err) = fs::remove_file(&tmp_path) {
            eprintln!(
                "repair: warning: could not remove temp file {}: {rm_err}",
                tmp_path.display()
            );
        }
        return Err(SarError::Io(err));
    }

    println!(
        "repair: success repaired_ranges={} degraded={}",
        report.repaired_ranges.len(),
        report.degraded
    );
    Ok(())
}
