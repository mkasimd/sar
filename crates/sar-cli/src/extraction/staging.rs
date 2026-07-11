use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sar_core::{ResourceLimits, SarError, sparse::SparseExtent};
use sar_sparse::validate_sparse_extents;

const ZERO_CHUNK_LEN: usize = 8192;

pub(crate) fn write_bytes_via_temp(out_path: &Path, data: &[u8]) -> Result<(), SarError> {
    let tmp_path = make_temp_output_path(out_path)?;
    let result = (|| -> Result<(), SarError> {
        let mut file = open_temp_file(&tmp_path)?;
        file.write_all(data)?;
        drop(file);
        finalize_temp_file(&tmp_path, out_path)
    })();
    if result.is_err() {
        remove_temp_file_if_exists(&tmp_path);
    }
    result
}

pub(crate) fn write_sparse_payload_via_temp(
    out_path: &Path,
    payload: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<(), SarError> {
    limits.check_decoded_entry_size(logical_size)?;
    validate_sparse_extents(extents, logical_size, &limits.sparse_limits())?;
    let tmp_path = make_temp_output_path(out_path)?;
    let result = (|| -> Result<(), SarError> {
        let mut file = open_temp_file(&tmp_path)?;
        file.set_len(logical_size)?;

        let mut payload_pos = 0usize;
        for extent in extents {
            let dst_offset = extent.offset;
            let len =
                usize::try_from(extent.length).map_err(|_| SarError::Overflow("extent length"))?;
            let src_end = payload_pos
                .checked_add(len)
                .ok_or(SarError::Overflow("payload position"))?;
            if src_end > payload.len() {
                return Err(SarError::Truncated(
                    "payload too short for declared sparse extents",
                ));
            }
            file.seek(SeekFrom::Start(dst_offset))?;
            file.write_all(&payload[payload_pos..src_end])?;
            payload_pos = src_end;
        }
        if payload_pos != payload.len() {
            return Err(SarError::InvalidMap(
                "sparse payload has excess bytes beyond declared extents",
            ));
        }
        drop(file);
        finalize_temp_file(&tmp_path, out_path)
    })();
    if result.is_err() {
        remove_temp_file_if_exists(&tmp_path);
    }
    result
}

pub(crate) fn compute_sparse_crc32(
    payload: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<u32, SarError> {
    limits.check_decoded_entry_size(logical_size)?;
    validate_sparse_extents(extents, logical_size, &limits.sparse_limits())?;
    let mut hasher = crc32fast::Hasher::new();
    let zero_chunk = [0u8; ZERO_CHUNK_LEN];
    let mut payload_pos = 0usize;
    let mut cursor = 0u64;

    for extent in extents {
        let gap = extent
            .offset
            .checked_sub(cursor)
            .ok_or(SarError::Overflow("sparse hole length"))?;
        hash_zero_bytes(&mut hasher, gap, &zero_chunk);
        let len =
            usize::try_from(extent.length).map_err(|_| SarError::Overflow("extent length"))?;
        let src_end = payload_pos
            .checked_add(len)
            .ok_or(SarError::Overflow("payload position"))?;
        if src_end > payload.len() {
            return Err(SarError::Truncated(
                "payload too short for declared sparse extents",
            ));
        }
        hasher.update(&payload[payload_pos..src_end]);
        payload_pos = src_end;
        cursor = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SarError::Overflow("sparse extent offset+length overflow"))?;
    }

    let trailing = logical_size
        .checked_sub(cursor)
        .ok_or(SarError::Overflow("trailing sparse hole length"))?;
    hash_zero_bytes(&mut hasher, trailing, &zero_chunk);

    if payload_pos != payload.len() {
        return Err(SarError::InvalidMap(
            "sparse payload has excess bytes beyond declared extents",
        ));
    }

    Ok(hasher.finalize())
}

pub(crate) fn verify_crc32(
    expected_crc: Option<u32>,
    actual_crc: u32,
    message: &'static str,
) -> Result<(), SarError> {
    if let Some(expected_crc) = expected_crc
        && expected_crc != actual_crc
    {
        return Err(SarError::CrcMismatch(message));
    }
    Ok(())
}

fn make_temp_output_path(final_path: &Path) -> Result<PathBuf, SarError> {
    let file_name = final_path
        .file_name()
        .ok_or(SarError::Malformed("output file name is missing"))?
        .to_string_lossy();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SarError::Internal("system clock before unix epoch"))?
        .as_nanos();
    Ok(final_path.with_file_name(format!(
        ".{file_name}.sar-tmp-{}-{nonce}",
        std::process::id()
    )))
}

fn open_temp_file(tmp_path: &Path) -> Result<File, SarError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)
        .map_err(SarError::Io)
}

fn remove_temp_file_if_exists(path: &Path) {
    let _ = fs::remove_file(path);
}

fn finalize_temp_file(tmp_path: &Path, final_path: &Path) -> Result<(), SarError> {
    match fs::rename(tmp_path, final_path) {
        Ok(()) => Ok(()),
        Err(err) => {
            remove_temp_file_if_exists(tmp_path);
            Err(SarError::Io(err))
        }
    }
}

fn hash_zero_bytes(
    hasher: &mut crc32fast::Hasher,
    mut len: u64,
    zero_chunk: &[u8; ZERO_CHUNK_LEN],
) {
    while len > 0 {
        let chunk_len = len.min(ZERO_CHUNK_LEN as u64) as usize;
        hasher.update(&zero_chunk[..chunk_len]);
        len -= chunk_len as u64;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sar_core::SarError;
    use tempfile::tempdir;

    use super::open_temp_file;

    #[test]
    fn open_temp_file_refuses_existing_path() {
        let td = tempdir().expect("tmp");
        let path = td.path().join(".file.tmp");
        fs::write(&path, b"existing").expect("write");
        let err = open_temp_file(&path).expect_err("existing path should fail");
        assert!(matches!(
            err,
            SarError::Io(ref io_err) if io_err.kind() == std::io::ErrorKind::AlreadyExists
        ));
    }
}
