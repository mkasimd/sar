// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

//! Builds a structurally valid archive whose CDC_MAP and Recipe are derived
//! from fuzz input (valid chunk hashes unless a mutation selector corrupts a
//! record) and drives archive-level Recipe resolution.  The raw input is also
//! fed to the reader so malformed maps in arbitrary archives are reached.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use sar_archive::{ArchiveReader, ArchiveReaderOptions};
use sar_core::{
    GlobalFlags, ResourceLimits, compute_cdc_chunk_hash,
    format::{
        CentralDictionary, Footer, GlobalHeader, LocalFileHeader, write_central_dictionary,
        write_footer, write_global_header, write_lfh,
    },
    tlv::Tlv,
};

fn limits() -> ResourceLimits {
    ResourceLimits {
        max_archive_size: 64 * 1024,
        max_entry_count: 16,
        max_decoded_entry_size: 32 * 1024,
        max_in_memory_buffer: 32 * 1024,
        max_total_pipeline_memory: 128 * 1024,
        max_cdc_chunk_count: 4,
        max_cdc_metadata_bytes: 8 * 1024,
        ..ResourceLimits::default()
    }
}

fn lfh(flags: &GlobalFlags, name: &[u8], cdc: u8, len: usize) -> Vec<u8> {
    let mut l = LocalFileHeader::minimal_store(name.to_vec(), len as u64);
    l.cdc_algo_id = Some(cdc);
    write_lfh(flags, &l).expect("lfh")
}

fn build(data: &[u8]) -> Option<Vec<u8>> {
    let (&sel, rest) = data.split_first()?;
    let (&mutation, rest) = rest.split_first()?;
    let alg = [0x30u8, 0x31, 0x32, 0x77][usize::from(sel & 3)];
    let count = usize::from(sel >> 2 & 7) + 1;
    let step = (rest.len() / count).max(1);
    let chunks: Vec<&[u8]> = rest.chunks(step).take(count).collect();
    if chunks.is_empty() {
        return None;
    }
    let store: Vec<u8> = chunks.concat();

    let flags = GlobalFlags::CDC_SUPPORT | GlobalFlags::OPT_PRESENT;
    let mut out = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .ok()?;
    let mut offsets = vec![out.len() as u64];
    let store_lfh = lfh(&flags, b"s", 0, store.len());
    let base = (out.len() + store_lfh.len()) as u64;
    out.extend_from_slice(&store_lfh);
    out.extend_from_slice(&store);

    let mut records = Vec::new();
    let mut recipe = Vec::new();
    let mut off = base;
    for c in &chunks {
        let h = compute_cdc_chunk_hash(if alg == 0x31 { 0x31 } else { 0x30 }, c).ok()?;
        records.push((h, off, u32::try_from(c.len()).ok()?));
        recipe.extend_from_slice(&h);
        off += c.len() as u64;
    }
    match mutation % 8 {
        1 => records[0].1 = records[0].1.wrapping_sub(u64::from(mutation)),
        2 => records[0].2 = records[0].2.wrapping_add(u32::from(mutation)),
        3 => records.push((records[0].0, records[0].1 + 1, records[0].2)),
        4 => {
            records.pop();
        }
        5 => recipe.push(mutation),
        6 => records[0].1 = u64::MAX - u64::from(mutation),
        _ => {}
    }
    let mut map = vec![1, alg, 0, 0];
    map.extend_from_slice(&u32::try_from(records.len()).ok()?.to_le_bytes());
    map.extend_from_slice(&48u16.to_le_bytes());
    map.extend_from_slice(&[0; 6]);
    for (h, o, s) in &records {
        let part = if mutation % 8 == 7 { 1u32 } else { 0 };
        map.extend_from_slice(h);
        map.extend_from_slice(&part.to_le_bytes());
        map.extend_from_slice(&o.to_le_bytes());
        map.extend_from_slice(&s.to_le_bytes());
    }

    offsets.push(out.len() as u64);
    out.extend_from_slice(&lfh(&flags, b"r", 0x02, recipe.len()));
    out.extend_from_slice(&recipe);
    let cd_offset = out.len() as u64;
    let cd = CentralDictionary {
        version: 1,
        file_count: 2,
        global_crc32: None,
        metadata: vec![Tlv {
            type_id: 0x40,
            value: map,
        }],
        offsets,
    };
    out.extend_from_slice(&write_central_dictionary(&cd, flags).ok()?);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&write_footer(Footer { cd_offset }));
    Some(out)
}

fn reader(bytes: &[u8]) -> Option<ArchiveReader<Cursor<&[u8]>>> {
    let options = ArchiveReaderOptions {
        limits: limits(),
        ..ArchiveReaderOptions::default()
    };
    ArchiveReader::with_options(Cursor::new(bytes), options).ok()
}

fn exercise(bytes: &[u8]) {
    for lossy in [false, true] {
        if let Some(mut r) = reader(bytes) {
            let _ = r.read_all_logical_files(lossy);
        }
    }
    if let Some(mut r) = reader(bytes) {
        let _ = r.verify();
    }
}

fuzz_target!(|data: &[u8]| {
    if let Some(archive) = build(data) {
        exercise(&archive);
    }
    exercise(data);
});
