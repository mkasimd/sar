// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! `repair` output staging and publication (`M13-EXTRACT-007`). The Unix tests
//! drive the real binary against a minimal global-EC archive; the race and
//! failure-injection cases live next to the implementation.

#![cfg(unix)]

use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::str::contains;
use sar_core::{
    GlobalFlags,
    format::{
        CentralDictionary, Footer, GlobalHeader, write_central_dictionary, write_footer,
        write_global_header,
    },
    tlv::Tlv,
};
use tempfile::tempdir;

fn global_ec_archive() -> Vec<u8> {
    let flags = GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT;
    let header = GlobalHeader {
        version: 0x01,
        flags,
        kms: None,
    };
    let header_bytes = write_global_header(&header).expect("header");
    let cd_offset = u64::try_from(header_bytes.len()).expect("len");
    let protected_len = cd_offset - 8;
    let stripes = protected_len.div_ceil(256);
    let mut value = vec![1u8, 0x00];
    value.extend_from_slice(&protected_len.to_le_bytes());
    value.extend_from_slice(&u32::try_from(stripes).expect("stripes").to_le_bytes());
    value.extend(vec![0u8; usize::try_from(stripes * 256).expect("parity")]);
    let cd = CentralDictionary {
        version: 0x01,
        file_count: 0,
        global_crc32: None,
        metadata: vec![Tlv {
            type_id: 0x14,
            value,
        }],
        offsets: Vec::new(),
    };
    let mut archive = header_bytes;
    archive.extend_from_slice(&write_central_dictionary(&cd, flags).expect("cd"));
    archive.extend_from_slice(&write_footer(Footer { cd_offset }));
    archive
}

fn repair(dir: &Path, output: &Path) -> assert_cmd::assert::Assert {
    let archive = dir.join("in.sar");
    if !archive.exists() {
        fs::write(&archive, global_ec_archive()).expect("archive");
    }
    let erasures = dir.join("erasures.json");
    fs::write(&erasures, br#"{"entries":[],"archive_ranges":[]}"#).expect("erasures");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .arg("repair")
        .arg(&archive)
        .arg(output)
        .args(["--fec", "--erasures"])
        .arg(&erasures)
        .assert()
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn symlink_at_former_tmp_name_is_not_followed() {
        let td = tempdir().expect("tmp");
        let victim = td.path().join("victim");
        fs::write(&victim, b"victim").expect("write");
        let out = td.path().join("out.sar");
        let legacy = td.path().join("out.sar.tmp");
        symlink(&victim, &legacy).expect("symlink");

        repair(td.path(), &out)
            .success()
            .stdout(contains("repair: success"));

        assert_eq!(fs::read(&victim).expect("read"), b"victim");
        assert!(
            fs::symlink_metadata(&legacy)
                .expect("meta")
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&out).expect("read"), global_ec_archive());
    }

    #[test]
    fn ordinary_file_at_former_tmp_name_is_untouched() {
        let td = tempdir().expect("tmp");
        let out = td.path().join("out.sar");
        fs::write(td.path().join("out.sar.tmp"), b"keep me").expect("write");

        repair(td.path(), &out).success();

        assert_eq!(
            fs::read(td.path().join("out.sar.tmp")).expect("read"),
            b"keep me"
        );
        assert_eq!(fs::read(&out).expect("read"), global_ec_archive());
    }

    #[test]
    fn existing_output_is_replaced_and_destination_symlink_is_not_followed() {
        let td = tempdir().expect("tmp");
        let out = td.path().join("out.sar");
        fs::write(&out, b"old").expect("write");
        repair(td.path(), &out).success();
        assert_eq!(fs::read(&out).expect("read"), global_ec_archive());

        let victim = td.path().join("victim");
        fs::write(&victim, b"victim").expect("write");
        let linked = td.path().join("linked.sar");
        symlink(&victim, &linked).expect("symlink");
        repair(td.path(), &linked).success();
        assert_eq!(fs::read(&victim).expect("read"), b"victim");
        assert_eq!(fs::read(&linked).expect("read"), global_ec_archive());
        assert!(
            !fs::symlink_metadata(&linked)
                .expect("meta")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn failed_repair_leaves_no_staging_file() {
        let td = tempdir().expect("tmp");
        let out = td.path().join("out.sar");
        fs::create_dir(&out).expect("dir");
        repair(td.path(), &out)
            .failure()
            .stderr(contains("output not published"));
        let mut names: Vec<_> = fs::read_dir(td.path())
            .expect("dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["erasures.json", "in.sar", "out.sar"]);
    }
}
