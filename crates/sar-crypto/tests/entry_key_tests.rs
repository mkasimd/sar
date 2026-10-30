// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Section 5.3.4 Entry-key derivation and Section 13.2.1 AAD known answers.

use zeroize::Zeroizing;

use sar_crypto::aad::build_aead_aad;
use sar_crypto::aead::{aead_decrypt, aead_encrypt};
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, SarCryptoError, derive_entry_key, hkdf_sha256_empty_salt,
    validate_entry_encr_algo_id,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn master() -> Zeroizing<Vec<u8>> {
    Zeroizing::new((0u8..32).collect())
}

fn aes_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..12].copy_from_slice(&[0x5C; 12]);
    n
}

fn iv() -> [u8; 24] {
    let mut iv = [0u8; 24];
    for (i, b) in iv.iter_mut().enumerate() {
        *b = 0xA0 + u8::try_from(i).expect("small");
    }
    iv
}

#[test]
fn hkdf_matches_rfc5869_case_3_empty_salt() {
    let okm = hkdf_sha256_empty_salt(&[0x0b; 22], b"", 42).expect("hkdf");
    assert_eq!(
        hex(&okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn entry_key_known_answers() {
    // Cross-checked against an independent HKDF-SHA256 implementation.
    let k = derive_entry_key(&master(), ENCR_AES256_GCM, &iv()).expect("aes key");
    assert_eq!(
        hex(&k),
        "2e518a4c7fa75b419901362807ca414a3d27a573be63e8b5e9e38bcf3f8efee2"
    );
    let k = derive_entry_key(&master(), ENCR_XCHACHA20_POLY, &iv()).expect("xchacha key");
    assert_eq!(
        hex(&k),
        "80b3c01a4c8ac668e4e3c65c0dc8cc3f3658c04b08c99fcaa3b57df848aaf99a"
    );
}

#[test]
fn entry_key_binds_algorithm_and_full_iv_field() {
    let base = derive_entry_key(&master(), ENCR_AES256_GCM, &iv()).expect("base");
    let mut other_iv = iv();
    other_iv[23] ^= 1; // reserved tail byte still participates
    let changed = derive_entry_key(&master(), ENCR_AES256_GCM, &other_iv).expect("iv");
    assert_ne!(base.as_slice(), changed.as_slice());
}

#[test]
fn master_secret_is_not_the_entry_key() {
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(&[9; 12]);
    let entry_key = derive_entry_key(&master(), ENCR_AES256_GCM, &nonce).expect("key");
    let ct = aead_encrypt(ENCR_AES256_GCM, &entry_key, &nonce, b"aad", b"plain").expect("enc");
    // Using the KMS Master Secret directly must not decrypt.
    let err = aead_decrypt(ENCR_AES256_GCM, &master(), &nonce, b"aad", &ct).expect_err("misuse");
    assert!(matches!(err, SarCryptoError::AuthFailed(_)));
    let pt = aead_decrypt(ENCR_AES256_GCM, &entry_key, &nonce, b"aad", &ct).expect("dec");
    assert_eq!(pt.as_slice(), b"plain");
}

#[test]
fn derivation_requires_32_byte_master_and_implemented_algorithm() {
    let short = Zeroizing::new(vec![0u8; 31]);
    assert!(matches!(
        derive_entry_key(&short, ENCR_AES256_GCM, &iv()),
        Err(SarCryptoError::InvalidLength(_))
    ));
    assert!(derive_entry_key(&master(), 0x00, &iv()).is_err());
    assert!(derive_entry_key(&master(), 0x02, &iv()).is_err());
}

#[test]
fn aad_binds_global_header_and_lfh() {
    let nonce = aes_nonce();
    let key = derive_entry_key(&master(), ENCR_AES256_GCM, &nonce).expect("key");
    let aad = build_aead_aad(b"GLOBAL-HEADER-WITH-KMS", b"LFH");
    let ct = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, &aad, b"x").expect("enc");
    for tampered in [
        build_aead_aad(b"GLOBAL-HEADER-WITH-KMt", b"LFH"),
        build_aead_aad(b"GLOBAL-HEADER-WITH-KMS", b"LFh"),
        build_aead_aad(b"GLOBAL-HEADER", b"LFH"),
    ] {
        assert!(matches!(
            aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &tampered, &ct),
            Err(SarCryptoError::AuthFailed(_))
        ));
    }
    aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &aad, &ct).expect("exact AAD");
}

#[test]
fn wrong_tag_and_wrong_nonce_fail_authentication() {
    let nonce = aes_nonce();
    let key = derive_entry_key(&master(), ENCR_AES256_GCM, &nonce).expect("key");
    let mut ct = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, b"a", b"data").expect("enc");
    let mut other = nonce;
    other[0] ^= 1;
    assert!(aead_decrypt(ENCR_AES256_GCM, &key, &other, b"a", &ct).is_err());
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(matches!(
        aead_decrypt(ENCR_AES256_GCM, &key, &nonce, b"a", &ct),
        Err(SarCryptoError::AuthFailed(_))
    ));
}

#[test]
fn entry_algorithm_registry_statuses() {
    assert!(matches!(
        validate_entry_encr_algo_id(0x00),
        Err(SarCryptoError::FlagConflict(_))
    ));
    assert!(validate_entry_encr_algo_id(0x01).is_ok());
    assert!(validate_entry_encr_algo_id(0x04).is_ok());
    for reserved in [0x02, 0x03] {
        assert!(matches!(
            validate_entry_encr_algo_id(reserved),
            Err(SarCryptoError::ReservedValue(_))
        ));
    }
    for unsupported in [0x05, 0x06] {
        assert!(matches!(
            validate_entry_encr_algo_id(unsupported),
            Err(SarCryptoError::Unsupported(_))
        ));
    }
}
