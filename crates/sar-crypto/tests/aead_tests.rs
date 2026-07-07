use zeroize::Zeroizing;

use sar_crypto::aead::{
    TAG_SIZE, aead_decrypt, aead_encrypt, generate_nonce, validate_nonce_field,
};
use sar_crypto::{ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, SarCryptoError, SecretBytes};

fn key(fill: u8) -> SecretBytes {
    Zeroizing::new(vec![fill; 32])
}

#[test]
fn aes256_gcm_round_trip() {
    let key = key(7);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"123456789012");
    let aad = b"sar-aad";
    let plaintext = b"aes-gcm plaintext";
    let encrypted = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, aad, plaintext).expect("encrypt");
    assert_eq!(encrypted.len(), plaintext.len() + TAG_SIZE);
    let decrypted = aead_decrypt(ENCR_AES256_GCM, &key, &nonce, aad, &encrypted).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn xchacha20_poly_round_trip() {
    let key = key(11);
    let mut nonce = [0u8; 24];
    for (idx, byte) in nonce.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    let aad = b"sar-aad-2";
    let plaintext = b"xchacha20 plaintext".repeat(8);
    let encrypted =
        aead_encrypt(ENCR_XCHACHA20_POLY, &key, &nonce, aad, &plaintext).expect("encrypt");
    let decrypted =
        aead_decrypt(ENCR_XCHACHA20_POLY, &key, &nonce, aad, &encrypted).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_key_fails_authentication() {
    let encryption_key = key(1);
    let wrong = key(2);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"nonce-for-12");
    let encrypted = aead_encrypt(
        ENCR_AES256_GCM,
        &encryption_key,
        &nonce,
        b"aad",
        b"plaintext",
    )
    .expect("encrypt");
    let err =
        aead_decrypt(ENCR_AES256_GCM, &wrong, &nonce, b"aad", &encrypted).expect_err("auth fail");
    assert!(matches!(err, SarCryptoError::AuthFailed(_)));
}

#[test]
fn corrupted_ciphertext_fails_authentication() {
    let key = key(9);
    let mut nonce = [0u8; 24];
    for (idx, byte) in nonce.iter_mut().enumerate() {
        *byte = (idx * 3) as u8;
    }
    let mut encrypted =
        aead_encrypt(ENCR_XCHACHA20_POLY, &key, &nonce, b"aad", b"payload").expect("encrypt");
    encrypted[0] ^= 0x40;
    let err =
        aead_decrypt(ENCR_XCHACHA20_POLY, &key, &nonce, b"aad", &encrypted).expect_err("auth fail");
    assert!(matches!(err, SarCryptoError::AuthFailed(_)));
}

#[test]
fn truncated_payload_is_rejected() {
    let key = key(3);
    let nonce = [0u8; 24];
    let err = aead_decrypt(ENCR_AES256_GCM, &key, &nonce, b"aad", b"tiny").expect_err("short");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));
}

#[test]
fn nonce_validation_and_generation_rules() {
    let mut aes_nonce = [0u8; 24];
    generate_nonce(ENCR_AES256_GCM, &mut aes_nonce).expect("aes nonce");
    assert!(aes_nonce[12..].iter().all(|byte| *byte == 0));
    validate_nonce_field(ENCR_AES256_GCM, &aes_nonce, true).expect("valid aes field");

    let mut invalid_aes = aes_nonce;
    invalid_aes[23] = 1;
    let err = validate_nonce_field(ENCR_AES256_GCM, &invalid_aes, true).expect_err("invalid aes");
    assert!(matches!(err, SarCryptoError::Malformed(_)));

    let mut xnonce = [0u8; 24];
    generate_nonce(ENCR_XCHACHA20_POLY, &mut xnonce).expect("xnonce");
    validate_nonce_field(ENCR_XCHACHA20_POLY, &xnonce, true).expect("valid xnonce");
}
