/// M10i additional-control-stream AAD derivation tests.
///
/// These tests verify the cryptographic properties of the AEAD Additional
/// Associated Data (AAD) construction for SAR entries, including entries on
/// LFH-direct additional QUIC control streams.
///
/// For KMS Mode `0x04 TLS_EXPORTER`:
/// - The Global Header portion of AAD MUST be the canonical encoded Global
///   Header bytes of the active SAR session associated with the LFH Stream ID.
/// - The LFH portion of AAD MUST be the LFH bytes physically present on that
///   additional control stream.
/// - Tampering with LFH fields authenticated as AAD MUST cause AEAD
///   authentication failure.
/// - Using wrong associated Global Header bytes for AAD MUST cause AEAD
///   authentication failure.
/// - AEAD failure MUST NOT expose plaintext.

use sar_crypto::{
    ENCR_AES256_GCM, SecretBytes,
    aad::{build_aead_aad, global_header_aad_bytes},
    aead::{aead_decrypt, aead_encrypt},
};
use zeroize::Zeroizing;

// ── AAD construction helpers ─────────────────────────────────────────────────

fn test_key(fill: u8) -> SecretBytes {
    Zeroizing::new(vec![fill; 32])
}

/// Builds the Global Header AAD bytes using the standard SAR magic and a simple
/// flag set, as used by the canonical `global_header_aad_bytes` helper.
fn make_global_header_aad(flags_bytes: &[u8]) -> Vec<u8> {
    global_header_aad_bytes(b"SAR!", 1, flags_bytes)
}

/// Builds a dummy LFH byte slice (simplified, not a real SAR LFH).
fn make_lfh_bytes(stream_id: u16, sequence_no: u16, tag: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(12);
    // Minimal pseudo-LFH for AAD purposes: header_size(4) + entry_mode(2)
    // + stream_id(2) + sequence_no(2) + tag(1) + pad(1).
    b.extend_from_slice(&12u32.to_le_bytes()); // header_size
    b.extend_from_slice(&0x2100u16.to_le_bytes()); // SESSION_CONTROL | opcode
    b.extend_from_slice(&stream_id.to_le_bytes());
    b.extend_from_slice(&sequence_no.to_le_bytes());
    b.push(tag);
    b.push(0x00); // pad
    b
}

// ── Test 1: Global Header bytes are included in AAD ───────────────────────

/// The `global_header_aad_bytes` function must produce the canonical layout:
/// `magic(4) + version(1) + reserved(1) + flags_size(2) + flags_bytes(n)`.
#[test]
fn global_header_aad_bytes_layout_is_canonical() {
    let flags_bytes = [0x01u8, 0x00, 0x00, 0x00]; // NO_INDEX
    let aad = make_global_header_aad(&flags_bytes);

    // magic
    assert_eq!(&aad[0..4], b"SAR!");
    // version
    assert_eq!(aad[4], 1);
    // reserved
    assert_eq!(aad[5], 0);
    // flags_size LE
    assert_eq!(u16::from_le_bytes([aad[6], aad[7]]), 4);
    // flags_bytes
    assert_eq!(&aad[8..12], &flags_bytes);
}

// ── Test 2: AAD concatenates global-header section and LFH section ────────

/// `build_aead_aad` MUST produce the concatenation of the global-header AAD
/// section and the LFH bytes.
#[test]
fn build_aead_aad_is_concatenation_of_sections() {
    let gh_section = make_global_header_aad(&[0x01, 0x00]);
    let lfh_bytes = make_lfh_bytes(42, 7, 0xAB);
    let aad = build_aead_aad(&gh_section, &lfh_bytes);

    assert_eq!(&aad[..gh_section.len()], &gh_section[..]);
    assert_eq!(&aad[gh_section.len()..], &lfh_bytes[..]);
}

// ── Test 3: Tampering with LFH bytes after encryption causes auth failure ─

/// Tampering with any LFH field that is part of AAD MUST cause AEAD
/// authentication failure.  The AEAD tag is computed over the AAD that
/// includes the LFH bytes; any modification to those bytes after encryption
/// renders the tag invalid.
#[test]
fn tampering_lfh_in_aad_causes_aead_auth_failure() {
    let key = test_key(0x42);
    let nonce = {
        let mut n = [0u8; 24];
        n[..12].copy_from_slice(b"test-nonce12");
        n
    };
    let plaintext = b"sensitive-session-payload";
    let lfh_bytes = make_lfh_bytes(7, 3, 0xCC);
    let gh_section = make_global_header_aad(&[0x01, 0x00, 0x00, 0x00]);
    let aad = build_aead_aad(&gh_section, &lfh_bytes);

    let ciphertext = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, &aad, plaintext)
        .expect("encrypt must succeed");

    // Tamper with one byte of the LFH (flip tag byte).
    let mut tampered_lfh = lfh_bytes.clone();
    tampered_lfh[10] ^= 0xFF;
    let tampered_aad = build_aead_aad(&gh_section, &tampered_lfh);

    let result = aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &tampered_aad, &ciphertext);
    assert!(
        result.is_err(),
        "tampering with LFH bytes in AAD must cause AEAD auth failure"
    );
    // Verify the error is an auth failure, not some other error.
    assert!(
        matches!(result.unwrap_err(), sar_crypto::SarCryptoError::AuthFailed(_)),
        "error must be AuthFailed"
    );
}

// ── Test 4: Correct LFH bytes produce successful decryption ───────────────

/// When the same LFH bytes are used for both encryption and decryption, AEAD
/// MUST succeed and return the original plaintext.
#[test]
fn correct_lfh_bytes_in_aad_allows_successful_decryption() {
    let key = test_key(0x77);
    let nonce = {
        let mut n = [0u8; 24];
        n[..12].copy_from_slice(b"correct-nonc");
        n
    };
    let plaintext = b"correct-payload-bytes";
    let lfh_bytes = make_lfh_bytes(11, 5, 0xDE);
    let gh_section = make_global_header_aad(&[0x01, 0x00, 0x00, 0x00]);
    let aad = build_aead_aad(&gh_section, &lfh_bytes);

    let ciphertext = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, &aad, plaintext)
        .expect("encrypt must succeed");
    let decrypted = aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &aad, &ciphertext)
        .expect("decrypt must succeed with correct AAD");

    assert_eq!(decrypted, plaintext);
}

// ── Test 5: Wrong Global Header bytes for AAD causes auth failure ─────────

/// Using the Global Header bytes from a different session (wrong Stream ID or
/// different flags) as the AAD for an additional control stream entry MUST
/// cause AEAD authentication failure.
///
/// This confirms that the `global_header_aad_bytes` of the associated SAR
/// session must be used, not those of a different session.
#[test]
fn wrong_global_header_bytes_for_aad_causes_aead_auth_failure() {
    let key = test_key(0x55);
    let nonce = {
        let mut n = [0u8; 24];
        n[..12].copy_from_slice(b"session-nonc");
        n
    };
    let plaintext = b"entry-payload-for-session-A";
    let lfh_bytes = make_lfh_bytes(3, 1, 0xAA);

    // Session A: flags = [0x01, 0x00, 0x00, 0x00] (NO_INDEX).
    let gh_section_a = make_global_header_aad(&[0x01, 0x00, 0x00, 0x00]);
    let aad_a = build_aead_aad(&gh_section_a, &lfh_bytes);

    let ciphertext = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, &aad_a, plaintext)
        .expect("encrypt must succeed");

    // Session B: different flags — simulates a different session's global header.
    let gh_section_b = make_global_header_aad(&[0x03, 0x00, 0x00, 0x00]);
    let aad_b = build_aead_aad(&gh_section_b, &lfh_bytes);

    let result = aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &aad_b, &ciphertext);
    assert!(
        result.is_err(),
        "wrong Global Header bytes for AAD must cause AEAD auth failure"
    );
    assert!(
        matches!(result.unwrap_err(), sar_crypto::SarCryptoError::AuthFailed(_)),
        "error must be AuthFailed"
    );
}

// ── Test 6: AEAD failure does not expose plaintext ────────────────────────

/// When AEAD authentication fails, the implementation MUST NOT return any
/// plaintext.  The `aead_decrypt` function must return `Err(AuthFailed)` and
/// not expose the partially decrypted buffer.
#[test]
fn aead_failure_does_not_expose_plaintext() {
    let key = test_key(0x99);
    let nonce = {
        let mut n = [0u8; 24];
        n[..12].copy_from_slice(b"no-expose-no");
        n
    };
    let plaintext = b"this-must-not-leak-out";
    let lfh_bytes = make_lfh_bytes(5, 2, 0xBB);
    let gh_section = make_global_header_aad(&[0x01, 0x00, 0x00, 0x00]);
    let aad = build_aead_aad(&gh_section, &lfh_bytes);

    let ciphertext =
        aead_encrypt(ENCR_AES256_GCM, &key, &nonce, &aad, plaintext).expect("encrypt");

    // Use wrong AAD to force auth failure.
    let wrong_aad = build_aead_aad(b"wrong-gh", &lfh_bytes);
    let result = aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &wrong_aad, &ciphertext);

    // The result MUST be an error — no plaintext is returned.
    match result {
        Err(sar_crypto::SarCryptoError::AuthFailed(_)) => {}
        Err(other) => panic!("expected AuthFailed, got: {other:?}"),
        Ok(exposed) => panic!(
            "AEAD failure MUST NOT return plaintext; got {} bytes",
            exposed.len()
        ),
    }
}

// ── Test 7: Different additional-control-stream LFH bytes produce different
//            ciphertexts ────────────────────────────────────────────────────

/// Two entries with the same plaintext and key but different LFH fields MUST
/// produce different ciphertexts when using the same nonce (AAD differs).
///
/// This confirms that the LFH bytes are cryptographically bound into the
/// authenticated data.
#[test]
fn different_lfh_fields_produce_different_authentication_outcomes() {
    let key = test_key(0x33);
    let nonce = {
        let mut n = [0u8; 24];
        n[..12].copy_from_slice(b"lfh-diff-non");
        n
    };
    let plaintext = b"shared-payload";
    let gh_section = make_global_header_aad(&[0x01, 0x00, 0x00, 0x00]);

    let lfh_stream_a = make_lfh_bytes(1, 0, 0x01);
    let lfh_stream_b = make_lfh_bytes(2, 0, 0x02);

    let aad_a = build_aead_aad(&gh_section, &lfh_stream_a);
    let aad_b = build_aead_aad(&gh_section, &lfh_stream_b);

    let ct_a = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, &aad_a, plaintext)
        .expect("encrypt A");
    let ct_b = aead_encrypt(ENCR_AES256_GCM, &key, &nonce, &aad_b, plaintext)
        .expect("encrypt B");

    // Different AAD ⇒ different authentication tags (even with same plaintext/key/nonce).
    assert_ne!(
        ct_a, ct_b,
        "different LFH fields must produce different AEAD outputs"
    );

    // Cross-decryption MUST fail.
    assert!(
        aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &aad_b, &ct_a).is_err(),
        "decrypting A's ciphertext with B's AAD must fail"
    );
    assert!(
        aead_decrypt(ENCR_AES256_GCM, &key, &nonce, &aad_a, &ct_b).is_err(),
        "decrypting B's ciphertext with A's AAD must fail"
    );
}
