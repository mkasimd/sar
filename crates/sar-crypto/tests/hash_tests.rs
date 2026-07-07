use sar_crypto::hash::{blake3_hash, ct_eq, hash_data, new_hasher, sha256};
use sar_crypto::{HASH_BLAKE3, HASH_SHA3_256, HASH_SHA256, SarCryptoError};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sha256_known_vector() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn blake3_known_vector() {
    assert_eq!(
        hex(&blake3_hash(b"abc")),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
}

#[test]
fn streaming_hashers_match_one_shot() {
    let data = b"streaming-hash-input".repeat(32);
    let mut sha = new_hasher(HASH_SHA256).expect("sha");
    sha.update(&data[..13]);
    sha.update(&data[13..]);
    assert!(ct_eq(&sha.finalize(), &sha256(&data)));

    let mut blake = new_hasher(HASH_BLAKE3).expect("blake3");
    blake.update(&data[..7]);
    blake.update(&data[7..]);
    assert!(ct_eq(&blake.finalize(), &blake3_hash(&data)));
}

#[test]
fn hash_data_dispatches() {
    let data = b"dispatch-data";
    assert!(ct_eq(
        &hash_data(HASH_SHA256, data).expect("sha256"),
        &sha256(data)
    ));
    assert!(ct_eq(
        &hash_data(HASH_BLAKE3, data).expect("blake3"),
        &blake3_hash(data)
    ));
}

#[test]
fn unsupported_and_reserved_hash_ids_fail() {
    let sha3 = hash_data(HASH_SHA3_256, b"x").expect_err("sha3 unsupported");
    assert!(matches!(sha3, SarCryptoError::Unsupported(_)));

    let reserved = match new_hasher(0x01) {
        Ok(_) => panic!("reserved id should fail"),
        Err(err) => err,
    };
    assert!(matches!(reserved, SarCryptoError::ReservedValue(_)));
}
