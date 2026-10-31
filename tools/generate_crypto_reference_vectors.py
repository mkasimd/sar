#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic SAR cryptographic reference vectors.

Output: test-vectors/crypto-reference/crypto_reference_vectors.json

Independence model
------------------
Every value is computed by third-party libraries that share no code with the
SAR Rust crates:

* PBKDF2-HMAC-SHA256: ``cryptography`` (OpenSSL) cross-checked with the Python
  standard library ``hashlib.pbkdf2_hmac``.
* Argon2id v0x13: ``argon2-cffi`` (Argon2 reference C implementation)
  cross-checked with ``cryptography`` (OpenSSL).
* HKDF-SHA256: ``cryptography``.
* AES-256-GCM / ChaCha20-Poly1305: ``cryptography``.
* XChaCha20-Poly1305: HChaCha20 implemented here per
  draft-irtf-cfrg-xchacha-03 section 2.2, then ChaCha20-Poly1305 from
  ``cryptography``.
* SHA-256: ``hashlib``. BLAKE3-256: ``blake3``.
* The Global Header and LFH bytes are assembled here directly from the
  specification field layout (Sections 5.2, 6 and 13.2.1), not by SAR code.

Published known-answer self-checks (RFC 7914 PBKDF2, RFC 5869 HKDF,
RFC 9106 Argon2id, draft-irtf-cfrg-xchacha-03 HChaCha20 and AEAD, NIST SHA-256,
official BLAKE3) are asserted before any SAR vector is emitted, so a broken
reference library cannot silently produce vectors.

Usage::

    python tools/generate_crypto_reference_vectors.py          # (re)write
    python tools/generate_crypto_reference_vectors.py --check  # verify file

Pinned reference versions are recorded in the output ``provenance`` block and
in ``tools/crypto_reference_requirements.txt``.
"""

import argparse
import hashlib
import json
import struct
import sys
from importlib import metadata
from pathlib import Path

import blake3
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

OUT = Path(__file__).resolve().parent.parent / "test-vectors" / "crypto-reference" / "crypto_reference_vectors.json"

ENCR_AES256_GCM = 0x01
ENCR_XCHACHA20_POLY = 0x04
HASH_SHA256 = 0x30
HASH_BLAKE3 = 0x31
KMS_PBKDF2 = 0x01
KMS_ARGON2 = 0x02
FLAG_ENCRYPTED = 1 << 10
FLAG_DEDUPLICATION = 1 << 29
ENTRY_MODE_ENCRYPTED = 1 << 2


def hx(b):
    return bytes(b).hex()


def pattern(n, start=0):
    return bytes((start + i) & 0xFF for i in range(n))


# --------------------------------------------------------------- primitives

def pbkdf2(password, salt, iterations):
    a = PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(password)
    b = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, 32)
    assert a == b, "PBKDF2 reference libraries disagree"
    return a


def argon2id(password, salt, mem_kib, time, par):
    a = hash_secret_raw(password, salt, time, mem_kib, par, 32, Type.ID, version=0x13)
    b = Argon2id(
        salt=salt, length=32, iterations=time, lanes=par, memory_cost=mem_kib
    ).derive(password)
    assert a == b, "Argon2id reference libraries disagree"
    return a


def hkdf_sha256_empty_salt(ikm, info, length):
    # HKDF with salt=None is HashLen zero bytes (RFC 5869 section 2.2).
    return HKDF(hashes.SHA256(), length, None, info).derive(ikm)


def entry_key(master, algo, iv_field):
    return hkdf_sha256_empty_salt(master, b"SAR-v1-entry-key" + bytes([algo]) + iv_field, 32)


def _rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key, nonce16):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13); _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12); _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha20_poly1305_encrypt(key, nonce24, aad, plaintext):
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\0\0\0\0" + nonce24[16:], plaintext, aad)


def aead_encrypt(algo, key, iv_field, aad, plaintext):
    if algo == ENCR_AES256_GCM:
        assert iv_field[12:] == bytes(12)
        return AESGCM(key).encrypt(iv_field[:12], plaintext, aad)
    if algo == ENCR_XCHACHA20_POLY:
        return xchacha20_poly1305_encrypt(key, iv_field, aad, plaintext)
    raise ValueError(algo)


def content_hash(hash_algo, data):
    if hash_algo == HASH_SHA256:
        return hashlib.sha256(data).digest()
    if hash_algo == HASH_BLAKE3:
        return blake3.blake3(data).digest(32)
    raise ValueError(hash_algo)


# ---------------------------------------------------- published KAT self-checks

def self_check_published():
    # RFC 7914 section 11, PBKDF2-HMAC-SHA-256 (c=1, dkLen=64).
    assert hashlib.pbkdf2_hmac("sha256", b"passwd", b"salt", 1, 64).hex() == (
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    )
    # RFC 5869 test case 3 (empty salt/info).
    assert HKDF(hashes.SHA256(), 42, None, b"").derive(bytes([0x0B]) * 22).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )
    # RFC 9106 section 5.3 Argon2id (uses secret and associated data).
    rfc9106 = Argon2id(
        salt=bytes([2]) * 16, length=32, iterations=3, lanes=4, memory_cost=32,
        ad=bytes([4]) * 12, secret=bytes([3]) * 8,
    ).derive(bytes([1]) * 32)
    assert rfc9106.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    # draft-irtf-cfrg-xchacha-03 section 2.2.1 HChaCha20.
    assert hchacha20(
        pattern(32), bytes.fromhex("000000090000004a0000000031415927")
    ).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    # draft-irtf-cfrg-xchacha-03 appendix A.3.1 AEAD_XCHACHA20_POLY1305.
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
        b"tip for the future, sunscreen would be it."
    )
    ct = xchacha20_poly1305_encrypt(
        pattern(32, 0x80), pattern(24, 0x40), bytes.fromhex("50515253c0c1c2c3c4c5c6c7"), pt
    )
    assert ct[-16:].hex() == "c0875924c1c7987947deafd8780acf49", "XChaCha20 AEAD KAT"
    # NIST SHA-256("abc") and official BLAKE3("") test vectors.
    assert hashlib.sha256(b"abc").hexdigest() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert blake3.blake3(b"").hexdigest() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    )
    return [
        "RFC 7914 section 11 PBKDF2-HMAC-SHA-256 (c=1)",
        "RFC 5869 appendix A.3 HKDF-SHA-256 empty salt/info",
        "RFC 9106 section 5.3 Argon2id",
        "draft-irtf-cfrg-xchacha-03 section 2.2.1 HChaCha20",
        "draft-irtf-cfrg-xchacha-03 appendix A.3.1 XChaCha20-Poly1305 tag",
        "NIST SHA-256 'abc'",
        "BLAKE3 official empty-input digest",
    ]


# ---------------------------------------------------------------- SAR layouts

def kms_payload_pbkdf2(iterations, salt):
    return bytes([0x01]) + struct.pack("<IHB", iterations, 32, len(salt)) + salt


def kms_payload_argon2(mem, time, par, salt):
    return bytes([0x03, 0x13]) + struct.pack("<IIHHB", mem, time, par, 32, len(salt)) + salt


def global_header(flags, kms_mode, kms_payload):
    out = b"SAR!" + bytes([0x01, 0x00]) + struct.pack("<H", 4) + struct.pack("<I", flags)
    return out + bytes([kms_mode]) + struct.pack("<I", len(kms_payload)) + kms_payload


def lfh(encr_algo, iv_field, hash_algo, digest, name, uncompressed, payload_size):
    # Flags: ENCRYPTED | DEDUPLICATION, 32-bit sizes (spec section 6.2).
    body = struct.pack("<HHH", ENTRY_MODE_ENCRYPTED, 0, 0)
    body += struct.pack("<II", uncompressed, payload_size)
    body += bytes([encr_algo]) + iv_field
    body += bytes([hash_algo]) + digest
    body += struct.pack("<H", len(name)) + name
    return struct.pack("<I", 4 + len(body)) + body


def archive_case(case_id, kms, encr_algo, hash_algo, password, nonce, plaintext, name):
    flags = FLAG_ENCRYPTED | FLAG_DEDUPLICATION
    if kms["mode"] == KMS_PBKDF2:
        payload = kms_payload_pbkdf2(kms["iterations"], kms["salt"])
        master = pbkdf2(password, kms["salt"], kms["iterations"])
    else:
        payload = kms_payload_argon2(kms["memory_kib"], kms["time"], kms["parallelism"], kms["salt"])
        master = argon2id(password, kms["salt"], kms["memory_kib"], kms["time"], kms["parallelism"])
    iv_field = nonce + bytes(24 - len(nonce))
    key = entry_key(master, encr_algo, iv_field)
    digest = content_hash(hash_algo, plaintext)
    ghdr = global_header(flags, kms["mode"], payload)
    lfh_bytes = lfh(encr_algo, iv_field, hash_algo, digest, name, len(plaintext), len(plaintext) + 16)
    aad = ghdr + lfh_bytes
    ct = aead_encrypt(encr_algo, key, iv_field, aad, plaintext)
    assert len(ct) == len(plaintext) + 16
    return {
        "id": case_id,
        "kms_mode": kms["mode"],
        "kms_payload": hx(payload),
        "encr_algo_id": encr_algo,
        "hash_algo_id": hash_algo,
        "password_hex": hx(password),
        "iv_nonce_field": hx(iv_field),
        "entry_name_hex": hx(name),
        "plaintext_hex": hx(plaintext),
        "master_secret": hx(master),
        "entry_key": hx(key),
        "content_hash": hx(digest),
        "global_header": hx(ghdr),
        "lfh": hx(lfh_bytes),
        "aad": hx(aad),
        "ciphertext_and_tag": hx(ct),
    }


def sparse_digest(hash_algo, extents, logical_size):
    data = bytearray(logical_size)
    gathered = b""
    for off, chunk in extents:
        data[off:off + len(chunk)] = chunk
        gathered += chunk
    return gathered, content_hash(hash_algo, bytes(data))


# --------------------------------------------------------------------- main

def build():
    checks = self_check_published()
    password = b"sar-reference-password"
    vectors = {}

    vectors["pbkdf2_hmac_sha256"] = []
    for iters, slen in [(100000, 16), (100000, 64), (600000, 16), (600000, 64), (350000, 33)]:
        salt = pattern(slen, 0x10)
        vectors["pbkdf2_hmac_sha256"].append({
            "iterations": iters, "salt": hx(salt), "password_hex": hx(password),
            "derived_key": hx(pbkdf2(password, salt, iters)),
        })

    vectors["argon2id_v13"] = []
    for mem, t, p, slen in [
        (19456, 2, 1, 16),    # lower corner of every mandatory range
        (65536, 3, 4, 64),    # upper corner of every mandatory range, 64-byte salt
        (65536, 3, 4, 16),    # RFC 9106 second recommended option (64 MiB, t=3, p=4)
        (19456, 3, 4, 32),
        (65536, 2, 1, 24),
        (32768, 2, 2, 17),
    ]:
        salt = pattern(slen, 0x20)
        vectors["argon2id_v13"].append({
            "memory_kib": mem, "time": t, "parallelism": p, "salt": hx(salt),
            "password_hex": hx(password), "derived_key": hx(argon2id(password, salt, mem, t, p)),
        })

    master = pattern(32)
    vectors["entry_key_hkdf_sha256"] = []
    for algo, fill in [(ENCR_AES256_GCM, 0xA0), (ENCR_XCHACHA20_POLY, 0xA0)]:
        iv = bytes(0xA0 + i for i in range(24)) if algo == ENCR_XCHACHA20_POLY else bytes(range(0xA0, 0xAC)) + bytes(12)
        vectors["entry_key_hkdf_sha256"].append({
            "master_secret": hx(master), "encr_algo_id": algo, "iv_nonce_field": hx(iv),
            "entry_key": hx(entry_key(master, algo, iv)),
        })

    vectors["aead"] = []
    key = pattern(32, 0x40)
    for algo, nonce in [(ENCR_AES256_GCM, pattern(12, 0x70)), (ENCR_XCHACHA20_POLY, pattern(24, 0x70))]:
        iv = nonce + bytes(24 - len(nonce))
        aad = b"SAR-test-aad" * 3
        pt = b"fixed test-only AEAD plaintext"
        vectors["aead"].append({
            "encr_algo_id": algo, "key": hx(key), "iv_nonce_field": hx(iv), "aad": hx(aad),
            "plaintext_hex": hx(pt), "ciphertext_and_tag": hx(aead_encrypt(algo, key, iv, aad, pt)),
        })

    big = bytes((i * 31 + 7) & 0xFF for i in range(3000))
    vectors["archive_entries"] = [
        archive_case("pbkdf2-100000-aes256gcm-sha256",
                     {"mode": KMS_PBKDF2, "iterations": 100000, "salt": pattern(16, 0x30)},
                     ENCR_AES256_GCM, HASH_SHA256, password, pattern(12, 0x50),
                     b"SAR reference entry: AES-256-GCM / SHA-256\n", b"reference-aes.txt"),
        archive_case("pbkdf2-600000-xchacha-blake3",
                     {"mode": KMS_PBKDF2, "iterations": 600000, "salt": pattern(64, 0x30)},
                     ENCR_XCHACHA20_POLY, HASH_BLAKE3, password, pattern(24, 0x50),
                     big, b"reference-xchacha.bin"),
        archive_case("argon2id-19456-2-1-aes256gcm-blake3",
                     {"mode": KMS_ARGON2, "memory_kib": 19456, "time": 2, "parallelism": 1, "salt": pattern(16, 0x30)},
                     ENCR_AES256_GCM, HASH_BLAKE3, password, pattern(12, 0x60),
                     b"", b"empty.bin"),
        archive_case("argon2id-65536-3-4-xchacha-sha256",
                     {"mode": KMS_ARGON2, "memory_kib": 65536, "time": 3, "parallelism": 4, "salt": pattern(64, 0x30)},
                     ENCR_XCHACHA20_POLY, HASH_SHA256, password, pattern(24, 0x60),
                     b"SAR reference entry: XChaCha20-Poly1305 / SHA-256\n" * 10, b"reference-argon2.txt"),
    ]

    vectors["content_hash"] = []
    for algo in (HASH_SHA256, HASH_BLAKE3):
        frags = [pattern(1000, 0), pattern(1, 9), b"", pattern(4096, 3)]
        vectors["content_hash"].append({
            "kind": "plain", "hash_algo_id": algo, "data": hx(b"abc"),
            "digest": hx(content_hash(algo, b"abc")),
        })
        vectors["content_hash"].append({
            "kind": "fragmented", "hash_algo_id": algo, "fragments": [hx(f) for f in frags],
            "digest": hx(content_hash(algo, b"".join(frags))),
        })
        extents = [(0, b"head"), (10000, b"mid-run"), (20000, b"tail")]
        logical = 20004 + 7000  # trailing hole
        gathered, digest = sparse_digest(algo, extents, logical)
        vectors["content_hash"].append({
            "kind": "sparse", "hash_algo_id": algo, "logical_size": logical,
            "extents": [{"offset": o, "data": hx(d)} for o, d in extents],
            "gathered": hx(gathered), "digest": hx(digest),
        })
        # A fragmented sparse group: the digest covers the group's logical file.
        parts = [(0, b"head"), (4096, b"x" * 100)]
        g, d = sparse_digest(algo, parts, 8192)
        vectors["content_hash"].append({
            "kind": "sparse-fragment-group", "hash_algo_id": algo, "logical_size": 8192,
            "extents": [{"offset": o, "data": hx(dd)} for o, dd in parts],
            "gathered": hx(g), "digest": hx(d),
        })

    def ver(name):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            return "unknown"

    return {
        "format": "sar-crypto-reference-vectors/1",
        "provenance": {
            "generator": "tools/generate_crypto_reference_vectors.py",
            "references": {
                "cryptography": ver("cryptography"),
                "argon2-cffi": ver("argon2-cffi"),
                "blake3": ver("blake3"),
                "python-stdlib": "hashlib.pbkdf2_hmac / hashlib.sha256",
            },
            "published_kat_self_checks": checks,
            "evidence_level": (
                "independent-library agreement; test-only keys, nonces and passwords; "
                "NOT second-implementation SAR archive interoperability"
            ),
        },
        "vectors": vectors,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.check:
        # Reference library versions may legitimately differ; compare vectors only.
        current = json.loads(OUT.read_text())["vectors"]
        if current != json.loads(text)["vectors"]:
            print("crypto reference vectors are stale", file=sys.stderr)
            return 1
        print("crypto reference vectors match")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
