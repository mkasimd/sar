macro_rules! impl_algorithm_enum {
    ($name:ident { $default:ident, $($variant:ident = $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant,)+
            Unknown(u8),
        }

        impl Default for $name {
            fn default() -> Self {
                Self::$default
            }
        }

        impl From<u8> for $name {
            fn from(value: u8) -> Self {
                match value {
                    $($value => Self::$variant,)+
                    other => Self::Unknown(other),
                }
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value, )+
                    $name::Unknown(other) => other,
                }
            }
        }
    };
}

impl_algorithm_enum!(CompressionAlgorithm {
    None,
    None = 0,
    Deflate = 1,
    Zstd = 2,
    Lz4 = 3,
    Brotli = 4,
});

impl_algorithm_enum!(EncryptionAlgorithm {
    None,
    None = 0,
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
});

impl_algorithm_enum!(CdcAlgorithm {
    None,
    None = 0,
    FastCdc = 1,
    RollSum = 2,
});

impl_algorithm_enum!(FecAlgorithm {
    None,
    None = 0,
    ReedSolomon = 1,
});

impl_algorithm_enum!(DeltaAlgorithm {
    None,
    None = 0,
    Bsdiff = 1,
    ZstdDelta = 2,
});

impl_algorithm_enum!(HashAlgorithm {
    Sha256,
    Sha256 = 0,
    Blake3 = 1,
    Sha512 = 2,
});
