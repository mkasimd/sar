use crate::error::SarCryptoError;
use crate::kms::types::{KmsContext, KmsParams};
use crate::secret::{SecretBytes, SecretString};

/// Supplies CEKs or password material to archive readers and writers.
pub trait KeyProvider: Send + Sync {
    /// Return the password to use for PBKDF2 or Argon2 derivation.
    fn password_for(&self, context: &KmsContext) -> Result<Option<SecretString>, SarCryptoError>;

    /// Attempt to unwrap a recipient-specific wrapped CEK blob.
    fn unwrap_key(
        &self,
        context: &KmsContext,
        wrapped_key: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError>;

    /// Return an externally supplied CEK directly.
    fn external_key(&self, context: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError>;
}

/// Resolve the content-encryption key for `context` from `provider`.
pub fn resolve_cek(
    provider: &dyn KeyProvider,
    context: &KmsContext,
) -> Result<SecretBytes, SarCryptoError> {
    if let Some(key) = provider.external_key(context)? {
        return Ok(key);
    }

    match &context.params {
        KmsParams::Pbkdf2(params) => {
            let password = provider
                .password_for(context)?
                .ok_or(SarCryptoError::KeyMissing(
                    "no password provided for PBKDF2",
                ))?;
            crate::kms::pbkdf2::derive_key(params, password.as_bytes())
        }
        KmsParams::Argon2(params) => {
            let password = provider
                .password_for(context)?
                .ok_or(SarCryptoError::KeyMissing(
                    "no password provided for Argon2",
                ))?;
            crate::kms::argon2::derive_key(params, password.as_bytes())
        }
        KmsParams::AsymmetricWrap(params) => {
            for recipient in &params.recipients {
                if let Some(key) = provider.unwrap_key(context, &recipient.wrapped_key)? {
                    return Ok(key);
                }
            }
            Err(SarCryptoError::KeyMissing(
                "no recipient key available for ASYMMETRIC_WRAP",
            ))
        }
        KmsParams::TlsExporter(_) => {
            // TLS_EXPORTER key derivation requires the transport layer to
            // supply the exporter material.  A key provider that wraps a
            // pre-derived key should override `external_key` above.
            Err(SarCryptoError::Unsupported(
                "KMS_TLS_EXPORTER requires a transport-provided TlsExporterKeyProvider",
            ))
        }
    }
}
