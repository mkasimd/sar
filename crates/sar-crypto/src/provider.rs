// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use crate::algorithm::KMS_MASTER_SECRET_SIZE;
use crate::error::SarCryptoError;
use crate::kms::limits::KdfLimits;
use crate::kms::types::{KmsContext, KmsParams};
use crate::secret::{SecretBytes, SecretString};

/// Supplies KMS Master Secrets or password material to archive readers and writers.
pub trait KeyProvider: Send + Sync {
    /// Return the password to use for PBKDF2 or Argon2 derivation.
    fn password_for(&self, context: &KmsContext) -> Result<Option<SecretString>, SarCryptoError>;

    /// Attempt to unwrap a recipient-specific wrapped KMS Master Secret blob.
    ///
    /// The unwrapped value MUST be exactly 32 bytes.
    fn unwrap_key(
        &self,
        context: &KmsContext,
        wrapped_key: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError>;

    /// Return an externally supplied 32-byte KMS Master Secret directly.
    fn external_key(&self, context: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError>;
}

/// Resolve the 32-byte KMS Master Secret for `context` from `provider`.
///
/// The returned value is the KMS Master Secret of Section 5.3.4.  It MUST NOT
/// be used as an Entry encryption key; derive that key with
/// [`crate::entry_key::derive_entry_key`].  KDF parameters are checked against
/// `limits` before any expensive derivation.
///
/// # Errors
///
/// * [`SarCryptoError::KeyMissing`] when no password or recipient key is available.
/// * [`SarCryptoError::KeyRejected`] when a provider-supplied or unwrapped
///   secret is not exactly 32 bytes, or an unwrap fails.
/// * [`SarCryptoError::LimitExceeded`] when KDF parameters exceed `limits`.
pub fn resolve_master_secret(
    provider: &dyn KeyProvider,
    context: &KmsContext,
    limits: &KdfLimits,
) -> Result<SecretBytes, SarCryptoError> {
    if let Some(key) = provider.external_key(context)? {
        if key.len() != KMS_MASTER_SECRET_SIZE {
            return Err(SarCryptoError::KeyRejected(
                "externally supplied KMS Master Secret must be 32 bytes",
            ));
        }
        return Ok(key);
    }

    match &context.params {
        KmsParams::Pbkdf2(params) => {
            let password = provider
                .password_for(context)?
                .ok_or(SarCryptoError::KeyMissing(
                    "no password provided for PBKDF2",
                ))?;
            crate::kms::pbkdf2::derive_key(params, password.as_bytes(), limits)
        }
        KmsParams::Argon2(params) => {
            let password = provider
                .password_for(context)?
                .ok_or(SarCryptoError::KeyMissing(
                    "no password provided for Argon2",
                ))?;
            crate::kms::argon2::derive_key(params, password.as_bytes(), limits)
        }
        KmsParams::AsymmetricWrap(params) => {
            for recipient in &params.recipients {
                match crate::kms::asymmetric::check_recovered(
                    provider.unwrap_key(context, &recipient.wrapped_key),
                ) {
                    Ok(secret) => return Ok(secret),
                    Err(SarCryptoError::KeyMissing(_)) => {}
                    Err(err) => return Err(err),
                }
            }
            Err(SarCryptoError::KeyMissing(
                "no recipient key available for ASYMMETRIC_WRAP",
            ))
        }
        KmsParams::TlsExporter(_) => {
            // TLS_EXPORTER key derivation requires the transport layer to
            // supply the exporter material through `external_key` above; when
            // none is supplied the key material is missing.
            Err(SarCryptoError::KeyMissing(
                "KMS_TLS_EXPORTER requires transport-provided exporter material",
            ))
        }
    }
}
