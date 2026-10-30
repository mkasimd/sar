// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use crate::algorithm::KMS_MASTER_SECRET_SIZE;
use crate::error::SarCryptoError;
use crate::kms::types::AsymmetricWrapParams;
use crate::secret::SecretBytes;

/// Recover the KMS Master Secret for `recipient_id` using an external unwrap callback.
///
/// SAR validates the wrap construction outside the callback: the recovered
/// value must be exactly 32 bytes (the KMS Master Secret, never an Entry key).
/// An unwrap failure and a wrong-length result are both reported as
/// [`SarCryptoError::KeyRejected`] without distinguishing the step that failed.
/// A missing recipient key is [`SarCryptoError::KeyMissing`].
pub fn unwrap_cek<F>(
    params: &AsymmetricWrapParams,
    recipient_id: &[u8],
    unwrap_fn: F,
) -> Result<SecretBytes, SarCryptoError>
where
    F: Fn(u8, &[u8], &[u8]) -> Result<Option<SecretBytes>, SarCryptoError>,
{
    for recipient in &params.recipients {
        if recipient.recipient_id == recipient_id {
            return check_recovered(unwrap_fn(
                params.wrap_algo_id,
                &recipient.recipient_id,
                &recipient.wrapped_key,
            ));
        }
    }
    Err(SarCryptoError::KeyMissing("no matching recipient found"))
}

/// Normalizes the outcome of an external unwrap into the SAR error model.
pub(crate) fn check_recovered(
    result: Result<Option<SecretBytes>, SarCryptoError>,
) -> Result<SecretBytes, SarCryptoError> {
    match result {
        Ok(Some(secret)) if secret.len() == KMS_MASTER_SECRET_SIZE => Ok(secret),
        Err(SarCryptoError::KeyMissing(msg)) => Err(SarCryptoError::KeyMissing(msg)),
        Ok(Some(_)) | Err(_) => Err(SarCryptoError::KeyRejected(
            "recipient key unwrap was rejected",
        )),
        Ok(None) => Err(SarCryptoError::KeyMissing("unwrap_fn returned no key")),
    }
}
