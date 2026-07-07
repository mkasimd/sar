use crate::error::SarCryptoError;
use crate::kms::types::AsymmetricWrapParams;
use crate::secret::SecretBytes;

/// Unwrap a CEK for `recipient_id` using an external callback.
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
            match unwrap_fn(
                params.wrap_algo_id,
                &recipient.recipient_id,
                &recipient.wrapped_key,
            )? {
                Some(key) => return Ok(key),
                None => return Err(SarCryptoError::KeyMissing("unwrap_fn returned no key")),
            }
        }
    }
    Err(SarCryptoError::KeyMissing("no matching recipient found"))
}
