// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::env;

use sar_core::SarError;
use sar_crypto::{KeyProvider, KmsContext, SarCryptoError, SecretBytes, SecretString};

pub(crate) const PASSWORD_ENV: &str = "SAR_PASSWORD";

pub(crate) struct CliKeyProvider {
    password: Option<SecretString>,
}

impl CliKeyProvider {
    pub(crate) fn new(password: Option<SecretString>) -> Self {
        Self { password }
    }
}

impl KeyProvider for CliKeyProvider {
    fn password_for(&self, _context: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(self.password.clone())
    }

    fn unwrap_key(
        &self,
        _context: &KmsContext,
        _wrapped_key: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }

    fn external_key(&self, _context: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
}

pub(crate) fn load_password(explicit: Option<String>) -> Result<SecretString, SarError> {
    if let Some(value) = explicit {
        return Ok(SecretString::new(value));
    }
    if let Ok(value) = env::var(PASSWORD_ENV) {
        return Ok(SecretString::new(value));
    }
    let prompted = rpassword::prompt_password("SAR password: ")
        .map_err(|_| SarError::KeyMissing("password not provided and prompt failed"))?;
    Ok(SecretString::new(prompted))
}
