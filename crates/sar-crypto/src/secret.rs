// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

/// Zeroizing container for secret bytes such as CEKs and derived keys.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Zeroizing container for a password string.
pub type SecretString = Zeroizing<String>;
