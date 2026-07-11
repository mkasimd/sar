use std::io::Write;

use sar_core::SarError;

const SAR_SPEC_VERSION: &str = "1.0";
const SAR_CD_VERSION: &str = "1";

pub(crate) fn print_version() -> Result<(), SarError> {
    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "sar-cli {} | sar-spec v{} | cd-v{}",
        env!("CARGO_PKG_VERSION"),
        SAR_SPEC_VERSION,
        SAR_CD_VERSION
    )
    .map_err(SarError::Io)
}
