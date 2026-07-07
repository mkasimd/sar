#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, File},
    io::{BufReader, Write},
    path::{Component, Path, PathBuf},
};

use clap::{ArgAction, Parser, Subcommand};
use serde_json::json;
use walkdir::WalkDir;

use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_STORE, COMP_ALGO_ZSTD};
use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EncryptionSettings,
    EntryInput, FecSettings, GlobalFlags, KeyProvider, KmsContext, KmsParams, SarError,
    SecretBytes,
};
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params, SecretString,
};

const SAR_SPEC_VERSION: &str = "1.0";
const SAR_CD_VERSION: &str = "1";
const PASSWORD_ENV: &str = "SAR_PASSWORD";

#[derive(Parser)]
#[command(name = "sar", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum CompressionChoice {
    Store,
    Deflate,
    Zstd,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum EncryptionChoice {
    #[value(name = "aes256-gcm")]
    Aes256Gcm,
    #[value(name = "xchacha20-poly")]
    XChaCha20Poly,
}

/// FEC algorithm selector for the `--fec` flag.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum FecChoice {
    /// XOR parity (algorithm 0x14).
    Xor,
    /// Reed-Solomon (algorithm 0x11).
    #[value(name = "rs")]
    Rs,
}

#[derive(Debug, Clone, Copy)]
struct CreateCompression {
    algo_id: u8,
    level: Option<u8>,
}

struct CliKeyProvider {
    password: Option<SecretString>,
}

impl CliKeyProvider {
    fn new(password: Option<SecretString>) -> Self {
        Self { password }
    }
}

impl KeyProvider for CliKeyProvider {
    fn password_for(
        &self,
        _context: &KmsContext,
    ) -> Result<Option<SecretString>, sar_core::SarCryptoError> {
        Ok(self.password.clone())
    }

    fn unwrap_key(
        &self,
        _context: &KmsContext,
        _wrapped_key: &[u8],
    ) -> Result<Option<SecretBytes>, sar_core::SarCryptoError> {
        Ok(None)
    }

    fn external_key(
        &self,
        _context: &KmsContext,
    ) -> Result<Option<SecretBytes>, sar_core::SarCryptoError> {
        Ok(None)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create archive from file or directory.
    Create {
        /// Input file or directory.
        input: PathBuf,
        /// Output archive path.
        output: PathBuf,
        /// Force indexed mode.
        #[arg(long, action = ArgAction::SetTrue)]
        indexed: bool,
        /// Force NO_INDEX mode.
        #[arg(long, action = ArgAction::SetTrue)]
        no_index: bool,
        /// Compression algorithm for entries.
        #[arg(long, value_enum)]
        compression: Option<CompressionChoice>,
        /// Use zstd compression.
        #[arg(short = 'Z', action = ArgAction::SetTrue)]
        zstd: bool,
        /// Use deflate compression.
        #[arg(short = 'z', action = ArgAction::SetTrue)]
        deflate: bool,
        /// Force STORE/no compression.
        #[arg(short = 'S', action = ArgAction::SetTrue)]
        store: bool,
        /// Compression level (0-9), supports shorthand like `-9`.
        #[arg(long = "compression-level", value_parser = clap::value_parser!(u8).range(0..=9))]
        compression_level: Option<u8>,
        /// Encrypt entry payloads with the selected AEAD algorithm.
        #[arg(long, value_enum)]
        encrypt: Option<EncryptionChoice>,
        /// Archive password. Falls back to `SAR_PASSWORD` or a terminal prompt.
        #[arg(long)]
        password: Option<String>,
        /// Protect each entry payload with file-level FEC (Selective FEC).
        /// Use `xor` for XOR parity or `rs` for Reed-Solomon.
        #[arg(long, value_enum)]
        fec: Option<FecChoice>,
    },
    /// Extract archive to output directory.
    Extract {
        /// Archive path.
        archive: PathBuf,
        /// Output directory.
        output_dir: PathBuf,
        /// Archive password. Falls back to `SAR_PASSWORD` or a terminal prompt.
        #[arg(long)]
        password: Option<String>,
    },
    /// List archive entries.
    List {
        /// Archive path.
        archive: PathBuf,
    },
    /// Verify archive structure.
    Verify {
        /// Archive path.
        archive: PathBuf,
        /// Archive password. Falls back to `SAR_PASSWORD` or a terminal prompt.
        #[arg(long)]
        password: Option<String>,
    },
    /// Inspect archive metadata.
    Inspect {
        /// Archive path.
        archive: PathBuf,
        /// Emit JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Print version information.
    Version,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if let Some(outcome) = try_handle_shorthand(&args) {
        outcome
    } else {
        handle_normal_cli(&normalize_level_shorthand(&args))
    };

    if let Err(error) = result {
        eprintln!("error ({}): {error}", error.status());
        std::process::exit(1);
    }
}

fn try_handle_shorthand(args: &[String]) -> Option<Result<(), SarError>> {
    if args.len() <= 1 {
        return None;
    }

    if args.iter().any(|arg| arg == "-V") {
        return Some(print_version());
    }

    let mode_flags = ["-c", "-x", "-t", "-v"];
    let active: Vec<&str> = mode_flags
        .iter()
        .copied()
        .filter(|flag| args.iter().any(|arg| arg == flag))
        .collect();
    if active.is_empty() {
        return None;
    }
    if active.len() > 1 {
        return Some(Err(SarError::Malformed(
            "ambiguous shorthand: provide only one of -c/-x/-t/-v",
        )));
    }

    match active[0] {
        "-c" => {
            let input = args
                .iter()
                .skip(1)
                .find(|arg| !arg.starts_with('-'))
                .map(PathBuf::from)
                .ok_or(SarError::Malformed("-c requires <input>"));
            let output = value_after_flag(args, "-f");
            let compression = resolve_shorthand_compression(args);
            Some(match (input, output, compression) {
                (Ok(input), Ok(output), Ok(compression)) => {
                    create_archive(input, output, false, compression, None, None, None)
                }
                (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => Err(err),
            })
        }
        "-x" => {
            let archive = value_after_flag(args, "-f");
            let out = value_after_flag(args, "-C");
            Some(match (archive, out) {
                (Ok(archive), Ok(out)) => extract_archive(archive, out, None),
                (Err(err), _) | (_, Err(err)) => Err(err),
            })
        }
        "-t" => Some(value_after_flag(args, "-f").and_then(list_archive)),
        "-v" => Some(value_after_flag(args, "-f").and_then(|path| verify_archive(path, None))),
        _ => None,
    }
}

fn resolve_shorthand_compression(args: &[String]) -> Result<CreateCompression, SarError> {
    let algo_flags = [
        ("-S", CompressionChoice::Store),
        ("-z", CompressionChoice::Deflate),
        ("-Z", CompressionChoice::Zstd),
    ];
    let selected: Vec<CompressionChoice> = algo_flags
        .iter()
        .filter_map(|(flag, value)| args.iter().any(|arg| arg == *flag).then_some(*value))
        .collect();
    if selected.len() > 1 {
        return Err(SarError::Malformed(
            "ambiguous compression shorthand: choose one of -S/-z/-Z",
        ));
    }
    let level = parse_level_shorthand(args)?;
    Ok(CreateCompression {
        algo_id: compression_to_algo_id(
            selected
                .first()
                .copied()
                .unwrap_or(CompressionChoice::Store),
        ),
        level,
    })
}

fn parse_level_shorthand(args: &[String]) -> Result<Option<u8>, SarError> {
    let levels: Vec<u8> = args
        .iter()
        .filter_map(|arg| {
            if arg.len() == 2 && arg.starts_with('-') {
                arg.chars()
                    .nth(1)
                    .and_then(|c| c.to_digit(10))
                    .map(|d| d as u8)
            } else {
                None
            }
        })
        .collect();
    if levels.len() > 1 {
        return Err(SarError::Malformed(
            "multiple compression levels specified; choose one of -0..-9",
        ));
    }
    Ok(levels.first().copied())
}

fn normalize_level_shorthand(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|arg| {
            if arg.len() == 2
                && arg.starts_with('-')
                && arg
                    .chars()
                    .nth(1)
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                format!("--compression-level={}", &arg[1..])
            } else {
                arg.clone()
            }
        })
        .collect()
}

fn value_after_flag(args: &[String], flag: &str) -> Result<PathBuf, SarError> {
    let idx = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or(SarError::Malformed("required shorthand flag missing"))?;
    let value = args
        .get(idx + 1)
        .ok_or(SarError::Malformed("flag value missing"))?;
    Ok(PathBuf::from(value))
}

fn handle_normal_cli(args: &[String]) -> Result<(), SarError> {
    let cli = Cli::parse_from(args);
    match cli.command.unwrap_or(Command::Version) {
        Command::Create {
            input,
            output,
            indexed,
            no_index,
            compression,
            zstd,
            deflate,
            store,
            compression_level,
            encrypt,
            password,
            fec,
        } => {
            if indexed && no_index {
                return Err(SarError::Malformed(
                    "--indexed and --no-index cannot be used together",
                ));
            }
            let compression =
                resolve_create_compression(compression, zstd, deflate, store, compression_level)?;
            create_archive(
                input,
                output,
                no_index && !indexed,
                compression,
                encrypt,
                password,
                fec,
            )
        }
        Command::Extract {
            archive,
            output_dir,
            password,
        } => extract_archive(archive, output_dir, password),
        Command::List { archive } => list_archive(archive),
        Command::Verify { archive, password } => verify_archive(archive, password),
        Command::Inspect { archive, json } => inspect_archive(archive, json),
        Command::Version => print_version(),
    }
}

fn compression_to_algo_id(compression: CompressionChoice) -> u8 {
    match compression {
        CompressionChoice::Store => COMP_ALGO_STORE,
        CompressionChoice::Deflate => COMP_ALGO_DEFLATE,
        CompressionChoice::Zstd => COMP_ALGO_ZSTD,
    }
}

fn fec_to_settings(fec: FecChoice) -> FecSettings {
    match fec {
        FecChoice::Xor => FecSettings::default_xor(),
        FecChoice::Rs => FecSettings::default_rs(),
    }
}

fn encryption_to_algo_id(encryption: EncryptionChoice) -> u8 {
    match encryption {
        EncryptionChoice::Aes256Gcm => ENCR_AES256_GCM,
        EncryptionChoice::XChaCha20Poly => ENCR_XCHACHA20_POLY,
    }
}

fn default_compression() -> CreateCompression {
    CreateCompression {
        algo_id: COMP_ALGO_STORE,
        level: None,
    }
}

fn resolve_create_compression(
    compression: Option<CompressionChoice>,
    zstd: bool,
    deflate: bool,
    store: bool,
    compression_level: Option<u8>,
) -> Result<CreateCompression, SarError> {
    let mut selected = Vec::new();
    if let Some(explicit) = compression {
        selected.push(explicit);
    }
    if zstd {
        selected.push(CompressionChoice::Zstd);
    }
    if deflate {
        selected.push(CompressionChoice::Deflate);
    }
    if store {
        selected.push(CompressionChoice::Store);
    }
    let Some(first) = selected.first().copied() else {
        return Ok(default_compression());
    };
    if selected.iter().any(|value| *value != first) {
        return Err(SarError::Malformed(
            "conflicting compression selectors; choose one of --compression/-Z/-z/-S",
        ));
    }
    Ok(CreateCompression {
        algo_id: compression_to_algo_id(first),
        level: compression_level,
    })
}

fn print_version() -> Result<(), SarError> {
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

fn create_archive(
    input: PathBuf,
    output: PathBuf,
    no_index: bool,
    compression: CreateCompression,
    encrypt: Option<EncryptionChoice>,
    password: Option<String>,
    fec: Option<FecChoice>,
) -> Result<(), SarError> {
    if encrypt.is_none() && (password.is_some() || env::var_os(PASSWORD_ENV).is_some()) {
        return Err(SarError::Malformed(
            "create only accepts passwords when --encrypt is specified",
        ));
    }

    let encryption = if let Some(choice) = encrypt {
        let password = load_password(password)?;
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| SarError::Internal("random salt generation failed"))?;
        let settings = EncryptionSettings {
            algo_id: encryption_to_algo_id(choice),
            kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
                salt: salt.to_vec(),
                iterations: 100_000,
                derived_key_length: 32,
            }),
        };
        Some((settings, password))
    } else {
        None
    };

    let fec_settings = fec.map(fec_to_settings);

    let file = File::create(output)?;
    let mut writer = match encryption {
        Some((settings, password)) => ArchiveWriter::new_with_compression_and_key_provider(
            file,
            ArchiveWriterOptions {
                no_index,
                encryption: Some(settings),
                fec: fec_settings,
            },
            CompressionSettings {
                algo_id: compression.algo_id,
                level: compression.level,
            },
            Some(Box::new(CliKeyProvider::new(Some(password)))),
        )?,
        None => ArchiveWriter::new_with_compression(
            file,
            ArchiveWriterOptions {
                no_index,
                encryption: None,
                fec: fec_settings,
            },
            CompressionSettings {
                algo_id: compression.algo_id,
                level: compression.level,
            },
        )?,
    };

    if input.is_file() {
        let name = input
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or(SarError::Malformed("input file name is missing"))?;
        let payload = fs::read(&input)?;
        writer.add_entry(EntryInput { name, payload })?;
    } else if input.is_dir() {
        for entry in WalkDir::new(&input).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(&input)
                .map_err(|_| SarError::Malformed("failed to compute relative path"))?;
            let name = rel.to_string_lossy().replace('\\', "/");
            let payload = fs::read(entry.path())?;
            writer.add_entry(EntryInput { name, payload })?;
        }
    } else {
        return Err(SarError::Malformed(
            "input path must be a file or directory",
        ));
    }

    let summary = writer.finish()?;
    println!(
        "created archive: {} entries, indexed={} size={} bytes",
        summary.entry_count, summary.indexed, summary.archive_size
    );
    Ok(())
}

fn list_archive(archive: PathBuf) -> Result<(), SarError> {
    let mut reader = ArchiveReader::new(BufReader::new(File::open(archive)?))?;
    let _ = reader.read_global_header()?;
    while let Some(entry) = reader.next_entry()? {
        println!(
            "{}\t{}\tencoded={}\tuncompressed={}",
            entry.metadata.name,
            entry.metadata.compression_algorithm,
            entry.metadata.payload_size,
            entry.metadata.uncompressed_size
        );
    }
    Ok(())
}

fn sanitize_relative(name: &str) -> Result<PathBuf, SarError> {
    let rel = Path::new(name);
    if rel.is_absolute() {
        return Err(SarError::Malformed("absolute paths are not allowed"));
    }
    if rel
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SarError::Malformed(
            "parent directory traversal is not allowed",
        ));
    }
    Ok(rel.to_path_buf())
}

fn extract_archive(
    archive: PathBuf,
    output_dir: PathBuf,
    password: Option<String>,
) -> Result<(), SarError> {
    fs::create_dir_all(&output_dir)?;
    let mut reader = ArchiveReader::new(BufReader::new(File::open(&archive)?))?;
    let header = reader.read_global_header()?;
    if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        let password = load_password(password)?;
        reader = reader.with_key_provider(Box::new(CliKeyProvider::new(Some(password))));
    }

    while let Some(entry) = reader.next_entry()? {
        let rel = sanitize_relative(&entry.metadata.name)?;
        let out_path = output_dir.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, entry.payload)?;
    }

    Ok(())
}

fn verify_archive(archive: PathBuf, password: Option<String>) -> Result<(), SarError> {
    let mut reader = ArchiveReader::new(BufReader::new(File::open(&archive)?))?;
    let header = reader.read_global_header()?;
    if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        let password = load_password(password)?;
        reader = reader.with_key_provider(Box::new(CliKeyProvider::new(Some(password))));
    }
    let report = reader.verify()?;
    println!(
        "verify: valid={} entries={} indexed={}",
        report.valid, report.entry_count, report.indexed
    );
    Ok(())
}

fn inspect_archive(archive: PathBuf, as_json: bool) -> Result<(), SarError> {
    let mut reader = ArchiveReader::new(BufReader::new(File::open(archive)?))?;
    let header = reader.read_global_header()?;

    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        entries.push(entry.metadata);
    }

    let metadata = reader.metadata();
    let recovery_tlvs: Vec<_> = metadata
        .as_ref()
        .and_then(|m| m.central_dictionary.as_ref())
        .map(|cd| {
            cd.metadata
                .iter()
                .filter(|tlv| (0x10..=0x1F).contains(&tlv.type_id))
                .map(|tlv| {
                    json!({
                        "type_id": format!("0x{:02X}", tlv.type_id),
                        "value_len": tlv.value.len(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    if as_json {
        let output = json!({
            "global_version": header.version,
            "flags": header.flags.bits(),
            "flags_size": header.flags_bytes.len(),
            "indexed": !header.flags.contains(GlobalFlags::NO_INDEX),
            "selective_fec": header.flags.contains(GlobalFlags::SELECTIVE_FEC),
            "entry_count": entries.len(),
            "recovery_tlvs": recovery_tlvs,
            "entries": entries,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| SarError::Generic)?
        );
    } else {
        println!("global_version={}", header.version);
        println!("flags=0x{:08X}", header.flags.bits());
        println!(
            "selective_fec={}",
            header.flags.contains(GlobalFlags::SELECTIVE_FEC)
        );
        println!("entries={}", entries.len());
        for entry in &entries {
            if let Some(fec) = &entry.fec {
                let fec_line = match fec {
                    sar_core::fec::FecSummary::Xor {
                        stripe_size,
                        block_size,
                        parity_data_len,
                        ..
                    } => format!(
                        "algo=xor stripe_size={stripe_size} block_size={block_size} parity_bytes={parity_data_len}"
                    ),
                    sar_core::fec::FecSummary::ReedSolomon {
                        k,
                        parity_count,
                        symbol_size,
                        parity_data_len,
                        ..
                    } => format!(
                        "algo=reed-solomon k={k} parity_count={parity_count} symbol_size={symbol_size} parity_bytes={parity_data_len}"
                    ),
                };
                println!("  entry={} fec={}", entry.name, fec_line);
            }
        }
        if !recovery_tlvs.is_empty() {
            println!("recovery_tlvs={}", recovery_tlvs.len());
        }
    }

    Ok(())
}

fn load_password(explicit: Option<String>) -> Result<SecretString, SarError> {
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
