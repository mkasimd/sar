#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, File},
    io::{BufReader, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{ArgAction, Args, Parser, Subcommand};
use serde_json::json;
use walkdir::WalkDir;

use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_STORE, COMP_ALGO_ZSTD};
use sar_core::{
    ArchiveReader, ArchiveReaderOptions, ArchiveWriter, ArchiveWriterOptions, CompressionSettings,
    EncryptionSettings, EntryInput, ErasureInput, FecSettings, GlobalFlags, KeyProvider,
    KmsContext, KmsParams, ResourceLimits, SarError, SecretBytes,
    fec::validate_recovery_tlv,
    fragment::FragmentDescriptor,
    fragment::FragmentEntry,
    fragment::reconstruct_fragments,
    fragment::validate_fragment_group,
    inspect_recovery_metadata, plan_archive_repair, repair_archive,
    sparse::{SparseExtent, validate_sparse_extents},
};
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params, SecretString,
};

const SAR_SPEC_VERSION: &str = "1.0";
const SAR_CD_VERSION: &str = "1";
const PASSWORD_ENV: &str = "SAR_PASSWORD";
const ZERO_CHUNK_LEN: usize = 8192;

#[derive(Parser)]
#[command(name = "sar", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args, Debug, Clone, Copy, Default)]
struct LimitArgs {
    /// Override the maximum archive size accepted for in-memory archive operations.
    #[arg(long, value_name = "BYTES")]
    max_archive_size: Option<u64>,
    /// Override the maximum logical output size accepted for a single extracted entry.
    #[arg(long, value_name = "BYTES")]
    max_decoded_entry_size: Option<u64>,
    /// Override the maximum size of any single in-memory buffer.
    #[arg(long, value_name = "BYTES")]
    max_in_memory_buffer: Option<u64>,
    /// Override the maximum cumulative pipeline memory budget.
    #[arg(long, value_name = "BYTES")]
    max_total_pipeline_memory: Option<u64>,
    /// Override the maximum sparse-map byte length accepted from an LFH.
    #[arg(long, value_name = "BYTES")]
    max_sparse_map_bytes: Option<usize>,
    /// Override the maximum sparse extent descriptor count.
    #[arg(long, value_name = "COUNT")]
    max_sparse_descriptors: Option<usize>,
    /// Override the maximum fragment count accepted for one logical file.
    #[arg(long, value_name = "COUNT")]
    max_fragment_count: Option<usize>,
    /// Override the maximum fragment-group span accepted for one logical file.
    #[arg(long, value_name = "BYTES")]
    max_fragment_group_span: Option<u64>,
    /// Override the maximum permitted LOSS_TOLERANT fragment gap.
    #[arg(long, value_name = "BYTES")]
    max_loss_tolerant_gap: Option<u64>,
    /// Override the maximum protected range accepted for archive-level repair.
    #[arg(long, value_name = "BYTES")]
    max_recovery_protected_range: Option<u64>,
    /// Override the maximum working set accepted for archive-level repair.
    #[arg(long, value_name = "BYTES")]
    max_repair_working_set: Option<u64>,
}

impl LimitArgs {
    fn resource_limits(self) -> ResourceLimits {
        let mut limits = ResourceLimits::default();
        if let Some(value) = self.max_archive_size {
            limits.max_archive_size = value;
        }
        if let Some(value) = self.max_decoded_entry_size {
            limits.max_decoded_entry_size = value;
        }
        if let Some(value) = self.max_in_memory_buffer {
            limits.max_in_memory_buffer = value;
        }
        if let Some(value) = self.max_total_pipeline_memory {
            limits.max_total_pipeline_memory = value;
        }
        if let Some(value) = self.max_sparse_map_bytes {
            limits.max_sparse_map_bytes = value;
        }
        if let Some(value) = self.max_sparse_descriptors {
            limits.max_sparse_descriptors = value;
        }
        if let Some(value) = self.max_fragment_count {
            limits.max_fragment_count = value;
        }
        if let Some(value) = self.max_fragment_group_span {
            limits.max_fragment_group_span = value;
        }
        if let Some(value) = self.max_loss_tolerant_gap {
            limits.max_loss_tolerant_gap = value;
        }
        if let Some(value) = self.max_recovery_protected_range {
            limits.max_recovery_protected_range = value;
        }
        if let Some(value) = self.max_repair_working_set {
            limits.max_repair_working_set = value;
        }
        limits
    }
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
        /// Permit degraded (loss-tolerant) output when entries have LOSS_TOLERANT set.
        #[arg(long, action = ArgAction::SetTrue)]
        allow_lossy: bool,
        #[command(flatten)]
        limits: LimitArgs,
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
        /// Additionally validate fragmentation, sparse, and Data Recovery TLV metadata.
        #[arg(long, action = ArgAction::SetTrue)]
        recovery: bool,
        /// Validate CDC algorithm IDs and CDC_MAP TLVs (when CDC_SUPPORT is active).
        #[arg(long, action = ArgAction::SetTrue)]
        cdc: bool,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Inspect archive metadata.
    Inspect {
        /// Archive path.
        archive: PathBuf,
        /// Emit JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Repair archive using archive-level FEC Data Recovery TLVs.
    Repair {
        /// Archive path to repair.
        archive: PathBuf,
        /// Output path for the repaired archive.
        output: PathBuf,
        /// Activate FEC-based repair (required).
        #[arg(long, action = ArgAction::SetTrue)]
        fec: bool,
        /// Path to a JSON file describing explicit byte erasures.
        #[arg(long, value_name = "erasures.json")]
        erasures: Option<PathBuf>,
        #[command(flatten)]
        limits: LimitArgs,
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
        let prefix = if matches!(error, SarError::LimitExceeded(_)) {
            "resource-limit error"
        } else {
            "error"
        };
        eprintln!("{prefix} ({}): {error}", error.status());
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
                (Ok(archive), Ok(out)) => {
                    extract_archive(archive, out, None, false, ResourceLimits::default())
                }
                (Err(err), _) | (_, Err(err)) => Err(err),
            })
        }
        "-t" => Some(value_after_flag(args, "-f").and_then(list_archive)),
        "-v" => {
            Some(value_after_flag(args, "-f").and_then(|path| {
                verify_archive(path, None, false, false, ResourceLimits::default())
            }))
        }
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
            allow_lossy,
            limits,
        } => extract_archive(
            archive,
            output_dir,
            password,
            allow_lossy,
            limits.resource_limits(),
        ),
        Command::List { archive } => list_archive(archive),
        Command::Verify {
            archive,
            password,
            recovery,
            cdc,
            limits,
        } => verify_archive(archive, password, recovery, cdc, limits.resource_limits()),
        Command::Inspect { archive, json } => inspect_archive(archive, json),
        Command::Repair {
            archive,
            output,
            fec,
            erasures,
            limits,
        } => repair_cmd(archive, output, fec, erasures, limits.resource_limits()),
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
                sparse: false,
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
                sparse: false,
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

fn make_temp_output_path(final_path: &Path) -> Result<PathBuf, SarError> {
    let file_name = final_path
        .file_name()
        .ok_or(SarError::Malformed("output file name is missing"))?
        .to_string_lossy();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SarError::Internal("system clock before unix epoch"))?
        .as_nanos();
    Ok(final_path.with_file_name(format!(
        ".{file_name}.sar-tmp-{}-{nonce}",
        std::process::id()
    )))
}

fn remove_temp_file_if_exists(path: &Path) {
    let _ = fs::remove_file(path);
}

fn finalize_temp_file(tmp_path: &Path, final_path: &Path) -> Result<(), SarError> {
    match fs::rename(tmp_path, final_path) {
        Ok(()) => Ok(()),
        Err(err) => {
            remove_temp_file_if_exists(tmp_path);
            Err(SarError::Io(err))
        }
    }
}

fn write_bytes_via_temp(out_path: &Path, data: &[u8]) -> Result<(), SarError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = make_temp_output_path(out_path)?;
    let result = (|| -> Result<(), SarError> {
        let mut file = File::create(&tmp_path)?;
        file.write_all(data)?;
        drop(file);
        finalize_temp_file(&tmp_path, out_path)
    })();
    if result.is_err() {
        remove_temp_file_if_exists(&tmp_path);
    }
    result
}

fn write_sparse_payload_via_temp(
    out_path: &Path,
    payload: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<(), SarError> {
    limits.check_decoded_entry_size(logical_size)?;
    validate_sparse_extents(extents, logical_size, limits)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = make_temp_output_path(out_path)?;
    let result = (|| -> Result<(), SarError> {
        let mut file = File::create(&tmp_path)?;
        file.set_len(logical_size)?;

        let mut payload_pos = 0usize;
        for extent in extents {
            let dst_offset = extent.offset;
            let len =
                usize::try_from(extent.length).map_err(|_| SarError::Overflow("extent length"))?;
            let src_end = payload_pos
                .checked_add(len)
                .ok_or(SarError::Overflow("payload position"))?;
            if src_end > payload.len() {
                return Err(SarError::Truncated(
                    "payload too short for declared sparse extents",
                ));
            }
            file.seek(SeekFrom::Start(dst_offset))?;
            file.write_all(&payload[payload_pos..src_end])?;
            payload_pos = src_end;
        }
        if payload_pos != payload.len() {
            return Err(SarError::InvalidMap(
                "sparse payload has excess bytes beyond declared extents",
            ));
        }
        drop(file);
        finalize_temp_file(&tmp_path, out_path)
    })();
    if result.is_err() {
        remove_temp_file_if_exists(&tmp_path);
    }
    result
}

fn compute_sparse_crc32(
    payload: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<u32, SarError> {
    limits.check_decoded_entry_size(logical_size)?;
    validate_sparse_extents(extents, logical_size, limits)?;
    let mut hasher = crc32fast::Hasher::new();
    let zero_chunk = [0u8; ZERO_CHUNK_LEN];
    let mut payload_pos = 0usize;
    let mut cursor = 0u64;

    for extent in extents {
        let gap = extent
            .offset
            .checked_sub(cursor)
            .ok_or(SarError::Overflow("sparse hole length"))?;
        hash_zero_bytes(&mut hasher, gap, &zero_chunk);
        let len =
            usize::try_from(extent.length).map_err(|_| SarError::Overflow("extent length"))?;
        let src_end = payload_pos
            .checked_add(len)
            .ok_or(SarError::Overflow("payload position"))?;
        if src_end > payload.len() {
            return Err(SarError::Truncated(
                "payload too short for declared sparse extents",
            ));
        }
        hasher.update(&payload[payload_pos..src_end]);
        payload_pos = src_end;
        cursor = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SarError::Overflow("sparse extent offset+length overflow"))?;
    }

    let trailing = logical_size
        .checked_sub(cursor)
        .ok_or(SarError::Overflow("trailing sparse hole length"))?;
    hash_zero_bytes(&mut hasher, trailing, &zero_chunk);

    if payload_pos != payload.len() {
        return Err(SarError::InvalidMap(
            "sparse payload has excess bytes beyond declared extents",
        ));
    }

    Ok(hasher.finalize())
}

fn hash_zero_bytes(
    hasher: &mut crc32fast::Hasher,
    mut len: u64,
    zero_chunk: &[u8; ZERO_CHUNK_LEN],
) {
    while len > 0 {
        let chunk_len = usize::try_from(len.min(ZERO_CHUNK_LEN as u64)).unwrap_or(ZERO_CHUNK_LEN);
        hasher.update(&zero_chunk[..chunk_len]);
        len -= u64::try_from(chunk_len).unwrap_or(0);
    }
}

fn read_file_with_archive_limit(path: &Path, limits: &ResourceLimits) -> Result<Vec<u8>, SarError> {
    let archive_len = fs::metadata(path)?.len();
    limits.check_archive_size(archive_len)?;
    fs::read(path).map_err(SarError::Io)
}

fn verify_crc32(
    expected_crc: Option<u32>,
    actual_crc: u32,
    message: &'static str,
) -> Result<(), SarError> {
    if let Some(expected_crc) = expected_crc
        && expected_crc != actual_crc
    {
        return Err(SarError::CrcMismatch(message));
    }
    Ok(())
}

fn extract_archive(
    archive: PathBuf,
    output_dir: PathBuf,
    password: Option<String>,
    allow_lossy: bool,
    limits: ResourceLimits,
) -> Result<(), SarError> {
    fs::create_dir_all(&output_dir)?;
    let mut reader = ArchiveReader::with_options(
        BufReader::new(File::open(&archive)?),
        ArchiveReaderOptions { limits },
    )?;
    let header = reader.read_global_header()?;
    if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        let password = load_password(password)?;
        reader = reader.with_key_provider(Box::new(CliKeyProvider::new(Some(password))));
    }

    #[derive(Debug)]
    struct FragGroup {
        name: String,
        entries: Vec<sar_core::archive::EntryReader>,
        sparse_extents: Option<Vec<SparseExtent>>,
        sparse_uncompressed_size: u64,
        file_crc32: Option<u32>,
    }

    let mut frag_order = Vec::new();
    let mut frag_groups = std::collections::HashMap::<u32, FragGroup>::new();

    while let Some(entry) = reader.next_entry()? {
        if entry.metadata.name.is_empty() && !entry.metadata.is_fragment {
            continue;
        }

        if entry.metadata.is_fragment {
            let fid = entry.metadata.fragment_id.ok_or(SarError::Malformed(
                "IS_FRAGMENT set but fragment_id is absent",
            ))?;
            let has_sparse = entry.metadata.sparse_extents.is_some();
            if has_sparse && entry.metadata.fragment_index != Some(0) {
                return Err(SarError::InvalidMap(
                    "sparse map present on non-zero fragment index; Sparse Map MUST appear only in fragment with Fragment Index = 0",
                ));
            }

            let group = frag_groups.entry(fid).or_insert_with(|| {
                frag_order.push(fid);
                FragGroup {
                    name: entry.metadata.name.clone(),
                    entries: Vec::new(),
                    sparse_extents: None,
                    sparse_uncompressed_size: 0,
                    file_crc32: None,
                }
            });
            limits.check_fragment_count(
                group
                    .entries
                    .len()
                    .checked_add(1)
                    .ok_or(SarError::Overflow("fragment count"))?,
            )?;

            if entry.metadata.fragment_index == Some(0) {
                if has_sparse {
                    group.sparse_extents = entry.metadata.sparse_extents.clone();
                    group.sparse_uncompressed_size = entry.metadata.uncompressed_size;
                }
                group.file_crc32 = entry.metadata.file_crc32;
            }

            group.entries.push(entry);
            continue;
        }

        let rel = sanitize_relative(&entry.metadata.name)?;
        let out_path = output_dir.join(rel);
        if let Some(extents) = entry.metadata.sparse_extents.as_ref() {
            let actual_crc = compute_sparse_crc32(
                &entry.payload,
                extents,
                entry.metadata.uncompressed_size,
                &limits,
            )?;
            if header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    entry.metadata.file_crc32,
                    actual_crc,
                    "file CRC32 mismatch on reconstructed logical file",
                )?;
            }
            write_sparse_payload_via_temp(
                &out_path,
                &entry.payload,
                extents,
                entry.metadata.uncompressed_size,
                &limits,
            )?;
        } else {
            if header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    entry.metadata.file_crc32,
                    crc32fast::hash(&entry.payload),
                    "file CRC32 mismatch on reconstructed logical file",
                )?;
            }
            write_bytes_via_temp(&out_path, &entry.payload)?;
        }
    }

    for fid in frag_order {
        let FragGroup {
            name,
            entries: group_entries,
            sparse_extents,
            sparse_uncompressed_size,
            file_crc32,
        } = frag_groups.remove(&fid).ok_or(SarError::Malformed(
            "fragment group ID vanished during reconstruction",
        ))?;

        let mut assembled_size = 0u64;
        for entry in &group_entries {
            if let Some(desc) = &entry.metadata.fragment_descriptor {
                let end = desc
                    .absolute_offset
                    .checked_add(u64::from(desc.fragment_size))
                    .ok_or(SarError::Overflow("fragment descriptor end overflow"))?;
                assembled_size = assembled_size.max(end);
            }
        }

        let frag_entries: Vec<FragmentEntry> = group_entries
            .into_iter()
            .filter_map(|entry| {
                let desc = entry.metadata.fragment_descriptor?;
                Some(FragmentEntry {
                    fragment_index: entry.metadata.fragment_index.unwrap_or(0),
                    is_last_fragment: entry.metadata.is_last_fragment,
                    is_loss_tolerant: entry.metadata.is_loss_tolerant,
                    descriptor: desc,
                    payload: entry.payload,
                })
            })
            .collect();

        let (raw, is_degraded) = reconstruct_fragments(frag_entries, assembled_size, &limits)?;
        if is_degraded && !allow_lossy {
            return Err(SarError::FragmentGap(
                "fragment group has gaps; use allow_lossy to permit degraded output",
            ));
        }
        if is_degraded {
            eprintln!(
                "warning: '{}' extracted with degraded (incomplete) content; \
                 missing fragments were replaced with zero bytes (LOSS_TOLERANT). \
                 This output MUST NOT be used for integrity-critical purposes.",
                name
            );
        }

        let rel = sanitize_relative(&name)?;
        let out_path = output_dir.join(rel);
        if let Some(extents) = sparse_extents.as_ref() {
            let actual_crc =
                compute_sparse_crc32(&raw, extents, sparse_uncompressed_size, &limits)?;
            if header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    file_crc32,
                    actual_crc,
                    "file CRC32 mismatch on reconstructed fragment-group logical file",
                )?;
            }
            write_sparse_payload_via_temp(
                &out_path,
                &raw,
                extents,
                sparse_uncompressed_size,
                &limits,
            )?;
        } else {
            if header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    file_crc32,
                    crc32fast::hash(&raw),
                    "file CRC32 mismatch on reconstructed fragment-group logical file",
                )?;
            }
            write_bytes_via_temp(&out_path, &raw)?;
        }
    }

    Ok(())
}

fn verify_archive(
    archive: PathBuf,
    password: Option<String>,
    recovery: bool,
    cdc: bool,
    limits: ResourceLimits,
) -> Result<(), SarError> {
    let mut reader = ArchiveReader::with_options(
        BufReader::new(File::open(&archive)?),
        ArchiveReaderOptions { limits },
    )?;
    let header = reader.read_global_header()?;
    let password = if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        Some(load_password(password)?)
    } else {
        None
    };
    if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        reader = reader.with_key_provider(Box::new(CliKeyProvider::new(password.clone())));
    }
    let report = reader.verify()?;
    println!(
        "verify: valid={} entries={} indexed={}",
        report.valid, report.entry_count, report.indexed
    );

    if cdc || report.cdc_support {
        println!(
            "verify: cdc_support={} cdc_entries={}",
            report.cdc_support, report.cdc_entry_count
        );
        if report.cdc_support && cdc {
            println!("verify: cdc_validation=pass");
        } else if cdc && !report.cdc_support {
            println!("verify: cdc_support=false (CDC_SUPPORT flag not set in archive)");
        }
    }

    if recovery {
        // Collect entries for additional recovery metadata validation
        let mut re_reader = ArchiveReader::with_options(
            BufReader::new(File::open(&archive)?),
            ArchiveReaderOptions { limits },
        )?;
        let _ = re_reader.read_global_header()?;
        if password.is_some() {
            re_reader = re_reader.with_key_provider(Box::new(CliKeyProvider::new(password)));
        }
        let mut entries = Vec::new();
        while let Some(entry) = re_reader.next_entry()? {
            entries.push(entry.metadata);
        }

        // Validate sparse extents for each entry that has them
        let mut sparse_errors = 0u32;
        for entry in &entries {
            if entry.sparse_extents.as_ref().is_some_and(|ext| {
                validate_sparse_extents(ext, entry.uncompressed_size, &limits).is_err()
            }) {
                eprintln!("recovery verify: sparse extent error in '{}'", entry.name);
                sparse_errors += 1;
            }
        }

        // Group entries by fragment_id and validate fragment groups
        let mut frag_groups: std::collections::HashMap<u32, Vec<&sar_core::EntryMetadata>> =
            std::collections::HashMap::new();
        for entry in &entries {
            if let (true, Some(fid)) = (entry.is_fragment, entry.fragment_id) {
                frag_groups.entry(fid).or_default().push(entry);
            }
        }

        let mut frag_errors = 0u32;
        for (fid, group) in &frag_groups {
            // Build FragmentEntry list for validation
            let frag_entries: Vec<FragmentEntry> = group
                .iter()
                .filter_map(|entry| {
                    let desc = entry.fragment_descriptor.as_ref()?;
                    Some(FragmentEntry {
                        fragment_index: entry.fragment_index.unwrap_or(0),
                        is_last_fragment: entry.is_last_fragment,
                        is_loss_tolerant: entry.is_loss_tolerant,
                        descriptor: FragmentDescriptor {
                            absolute_offset: desc.absolute_offset,
                            fragment_size: desc.fragment_size,
                        },
                        payload: Vec::new(), // not needed for validation
                    })
                })
                .collect();

            let max_offset = frag_entries.iter().try_fold(0u64, |max_end, f| {
                let end = f
                    .descriptor
                    .absolute_offset
                    .checked_add(u64::from(f.descriptor.fragment_size))
                    .ok_or(SarError::Overflow("fragment descriptor end"))?;
                Ok::<u64, SarError>(max_end.max(end))
            })?;

            if let Err(err) = validate_fragment_group(&frag_entries, max_offset, &limits) {
                eprintln!("recovery verify: fragment group {fid} error: {err}");
                frag_errors += 1;
            }
        }

        // Validate recovery TLVs and check repair_possible
        let archive_bytes = read_file_with_archive_limit(&archive, &limits)?;
        let rec_meta = inspect_recovery_metadata(&archive_bytes, &limits)?;

        println!(
            "recovery verify: sparse_errors={sparse_errors} fragment_group_errors={frag_errors}"
        );
        println!(
            "recovery verify: has_global_ec={} recovery_tlv_count={} repair_possible={}",
            rec_meta.has_global_ec,
            rec_meta.recovery_tlvs.len(),
            rec_meta.repair_possible
        );
        if let Some(reason) = rec_meta.repair_unavailable_reason {
            println!("recovery verify: repair_unavailable_reason={reason}");
        }

        if sparse_errors > 0 || frag_errors > 0 {
            return Err(SarError::Malformed(
                "recovery metadata validation found errors",
            ));
        }
    }

    Ok(())
}

fn inspect_archive(archive: PathBuf, as_json: bool) -> Result<(), SarError> {
    let limits = ResourceLimits::default();
    let mut reader = ArchiveReader::new(BufReader::new(File::open(&archive)?))?;
    let header = reader.read_global_header()?;

    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        entries.push(entry.metadata);
    }

    let metadata = reader.metadata();
    let has_global_ec = header.flags.contains(GlobalFlags::HAS_GLOBAL_EC);
    let cdc_support = header.flags.contains(GlobalFlags::CDC_SUPPORT);

    // Build recovery TLV list with validated summaries
    let recovery_tlvs_raw: Vec<_> = metadata
        .as_ref()
        .and_then(|m| m.central_dictionary.as_ref())
        .map(|cd| {
            cd.metadata
                .iter()
                .filter(|tlv| (0x10..=0x1F).contains(&tlv.type_id))
                .map(|tlv| {
                    let summary = validate_recovery_tlv(tlv.type_id, &tlv.value, &limits).ok();
                    (tlv.type_id, tlv.value.len(), summary)
                })
                .collect()
        })
        .unwrap_or_default();

    // Collect CDC_MAP TLV info (record count).
    let cdc_map_tlvs_raw: Vec<_> = metadata
        .as_ref()
        .and_then(|m| m.central_dictionary.as_ref())
        .map(|cd| {
            cd.metadata
                .iter()
                .filter(|tlv| (0x40..=0x4F).contains(&tlv.type_id))
                .map(|tlv| {
                    use sar_core::CDC_MAP_RECORD_LEN;
                    let record_count = if tlv.value.len() % CDC_MAP_RECORD_LEN == 0 {
                        tlv.value.len() / CDC_MAP_RECORD_LEN
                    } else {
                        0
                    };
                    (tlv.type_id, tlv.value.len(), record_count)
                })
                .collect()
        })
        .unwrap_or_default();

    let repair_possible = has_global_ec && !recovery_tlvs_raw.is_empty();

    if as_json {
        let recovery_tlvs_json: Vec<serde_json::Value> = recovery_tlvs_raw
            .iter()
            .map(|(type_id, value_len, summary)| {
                json!({
                    "type_id": format!("0x{type_id:02X}"),
                    "value_len": value_len,
                    "summary": summary,
                })
            })
            .collect();

        let cdc_map_tlvs_json: Vec<serde_json::Value> = cdc_map_tlvs_raw
            .iter()
            .map(|(type_id, value_len, record_count)| {
                json!({
                    "type_id": format!("0x{type_id:02X}"),
                    "value_len": value_len,
                    "record_count": record_count,
                })
            })
            .collect();

        // Build per-entry JSON, adding sparse_extent_count and cdc_algo_id
        let entries_json: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| {
                let sparse_extent_count = entry.sparse_extents.as_ref().map_or(0, Vec::len);
                let mut val = serde_json::to_value(entry).unwrap_or(json!({}));
                if let Some(obj) = val.as_object_mut() {
                    obj.insert(
                        "sparse_extent_count".to_string(),
                        json!(sparse_extent_count),
                    );
                }
                val
            })
            .collect();

        let output = json!({
            "global_version": header.version,
            "flags": header.flags.bits(),
            "flags_size": header.flags_bytes.len(),
            "indexed": !header.flags.contains(GlobalFlags::NO_INDEX),
            "selective_fec": header.flags.contains(GlobalFlags::SELECTIVE_FEC),
            "global_ec": has_global_ec,
            "fragmentation": header.flags.contains(GlobalFlags::FILE_FRAGMENTATION),
            "sparse_files": header.flags.contains(GlobalFlags::SPARSE_FILES),
            "cdc_support": cdc_support,
            "entry_count": entries.len(),
            "recovery_tlvs": recovery_tlvs_json,
            "cdc_map_tlvs": cdc_map_tlvs_json,
            "repair_possible": repair_possible,
            "entries": entries_json,
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
        println!("global_ec={has_global_ec}");
        println!("cdc_support={cdc_support}");
        println!(
            "fragmentation={}",
            header.flags.contains(GlobalFlags::FILE_FRAGMENTATION)
        );
        println!(
            "sparse_files={}",
            header.flags.contains(GlobalFlags::SPARSE_FILES)
        );
        println!("entries={}", entries.len());
        println!("repair_possible={repair_possible}");
        if !cdc_map_tlvs_raw.is_empty() {
            println!("cdc_map_tlvs={}", cdc_map_tlvs_raw.len());
            for (type_id, value_len, record_count) in &cdc_map_tlvs_raw {
                println!(
                    "  cdc_map: type_id=0x{type_id:02X} value_len={value_len} record_count={record_count}"
                );
            }
        }
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
            if entry.is_fragment {
                println!(
                    "  entry={} fragment_id={:?} fragment_index={:?} last={} loss_tolerant={}",
                    entry.name,
                    entry.fragment_id,
                    entry.fragment_index,
                    entry.is_last_fragment,
                    entry.is_loss_tolerant
                );
            }
            if let Some(extents) = &entry.sparse_extents {
                println!(
                    "  entry={} sparse_extent_count={}",
                    entry.name,
                    extents.len()
                );
            }
            if let Some(algo_id) = entry.cdc_algo_id {
                let name = sar_cdc::algo_name(algo_id);
                println!(
                    "  entry={} cdc_algo_id=0x{algo_id:02X} ({name})",
                    entry.name
                );
            }
        }
        if !recovery_tlvs_raw.is_empty() {
            println!("recovery_tlvs={}", recovery_tlvs_raw.len());
        }
    }

    Ok(())
}

fn repair_cmd(
    archive: PathBuf,
    output: PathBuf,
    fec: bool,
    erasures_path: Option<PathBuf>,
    limits: ResourceLimits,
) -> Result<(), SarError> {
    if !fec {
        return Err(SarError::Malformed("repair requires --fec"));
    }

    let erasures_file =
        erasures_path.ok_or(SarError::Malformed("repair requires --erasures <file>"))?;

    // Parse erasure input from JSON
    let erasures_bytes = fs::read(&erasures_file)?;
    let erasures: ErasureInput = serde_json::from_slice(&erasures_bytes)
        .map_err(|_| SarError::Malformed("failed to parse erasures JSON"))?;

    // Read archive bytes
    let archive_bytes = read_file_with_archive_limit(&archive, &limits)?;

    // Inspect metadata
    let rec_meta = inspect_recovery_metadata(&archive_bytes, &limits)?;
    if !rec_meta.repair_possible {
        let reason = rec_meta
            .repair_unavailable_reason
            .unwrap_or("repair unavailable");
        eprintln!("repair: recovery unavailable — {reason}");
        return Err(SarError::RecoveryUnavailable(
            "archive-level repair is unavailable for this archive",
        ));
    }

    // Plan repair
    let plan = match plan_archive_repair(&archive_bytes, erasures, &limits) {
        Ok(plan) => plan,
        Err(SarError::RecoveryUnavailable(msg)) => {
            eprintln!("repair: planning failed — {msg}");
            return Err(SarError::RecoveryUnavailable(msg));
        }
        Err(err) => return Err(err),
    };

    // Execute repair
    let (repaired_bytes, report) = match repair_archive(&archive_bytes, &plan, &limits) {
        Ok(pair) => pair,
        Err(SarError::EcFailed(msg)) => {
            eprintln!("repair: FEC repair failed (too many erasures) — {msg}");
            return Err(SarError::EcFailed(msg));
        }
        Err(SarError::RecoveryUnavailable(msg)) => {
            eprintln!("repair: recovery unavailable — {msg}");
            return Err(SarError::RecoveryUnavailable(msg));
        }
        Err(err) => return Err(err),
    };

    // Write to temp file first — append .tmp to the full output path to avoid extension confusion
    let tmp_path = PathBuf::from(format!("{}.tmp", output.display()));
    if let Err(err) = fs::write(&tmp_path, &repaired_bytes) {
        eprintln!("repair: failed to write temp file: {err}");
        return Err(SarError::Io(err));
    }

    // Verify temp file structure
    let verify_result = (|| -> Result<(), SarError> {
        let mut re_reader = ArchiveReader::new(BufReader::new(File::open(&tmp_path)?))?;
        let _ = re_reader.read_global_header()?;
        re_reader.verify()?;
        Ok(())
    })();

    if let Err(err) = verify_result {
        eprintln!("repair: temp file verification failed: {err}");
        if let Err(rm_err) = fs::remove_file(&tmp_path) {
            eprintln!(
                "repair: warning: could not remove temp file {}: {rm_err}",
                tmp_path.display()
            );
        }
        return Err(err);
    }

    // Rename temp to final output
    if let Err(err) = fs::rename(&tmp_path, &output) {
        if let Err(rm_err) = fs::remove_file(&tmp_path) {
            eprintln!(
                "repair: warning: could not remove temp file {}: {rm_err}",
                tmp_path.display()
            );
        }
        return Err(SarError::Io(err));
    }

    println!(
        "repair: success repaired_ranges={} degraded={}",
        report.repaired_ranges.len(),
        report.degraded
    );
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
