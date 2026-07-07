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
    EntryInput, ErasureInput, FecSettings, GlobalFlags, KeyProvider, KmsContext, KmsParams,
    SarError, SecretBytes, fec::validate_recovery_tlv, fragment::FragmentDescriptor,
    fragment::FragmentEntry, fragment::validate_fragment_group, inspect_recovery_metadata,
    plan_archive_repair, repair_archive, sparse::validate_sparse_extents,
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
        /// Permit degraded (loss-tolerant) output when entries have LOSS_TOLERANT set.
        #[arg(long, action = ArgAction::SetTrue)]
        allow_lossy: bool,
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
                (Ok(archive), Ok(out)) => extract_archive(archive, out, None, false),
                (Err(err), _) | (_, Err(err)) => Err(err),
            })
        }
        "-t" => Some(value_after_flag(args, "-f").and_then(list_archive)),
        "-v" => {
            Some(value_after_flag(args, "-f").and_then(|path| verify_archive(path, None, false)))
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
        } => extract_archive(archive, output_dir, password, allow_lossy),
        Command::List { archive } => list_archive(archive),
        Command::Verify {
            archive,
            password,
            recovery,
        } => verify_archive(archive, password, recovery),
        Command::Inspect { archive, json } => inspect_archive(archive, json),
        Command::Repair {
            archive,
            output,
            fec,
            erasures,
        } => repair_cmd(archive, output, fec, erasures),
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
    allow_lossy: bool,
) -> Result<(), SarError> {
    fs::create_dir_all(&output_dir)?;
    let mut reader = ArchiveReader::new(BufReader::new(File::open(&archive)?))?;
    let header = reader.read_global_header()?;
    if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        let password = load_password(password)?;
        reader = reader.with_key_provider(Box::new(CliKeyProvider::new(Some(password))));
    }

    while let Some(entry) = reader.next_entry()? {
        // Warn about loss-tolerant entries since full fragment reconstruction
        // is not yet implemented in archival mode.
        if entry.metadata.is_loss_tolerant && !allow_lossy {
            eprintln!(
                "warning: entry '{}' has LOSS_TOLERANT set; full loss-tolerant extraction \
                 requires fragment support (use --allow-lossy to suppress this warning)",
                entry.metadata.name
            );
        }

        let rel = sanitize_relative(&entry.metadata.name)?;
        let out_path = output_dir.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, entry.payload)?;
    }

    Ok(())
}

fn verify_archive(
    archive: PathBuf,
    password: Option<String>,
    recovery: bool,
) -> Result<(), SarError> {
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

    if recovery {
        // Collect entries for additional recovery metadata validation
        let mut re_reader = ArchiveReader::new(BufReader::new(File::open(&archive)?))?;
        let _ = re_reader.read_global_header()?;
        let mut entries = Vec::new();
        while let Some(entry) = re_reader.next_entry()? {
            entries.push(entry.metadata);
        }

        // Validate sparse extents for each entry that has them
        let mut sparse_errors = 0u32;
        for entry in &entries {
            if entry
                .sparse_extents
                .as_ref()
                .is_some_and(|ext| validate_sparse_extents(ext, entry.uncompressed_size).is_err())
            {
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

            let max_offset = frag_entries
                .iter()
                .map(|f| {
                    f.descriptor
                        .absolute_offset
                        .saturating_add(u64::from(f.descriptor.fragment_size))
                })
                .max()
                .unwrap_or(0);

            if let Err(err) = validate_fragment_group(&frag_entries, max_offset) {
                eprintln!("recovery verify: fragment group {fid} error: {err}");
                frag_errors += 1;
            }
        }

        // Validate recovery TLVs and check repair_possible
        let archive_bytes = fs::read(&archive)?;
        let rec_meta = inspect_recovery_metadata(&archive_bytes)?;

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
    let mut reader = ArchiveReader::new(BufReader::new(File::open(&archive)?))?;
    let header = reader.read_global_header()?;

    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        entries.push(entry.metadata);
    }

    let metadata = reader.metadata();
    let has_global_ec = header.flags.contains(GlobalFlags::HAS_GLOBAL_EC);

    // Build recovery TLV list with validated summaries
    let recovery_tlvs_raw: Vec<_> = metadata
        .as_ref()
        .and_then(|m| m.central_dictionary.as_ref())
        .map(|cd| {
            cd.metadata
                .iter()
                .filter(|tlv| (0x10..=0x1F).contains(&tlv.type_id))
                .map(|tlv| {
                    let summary = validate_recovery_tlv(tlv.type_id, &tlv.value).ok();
                    (tlv.type_id, tlv.value.len(), summary)
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

        // Build per-entry JSON, adding sparse_extent_count
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
            "entry_count": entries.len(),
            "recovery_tlvs": recovery_tlvs_json,
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
    let archive_bytes = fs::read(&archive)?;

    // Inspect metadata
    let rec_meta = inspect_recovery_metadata(&archive_bytes)?;
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
    let plan = match plan_archive_repair(&archive_bytes, erasures) {
        Ok(plan) => plan,
        Err(SarError::RecoveryUnavailable(msg)) => {
            eprintln!("repair: planning failed — {msg}");
            return Err(SarError::RecoveryUnavailable(msg));
        }
        Err(err) => return Err(err),
    };

    // Execute repair
    let (repaired_bytes, report) = match repair_archive(&archive_bytes, &plan) {
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
