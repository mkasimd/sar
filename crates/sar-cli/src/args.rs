use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};
use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_STORE, COMP_ALGO_ZSTD};
use sar_core::{ResourceLimits, SarError};

use crate::extraction::policy::ExtractMetadataOptions;

#[derive(Parser)]
#[command(name = "sar", version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Args, Debug, Clone, Copy, Default)]
pub(crate) struct LimitArgs {
    #[arg(long, value_name = "BYTES")]
    max_archive_size: Option<u64>,
    #[arg(long, value_name = "BYTES")]
    max_decoded_entry_size: Option<u64>,
    #[arg(long, value_name = "BYTES")]
    max_in_memory_buffer: Option<u64>,
    #[arg(long, value_name = "BYTES")]
    max_total_pipeline_memory: Option<u64>,
    #[arg(long, value_name = "BYTES")]
    max_sparse_map_bytes: Option<usize>,
    #[arg(long, value_name = "COUNT")]
    max_sparse_descriptors: Option<usize>,
    #[arg(long, value_name = "COUNT")]
    max_fragment_count: Option<usize>,
    #[arg(long, value_name = "BYTES")]
    max_fragment_group_span: Option<u64>,
    #[arg(long, value_name = "BYTES")]
    max_loss_tolerant_gap: Option<u64>,
    #[arg(long, value_name = "BYTES")]
    max_recovery_protected_range: Option<u64>,
    #[arg(long, value_name = "BYTES")]
    max_repair_working_set: Option<u64>,
}

impl LimitArgs {
    pub(crate) fn resource_limits(self) -> ResourceLimits {
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
pub(crate) enum CompressionChoice {
    Store,
    Deflate,
    Zstd,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EncryptionChoice {
    #[value(name = "aes256-gcm")]
    Aes256Gcm,
    #[value(name = "xchacha20-poly")]
    XChaCha20Poly,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FecChoice {
    Xor,
    #[value(name = "rs")]
    Rs,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum SymlinkCreatePolicy {
    #[default]
    Skip,
    Follow,
    Archive,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CreateCompression {
    pub(crate) algo_id: u8,
    pub(crate) level: Option<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct CreateCommandOptions {
    pub(crate) no_index: bool,
    pub(crate) compression: CreateCompression,
    pub(crate) encrypt: Option<EncryptionChoice>,
    pub(crate) password: Option<String>,
    pub(crate) fec: Option<FecChoice>,
    pub(crate) metadata: CreateMetadataOptions,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CreateMetadataOptions {
    pub(crate) preserve_permissions: bool,
    pub(crate) preserve_owner: bool,
    pub(crate) preserve_times: bool,
    pub(crate) symlink_policy: SymlinkCreatePolicy,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Create {
        input: PathBuf,
        output: PathBuf,
        #[arg(long, action = ArgAction::SetTrue)]
        indexed: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        no_index: bool,
        #[arg(long, value_enum)]
        compression: Option<CompressionChoice>,
        #[arg(short = 'Z', action = ArgAction::SetTrue)]
        zstd: bool,
        #[arg(short = 'z', action = ArgAction::SetTrue)]
        deflate: bool,
        #[arg(short = 'S', action = ArgAction::SetTrue)]
        store: bool,
        #[arg(long = "compression-level", value_parser = clap::value_parser!(u8).range(0..=9))]
        compression_level: Option<u8>,
        #[arg(long, value_enum)]
        encrypt: Option<EncryptionChoice>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, value_enum)]
        fec: Option<FecChoice>,
        #[arg(long, action = ArgAction::SetTrue)]
        preserve_permissions: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        preserve_owner: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        preserve_times: bool,
        #[arg(long, value_enum, default_value_t = SymlinkCreatePolicy::Skip)]
        symlinks: SymlinkCreatePolicy,
    },
    Extract {
        archive: PathBuf,
        output_dir: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        allow_lossy: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        preserve_permissions: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        preserve_times: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        preserve_owner: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        allow_symlinks: bool,
        #[command(flatten)]
        limits: LimitArgs,
    },
    List {
        archive: PathBuf,
        #[arg(long, action = ArgAction::SetTrue)]
        metadata: bool,
    },
    Verify {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        recovery: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        cdc: bool,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Inspect {
        archive: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Repair {
        archive: PathBuf,
        output: PathBuf,
        #[arg(long, action = ArgAction::SetTrue)]
        fec: bool,
        #[arg(long, value_name = "erasures.json")]
        erasures: Option<PathBuf>,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Version,
}

pub(crate) enum ParsedInvocation {
    Shorthand(ShorthandCommand),
    Standard(Command),
}

pub(crate) enum ShorthandCommand {
    Create {
        input: PathBuf,
        output: PathBuf,
        options: CreateCommandOptions,
    },
    Extract {
        archive: PathBuf,
        output_dir: PathBuf,
        metadata: ExtractMetadataOptions,
    },
    List {
        archive: PathBuf,
    },
    Verify {
        archive: PathBuf,
    },
    Version,
}

pub(crate) fn parse_invocation(args: &[String]) -> Result<ParsedInvocation, SarError> {
    if let Some(shorthand) = try_parse_shorthand(args)? {
        return Ok(ParsedInvocation::Shorthand(shorthand));
    }
    let normalized = normalize_level_shorthand(args);
    let cli = Cli::parse_from(normalized);
    Ok(ParsedInvocation::Standard(
        cli.command.unwrap_or(Command::Version),
    ))
}

fn try_parse_shorthand(args: &[String]) -> Result<Option<ShorthandCommand>, SarError> {
    if args.len() <= 1 {
        return Ok(None);
    }
    if args.iter().any(|arg| arg == "-V") {
        return Ok(Some(ShorthandCommand::Version));
    }

    let mode_flags = ["-c", "-x", "-t", "-v"];
    let active: Vec<&str> = mode_flags
        .iter()
        .copied()
        .filter(|flag| args.iter().any(|arg| arg == flag))
        .collect();
    if active.is_empty() {
        return Ok(None);
    }
    if active.len() > 1 {
        return Err(SarError::Malformed(
            "ambiguous shorthand: provide only one of -c/-x/-t/-v",
        ));
    }

    match active[0] {
        "-c" => {
            let input = args
                .iter()
                .skip(1)
                .find(|arg| !arg.starts_with('-'))
                .map(PathBuf::from)
                .ok_or(SarError::Malformed("-c requires <input>"))?;
            let output = value_after_flag(args, "-f")?;
            let compression = resolve_shorthand_compression(args)?;
            Ok(Some(ShorthandCommand::Create {
                input,
                output,
                options: CreateCommandOptions {
                    no_index: false,
                    compression,
                    encrypt: None,
                    password: None,
                    fec: None,
                    metadata: CreateMetadataOptions {
                        preserve_permissions: false,
                        preserve_owner: false,
                        preserve_times: false,
                        symlink_policy: SymlinkCreatePolicy::Skip,
                    },
                },
            }))
        }
        "-x" => Ok(Some(ShorthandCommand::Extract {
            archive: value_after_flag(args, "-f")?,
            output_dir: value_after_flag(args, "-C")?,
            metadata: ExtractMetadataOptions::default(),
        })),
        "-t" => Ok(Some(ShorthandCommand::List {
            archive: value_after_flag(args, "-f")?,
        })),
        "-v" => Ok(Some(ShorthandCommand::Verify {
            archive: value_after_flag(args, "-f")?,
        })),
        _ => Ok(None),
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
    Ok(CreateCompression {
        algo_id: compression_to_algo_id(
            selected
                .first()
                .copied()
                .unwrap_or(CompressionChoice::Store),
        ),
        level: parse_level_shorthand(args)?,
    })
}

pub(crate) fn resolve_create_compression(
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
        return Ok(CreateCompression {
            algo_id: COMP_ALGO_STORE,
            level: None,
        });
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

fn compression_to_algo_id(compression: CompressionChoice) -> u8 {
    match compression {
        CompressionChoice::Store => COMP_ALGO_STORE,
        CompressionChoice::Deflate => COMP_ALGO_DEFLATE,
        CompressionChoice::Zstd => COMP_ALGO_ZSTD,
    }
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
