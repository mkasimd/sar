#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    io::{BufReader, Write},
    path::{Component, Path, PathBuf},
};

use clap::{ArgAction, Parser, Subcommand};
use serde_json::json;
use walkdir::WalkDir;

use sar_core::{ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput, SarError};

const SAR_SPEC_VERSION: &str = "1.0";
const SAR_CD_VERSION: &str = "1";

#[derive(Parser)]
#[command(name = "sar", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
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
    },
    /// Extract archive to output directory.
    Extract {
        /// Archive path.
        archive: PathBuf,
        /// Output directory.
        output_dir: PathBuf,
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
    let args: Vec<String> = std::env::args().collect();
    let result = if let Some(outcome) = try_handle_shorthand(&args) {
        outcome
    } else {
        handle_normal_cli()
    };

    if let Err(error) = result {
        eprintln!("error ({:?}): {error}", error.status());
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
            Some(match (input, output) {
                (Ok(input), Ok(output)) => create_archive(input, output, false),
                (Err(e), _) | (_, Err(e)) => Err(e),
            })
        }
        "-x" => {
            let archive = value_after_flag(args, "-f");
            let out = value_after_flag(args, "-C");
            Some(match (archive, out) {
                (Ok(archive), Ok(out)) => extract_archive(archive, out),
                (Err(e), _) | (_, Err(e)) => Err(e),
            })
        }
        "-t" => Some(value_after_flag(args, "-f").and_then(list_archive)),
        "-v" => Some(value_after_flag(args, "-f").and_then(verify_archive)),
        _ => None,
    }
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

fn handle_normal_cli() -> Result<(), SarError> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Version) {
        Command::Create {
            input,
            output,
            indexed,
            no_index,
        } => {
            if indexed && no_index {
                return Err(SarError::Malformed(
                    "--indexed and --no-index cannot be used together",
                ));
            }
            create_archive(input, output, no_index && !indexed)
        }
        Command::Extract {
            archive,
            output_dir,
        } => extract_archive(archive, output_dir),
        Command::List { archive } => list_archive(archive),
        Command::Verify { archive } => verify_archive(archive),
        Command::Inspect { archive, json } => inspect_archive(archive, json),
        Command::Version => print_version(),
    }
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

fn create_archive(input: PathBuf, output: PathBuf, no_index: bool) -> Result<(), SarError> {
    let file = File::create(output)?;
    let mut writer = ArchiveWriter::new(file, ArchiveWriterOptions { no_index })?;

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
        println!("{}", entry.metadata.name);
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

fn extract_archive(archive: PathBuf, output_dir: PathBuf) -> Result<(), SarError> {
    fs::create_dir_all(&output_dir)?;
    let mut reader = ArchiveReader::new(BufReader::new(File::open(archive)?))?;
    let _ = reader.read_global_header()?;

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

fn verify_archive(archive: PathBuf) -> Result<(), SarError> {
    let mut reader = ArchiveReader::new(BufReader::new(File::open(archive)?))?;
    let _ = reader.read_global_header()?;
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

    if as_json {
        let output = json!({
            "global_version": header.version,
            "flags": header.flags.bits(),
            "flags_size": header.flags_bytes.len(),
            "indexed": !header.flags.contains(sar_core::GlobalFlags::NO_INDEX),
            "entry_count": entries.len(),
            "entries": entries,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|_| SarError::Generic)?
        );
    } else {
        println!("global_version={}", header.version);
        println!("flags=0x{:08X}", header.flags.bits());
        println!("entries={}", entries.len());
    }

    Ok(())
}
