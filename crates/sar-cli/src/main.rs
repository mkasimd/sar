use std::{env, fs::File, process::ExitCode};

use sar_core::ArchiveReader;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage());
    };
    let Some(path) = args.next() else {
        return Err(usage());
    };
    if args.next().is_some() {
        return Err(usage());
    }

    match command.as_str() {
        "list" => list_archive(&path).map_err(|err| err.to_string()),
        "info" => info_archive(&path).map_err(|err| err.to_string()),
        _ => Err(usage()),
    }
}

fn list_archive(path: &str) -> Result<(), sar_core::SarError> {
    let file = File::open(path)?;
    let reader = ArchiveReader::new(file)?;
    for entry in reader {
        let (metadata, _) = entry?;
        println!("{}", metadata.name);
    }
    Ok(())
}

fn info_archive(path: &str) -> Result<(), sar_core::SarError> {
    let file = File::open(path)?;
    let reader = ArchiveReader::new(file)?;
    println!("global_flags=0x{:08x}", reader.global_flags().bits());
    println!("entry_count={}", reader.entry_count());
    Ok(())
}

fn usage() -> String {
    "Usage: sar-cli <list|info> <archive>".to_string()
}
