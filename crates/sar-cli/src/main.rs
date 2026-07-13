// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use std::env;

use sar_core::{ResourceLimits, SarError};

mod args;
mod commands;
mod extraction;
mod password;

use args::{Command, ParsedInvocation, ShorthandCommand};

fn main() {
    let args: Vec<String> = env::args().collect();
    if let Err(error) = run(&args) {
        let prefix = if matches!(error, SarError::LimitExceeded(_)) {
            "resource-limit error"
        } else {
            "error"
        };
        eprintln!("{prefix} ({}): {error}", error.status());
        std::process::exit(1);
    }
}

fn run(argsv: &[String]) -> Result<(), SarError> {
    match args::parse_invocation(argsv)? {
        ParsedInvocation::Shorthand(sh) => dispatch_shorthand(sh),
        ParsedInvocation::Standard(cmd) => dispatch_command(cmd),
    }
}

fn dispatch_shorthand(command: ShorthandCommand) -> Result<(), SarError> {
    match command {
        ShorthandCommand::Create {
            input,
            output,
            options,
        } => commands::create::create_archive(input, output, options),
        ShorthandCommand::Extract {
            archive,
            output_dir,
            metadata,
        } => commands::extract::extract_archive(
            archive,
            output_dir,
            None,
            false,
            ResourceLimits::default(),
            metadata,
        ),
        ShorthandCommand::List { archive } => commands::list::list_archive(archive, false),
        ShorthandCommand::Verify { archive } => {
            commands::verify::verify_archive(archive, None, false, false, ResourceLimits::default())
        }
        ShorthandCommand::Version => commands::version::print_version(),
    }
}

fn dispatch_command(command: Command) -> Result<(), SarError> {
    match command {
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
            preserve_permissions,
            preserve_owner,
            preserve_times,
            symlinks,
        } => {
            if indexed && no_index {
                return Err(SarError::Malformed(
                    "--indexed and --no-index cannot be used together",
                ));
            }
            let compression = args::resolve_create_compression(
                compression,
                zstd,
                deflate,
                store,
                compression_level,
            )?;
            commands::create::create_archive(
                input,
                output,
                args::CreateCommandOptions {
                    no_index: no_index && !indexed,
                    compression,
                    encrypt,
                    password,
                    fec,
                    metadata: args::CreateMetadataOptions {
                        preserve_permissions,
                        preserve_owner,
                        preserve_times,
                        symlink_policy: symlinks,
                    },
                },
            )
        }
        Command::Extract {
            archive,
            output_dir,
            password,
            allow_lossy,
            preserve_permissions,
            preserve_times,
            preserve_owner,
            allow_symlinks,
            limits,
        } => commands::extract::extract_archive(
            archive,
            output_dir,
            password,
            allow_lossy,
            limits.resource_limits(),
            extraction::policy::ExtractMetadataOptions {
                preserve_permissions,
                preserve_times,
                preserve_owner,
                allow_symlinks,
            },
        ),
        Command::List { archive, metadata } => commands::list::list_archive(archive, metadata),
        Command::Verify {
            archive,
            password,
            recovery,
            cdc,
            limits,
        } => commands::verify::verify_archive(
            archive,
            password,
            recovery,
            cdc,
            limits.resource_limits(),
        ),
        Command::Inspect { archive, json } => commands::inspect::inspect_archive(archive, json),
        Command::Repair {
            archive,
            output,
            fec,
            erasures,
            limits,
        } => commands::repair::repair_cmd(archive, output, fec, erasures, limits.resource_limits()),
        Command::Version => commands::version::print_version(),
    }
}
