//! Command-line entry point. Scan and hook commands are reserved for implementation.

use std::process::ExitCode;

const HELP: &str = "rayloc — a secret scanner for Git workflows

Usage: rayloc [COMMAND | OPTION]

Options:
  -h, --help       Print help
  -V, --version    Print version

Planned commands:
  scan            Scan files, directories, or added Git diff lines
  hook            Manage the Git pre-commit hook

Scanning and hook management are not implemented yet.";

/// Run the CLI, returning exit code 2 for unsupported operations.
pub fn run() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    };

    match command.to_str() {
        Some("-h" | "--help") if args.next().is_none() => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") if args.next().is_none() => {
            println!("rayloc {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("scan" | "hook") => {
            eprintln!("rayloc: scanning and hook management are not implemented yet");
            ExitCode::from(2)
        }
        _ => {
            // Arguments may contain sensitive values; never echo them in errors.
            eprintln!("rayloc: unrecognized command or arguments; use --help");
            ExitCode::from(2)
        }
    }
}
