//! Command-line entry point. Scan and hook commands are reserved for implementation.

use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

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
    ExitCode::from(run_with_args(
        std::env::args_os().skip(1),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    ))
}

fn run_with_args(
    args: impl IntoIterator<Item = OsString>,
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> u8 {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return print_help(output, errors);
    };

    match command.to_str() {
        Some("-h" | "--help") if args.next().is_none() => print_help(output, errors),
        Some("-V" | "--version") if args.next().is_none() => write_output(
            output,
            errors,
            format_args!("rayloc {}", env!("CARGO_PKG_VERSION")),
        ),
        Some("scan" | "hook") => {
            let _ = writeln!(
                errors,
                "rayloc: scanning and hook management are not implemented yet"
            );
            2
        }
        _ => {
            // Arguments may contain sensitive values; never echo them in errors.
            let _ = writeln!(
                errors,
                "rayloc: unrecognized command or arguments; use --help"
            );
            2
        }
    }
}

fn print_help(output: &mut dyn Write, errors: &mut dyn Write) -> u8 {
    write_output(output, errors, format_args!("{HELP}"))
}

fn write_output(
    output: &mut dyn Write,
    errors: &mut dyn Write,
    message: std::fmt::Arguments<'_>,
) -> u8 {
    if writeln!(output, "{message}").is_err() {
        let _ = writeln!(errors, "rayloc: cannot write command output");
        2
    } else {
        0
    }
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
