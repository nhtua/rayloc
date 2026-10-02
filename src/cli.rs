//! OS-native explicit-file CLI with safe configuration and reporting boundaries.

use std::{
    ffi::OsString,
    fs,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

const HELP: &str = "rayloc — a secret scanner for Git workflows

Usage: rayloc [COMMAND | OPTION]

Options:
  -h, --help       Print help
  -V, --version    Print version

Commands:
  scan <file> [--config <file>]  Scan an explicit regular file

Directory, glob, Git diff, and hook modes are not available yet.";

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
        Some("scan") => scan(args, output, errors),
        Some("hook") => {
            let _ = writeln!(errors, "rayloc: hook management is not implemented yet");
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

fn scan(
    args: impl Iterator<Item = OsString>,
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> u8 {
    let mut args = args.peekable();
    let mut path = None;
    let mut explicit = None;
    let mut positional = false;
    while let Some(arg) = args.next() {
        if !positional && arg == "--" {
            positional = true;
            continue;
        }
        if !positional && arg == "--config" {
            if explicit.is_some() {
                return scan_error(errors, "invalid scan arguments");
            }
            let Some(value) = args.next() else {
                return scan_error(errors, "invalid scan arguments");
            };
            explicit = Some(value);
            continue;
        }
        if !positional
            && matches!(arg.to_str(), Some("--help" | "-h"))
            && path.is_none()
            && explicit.is_none()
            && args.peek().is_none()
        {
            return print_help(output, errors);
        }
        if (!positional && arg.to_str().is_some_and(|s| s.starts_with('-'))) || path.is_some() {
            return scan_error(errors, "invalid scan arguments");
        }
        path = Some(arg);
    }
    let Some(path) = path else {
        return scan_error(errors, "explicit file target required");
    };
    let path = Path::new(&path);
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return scan_error(errors, "selected path is not a regular file"),
        Err(_) => return scan_error(errors, "cannot open selected file"),
    }
    let policy = (|| {
        let root = crate::config::discover_root(path)?;
        let config = crate::config::load(&root, explicit.as_deref().map(Path::new))?;
        let registry = crate::rules::Registry::compile(config)?;
        let exclusions = crate::config::ignore::Exclusions::load(&root)?;
        let absolute = fs::canonicalize(path).map_err(|_| crate::config::ConfigError::Read)?;
        Ok::<_, crate::config::ConfigError>((
            registry,
            exclusions.excludes(&absolute) || absolute.starts_with(root.join(".git")),
        ))
    })();
    let (registry, excluded) = match policy {
        Ok(policy) => policy,
        Err(error) => return scan_error(errors, &error.to_string()),
    };
    let outcome = if excluded {
        let mut outcome = crate::scanner::ScanOutcome::default();
        outcome.stats.files_excluded = 1;
        outcome
    } else {
        crate::scanner::engine::scan_file_with_registry(path, 1, &registry)
    };
    if crate::report::terminal::render(&outcome, output).is_err() {
        return scan_error(errors, "cannot write command output");
    }
    outcome.exit_code()
}
fn scan_error(errors: &mut dyn Write, category: &str) -> u8 {
    let _ = writeln!(errors, "rayloc: {category}");
    2
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
