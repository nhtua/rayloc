//! OS-native scope selection with safe configuration and reporting boundaries.

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
  scan [<file|directory> | --glob <pattern> | --staged | --diff <ref>] [--threads <count>] [--config <file>] [--no-inline-ignores]
                  Scan files, a directory (default: current directory), or a glob
                  --threads applies to directory and glob scans (1-64)

  accept <id>     Accept a reviewed finding by its report ID in the root .rayloc.yaml;
                  the ID covers that value in that file only

  hook install    Install a managed pre-commit hook into Git's active hooks directory

Staged mode scans added index lines; --diff scans tracked additions against a commit.";

/// Run the CLI, returning exit code 2 for unsupported operations.
pub fn run() -> ExitCode {
    // Pass the unlocked stdout handle: worker threads acquire stdout during
    // the scan to emit redacted findings, and the main thread's lock must
    // not be held while they do so.
    ExitCode::from(run_with_args(
        std::env::args_os().skip(1),
        &mut io::stdout(),
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
        Some("accept") => accept(args, output, errors),
        Some("hook") => {
            if args.next().as_deref() != Some(std::ffi::OsStr::new("install"))
                || args.next().is_some()
            {
                return scan_error(errors, "invalid hook arguments; use hook install");
            }
            match crate::hook::install(Path::new(".")) {
                Ok(()) => write_output(
                    output,
                    errors,
                    format_args!("rayloc: managed pre-commit hook installed"),
                ),
                Err(category) => scan_error(errors, category),
            }
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
    let mut no_inline = false;
    let mut glob = None;
    let mut staged = false;
    let mut reference = None;
    let mut threads: Option<usize> = None;
    while let Some(arg) = args.next() {
        if !positional && arg == "--" {
            positional = true;
            continue;
        }
        if !positional && arg == "--diff" {
            if reference.is_some() || staged || path.is_some() || glob.is_some() {
                return scan_error(errors, "invalid scan arguments");
            }
            let Some(value) = args.next() else {
                return scan_error(errors, "invalid scan arguments");
            };
            reference = Some(value);
            continue;
        }
        if !positional && arg == "--staged" {
            if reference.is_some() || staged || path.is_some() || glob.is_some() {
                return scan_error(errors, "invalid scan arguments");
            }
            staged = true;
            continue;
        }
        if !positional && arg == "--no-inline-ignores" {
            no_inline = true;
            continue;
        }
        if !positional && arg == "--threads" {
            if threads.is_some() {
                return scan_error(errors, "invalid scan thread count");
            }
            let Some(value) = args.next() else {
                return scan_error(errors, "invalid scan thread count");
            };
            threads = match value.to_str().and_then(|s| s.parse::<usize>().ok()) {
                Some(value) => Some(value),
                None => return scan_error(errors, "invalid scan thread count"),
            };
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
        if !positional && arg == "--glob" {
            if reference.is_some() || staged || glob.is_some() || path.is_some() {
                return scan_error(errors, "invalid scan arguments");
            }
            let Some(pattern) = args.next() else {
                return scan_error(errors, "invalid scan arguments");
            };
            glob = Some(pattern);
            continue;
        }
        if !positional
            && matches!(arg.to_str(), Some("--help" | "-h"))
            && !staged
            && reference.is_none()
            && path.is_none()
            && explicit.is_none()
            && glob.is_none()
            && args.peek().is_none()
        {
            return print_help(output, errors);
        }
        if (!positional && arg.to_str().is_some_and(|s| s.starts_with('-')))
            || staged
            || reference.is_some()
            || path.is_some()
            || glob.is_some()
        {
            return scan_error(errors, "invalid scan arguments");
        }
        path = Some(arg);
    }
    if threads.is_some() && (staged || reference.is_some()) {
        return scan_error(
            errors,
            "--threads is supported only for file, directory and glob scans",
        );
    }
    let emitter = crate::report::emitter::SharedEmitter::new(Box::new(
        crate::report::emitter::TerminalEmitter::new(std::io::stdout()),
    ));
    if staged || reference.is_some() {
        let outcome = if let Some(reference) = reference {
            crate::scanner::worktree::scan_diff_with_emitter(
                Path::new("."),
                &reference,
                explicit.as_deref().map(Path::new),
                no_inline,
                Some(emitter.clone()),
            )
        } else {
            crate::scanner::staged::scan_staged_with_emitter(
                Path::new("."),
                explicit.as_deref().map(Path::new),
                no_inline,
                Some(emitter.clone()),
            )
        };
        emitter.finish_scan(&outcome);
        return outcome.exit_code();
    }
    if let Some(target) = &path {
        if fs::symlink_metadata(target).is_err()
            && target
                .to_str()
                .is_some_and(|s| s.contains(['*', '?', '[', '{']))
        {
            glob = path.take();
        }
    }
    let target = path.unwrap_or_else(|| OsString::from("."));
    // Components remove trailing separators before lstat without resolving ancestors.
    let selected: std::path::PathBuf = Path::new(&target).components().collect();
    let path = selected.as_path();
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.is_dir() => metadata,
        Ok(_) => return scan_error(errors, "selected path is not a regular file or directory"),
        Err(_) => return scan_error(errors, "cannot open selected file"),
    };
    let workers = if metadata.is_file() && threads.is_none() {
        // File scan without explicit --threads: use serial (1 worker)
        1
    } else {
        match crate::scanner::execution::resolve_threads(
            threads,
            std::env::var_os("RAYON_NUM_THREADS").as_deref(),
            std::thread::available_parallelism().map_or(1, |n| n.get()),
        ) {
            Ok(workers) => workers,
            Err(_) => return scan_error(errors, "invalid scan thread count"),
        }
    };
    let pattern = match glob.as_ref().map(|pattern| pattern.to_str()) {
        Some(None) => return scan_error(errors, "invalid scope pattern"),
        Some(Some(pattern)) => Some(pattern),
        None => None,
    };
    let policy = (|| {
        let root = crate::config::discover_scope_root(path)?;
        let config = crate::config::load(&root.root, explicit.as_deref().map(Path::new))?;
        let mut registry = crate::rules::Registry::compile(config)?;
        registry.inline_ignores = !no_inline;
        let exclusions = crate::config::ignore::Exclusions::load(&root.root)?;
        let absolute = fs::canonicalize(path).map_err(|_| crate::config::ConfigError::Read)?;
        let admin = absolute.starts_with(root.root.join(".git"))
            || root
                .administration
                .iter()
                .any(|path| absolute.starts_with(path));
        let excluded = admin || (metadata.is_file() && exclusions.excludes(&absolute));
        Ok::<_, crate::config::ConfigError>((registry, root, absolute, excluded))
    })();
    let (registry, root, absolute, excluded) = match policy {
        Ok(policy) => policy,
        Err(error) => return scan_error(errors, &error.to_string()),
    };
    let outcome = if excluded {
        let mut outcome = crate::scanner::ScanOutcome::default();
        outcome.stats.files_excluded = 1;
        outcome
    } else if metadata.is_file() {
        let label = absolute.strip_prefix(&root.root).unwrap_or(&absolute);
        // For single files, use file_with_batches for parallel line batching
        // if workers > 1, otherwise use serial scan
        if workers > 1 {
            let run = crate::scanner::engine::scan_file_with_registry_and_options(
                &absolute,
                label,
                1,
                &registry,
                crate::scanner::engine::FileScanOptions { workers },
                Some(emitter.clone()),
            );
            run.outcome
        } else {
            crate::scanner::engine::scan_file_with_registry_and_emitter(
                &absolute,
                label,
                1,
                &registry,
                Some(emitter.clone()),
            )
        }
    } else {
        let selected = if pattern.is_some() {
            root.root.as_path()
        } else {
            absolute.as_path()
        };
        crate::scanner::scope::scan_directory_with_options_and_emitter(
            &root,
            selected,
            pattern,
            &registry,
            crate::scanner::scope::ScopeOptions {
                workers,
                ..Default::default()
            },
            emitter.clone(),
        )
    };
    emitter.finish_scan(&outcome);
    outcome.exit_code()
}
fn accept(
    mut args: impl Iterator<Item = OsString>,
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> u8 {
    let id = args.next();
    let id = match id.as_ref().and_then(|id| id.to_str()) {
        Some("-h" | "--help") if args.next().is_none() => return print_help(output, errors),
        Some(id) if args.next().is_none() => crate::scanner::fingerprint::FindingId::parse(id),
        _ => None,
    };
    // Never echo an unvalidated argument: it may be a pasted secret.
    let Some(id) = id else {
        return scan_error(
            errors,
            "invalid accept arguments; use a 5-character report ID",
        );
    };
    let result = crate::config::discover_root(Path::new("."))
        .and_then(|root| crate::config::accept(&root, id));
    use crate::config::Acceptance;
    match result {
        Ok(Acceptance::Created) => write_output(
            output,
            errors,
            format_args!(
                "rayloc: created .rayloc.yaml and accepted {id}; stage it for --staged scans"
            ),
        ),
        Ok(Acceptance::Added) => write_output(
            output,
            errors,
            format_args!("rayloc: accepted {id} in .rayloc.yaml; stage it for --staged scans"),
        ),
        Ok(Acceptance::Already) => write_output(
            output,
            errors,
            format_args!("rayloc: {id} is already accepted"),
        ),
        Err(error) => scan_error(errors, &error.to_string()),
    }
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
