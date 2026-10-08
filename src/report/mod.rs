//! Reporting of safe findings using masked values and sanitized paths only.

pub mod emitter;
pub mod terminal;

pub(super) fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64;
    let mut selected_unit = "EiB";
    for unit in UNITS {
        value /= 1024.0;
        selected_unit = unit;
        if value < 1024.0 {
            break;
        }
    }
    let formatted = format!("{value:.2}");
    let concise = formatted.trim_end_matches('0').trim_end_matches('.');
    format!("{concise} {selected_unit}")
}

#[cfg(test)]
#[path = "../../tests/unit/emitter.rs"]
mod tests;
