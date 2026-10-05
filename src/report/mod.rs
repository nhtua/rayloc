//! Reporting of safe findings using masked values and sanitized paths only.

pub mod emitter;
pub mod terminal;

#[cfg(test)]
#[path = "../../tests/unit/emitter.rs"]
mod tests;
