//! Core modules for the rayloc secret scanner.
//!
//! The library provides a bounded byte scanner, core provider signatures, and
//! safe findings/reports, and strict policy for explicit-file CLI scanning.

pub mod cli;
pub mod config;
pub mod report;
pub mod rules;
pub mod scanner;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub(crate) mod test_support;
