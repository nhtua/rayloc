//! Core modules for the rayloc secret scanner.
//!
//! The library provides a bounded byte scanner, core provider signatures, and
//! safe findings/reports. CLI scanning awaits configuration and scope policy.

pub mod cli;
pub mod config;
pub mod report;
pub mod rules;
pub mod scanner;
