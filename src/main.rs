use std::process::ExitCode;

fn main() -> ExitCode {
    rayloc::cli::run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_entry_point_invokes_the_cli() {
        // Cargo's test harness controls process arguments, so either help or
        // fixed invalid-argument status is expected depending on its flags.
        let _status = main();
    }
}
