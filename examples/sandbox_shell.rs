//! Example: Spawning a shell in the Bubblewrap sandbox.
//!
//! This example demonstrates how to use the BwrapBuilder to construct
//! a manual sandbox and run /bin/bash inside it.

use secure_llm::sandbox::BwrapBuilder;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    println!("secure-llm sandbox shell example");
    println!("================================");

    // Build the bwrap command
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let work_dir = std::env::current_dir().unwrap_or_else(|_| Path::new("/").to_path_buf());

    let builder = BwrapBuilder::new()
        // Namespace isolation (rootless!)
        .unshare_user()
        .map_current_user()
        .unshare_pid()
        .unshare_uts()
        // Standard system directories
        .standard_system_mounts(Path::new("/etc/resolv.conf"))
        // Mount current working directory read-write
        .bind_rw(&work_dir, &work_dir)
        // User config (read-only for safety)
        .user_config_mounts(Path::new(&home))
        // Process settings
        .chdir(&work_dir)
        .hostname("sandbox-shell")
        .die_with_parent()
        // Command to run
        .command(Path::new("/bin/bash"), &["--norc".to_string()]);

    println!("Running: {}", builder.to_command_line());
    println!("Type 'exit' to leave the sandbox.");
    println!();

    let mut cmd = builder.build();

    // Inherit stdin/stdout/stderr for interactive bash
    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    match cmd.status() {
        Ok(s) if s.success() => {
            println!("\nSandbox exited successfully.");
            ExitCode::SUCCESS
        }
        Ok(s) => {
            println!("\nSandbox exited with: {:?}", s.code());
            ExitCode::from(s.code().unwrap_or(1) as u8)
        }
        Err(e) => {
            eprintln!("\nFailed to run sandbox: {}", e);
            ExitCode::from(1)
        }
    }
}