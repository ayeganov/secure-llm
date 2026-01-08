//! Launch an interactive shell inside the sandbox for manual inspection.
//!
//! Usage:
//!   cargo run --example sandbox_shell
//!   cargo run --example sandbox_shell -- /path/to/workdir
//!
//! This gives you a bash shell inside the sandbox where you can:
//! - Inspect the filesystem layout
//! - Check environment variables
//! - Test what commands are available
//! - Verify bind mounts are working

use secure_llm::sandbox::bwrap::BwrapBuilder;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let work_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| std::env::current_dir().unwrap().to_string_lossy().to_string());

    let work_dir = Path::new(&work_dir);

    if !work_dir.exists() {
        eprintln!("Error: Work directory does not exist: {:?}", work_dir);
        return ExitCode::from(1);
    }

    println!("=== Sandbox Shell ===");
    println!("Work directory: {:?}", work_dir);
    println!();
    println!("You're about to enter a sandboxed bash shell.");
    println!("The sandbox has:");
    println!("  - Read-only access to /usr, /lib, /lib64, /bin, /sbin");
    println!("  - Read-write access to {:?}", work_dir);
    println!("  - Isolated /tmp, /proc, /dev");
    println!("  - No network access");
    println!();
    println!("Useful commands to try:");
    println!("  ls /                    # See the filesystem layout");
    println!("  mount                   # See bind mounts");
    println!("  env                     # See environment variables");
    println!("  cat /etc/resolv.conf    # DNS config (will fail - not mounted)");
    println!("  ping google.com         # Network test (will fail - no network)");
    println!("  touch /usr/test         # Write test (will fail - read-only)");
    println!("  touch /tmp/test         # Write test (will succeed)");
    println!();
    println!("Type 'exit' to leave the sandbox.");
    println!("=========================================");
    println!();

    // Build the sandbox
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    let builder = BwrapBuilder::new()
        // Namespace isolation
        .unshare_user()
        .map_current_user()
        .unshare_pid()
        .unshare_net() // No network
        // System directories (read-only)
        .bind_ro(Path::new("/usr"), Path::new("/usr"))
        .bind_ro(Path::new("/lib"), Path::new("/lib"))
        .bind_ro_try(Path::new("/lib64"), Path::new("/lib64"))
        .bind_ro_try(Path::new("/lib32"), Path::new("/lib32"))
        .bind_ro(Path::new("/bin"), Path::new("/bin"))
        .bind_ro_try(Path::new("/sbin"), Path::new("/sbin"))
        // Work directory (read-write)
        .bind_rw(work_dir, work_dir)
        // Virtual filesystems
        .tmpfs(Path::new("/tmp"))
        .proc_mount(Path::new("/proc"))
        .dev_minimal()
        // Environment
        .setenv("HOME", &home)
        .setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin")
        .setenv("TERM", &std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string()))
        .setenv("PS1", "\\[\\033[1;31m\\][SANDBOX]\\[\\033[0m\\] \\w $ ")
        // Working directory
        .chdir(work_dir)
        // Die when parent dies
        .die_with_parent()
        // Run bash
        .command(Path::new("/bin/bash"), &["--norc".to_string()]);

    let mut cmd = builder.build();

    // Make it interactive
    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("\nExited sandbox cleanly.");
            ExitCode::SUCCESS
        }
        Ok(s) => {
            println!("\nSandbox exited with: {:?}", s.code());
            ExitCode::from(s.code().unwrap_or(1) as u8)
        }
        Err(e) => {
            eprintln!("\nFailed to run sandbox: {}", e);
            eprintln!();
            eprintln!("Make sure bubblewrap is installed:");
            eprintln!("  sudo apt install bubblewrap");
            ExitCode::from(1)
        }
    }
}
