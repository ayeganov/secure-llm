//! Integration tests for sandbox functionality.
//!
//! Run with: sudo cargo test --test sandbox_integration

use secure_llm::sandbox::{
    bwrap::BwrapBuilder,
    ca::EphemeralCa,
    cleanup::cleanup_stale_resources,
    mounts::MountVerifier,
    netns::{NetnsConfig, NetworkNamespace},
};
use std::path::Path;
use std::process::Command;

/// Test that we can create and destroy a network namespace.
#[test]
fn test_network_namespace_lifecycle() {
    // Skip if not root
    if !is_root() {
        eprintln!("Skipping test_network_namespace_lifecycle: requires root");
        return;
    }

    let config = NetnsConfig {
        name: "secure-llm-test-lifecycle".to_string(),
        ..Default::default()
    };

    // Create namespace
    let netns = NetworkNamespace::create(config).expect("Failed to create namespace");

    // Verify it exists
    assert!(netns.path().exists(), "Namespace file should exist");

    // Verify resolv.conf was created
    assert!(
        netns.resolv_conf_path.exists(),
        "resolv.conf should be created"
    );

    // Test ping from namespace to host
    let output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns.name,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            &netns.host_ip.to_string(),
        ])
        .output()
        .expect("Failed to run ping");

    assert!(
        output.status.success(),
        "Should be able to ping host from namespace: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Drop should clean up
    let name = netns.name.clone();
    drop(netns);

    // Verify cleanup
    assert!(
        !std::path::Path::new(&format!("/run/netns/{}", name)).exists(),
        "Namespace should be deleted after drop"
    );
}

/// Test ephemeral CA generation and certificate signing.
#[test]
fn test_ca_certificate_chain() {
    let ca = EphemeralCa::generate().expect("Failed to generate CA");

    // Generate a domain certificate
    let domain_cert = ca
        .generate_cert("test.example.com")
        .expect("Failed to generate domain cert");

    // Verify the certificate contains expected markers
    assert!(domain_cert.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(domain_cert.key_pem.contains("-----BEGIN PRIVATE KEY-----"));

    // Test multi-domain certificate
    let multi_cert = ca
        .generate_cert_multi(&["api.example.com", "www.example.com", "*.example.com"])
        .expect("Failed to generate multi-domain cert");

    assert!(multi_cert.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
}

/// Test mount verification with real filesystem.
#[test]
fn test_mount_verification() {
    // Create verifier with empty denylist
    let verifier = MountVerifier::new(&[]).expect("Failed to create verifier");

    // Current directory should be verifiable
    let cwd = std::env::current_dir().expect("Failed to get cwd");
    let result = verifier.verify_path(&cwd);
    assert!(result.is_ok(), "CWD should be verifiable: {:?}", result);

    // Test with a non-existent path (should verify parent)
    let nonexistent = cwd.join("nonexistent_test_dir_12345");
    let result = verifier.verify_path(&nonexistent);
    assert!(
        result.is_ok(),
        "Non-existent path should verify parent: {:?}",
        result
    );
}

/// Test bwrap builder produces valid command line.
#[test]
fn test_bwrap_command_construction() {
    let builder = BwrapBuilder::new()
        .unshare_user()
        .map_current_user()
        .unshare_net()
        .unshare_pid()
        .bind_ro(Path::new("/usr"), Path::new("/usr"))
        .bind_ro(Path::new("/lib"), Path::new("/lib"))
        .bind_ro_try(Path::new("/lib64"), Path::new("/lib64"))
        .tmpfs(Path::new("/tmp"))
        .proc_mount(Path::new("/proc"))
        .dev_minimal()
        .setenv("HOME", "/home/test")
        .setenv("PATH", "/usr/bin:/bin");

    let cmd = builder.build();

    // Verify we got a command back
    let program = cmd.get_program();
    assert_eq!(program, "bwrap", "Should build bwrap command");

    let args: Vec<_> = cmd.get_args().collect();
    assert!(!args.is_empty(), "Should have arguments");
}

/// Test cleanup of stale resources doesn't panic.
#[test]
fn test_cleanup_stale_resources() {
    // This should not panic even without privileges
    cleanup_stale_resources();
}

/// Test combined CA bundle creation.
#[test]
fn test_combined_ca_bundle() {
    let ca = EphemeralCa::generate().expect("Failed to generate CA");

    // Try to create a combined bundle with system CAs
    let system_ca_paths = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ];

    for path in &system_ca_paths {
        let path = std::path::Path::new(path);
        if path.exists() {
            let bundle = ca
                .create_combined_bundle(path)
                .expect("Failed to create combined bundle");
            assert!(bundle.exists(), "Combined bundle should exist");

            let content =
                std::fs::read_to_string(&bundle).expect("Failed to read combined bundle");
            assert!(
                content.contains("-----BEGIN CERTIFICATE-----"),
                "Bundle should contain certificates"
            );
            return;
        }
    }

    // If no system CA found, test with non-existent path
    let bundle = ca
        .create_combined_bundle(std::path::Path::new("/nonexistent"))
        .expect("Should handle missing host bundle");
    assert!(bundle.exists());
}

/// Test running echo in a minimal sandbox (requires bwrap, NOT root).
#[test]
fn test_sandbox_echo() {
    if !bwrap_available() {
        eprintln!("Skipping test_sandbox_echo: bwrap not found");
        return;
    }

    let builder = BwrapBuilder::new()
        .unshare_user()
        .map_current_user()
        .unshare_pid()
        .bind_ro(Path::new("/usr"), Path::new("/usr"))
        .bind_ro(Path::new("/lib"), Path::new("/lib"))
        .bind_ro_try(Path::new("/lib64"), Path::new("/lib64"))
        .bind_ro(Path::new("/bin"), Path::new("/bin"))
        .tmpfs(Path::new("/tmp"))
        .proc_mount(Path::new("/proc"))
        .dev_minimal()
        .setenv("PATH", "/usr/bin:/bin")
        .command(Path::new("/bin/echo"), &["hello from sandbox".to_string()]);

    let mut cmd = builder.build();
    let output = cmd.output().expect("Failed to run sandbox");

    assert!(
        output.status.success(),
        "Sandbox command should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello from sandbox"),
        "Should see echo output: {}",
        stdout
    );
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn bwrap_available() -> bool {
    Command::new("which")
        .arg("bwrap")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
