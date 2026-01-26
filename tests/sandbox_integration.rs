use std::path::Path;
use secure_llm::sandbox::{
    BwrapBuilder, SANDBOX_CA_BUNDLE_PATH, EphemeralCa, MountVerifier,
    cleanup::cleanup_stale_resources,
};

#[test]
fn test_bwrap_builder_basic() {
    let ca = EphemeralCa::generate().expect("Failed to generate CA");
    let builder = BwrapBuilder::new()
        .unshare_user()
        .map_current_user()
        .ca_certificate_mounts(ca.cert_path())
        .command(Path::new("/usr/bin/echo"), &["hello".to_string()]);

    let cmd_line = builder.to_command_line();
    assert!(cmd_line.contains("--unshare-user"));
    assert!(cmd_line.contains("--uid"));
    assert!(cmd_line.contains("--gid"));
    assert!(cmd_line.contains("/usr/bin/echo"));
    assert!(cmd_line.contains("hello"));
}

#[test]
fn test_mount_verifier_basic() {
    let verifier = MountVerifier::new(&[]).expect("Failed to create verifier");
    
    // /usr should be allowed by default (system path)
    assert!(verifier.verify_path(Path::new("/usr")).is_ok());
    
    // /etc/shadow should be blocked (security sensitive)
    assert!(verifier.verify_path(Path::new("/etc/shadow")).is_err());
}

#[test]
fn test_mount_verifier_denylist() {
    let verifier = MountVerifier::new(&["/home/user/secret".to_string()])
        .expect("Failed to create verifier");
    
    // Explicitly denylisted path
    assert!(verifier.verify_path(Path::new("/home/user/secret")).is_err());
    
    // Subpath of denylisted path
    assert!(verifier.verify_path(Path::new("/home/user/secret/key")).is_err());
    
    // Other path should be OK
    assert!(verifier.verify_path(Path::new("/home/user/public")).is_ok());
}

#[test]
fn test_sandbox_ca_mount() {
    let ca = EphemeralCa::generate().expect("Failed to generate CA");
    let builder = BwrapBuilder::new()
        .ca_certificate_mounts(ca.cert_path())
        .command(Path::new("/bin/sh"), &[]);

    let cmd_line = builder.to_command_line();
    assert!(cmd_line.contains(SANDBOX_CA_BUNDLE_PATH));
}

#[test]
fn test_full_sandbox_flow() {
    // This is a "dry run" test that builds the config but doesn't spawn
    // since we might not have bwrap or proper permissions in CI
    
    if !bwrap_is_available() {
        return;
    }

    cleanup_stale_resources();

    let work_dir = std::env::current_dir().unwrap();
    let ca = EphemeralCa::generate().expect("Failed to generate CA");
    
    let builder = BwrapBuilder::new()
        .unshare_user()
        .map_current_user()
        .unshare_pid()
        .unshare_net()
        .standard_system_mounts(Path::new("/etc/resolv.conf"))
        .ca_certificate_mounts(ca.cert_path())
        .chdir(&work_dir)
        .command(Path::new("/usr/bin/id"), &[]);

    let cmd_line = builder.to_command_line();
    assert!(cmd_line.contains("--unshare-user"));
    assert!(cmd_line.contains("--unshare-pid"));
    assert!(cmd_line.contains("--unshare-net"));
}

// Helper to check for bwrap without importing from lib (to avoid conflict)
fn bwrap_is_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}