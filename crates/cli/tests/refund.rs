use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn refund_local_dry_run() {
    let output = cargo_bin_cmd!("eswp-cli")
        .args([
            "refund-local",
            "--swap-id",
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--eth-expiry",
            "1",
            "--buffer-secs",
            "0",
            "--poll-secs",
            "1",
            "--escrow",
            "0x000000000000000000000000000000000000dead",
            "--dry-run",
        ])
        .output()
        .expect("CLI execution failed");

    assert!(
        output.status.success(),
        "refund-local exited with {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("refund tx hash"),
        "expected refund tx hash line in stdout: {stdout}"
    );
    assert!(
        stdout.contains("dry-run call"),
        "expected dry-run call details in stdout: {stdout}"
    );
}
