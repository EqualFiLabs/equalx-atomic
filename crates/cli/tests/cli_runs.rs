use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn eswp_cli_runs() {
    let output = cargo_bin_cmd!("eswp-cli")
        .args(["sample", "--i-star", "2", "--msg-hex", ""])
        .output()
        .expect("CLI execution failed");
    assert!(
        output.status.success(),
        "CLI exited with status {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pre_hash="),
        "stdout missing pre_hash line: {stdout}"
    );
    assert!(stdout.contains("t="), "stdout missing t line: {stdout}");

    // Basic sanity: parse hex outputs
    let mut pre_hash_hex = None;
    let mut t_hex = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("pre_hash=") {
            pre_hash_hex = Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("t=") {
            t_hex = Some(rest.trim().to_string());
        }
    }
    let pre = pre_hash_hex.expect("pre_hash hex present");
    let t = t_hex.expect("t hex present");
    assert_eq!(pre.len(), 64, "pre_hash must be 32 bytes hex");
    assert_eq!(t.len(), 64, "t must be 32 bytes hex");
    let _ = hex::decode(pre).expect("pre_hash must be valid hex");
    let _ = hex::decode(t).expect("t must be valid hex");
}
