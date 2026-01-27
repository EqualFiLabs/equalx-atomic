use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn settle_local_fixture_dry_run() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/settlement/settle_local_fixture.json");
    let fixture_str = fixture.to_str().expect("fixture path is valid utf-8");

    let output = cargo_bin_cmd!("eswp-cli")
        .args(["settle-local", "--fixture", fixture_str, "--dry-run"])
        .output()
        .expect("CLI execution failed");

    assert!(
        output.status.success(),
        "settle-local exited with status {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dry-run call"),
        "expected dry-run call info in stdout: {stdout}"
    );
    assert!(
        stdout.contains("settle() tx hash"),
        "expected settle tx hash in stdout: {stdout}"
    );
}
