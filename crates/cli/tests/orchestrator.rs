use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn orchestrator_maker_flow_runs() {
    let output = cargo_bin_cmd!("eswp-cli")
        .args(["orchestrator", "maker-flow"])
        .output()
        .expect("CLI execution failed");

    assert!(
        output.status.success(),
        "orchestrator maker-flow exited with {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("flow=maker"), "stdout: {stdout}");
    assert!(
        stdout.contains("final_state=Maker(Settled"),
        "stdout: {stdout}"
    );
}

#[test]
fn orchestrator_taker_flow_runs() {
    let output = cargo_bin_cmd!("eswp-cli")
        .args(["orchestrator", "taker-flow"])
        .output()
        .expect("CLI execution failed");

    assert!(
        output.status.success(),
        "orchestrator taker-flow exited with {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("flow=taker"), "stdout: {stdout}");
    assert!(
        stdout.contains("final_state=Taker(FinalSigPublished")
            || stdout.contains("final_state=Taker(Settled"),
        "stdout: {stdout}"
    );
}
