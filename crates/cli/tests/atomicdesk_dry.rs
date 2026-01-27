use assert_cmd::cargo::cargo_bin_cmd;
use hex;
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};

fn context_args() -> Vec<String> {
    vec![
        "--chain-id".into(),
        "31337".into(),
        "--escrow".into(),
        "0x0000000000000000000000000000000000000001".into(),
        "--swap-id".into(),
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        "--settle-digest".into(),
        "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
        "--m-digest".into(),
        "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
        "--maker".into(),
        "0x0000000000000000000000000000000000000002".into(),
        "--taker".into(),
        "0x0000000000000000000000000000000000000003".into(),
    ]
}

fn sample_pubkey(seed: u8) -> String {
    let secret = SecretKey::from_slice(&[seed; 32]).expect("valid secret key seed");
    let public = PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());
    format!(
        "0x{}",
        hex::encode(public.to_encoded_point(true).as_bytes())
    )
}

#[test]
fn publish_presig_no_broadcast_emits_envelope() {
    let mut args = vec![
        "atomic-desk".into(),
        "publish-presig".into(),
        "--taker-pubkey".into(),
        sample_pubkey(0x11),
        "--presig-hex".into(),
        "0x68656c6c6f".into(),
        "--mailbox".into(),
        "0x0000000000000000000000000000000000000100".into(),
        "--no-broadcast".into(),
    ];
    args.extend(context_args());

    let output = cargo_bin_cmd!("eswp-cli")
        .args(&args)
        .output()
        .expect("run publish-presig");

    assert!(
        output.status.success(),
        "publish-presig failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("reservationId="),
        "stdout must include reservationId line, got: {stdout}"
    );
    assert!(
        stdout.contains("envelope=0x"),
        "stdout must include envelope hex, got: {stdout}"
    );
}

#[test]
fn tx_proof_dry_run_prints_context() {
    let desk_pub = sample_pubkey(0x22);
    let taker_secret = format!("0x{}", "bb".repeat(32));
    let mut args = vec![
        "atomic-desk".into(),
        "tx-proof".into(),
        "--monero-tx-id".into(),
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        "--desk-pubkey".into(),
        desk_pub,
        "--taker-secret".into(),
        taker_secret,
        "--mailbox".into(),
        "0x0000000000000000000000000000000000000200".into(),
        "--dry-run".into(),
    ];
    args.extend(context_args());

    let output = cargo_bin_cmd!("eswp-cli")
        .args(&args)
        .output()
        .expect("run tx-proof dry run");

    assert!(
        output.status.success(),
        "tx-proof failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("envelope=0x"),
        "dry-run must emit envelope bytes: {stdout}"
    );
    assert!(
        stdout.contains("rpc=http://127.0.0.1:8545"),
        "default RPC URL should be printed: {stdout}"
    );
    assert!(
        stdout.contains(
            "moneroTxId=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "monero tx id missing in output: {stdout}"
    );
}
