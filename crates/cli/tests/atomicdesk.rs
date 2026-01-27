use std::{
    fs,
    process::{Command as StdCommand, Stdio},
    thread,
    time::Duration,
};

use alloy_primitives::{Address, FixedBytes};
use alloy_sol_types::SolCall;
use anyhow::{bail, Context, Result};
use assert_cmd::cargo::cargo_bin_cmd;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::Value;
use tempfile::NamedTempFile;

alloy_sol_types::sol! {
    #[allow(non_camel_case_types)]
    contract MailboxHarnessApi {
        function lastReservationId() view returns (bytes32 reservationId);
        function lastPoster() view returns (address poster);
        function lastEnvelope() view returns (bytes envelope);
    }
}

const ANVIL_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const RPC_URL: &str = "http://127.0.0.1:8545";

#[test]
fn atomicdesk_encrypt_and_post() -> Result<()> {
    let taker_secret = [0x11u8; 32];
    let taker_sk = k256::SecretKey::from_slice(&taker_secret)?;
    let taker_pub = k256::PublicKey::from_secret_scalar(&taker_sk.to_nonzero_scalar());
    let taker_pub_hex = format!(
        "0x{}",
        hex::encode(taker_pub.to_encoded_point(true).as_bytes())
    );

    let swap_id = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let settle = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let m_digest = "0x1111111111111111111111111111111111111111111111111111111111111111";

    let temp = NamedTempFile::new()?;
    let temp_path = temp.path().to_owned();

    cargo_bin_cmd!("eswp-cli")
        .args([
            "atomic-desk",
            "encrypt-context",
            "--chain-id",
            "31337",
            "--escrow",
            "0x0000000000000000000000000000000000000001",
            "--swap-id",
            swap_id,
            "--settle-digest",
            settle,
            "--m-digest",
            m_digest,
            "--maker",
            "0x0000000000000000000000000000000000000002",
            "--taker",
            "0x0000000000000000000000000000000000000003",
            "--taker-pubkey",
            &taker_pub_hex,
            "--presig-hex",
            "0x68656c6c6f",
            "--output-file",
            temp_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let json = fs::read_to_string(&temp_path)?;
    assert!(json.contains("envelope_hex"));

    let mut anvil = StdCommand::new("anvil")
        .arg("--silent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to launch anvil; ensure Foundry is installed")?;
    thread::sleep(Duration::from_secs(1));

    let mailbox = install_mailbox_code()?;

    let output = cargo_bin_cmd!("eswp-cli")
        .args([
            "atomic-desk",
            "publish-presig",
            "--chain-id",
            "31337",
            "--escrow",
            "0x0000000000000000000000000000000000000001",
            "--swap-id",
            swap_id,
            "--settle-digest",
            settle,
            "--m-digest",
            m_digest,
            "--maker",
            "0x0000000000000000000000000000000000000002",
            "--taker",
            "0x0000000000000000000000000000000000000003",
            "--taker-pubkey",
            &taker_pub_hex,
            "--presig-hex",
            "0x68656c6f",
            "--mailbox",
            &format!("0x{}", hex::encode(mailbox.as_slice())),
            "--rpc-url",
            RPC_URL,
            "--private-key",
            ANVIL_KEY,
        ])
        .output()?;

    assert!(
        output.status.success(),
        "post command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected_swap = FixedBytes::<32>::from_slice(&parse_hex_array::<32>(swap_id)?);
    let posted_swap = mailbox_call(
        mailbox,
        MailboxHarnessApi::lastReservationIdCall {}.abi_encode(),
    )?;
    let swap_decoded =
        MailboxHarnessApi::lastReservationIdCall::abi_decode_returns(&posted_swap, true)
            .context("decode lastReservationId")?;
    assert_eq!(swap_decoded.reservationId, expected_swap);

    let poster_raw = mailbox_call(mailbox, MailboxHarnessApi::lastPosterCall {}.abi_encode())?;
    let poster_decoded = MailboxHarnessApi::lastPosterCall::abi_decode_returns(&poster_raw, true)
        .context("decode lastPoster")?;
    assert_eq!(poster_decoded.poster, parse_address(ANVIL_ADDR)?);

    let envelope_raw = mailbox_call(mailbox, MailboxHarnessApi::lastEnvelopeCall {}.abi_encode())?;
    let envelope_decoded =
        MailboxHarnessApi::lastEnvelopeCall::abi_decode_returns(&envelope_raw, true)
            .context("decode lastEnvelope")?;
    assert!(
        !envelope_decoded.envelope.is_empty(),
        "expected envelope bytes"
    );

    let _ = anvil.kill();
    Ok(())
}

fn parse_address(value: &str) -> anyhow::Result<Address> {
    let bytes = hex::decode(value.trim_start_matches("0x"))?;
    Ok(Address::from_slice(&bytes))
}

fn parse_hex_array<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
    let raw = value.trim_start_matches("0x");
    let bytes = hex::decode(raw)?;
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn install_mailbox_code() -> anyhow::Result<Address> {
    let json: Value = serde_json::from_str(include_str!(
        "../../../evm/out/MailboxHarness.sol/MailboxHarness.json"
    ))?;
    let bytecode = json
        .get("deployedBytecode")
        .and_then(|v| v.get("object"))
        .and_then(|v| v.as_str())
        .context("missing deployed bytecode")?;
    let target = "0x1000000000000000000000000000000000000001";
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "anvil_setCode",
        "params": [target, bytecode]
    });
    let client = reqwest::blocking::Client::new();
    let resp = client.post(RPC_URL).json(&payload).send()?;
    let value: Value = resp.json()?;
    if value.get("error").is_some() {
        bail!("failed to set code: {:?}", value);
    }
    parse_address(target)
}

fn mailbox_call(mailbox: Address, calldata: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {
                "to": format!("0x{}", hex::encode(mailbox.as_slice())),
                "data": format!("0x{}", hex::encode(calldata)),
            },
            "latest"
        ]
    });
    let client = reqwest::blocking::Client::new();
    let resp = client.post(RPC_URL).json(&payload).send()?;
    let value: Value = resp.json()?;
    let hex_result = value
        .get("result")
        .and_then(|v| v.as_str())
        .context("eth_call missing result")?;
    let bytes =
        hex::decode(hex_result.trim_start_matches("0x")).context("decode eth_call result")?;
    Ok(bytes)
}
