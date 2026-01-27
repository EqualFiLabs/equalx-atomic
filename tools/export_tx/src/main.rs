use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hex::encode as hex_encode;
use monero_oxide::transaction::{Input as MoneroInput, Timelock};
use monero_rpc::MoneroWalletRpc;
use serde::Serialize;
use serde_json::Value;
use tx_builder::{
    find_clsag_regions,
    wallet::{transfer_and_decompose, DescribeTransferParams, TransferDestination, TransferParams},
    TxBlob, TxSkeleton,
};

#[derive(Parser, Debug)]
#[command(
    name = "export_tx",
    about = "Draft a wallet RPC transfer and export adaptor-ready data"
)]
struct Args {
    /// Wallet RPC base URL (e.g. http://127.0.0.1:18083)
    #[arg(long = "wallet-url", default_value = "http://127.0.0.1:18083")]
    wallet_url: String,

    /// Optional basic auth credentials "user:pass"
    #[arg(long = "auth", default_value = "")]
    auth: String,

    /// Destination spec in the form "address:amount". Amount is in XMR (e.g. 0.1234). Repeatable.
    #[arg(long = "dest", value_parser = parse_destination)]
    destinations: Vec<TransferDestination>,

    /// Wallet account index
    #[arg(long = "account-index")]
    account_index: Option<u32>,

    /// Wallet subaddress indices (repeat)
    #[arg(long = "subaddress")]
    subaddresses: Vec<u32>,

    /// Desired ring size (default 11)
    #[arg(long = "ring-size", default_value_t = 11)]
    ring_size: u32,

    /// Wallet priority
    #[arg(long = "priority")]
    priority: Option<u32>,

    /// Unlock time (block height or timestamp)
    #[arg(long = "unlock-time")]
    unlock_time: Option<u64>,

    /// Relay transaction (if omitted, uses do_not_relay=true)
    #[arg(long = "relay")]
    relay: bool,

    /// Output path for the JSON export
    #[arg(long = "output", default_value = "out/export_tx.json")]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.destinations.is_empty() {
        return Err(anyhow!("at least one --dest address:amount is required"));
    }

    let Args {
        wallet_url,
        auth,
        destinations,
        account_index,
        subaddresses,
        ring_size,
        priority,
        unlock_time,
        relay,
        output,
    } = args;

    let auth = if auth.is_empty() {
        None
    } else {
        let (user, pass) = auth.split_once(':').unwrap_or((&auth, ""));
        Some((user.to_string(), pass.to_string()))
    };

    let wallet = MoneroWalletRpc::new(&wallet_url, auth).context("init wallet rpc client")?;

    let params = TransferParams {
        destinations,
        account_index,
        subaddr_indices: if subaddresses.is_empty() {
            None
        } else {
            Some(subaddresses)
        },
        ring_size: Some(ring_size),
        priority,
        unlock_time,
        do_not_relay: Some(!relay),
        get_tx_hex: Some(true),
        get_tx_metadata: Some(true),
        get_unsigned_txset: Some(true),
        get_multisig_txset: Some(true),
        get_tx_key: Some(true),
        get_tx_keys: Some(true),
        ..TransferParams::default()
    };

    println!("[*] Requesting transfer draft (relay={})", relay);
    let wallet_transfer = transfer_and_decompose(&wallet, &params).context("wallet transfer")?;

    let params_json = serde_json::to_value(&params).expect("serialize transfer params");
    let skeleton = skeleton_summary(&wallet_transfer.skeleton, &wallet_transfer.tx_blob)?;
    let transfer_summary = TransferSummary::from(&wallet_transfer.transfer);
    let describe_json = wallet_transfer
        .transfer
        .tx_metadata
        .as_ref()
        .and_then(|meta| {
            let request = DescribeTransferParams {
                tx_metadata: meta.clone(),
            };
            tx_builder::wallet::describe_transfer(&wallet, &request)
                .map(|res| Value::Array(res.desc))
                .map_err(|err| {
                    eprintln!("[WARN] describe_transfer failed: {err}");
                    err
                })
                .ok()
        });

    let export = ExportBundle {
        wallet_url,
        relay,
        params: params_json,
        transfer: transfer_summary,
        tx_blob_hex: hex_encode(&wallet_transfer.tx_blob),
        skeleton,
        describe: describe_json,
    };

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let json_blob = serde_json::to_vec_pretty(&export).expect("serialize export bundle");
    fs::write(&output, json_blob).with_context(|| format!("write {}", output.display()))?;

    println!(
        "[OK] exported draft to {} (inputs={}, outputs={}, ring={})",
        output.display(),
        export.skeleton.inputs.len(),
        export.skeleton.outputs.len(),
        export.skeleton.ring_size
    );

    Ok(())
}

fn parse_destination(raw: &str) -> std::result::Result<TransferDestination, String> {
    let (address, amount) = raw
        .split_once(':')
        .ok_or_else(|| "destination must be ADDRESS:AMOUNT".to_string())?;
    let amount = parse_xmr_amount(amount).map_err(|e| e.to_string())?;
    Ok(TransferDestination {
        amount,
        address: address.to_string(),
    })
}

fn parse_xmr_amount(src: &str) -> Result<u64> {
    let src = src.trim();
    if src.is_empty() {
        return Err(anyhow!("amount is empty"));
    }
    let (whole, fractional) = match src.split_once('.') {
        Some((w, f)) => (w, f),
        None => (src, ""),
    };
    let whole: u128 = whole
        .parse()
        .map_err(|e| anyhow!("invalid whole XMR amount '{}': {e}", whole))?;
    if fractional.len() > 12 {
        return Err(anyhow!(
            "too many fractional digits ({} > 12)",
            fractional.len()
        ));
    }
    let mut frac = fractional.to_string();
    while frac.len() < 12 {
        frac.push('0');
    }
    let fractional: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse()
            .map_err(|e| anyhow!("invalid fractional part: {e}"))?
    };
    let amount = whole
        .checked_mul(1_000_000_000_000)
        .and_then(|w| w.checked_add(fractional))
        .ok_or_else(|| anyhow!("amount overflow"))?;
    u64::try_from(amount).map_err(|_| anyhow!("amount exceeds u64"))
}

#[derive(Serialize)]
struct ExportBundle {
    wallet_url: String,
    relay: bool,
    params: Value,
    transfer: TransferSummary,
    tx_blob_hex: String,
    skeleton: SkeletonSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    describe: Option<Value>,
}

#[derive(Serialize)]
struct TransferSummary {
    amount: Option<u64>,
    fee: Option<u64>,
    tx_hash: Option<String>,
    tx_key: Option<String>,
    tx_metadata: Option<String>,
    unsigned_txset: Option<String>,
    multisig_txset: Option<String>,
}

impl From<&tx_builder::wallet::TransferResult> for TransferSummary {
    fn from(value: &tx_builder::wallet::TransferResult) -> Self {
        Self {
            amount: value.amount,
            fee: value.fee,
            tx_hash: value.tx_hash.clone(),
            tx_key: value.tx_key.clone(),
            tx_metadata: value.tx_metadata.clone(),
            unsigned_txset: value.unsigned_txset.clone(),
            multisig_txset: value.multisig_txset.clone(),
        }
    }
}

#[derive(Serialize)]
struct SkeletonSummary {
    inputs: Vec<InputSummary>,
    outputs: Vec<OutputSummary>,
    input_count: usize,
    output_count: usize,
    ring_size: usize,
    clsag_regions: usize,
    timelock: String,
    extra_hex: String,
    pseudo_output_count: usize,
    commitment_count: usize,
    encrypted_amount_count: usize,
    clsag_count: usize,
}

#[derive(Serialize)]
struct InputSummary {
    amount: Option<u64>,
    key_offsets: Vec<u64>,
    key_image: String,
}

#[derive(Serialize)]
struct OutputSummary {
    amount: Option<u64>,
    key: String,
    view_tag: Option<u8>,
}

fn skeleton_summary(skeleton: &TxSkeleton, tx_blob: &TxBlob) -> Result<SkeletonSummary> {
    let inputs: Vec<InputSummary> = skeleton
        .inputs
        .iter()
        .filter_map(|input| match input {
            MoneroInput::ToKey {
                amount,
                key_offsets,
                key_image,
            } => Some(InputSummary {
                amount: *amount,
                key_offsets: key_offsets.clone(),
                key_image: hex_encode(key_image.0),
            }),
            _ => None,
        })
        .collect();

    let ring_size = inputs
        .first()
        .map(|i| i.key_offsets.len())
        .unwrap_or_default();

    let outputs: Vec<OutputSummary> = skeleton
        .outputs
        .iter()
        .map(|output| OutputSummary {
            amount: output.amount,
            key: hex_encode(output.key.0),
            view_tag: output.view_tag,
        })
        .collect();

    let clsag_regions = find_clsag_regions(tx_blob)?.len();
    let timelock = match skeleton.meta.timelock {
        Timelock::None => "none".to_string(),
        Timelock::Block(h) => format!("block:{h}"),
        Timelock::Time(t) => format!("time:{t}"),
    };
    let rct = &skeleton.meta.proofs;
    let pseudo_output_count = rct.prunable.pseudo_outs_len();
    let clsag_count = rct.prunable.clsag_len();
    let commitment_count = rct.base.commitments.len();
    let encrypted_amount_count = rct.base.encrypted_amounts.len();

    Ok(SkeletonSummary {
        input_count: inputs.len(),
        output_count: outputs.len(),
        ring_size,
        clsag_regions,
        timelock,
        extra_hex: hex_encode(&skeleton.meta.extra),
        pseudo_output_count,
        clsag_count,
        commitment_count,
        encrypted_amount_count,
        inputs,
        outputs,
    })
}

trait PrunableExt {
    fn pseudo_outs_len(&self) -> usize;
    fn clsag_len(&self) -> usize;
}

impl PrunableExt for monero_oxide::ringct::RctPrunable {
    fn pseudo_outs_len(&self) -> usize {
        match self {
            monero_oxide::ringct::RctPrunable::Clsag { pseudo_outs, .. } => pseudo_outs.len(),
            _ => 0,
        }
    }

    fn clsag_len(&self) -> usize {
        match self {
            monero_oxide::ringct::RctPrunable::Clsag { clsags, .. } => clsags.len(),
            _ => 0,
        }
    }
}
