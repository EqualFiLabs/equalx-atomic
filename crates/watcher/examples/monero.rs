// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf, time::Duration};

use adaptor_clsag::{PreSig, SettlementCtx};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use monero_rpc::MoneroRpc;
use serde::Deserialize;
use watcher::monero::{MoneroWatcher, WatchTarget};

#[derive(Debug, Parser)]
struct Args {
    /// Path to the pre-signature artifact (e.g. out/pre_sig.json).
    #[arg(long)]
    presig: PathBuf,

    /// Monero daemon RPC URL (stagenet default).
    #[arg(long, default_value = "http://127.0.0.1:38081")]
    rpc_url: String,

    /// Finalized transaction hash that spent the monitored input.
    #[arg(long)]
    tx_hash: String,

    /// Optional override for the key image (hex). Defaults to the artifact.
    #[arg(long)]
    key_image: Option<String>,

    /// Optional override for the input index in the transaction.
    #[arg(long)]
    input_index: Option<usize>,

    /// Optional override for the settlement digest (hex-32).
    #[arg(long)]
    settle_digest: Option<String>,

    /// Optional override for the watcher position key (hex).
    #[arg(long)]
    position_key: Option<String>,

    /// Optional override for the chain tag (e.g. evm:84532).
    #[arg(long)]
    chain_tag: Option<String>,

    /// Poll interval in seconds.
    #[arg(long, default_value_t = 30)]
    poll_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct PresigArtifact {
    #[serde(rename = "pre")]
    section: PresigSection,
    #[serde(rename = "settlement_ctx")]
    settlement_ctx: SettlementCtxSection,
    pre_hash: String,
    #[serde(rename = "pre_j")]
    pre_j: usize,
    key_image: String,
    input_index: usize,
    #[serde(default)]
    ring_global_indices: Vec<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct PresigSection {
    c1_tilde: String,
    d_tilde: String,
    pseudo_out: String,
    #[serde(default)]
    s_tilde: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SettlementCtxSection {
    chain_tag: String,
    position_key: String,
    settle_digest: String,
}

impl PresigArtifact {
    fn load(path: &PathBuf) -> Result<Self> {
        let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))
    }

    fn settlement_ctx(&self) -> Result<SettlementCtx> {
        self.settlement_ctx.to_ctx()
    }

    fn build_pre_sig(&self) -> Result<PreSig> {
        let ctx = self.settlement_ctx()?;
        let s_tilde = self
            .section
            .s_tilde
            .iter()
            .map(|entry| hex32(entry))
            .collect::<Result<Vec<_>>>()?;
        Ok(PreSig {
            c1_tilde: hex32(&self.section.c1_tilde)?,
            s_tilde,
            d_tilde: hex32(&self.section.d_tilde)?,
            pseudo_out: hex32(&self.section.pseudo_out)?,
            j: self.pre_j,
            ctx,
            pre_hash: hex32(&self.pre_hash)?,
        })
    }
}

impl SettlementCtxSection {
    fn to_ctx(&self) -> Result<SettlementCtx> {
        let position_key = hex32(&self.position_key)?;
        Ok(SettlementCtx {
            chain_tag: self.chain_tag.clone(),
            position_key,
            settle_digest: hex32(&self.settle_digest)?,
        })
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let artifact = PresigArtifact::load(&args.presig)?;

    let mut ctx = artifact.settlement_ctx()?;

    if let Some(ref override_tag) = args.chain_tag {
        ensure!(
            override_tag == &ctx.chain_tag,
            "chain_tag override does not match artifact binding"
        );
    }

    if let Some(ref position_override) = args.position_key {
        let position_bytes = hex32(position_override)?;
        ensure!(
            position_bytes == ctx.position_key,
            "position_key override does not match artifact binding"
        );
    }

    if let Some(ref settle_override) = args.settle_digest {
        let digest = hex32(settle_override)?;
        ensure!(
            digest == ctx.settle_digest,
            "settle_digest override does not match artifact binding"
        );
    }

    let pre_sig = artifact.build_pre_sig()?;

    let key_image = if let Some(ref value) = args.key_image {
        hex32(value)?
    } else {
        hex32(&artifact.key_image)?
    };

    let tx_hash_bytes = hex32(&args.tx_hash)?;
    let tx_hash = hex::encode(tx_hash_bytes);

    let input_index = args.input_index.unwrap_or(artifact.input_index);
    let poll_interval = Duration::from_secs(args.poll_seconds);

    let rpc = MoneroRpc::new(&args.rpc_url, None).context("create monero rpc client")?;
    let target = WatchTarget::new(key_image, tx_hash.clone(), input_index, pre_sig);
    let watcher = MoneroWatcher::new(rpc, vec![target]).with_poll_interval(poll_interval);

    println!(
        "Watching key image {} for tx {} (input {}) every {}s",
        hex::encode(key_image),
        format!("0x{}", tx_hash),
        input_index,
        args.poll_seconds
    );

    let event = watcher.watch()?;
    println!(
        "Spend detected in {} (state: {:?}) — τ = {}",
        format!("0x{}", event.tx_hash),
        event.spend_state,
        hex::encode(event.tau)
    );
    Ok(())
}

fn hex_bytes(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim_start_matches("0x");
    hex::decode(trimmed).with_context(|| format!("decode hex string {value}"))
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex_bytes(value)?;
    ensure!(
        bytes.len() == 32,
        "expected 32-byte hex string, got {} bytes",
        bytes.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
