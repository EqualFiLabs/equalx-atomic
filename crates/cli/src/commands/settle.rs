use std::{fs, path::PathBuf};

use adaptor_clsag::{PreSig, SettlementCtx as AdaptorSettlementCtx};
use anyhow::{anyhow, ensure, Context, Result};
use equalx_sdk::{
    await_settle, trigger_settlement, AlloyHttpTransport, EscrowClient, SettleArgs,
    SettlementOutcome, SettlementTarget,
};
use clap::{Args, ValueEnum};
use monero_rpc::MoneroRpc;
use serde::Deserialize;
use watcher::monero::{SpendState, TauEvent, WatchTarget};

use super::common::{
    format_tx_hash, parse_address, parse_hex_array, parse_hex_vec, DryRunTransport,
};
use equalx_sdk::transport::EvmTransport;

#[derive(Clone, Debug, Args)]
pub struct SettleLocalArgs {
    /// Path to sanitized pre-signature artifact (out/pre_sig.json).
    #[arg(long)]
    pub presig: Option<PathBuf>,

    /// Swap identifier hex (32 bytes).
    #[arg(long)]
    pub swap_id: Option<String>,

    /// Finalized Monero tx hash that spent the watched input.
    #[arg(long)]
    pub tx_hash: Option<String>,

    /// Monero daemon RPC endpoint (http://host:port).
    #[arg(long)]
    pub monero_rpc: Option<String>,

    /// Optional basic auth username for monerod.
    #[arg(long)]
    pub monero_user: Option<String>,

    /// Optional basic auth password for monerod.
    #[arg(long)]
    pub monero_pass: Option<String>,

    /// Override CLSAG input index from the artifact.
    #[arg(long)]
    pub input_index: Option<usize>,

    /// Escrow contract address (0x-prefixed).
    #[arg(long)]
    pub escrow: Option<String>,

    /// EVM JSON-RPC endpoint.
    #[arg(long)]
    pub evm_rpc: Option<String>,

    /// Private key (0x-prefixed) controlling the settlement caller.
    #[arg(long)]
    pub private_key: Option<String>,

    /// Do not send transactions; print calldata/value instead.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Fixture JSON to simulate a confirmed CLSAG (used for tests/demos).
    #[arg(long)]
    pub fixture: Option<PathBuf>,

    /// Settlement operation mode.
    #[arg(long, value_enum, default_value_t = SettleMode::Await)]
    pub mode: SettleMode,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SettleMode {
    Await,
    Trigger,
}

pub fn run(args: SettleLocalArgs) -> Result<()> {
    if let Some(fixture_path) = &args.fixture {
        ensure!(
            args.dry_run,
            "--fixture currently supports only --dry-run executions"
        );
        return run_fixture(fixture_path);
    }

    run_live(args)
}

fn run_live(args: SettleLocalArgs) -> Result<()> {
    let presig_path = args
        .presig
        .as_ref()
        .context("--presig is required unless --fixture is used")?;
    let tx_hash_raw = args
        .tx_hash
        .as_ref()
        .context("--tx-hash is required unless --fixture is used")?;
    let tx_hash_bytes = parse_hex_array::<32>(tx_hash_raw, "tx_hash")?;
    let tx_hash = hex::encode(tx_hash_bytes);
    let swap_id_hex = args
        .swap_id
        .as_ref()
        .context("--swap-id is required unless --fixture is used")?;
    let swap_id = parse_hex_array::<32>(swap_id_hex, "swap_id")?;

    let artifact = PresigArtifact::load(presig_path)?;
    let pre_sig = artifact.build_pre_sig()?;
    let key_image = artifact.key_image_bytes()?;
    let input_index = args.input_index.unwrap_or(artifact.input_index);
    let watch = WatchTarget::new(key_image, tx_hash, input_index, pre_sig);
    let target = SettlementTarget { swap_id, watch };

    let rpc_url = args
        .monero_rpc
        .as_ref()
        .context("--monero-rpc is required unless --fixture is used")?;
    let auth = match (args.monero_user.clone(), args.monero_pass.clone()) {
        (Some(user), Some(pass)) => Some((user, pass)),
        _ => None,
    };
    let monero_rpc = MoneroRpc::new(rpc_url, auth)?;
    let escrow_addr = args
        .escrow
        .as_ref()
        .context("--escrow is required unless --fixture is used")?;
    let escrow_address = parse_address(escrow_addr)?;

    if args.dry_run {
        let transport = DryRunTransport::default();
        let escrow = EscrowClient::new(escrow_address, transport.clone());
        let outcome = execute_settlement(args.mode, monero_rpc, vec![target], &escrow)?;
        handle_outcome(outcome, true, Some(&transport));
    } else {
        let evm_rpc = args
            .evm_rpc
            .as_ref()
            .context("--evm-rpc is required when not running --dry-run")?;
        let private_key = args
            .private_key
            .as_ref()
            .context("--private-key is required when not running --dry-run")?;
        let transport = AlloyHttpTransport::new(evm_rpc, private_key)?;
        let escrow = EscrowClient::new(escrow_address, transport);
        let outcome = execute_settlement(args.mode, monero_rpc, vec![target], &escrow)?;
        handle_outcome(outcome, false, None);
    }

    Ok(())
}

fn execute_settlement<E: EvmTransport>(
    mode: SettleMode,
    rpc: MoneroRpc,
    targets: Vec<SettlementTarget>,
    escrow: &EscrowClient<E>,
) -> Result<Option<SettlementOutcome>> {
    match mode {
        SettleMode::Await => Ok(Some(await_settle(rpc, targets, escrow)?)),
        SettleMode::Trigger => Ok(trigger_settlement(rpc, targets, escrow)?),
    }
}

fn handle_outcome(
    outcome: Option<SettlementOutcome>,
    dry_run: bool,
    dry_transport: Option<&DryRunTransport>,
) {
    if let Some(outcome) = outcome {
        println!(
            "Spend detected in 0x{} (input {}, state: {:?})",
            outcome.event.tx_hash, outcome.event.input_index, outcome.event.spend_state
        );
        println!("τ = 0x{}", hex::encode(outcome.event.tau));
        println!("settle() tx hash: {}", format_tx_hash(outcome.tx_hash));
        if dry_run {
            if let Some(transport) = dry_transport {
                if let Some(call) = transport.last_call() {
                    println!(
                        "dry-run call -> to: 0x{}, gas_limit: {}, value: {}, data: 0x{}",
                        hex::encode(call.to),
                        call.gas_limit.unwrap_or(0),
                        call.value,
                        hex::encode(&call.data)
                    );
                }
            }
        }
    } else {
        println!("No Monero spends detected yet (trigger mode).");
    }
}

fn run_fixture(path: &PathBuf) -> Result<()> {
    let artifact = PresigArtifact::load(path)?;
    let fixture = artifact
        .fixture
        .as_ref()
        .context("fixture JSON missing fixture section")?;
    let pre_sig = artifact.build_pre_sig()?;
    let tau = parse_hex_array::<32>(&fixture.tau, "fixture.tau")?;
    let swap_id = parse_hex_array::<32>(&fixture.swap_id, "fixture.swap_id")?;
    let key_image = artifact.key_image_bytes()?;
    let event = TauEvent {
        key_image,
        tx_hash: fixture.tx_hash.clone(),
        input_index: artifact.input_index,
        tau,
        spend_state: parse_spend_state(&fixture.spend_state)?,
    };
    let transport = DryRunTransport::default();
    let escrow_addr = parse_address(&fixture.escrow)?;
    let escrow = EscrowClient::new(escrow_addr, transport.clone());
    let tx_hash = escrow.settle(SettleArgs {
        swap_id,
        adaptor_secret: tau,
        gas_limit: None,
    })?;
    let outcome = SettlementOutcome { event, tx_hash };

    println!(
        "Loaded fixture with pre-sig j={} pre_hash=0x{}",
        pre_sig.j,
        hex::encode(pre_sig.pre_hash)
    );
    handle_outcome(Some(outcome), true, Some(&transport));
    Ok(())
}

fn parse_spend_state(value: &str) -> Result<SpendState> {
    if value.is_empty() {
        return Ok(SpendState::Confirmed);
    }
    value.parse::<SpendState>().map_err(|e| anyhow!(e))
}

#[derive(Debug, Deserialize)]
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
    #[allow(dead_code)]
    #[serde(default)]
    ring_global_indices: Vec<u64>,
    #[serde(default)]
    fixture: Option<FixtureSection>,
}

#[derive(Debug, Deserialize)]
struct PresigSection {
    c1_tilde: String,
    d_tilde: String,
    pseudo_out: String,
    #[serde(default)]
    s_tilde: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SettlementCtxSection {
    chain_tag: String,
    position_key: String,
    settle_digest: String,
}

#[derive(Debug, Deserialize)]
struct FixtureSection {
    swap_id: String,
    tau: String,
    tx_hash: String,
    escrow: String,
    #[serde(default = "default_spend_state")]
    spend_state: String,
}

fn default_spend_state() -> String {
    "confirmed".into()
}

impl PresigArtifact {
    fn load(path: &PathBuf) -> Result<Self> {
        let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))
    }

    fn build_pre_sig(&self) -> Result<PreSig> {
        let ctx = self.settlement_ctx()?;
        let s_tilde = self
            .section
            .s_tilde
            .iter()
            .map(|entry| parse_hex_array::<32>(entry, "s_tilde"))
            .collect::<Result<Vec<_>>>()?;
        Ok(PreSig {
            c1_tilde: parse_hex_array::<32>(&self.section.c1_tilde, "c1_tilde")?,
            s_tilde,
            d_tilde: parse_hex_array::<32>(&self.section.d_tilde, "d_tilde")?,
            pseudo_out: parse_hex_array::<32>(&self.section.pseudo_out, "pseudo_out")?,
            j: self.pre_j,
            ctx,
            pre_hash: parse_hex_array::<32>(&self.pre_hash, "pre_hash")?,
        })
    }

    fn settlement_ctx(&self) -> Result<AdaptorSettlementCtx> {
        let position_key = parse_hex_array::<32>(&self.settlement_ctx.position_key, "position_key")?;
        Ok(AdaptorSettlementCtx {
            chain_tag: self.settlement_ctx.chain_tag.clone(),
            position_key,
            settle_digest: parse_hex_array::<32>(
                &self.settlement_ctx.settle_digest,
                "settle_digest",
            )?,
        })
    }

    fn key_image_bytes(&self) -> Result<[u8; 32]> {
        parse_hex_array::<32>(&self.key_image, "key_image")
    }
}
