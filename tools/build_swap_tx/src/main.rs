use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, ensure, Context, Result};
use clap::{ArgGroup, Parser, ValueHint};
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use monero_address::{MoneroAddress, Network as MoneroNetwork};
use monero_oxide::{
    io::{read_byte, read_point, read_vec, CompressedPoint as OxCompressedPoint, VarInt},
    primitives::{keccak256, keccak256_to_scalar, Commitment, Decoys},
    transaction::{Input as MoneroInput, NotPruned, Transaction as OxTransaction},
};
use monero_rpc::{GetBlockParams, GetTransactionsRequest, MoneroRpc, RpcError};
use monero_wallet_core::FeeEstimator;
use monero_wallet_core::{
    DaemonFeeEstimator, InMemoryStore, OwnedOutput, RpcDecoyPicker, ScanParams, Scanner,
    SpendFilter, SpendableSet, SubAddr, WalletConfig,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroizing;

use adaptor_clsag::presig_region;
use adaptor_clsag::{index, tau};
use adaptor_clsag::{ClsagCtx, PreSig, SettlementCtx, SignerWitness};
use tx_builder::convert::{
    fetch_ring_keys_by_gi, inputs_from_plan_and_rings, OutputSpec, RingMemberData,
};
use tx_builder::{
    assemble_unsigned_tx, decompose_transaction, find_clsag_regions, replace_clsag_at,
    replace_clsag_region, replace_pseudo_out_at,
};

const DECOY_EXCLUDE_RECENT: u64 = 0;
const GLOBAL_INDEX_LOOKBACK: u64 = 64;
const DETERMINISTIC_RNG_SEED: [u8; 32] = [0x59; 32];
const MAX_RING_RETRIES: usize = 8;
const DECOY_RESAMPLE_PASSES: usize = 6;
const TX_SANITY_MIN_INDICES: usize = 10;
const TX_SANITY_MIN_TOTAL_RCT: u64 = 10_000;
const TX_SANITY_MIN_UNIQUE_RATIO_NUM: usize = 8;
const TX_SANITY_MIN_UNIQUE_RATIO_DEN: usize = 10;
const TX_SANITY_MEDIAN_RATIO_NUM: u64 = 6;
const TX_SANITY_MEDIAN_RATIO_DEN: u64 = 10;
const MAX_LOCKED_REPLACEMENT_ATTEMPTS: usize = 128;

/// Build a swap transaction using daemon RPC and monero-oxide primitives.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[command(group(
    ArgGroup::new("data_source")
        .args(["scan_start", "owned_json"])
        .required(true)
))]
struct Cli {
    /// RPC endpoint for the Monero daemon
    #[arg(long = "daemon-url")]
    daemon_url: String,

    /// Basic authentication credentials formatted as user:pass
    #[arg(long = "auth")]
    auth: Option<Auth>,

    /// Hex-encoded private view key
    #[arg(long = "view-key-hex")]
    view_key_hex: String,

    /// Hex-encoded private spend key
    #[arg(long = "spend-key-hex")]
    spend_key_hex: String,

    /// Hex-encoded public spend key (derived if omitted)
    #[arg(long = "spend-pub-hex")]
    spend_pub_hex: Option<String>,

    /// Network identifier (e.g. mainnet, testnet, stagenet)
    #[arg(long)]
    network: String,

    /// Subaddresses expressed as account:index, repeatable
    #[arg(long = "subaddr")]
    subaddresses: Vec<Subaddress>,

    /// Destination outputs formatted as address:amount
    #[arg(long = "dest")]
    destinations: Vec<Destination>,

    /// Target amount to plan for (in piconeros)
    #[arg(long = "target-amount")]
    target_amount: u64,

    /// Additional miner tip to include (in piconeros)
    #[arg(long)]
    tip: Option<u64>,

    /// CLSAG ring size to use when building inputs
    #[arg(long = "ring-size", default_value_t = 16)]
    ring_size: u16,

    /// Produce adaptor CLSAG pre-signature artifacts
    #[arg(long = "make-pre-sig", action = clap::ArgAction::SetTrue)]
    make_pre_sig: bool,
    /// Override adaptor secret (hex). Must accompany --make-pre-sig.
    #[arg(
        long = "adaptor-secret-hex",
        value_name = "HEX64",
        requires = "make_pre_sig"
    )]
    adaptor_secret_hex: Option<String>,

    /// Additionally finalize the CLSAG at `input-index` and emit final_tx.bin
    #[arg(long = "finalize", action = clap::ArgAction::SetTrue)]
    finalize: bool,

    /// Submit the finalized transaction to the daemon after writing it
    #[arg(long = "broadcast", action = clap::ArgAction::SetTrue)]
    broadcast: bool,

    /// Use `do_not_relay=true` when broadcasting (validation-only)
    #[arg(
        long = "broadcast-dry-run",
        requires = "broadcast",
        action = clap::ArgAction::SetTrue
    )]
    broadcast_dry_run: bool,

    /// Message to bind in the adaptor CLSAG (hex-encoded)
    #[arg(long = "message-hex", requires = "make_pre_sig")]
    message_hex: Option<String>,

    /// Input index to bias when constructing the pre-signature
    #[arg(long = "input-index", default_value_t = 0)]
    input_index: usize,

    /// Settlement chain tag (opaque, user-provided)
    #[arg(long = "chain-tag")]
    chain_tag: String,

    /// Position key hex string (bytes32)
    #[arg(long = "position-key-hex")]
    position_key_hex: String,

    /// Settlement digest hex string
    #[arg(long = "settle-digest-hex")]
    settle_digest_hex: String,

    /// Swap identifier hex string
    #[arg(long = "swap-id-hex")]
    swap_id_hex: String,

    /// Inclusive starting height for scanning owned outputs
    #[arg(long = "scan-start")]
    scan_start: Option<u64>,

    /// Exclusive ending height for scanning owned outputs
    #[arg(long = "scan-end")]
    scan_end: Option<u64>,

    /// Path to pre-captured owned outputs JSON fixture
    #[arg(long = "owned-json", value_hint = ValueHint::FilePath)]
    owned_json: Option<PathBuf>,

    /// Directory to write constructed artifacts
    #[arg(long = "out-dir", value_hint = ValueHint::DirPath)]
    out_dir: Option<PathBuf>,

    /// Skip writes and only log the intended operations
    #[arg(long = "dry-run", action = clap::ArgAction::SetTrue)]
    dry_run: bool,

    /// Emit verbose logs
    #[arg(long = "verbose", action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Use deterministic RNG seed for decoy selection (test fixtures)
    #[arg(long = "deterministic", action = clap::ArgAction::SetTrue)]
    deterministic: bool,
}

#[derive(Debug, Clone)]
struct Auth {
    user: String,
    pass: String,
}

impl FromStr for Auth {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (user, pass) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("expected auth in user:pass format"))?;

        if user.is_empty() || pass.is_empty() {
            return Err(anyhow!("auth requires both user and pass components"));
        }

        Ok(Auth {
            user: user.to_string(),
            pass: pass.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
struct Subaddress {
    account: u32,
    index: u32,
}

impl FromStr for Subaddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (account, index) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("subaddr must be formatted as account:index"))?;

        let account = account
            .parse::<u32>()
            .map_err(|_| anyhow!("invalid account index in subaddr"))?;
        let index = index
            .parse::<u32>()
            .map_err(|_| anyhow!("invalid subaddress index in subaddr"))?;

        Ok(Subaddress { account, index })
    }
}

#[derive(Debug, Clone)]
struct Destination {
    address: String,
    amount: u64,
}

impl FromStr for Destination {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (address, amount) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("dest must be formatted as address:amount"))?;

        if address.is_empty() {
            return Err(anyhow!("destination address cannot be empty"));
        }

        let amount = amount
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid amount for destination"))?;

        Ok(Destination {
            address: address.to_string(),
            amount,
        })
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        println!("Daemon URL: {}", cli.daemon_url);

        if let Some(auth) = &cli.auth {
            println!("Auth user: {}", auth.user);
            println!("Auth password length: {}", auth.pass.len());
        }

        println!("Network: {}", cli.network);
        println!("View key (hex): {}", cli.view_key_hex);
        println!("Spend key (hex): {}", mask_hex(&cli.spend_key_hex, 4));

        if let Some(pub_hex) = &cli.spend_pub_hex {
            println!("Spend pubkey (hex): {}", pub_hex);
        } else {
            println!("Spend pubkey will be derived from private key.");
        }

        for sub in &cli.subaddresses {
            println!("Subaddress account {} index {}", sub.account, sub.index);
        }

        if cli.destinations.is_empty() {
            println!("No explicit destinations (change-only output).");
        } else {
            for dest in &cli.destinations {
                println!("Destination {} amount {}", dest.address, dest.amount);
            }
        }

        println!("Target amount: {}", cli.target_amount);
        println!("Tip: {}", cli.tip.unwrap_or_default());
        println!("Ring size: {}", cli.ring_size);

        println!("Chain tag: {}", cli.chain_tag);
        println!("Position key (hex): {}", cli.position_key_hex);
        println!("Settlement digest (hex): {}", cli.settle_digest_hex);
        println!("Swap ID (hex): {}", cli.swap_id_hex);

        match (&cli.scan_start, &cli.scan_end, &cli.owned_json) {
            (Some(start), end, None) => {
                if let Some(end) = end {
                    println!("Scanning owned outputs from {} to {}", start, end);
                } else {
                    println!("Scanning owned outputs starting at {}", start);
                }
            }
            (None, _, Some(path)) => {
                println!("Using owned outputs fixture at {}", path.display());
            }
            _ => {}
        }

        if let Some(dir) = &cli.out_dir {
            println!("Output directory: {}", dir.display());
        }
    } else {
        println!("Planning swap spend; re-run with --verbose for full details.");
    }

    let tip_amount = cli.tip.unwrap_or_default();
    let total_with_tip = cli
        .target_amount
        .checked_add(tip_amount)
        .ok_or_else(|| anyhow!("target-amount plus tip would overflow u64"))?;

    let settle_digest = parse_fixed_hex::<32>(&cli.settle_digest_hex, "settlement digest hex")?;

    let auth = cli
        .auth
        .as_ref()
        .map(|auth| (auth.user.clone(), auth.pass.clone()));
    let rpc = MoneroRpc::new(&cli.daemon_url, auth)?;
    let chain_height = rpc.get_height().context("fetch daemon height")?;
    let as_of_height = cli
        .scan_end
        .and_then(|end| end.checked_sub(1))
        .unwrap_or(chain_height);

    let (owned_outputs, mut plan) = if let Some(path) = cli.owned_json.as_ref() {
        let outputs = load_owned_outputs(path)?;
        let fee_hint = DaemonFeeEstimator { rpc: rpc.clone() }.estimate()?;
        let spend_filter = SpendFilter {
            min_confirmations: 10,
            min_amount: 1,
            as_of_height,
        };
        let filtered = SpendableSet::filter(&outputs, spend_filter);
        let filtered = drop_spent_outputs(&rpc, filtered)?;
        let inputs_preview =
            monero_wallet_core::plan::preview_inputs(&filtered, total_with_tip, fee_hint)?;
        let decoys = if inputs_preview.is_empty() || fee_hint.ring_size <= 1 {
            Vec::new()
        } else {
            RpcDecoyPicker {
                rpc: rpc.clone(),
                ring_size: fee_hint.ring_size,
            }
            .pick(&inputs_preview)?
        };
        match monero_wallet_core::plan::build_spend_plan(
            &filtered,
            total_with_tip,
            fee_hint,
            settle_digest,
            decoys,
        ) {
            Ok(plan) => (outputs, plan),
            Err(err) => {
                let spendable_total: u64 = filtered.iter().map(|o| o.amount).sum();
                println!(
                    "Spendable outputs (count {}, total {} piconero) failed planning: {}",
                    filtered.len(),
                    spendable_total,
                    err
                );
                return Err(err);
            }
        }
    } else {
        let wallet_cfg = build_wallet_config(&cli)?;
        let store = InMemoryStore::new();
        let scanner = Scanner::new(wallet_cfg, store, rpc.clone());
        let scan_params = build_scan_params(&cli);
        scanner.scan(&scan_params)?;
        let outputs = scanner.list_owned()?;
        let spend_filter = SpendFilter {
            min_confirmations: 10,
            min_amount: 1,
            as_of_height,
        };
        let filtered = SpendableSet::filter(&outputs, spend_filter);
        let filtered = drop_spent_outputs(&rpc, filtered)?;
        let fee_hint = DaemonFeeEstimator { rpc: rpc.clone() }.estimate()?;
        let inputs_preview =
            monero_wallet_core::plan::preview_inputs(&filtered, total_with_tip, fee_hint)?;
        let decoys = if inputs_preview.is_empty() || fee_hint.ring_size <= 1 {
            Vec::new()
        } else {
            RpcDecoyPicker {
                rpc: rpc.clone(),
                ring_size: fee_hint.ring_size,
            }
            .pick(&inputs_preview)?
        };
        match monero_wallet_core::plan::build_spend_plan(
            &filtered,
            total_with_tip,
            fee_hint,
            settle_digest,
            decoys,
        ) {
            Ok(plan) => (outputs, plan),
            Err(err) => {
                let spendable_total: u64 = filtered.iter().map(|o| o.amount).sum();
                println!(
                    "Spendable outputs (count {}, total {} piconero) failed planning: {}",
                    filtered.len(),
                    spendable_total,
                    err
                );
                return Err(err);
            }
        }
    };

    if cli.verbose {
        println!("Target amount (with tip): {}", total_with_tip);
        println!("Owned outputs available: {}", owned_outputs.len());
        println!("Inputs selected: {}", plan.inputs.len());
        println!("Estimated fee (piconeros): {}", plan.fee_estimate);
        match plan.change {
            Some(change) => println!("Estimated change amount: {}", change),
            None => println!("No change output (all value consumed)."),
        }
        let decoys_per_input = if plan.inputs.is_empty() {
            0
        } else {
            plan.decoys.len() / plan.inputs.len()
        };
        println!("Decoys per input: {}", decoys_per_input);
        if decoys_per_input > 0 {
            for (idx, chunk) in plan.decoys.chunks(decoys_per_input).enumerate() {
                let indices: Vec<u64> = chunk.iter().map(|d| d.global_index).collect();
                println!("Input {} decoys: {:?}", idx, indices);
            }
        }
        // Print settle digest bound in the plan
        println!("Settle digest (plan): {}", hex::encode(plan.settle_digest));
        // Print key images for each planned input
        for (idx, inp) in plan.inputs.iter().enumerate() {
            println!(
                "Input {} key_image={}, gi={}",
                idx,
                hex::encode(inp.key_image),
                inp.global_index
            );
        }
    }

    if plan.inputs.is_empty() {
        return Err(anyhow!("spend plan produced no inputs; cannot build rings"));
    }

    let key_images: Vec<Vec<u8>> = plan
        .inputs
        .iter()
        .map(|inp| inp.key_image.to_vec())
        .collect();
    let spent_status = match rpc.is_key_image_spent(&key_images) {
        Ok(status) => Some(status),
        Err(RpcError::Node(msg))
            if msg.contains("HTTP 404") || msg.contains("Method not found") =>
        {
            None
        }
        Err(other) => {
            return Err(anyhow!("check key image spent status: {other}"));
        }
    };
    if let Some(statuses) = spent_status {
        for (idx, status) in statuses.iter().enumerate() {
            if *status != 0 {
                return Err(anyhow!(
                    "plan input {} key image {} is already spent (status {})",
                    idx,
                    hex::encode(plan.inputs[idx].key_image),
                    status
                ));
            }
        }
    }

    let mut rng = if cli.deterministic {
        ChaCha20Rng::from_seed(DETERMINISTIC_RNG_SEED)
    } else {
        ChaCha20Rng::from_entropy()
    };

    let max_input_gi = plan
        .inputs
        .iter()
        .map(|inp| inp.global_index)
        .max()
        .unwrap_or(0);
    let chain_max_gi = estimate_max_global_index(&rpc, chain_height, GLOBAL_INDEX_LOOKBACK)
        .context("estimate latest global index from chain")?;
    let max_global_index = chain_max_gi.unwrap_or(max_input_gi).max(max_input_gi);

    println!(
        "Global index ceiling: {} (inputs max {} / chain probe {:?})",
        max_global_index, max_input_gi, chain_max_gi
    );

    let mut rings = Vec::with_capacity(plan.inputs.len());
    let mut designated_positions = Vec::with_capacity(plan.inputs.len());
    let mut ring_attempt = 0usize;
    let ring_key_map = loop {
        rings.clear();
        designated_positions.clear();

        for (idx, input) in plan.inputs.iter().enumerate() {
            let ring_size = input.ring_member_count as usize;
            let (ring, designated) =
                build_ring_for_input(&mut rng, input.global_index, max_global_index, ring_size)
                    .with_context(|| format!("build ring for input {}", idx))?;
            println!(
                "Input {} ring (designated {}) -> {:?}",
                idx, designated, ring
            );
            rings.push(ring);
            designated_positions.push(designated);
        }

        let candidate_indices: Vec<u64> =
            rings.iter().flat_map(|ring| ring.iter().copied()).collect();
        let mut candidate_map = fetch_ring_keys_by_gi(&rpc, &candidate_indices)
            .context("fetch ring one-time keys via get_outs")?;

        if !rings_satisfy_sanity(&rings, max_global_index) {
            ring_attempt += 1;
            if ring_attempt >= MAX_RING_RETRIES {
                return Err(anyhow!(
                    "failed to assemble rings with acceptable decoy distribution after {} attempt(s)",
                    MAX_RING_RETRIES
                ));
            }
            println!(
                "Decoy median too old; resampling rings (attempt {}/{})",
                ring_attempt, MAX_RING_RETRIES
            );
            continue;
        }

        let unlocked_ok = ensure_unlocked_decoys(
            &rpc,
            &mut rng,
            &mut rings,
            &mut candidate_map,
            &plan,
            max_global_index,
        )
        .context("replace locked decoys")?;

        if unlocked_ok {
            if rings_satisfy_sanity(&rings, max_global_index) {
                break candidate_map;
            } else {
                ring_attempt += 1;
                if ring_attempt >= MAX_RING_RETRIES {
                    return Err(anyhow!(
                        "failed to assemble rings with acceptable decoy distribution after {} attempt(s)",
                        MAX_RING_RETRIES
                    ));
                }
                println!(
                    "Decoy median degraded after replacement; resampling (attempt {}/{})",
                    ring_attempt, MAX_RING_RETRIES
                );
            }
        } else {
            ring_attempt += 1;
            if ring_attempt >= MAX_RING_RETRIES {
                return Err(anyhow!(
                    "failed to assemble rings with unlocked decoys after {} attempt(s)",
                    MAX_RING_RETRIES
                ));
            }
            println!(
                "Ring set contained locked decoys; resampling (attempt {}/{})",
                ring_attempt, MAX_RING_RETRIES
            );
        }
    };
    // Canonical sort: inputs must be ordered by descending key image to satisfy daemon checks.
    let mut order: Vec<usize> = (0..plan.inputs.len()).collect();
    order.sort_by(|&a, &b| plan.inputs[b].key_image.cmp(&plan.inputs[a].key_image));
    if order.iter().enumerate().any(|(i, &orig)| orig != i) {
        let original_inputs = plan.inputs.clone();
        let mut reordered_rings = Vec::with_capacity(rings.len());
        let mut reordered_positions = Vec::with_capacity(designated_positions.len());
        for &idx in &order {
            reordered_rings.push(rings[idx].clone());
            reordered_positions.push(designated_positions[idx]);
        }
        rings = reordered_rings;
        designated_positions = reordered_positions;
        plan.inputs = order
            .iter()
            .map(|&idx| original_inputs[idx].clone())
            .collect();
    }
    println!("Designated indices per input: {:?}", designated_positions);

    println!(
        "Fetched {} unique ring keys across {} rings",
        ring_key_map.len(),
        rings.len()
    );
    if cli.verbose {
        for (idx, input) in plan.inputs.iter().enumerate() {
            if let Some(member) = ring_key_map.get(&input.global_index) {
                println!(
                    "  Input {} real key (gi={}): {}",
                    idx,
                    input.global_index,
                    hex::encode(member.key)
                );
            }
        }
    }

    let monero_inputs = inputs_from_plan_and_rings(&plan, &rings)
        .context("derive Monero inputs from ring indices")?;
    println!(
        "Assembled {} Monero inputs with ring size {}",
        monero_inputs.len(),
        plan.inputs
            .first()
            .map(|inp| inp.ring_member_count)
            .unwrap_or(0)
    );

    let (output_specs, extra_bytes, change_indices) =
        build_output_artifacts(&cli, &plan, &monero_inputs, &mut rng)
            .context("construct output specs")?;

    let mut input_amount_total = 0u64;
    for plan_input in &plan.inputs {
        let owned = owned_outputs
            .iter()
            .find(|owned| owned.global_index == plan_input.global_index)
            .ok_or_else(|| {
                anyhow!(
                    "owned output for plan input with global index {} not found",
                    plan_input.global_index
                )
            })?;
        input_amount_total = input_amount_total
            .checked_add(owned.amount)
            .ok_or_else(|| anyhow!("input amount overflow when summing owned outputs"))?;
    }
    let destination_amount_total: u64 = cli.destinations.iter().map(|dest| dest.amount).sum();
    let available_after_dest = input_amount_total
        .checked_sub(destination_amount_total)
        .ok_or_else(|| anyhow!("destination amounts exceed available input total"))?;
    let clsag_count = plan.inputs.len();
    let ring_size = cli.ring_size as usize;
    let fee_hint = DaemonFeeEstimator { rpc: rpc.clone() }.estimate()?;
    let fallback_per_byte = if fee_hint.fee_per_byte == 0 {
        200
    } else {
        fee_hint.fee_per_byte
    };
    let mut next_fee = fallback_per_byte.saturating_mul(1000);
    let mut outputs = Vec::new();
    let mut rct_meta = None;
    let mut output_mask_sum = None;
    let mut fee_iterations = 0usize;
    let mut converged = false;
    let mut converged_fee = next_fee;
    let mut weight = 0u64;

    for iter in 0..5 {
        fee_iterations = iter + 1;
        let fee = next_fee;
        converged_fee = fee;

        let mut candidate_specs = output_specs.clone();
        if !change_indices.is_empty() {
            let change_total = available_after_dest.checked_sub(fee).ok_or_else(|| {
                anyhow!(
                    "fee {} exceeds available value {} (inputs minus destinations)",
                    fee,
                    available_after_dest
                )
            })?;
            let change_count = change_indices.len() as u64;
            ensure!(
                change_total >= change_count,
                "change amount {} too small for {} outputs",
                change_total,
                change_indices.len()
            );
            let base = change_total / change_count;
            let mut remainder = change_total % change_count;
            for &idx in &change_indices {
                let mut amount = base;
                if remainder > 0 {
                    amount += 1;
                    remainder -= 1;
                }
                candidate_specs[idx].amount = amount;
            }
        } else {
            ensure!(
                available_after_dest == fee,
                "no change output configured but inputs ({}) != destinations ({}) + fee ({})",
                input_amount_total,
                destination_amount_total,
                fee
            );
        }

        let (candidate_outputs, candidate_meta, candidate_mask_sum) =
            tx_builder::convert::outputs_and_meta_from_specs(
                &candidate_specs,
                fee,
                extra_bytes.clone(),
                clsag_count,
                ring_size,
            )
            .context("convert outputs and RingCT metadata")?;

        let candidate_blob =
            assemble_unsigned_tx(&monero_inputs, &candidate_outputs, &candidate_meta)
                .map_err(|e| anyhow!("assemble_unsigned_tx failed: {e:?}"))?;
        weight = candidate_blob.len() as u64;

        let est = rpc
            .get_fee_estimate(None)
            .context("fetch fee estimate during convergence")?;
        let per_byte = if est.fee == 0 {
            fallback_per_byte
        } else {
            est.fee
        };
        let new_fee = per_byte.saturating_mul(weight);

        if cli.verbose {
            println!(
                "Fee loop iter {}: fee={} weight={} per-byte={}",
                fee_iterations, fee, weight, per_byte
            );
        }

        outputs = candidate_outputs;
        rct_meta = Some(candidate_meta);
        output_mask_sum = Some(candidate_mask_sum);

        if new_fee == fee {
            converged = true;
            break;
        }

        next_fee = new_fee;
    }

    let rct_meta = rct_meta.expect("fee convergence loop failed to produce metadata");
    let sum_output_masks = output_mask_sum.expect("missing output mask sum after fee loop");

    let final_change_amount = if change_indices.is_empty() {
        None
    } else {
        Some(
            available_after_dest
                .checked_sub(converged_fee)
                .expect("fee iteration invariants violated"),
        )
    };

    if converged {
        println!(
            "Fee convergence stabilized after {} iteration(s): fee {} weight {}",
            fee_iterations, converged_fee, weight
        );
    } else {
        println!(
            "Fee convergence exhausted {} iteration(s); using fee {} weight {}",
            fee_iterations, converged_fee, weight
        );
    }
    let change_desc = if let Some(amount) = final_change_amount {
        format!("yes ({amount})")
    } else {
        "no".to_string()
    };
    println!(
        "Prepared {} outputs ({} destinations, change: {})",
        outputs.len(),
        cli.destinations.len(),
        change_desc
    );
    println!(
        "Outputs ready for RingCT: {} | Extra bytes: {}",
        outputs.len(),
        extra_bytes.len()
    );

    let out_dir = cli.out_dir.clone().unwrap_or_else(|| PathBuf::from("out"));
    let plan_path = out_dir.join("plan.json");

    if cli.dry_run {
        println!("Dry run: no transactions will be constructed or written.");
        println!("Dry run: plan would be written to {}", plan_path.display());
    } else {
        fs::create_dir_all(&out_dir)
            .with_context(|| format!("create output dir {}", out_dir.display()))?;
        let json = serde_json::to_string_pretty(&plan)?;
        fs::write(&plan_path, json).with_context(|| format!("write {}", plan_path.display()))?;
        println!("Wrote spend plan to {}", plan_path.display());
    }

    let signing = build_signed_transaction(
        &cli,
        &rpc,
        &plan,
        &owned_outputs,
        &rings,
        &ring_key_map,
        &monero_inputs,
        &outputs,
        rct_meta,
        sum_output_masks,
    )?;

    run_preflight_checks(&signing.blob).context("preflight on constructed transaction")?;

    let mut finalized_blob: Option<Vec<u8>> = None;

    if cli.dry_run {
        println!("Dry run: constructed transaction blob (not written).");
    } else if let Some(ref adaptor) = signing.adaptor {
        fs::write(out_dir.join("pre_sig_tx.bin"), &signing.blob).context("write pre_sig_tx.bin")?;

        let s_tilde_hex: Vec<String> = adaptor.pre.s_tilde.iter().map(bytes_to_hex).collect();
        let ring_hex: Vec<u64> = adaptor.ring_indices.clone();
        let settlement_ctx_json = serde_json::json!({
            "chain_tag": adaptor.pre.ctx.chain_tag,
            "position_key": bytes_to_hex(&adaptor.pre.ctx.position_key),
            "settle_digest": bytes_to_hex(adaptor.pre.ctx.settle_digest),
        });
        let sanitized_json = serde_json::json!({
            "input_index": adaptor.input_index,
            "pre_j": adaptor.pre.j,
            "pre_hash": bytes_to_hex(adaptor.pre.pre_hash),
            "ring_global_indices": ring_hex,
            "key_image": bytes_to_hex(adaptor.key_image),
            "settlement_ctx": settlement_ctx_json.clone(),
            "swap_id_hex": cli.swap_id_hex.clone(),
            "pre": {
                "c1_tilde": bytes_to_hex(adaptor.pre.c1_tilde),
                "d_tilde": bytes_to_hex(adaptor.pre.d_tilde),
                "pseudo_out": bytes_to_hex(adaptor.pre.pseudo_out),
                "s_tilde": s_tilde_hex,
            },
        });
        let debug_json = serde_json::json!({
            "input_index": adaptor.input_index,
            "i_star": adaptor.witness.i_star,
            "pre_j": adaptor.pre.j,
            "pre_hash": bytes_to_hex(adaptor.pre.pre_hash),
            "ring_global_indices": ring_hex,
            "key_image": bytes_to_hex(adaptor.key_image),
            "settlement_ctx": settlement_ctx_json,
            "witness": {
                "x": bytes_to_hex(adaptor.witness.x),
                "mask": bytes_to_hex(adaptor.witness.mask),
                "amount": adaptor.witness.amount,
            },
            "swap_id_hex": cli.swap_id_hex.clone(),
            "pre": {
                "c1_tilde": bytes_to_hex(adaptor.pre.c1_tilde),
                "d_tilde": bytes_to_hex(adaptor.pre.d_tilde),
                "pseudo_out": bytes_to_hex(adaptor.pre.pseudo_out),
                "s_tilde": s_tilde_hex,
            },
            "tau": bytes_to_hex(adaptor.tau),
        });

        fs::write(
            out_dir.join("pre_sig.json"),
            serde_json::to_string_pretty(&sanitized_json)?,
        )
        .context("write pre_sig.json")?;
        fs::write(
            out_dir.join("pre_sig.debug.json"),
            serde_json::to_string_pretty(&debug_json)?,
        )
        .context("write pre_sig.debug.json")?;

        println!(
            "Adaptor pre-signature written to {}/pre_sig_tx.bin (sanitized pre_sig.json + private pre_sig.debug.json)",
            out_dir.display()
        );
    } else {
        let final_path = out_dir.join("final_tx.bin");
        fs::write(&final_path, &signing.blob).context("write final_tx.bin")?;
        println!(
            "Finalized transaction written to {} (ready for relay)",
            final_path.display()
        );
        match tx_hash_hex_from_blob(&signing.blob) {
            Ok(hash_hex) => println!("Final transaction hash: {}", hash_hex),
            Err(err) => println!("Failed to compute transaction hash: {err}"),
        }
        finalized_blob = Some(signing.blob.clone());
    }

    if cli.make_pre_sig && cli.finalize {
        ensure!(!cli.dry_run, "--finalize requires a non-dry-run invocation");
        let adaptor = signing
            .adaptor
            .as_ref()
            .ok_or_else(|| anyhow!("finalize requested without adaptor pre-signature"))?;

        let final_blob = adaptor_clsag::finalize_tx(
            &adaptor.pre,
            &adaptor.tau,
            signing.blob.clone(),
            adaptor.input_index,
        )
        .map_err(|e| anyhow!("finalize_tx failed: {e:?}"))?;

        run_preflight_checks(&final_blob).context("preflight after finalize")?;

        fs::write(out_dir.join("final_tx.bin"), &final_blob).context("write final_tx.bin")?;
        println!(
            "Finalized transaction written to {}/final_tx.bin (no relay)",
            out_dir.display()
        );
        match tx_hash_hex_from_blob(&final_blob) {
            Ok(hash_hex) => println!("Final transaction hash: {}", hash_hex),
            Err(err) => println!("Failed to compute transaction hash: {err}"),
        }
        finalized_blob = Some(final_blob);
    }

    if cli.broadcast {
        let blob = finalized_blob
            .as_deref()
            .ok_or_else(|| {
                anyhow!(
                    "--broadcast requires a finalized transaction. Use --finalize when generating a pre-signature."
                )
            })?;
        broadcast_transaction(&rpc, blob, cli.broadcast_dry_run)
            .context("broadcast finalized transaction")?;
    }

    Ok(())
}

struct SigningArtifacts {
    blob: tx_builder::TxBlob,
    adaptor: Option<AdaptorArtifact>,
}

struct AdaptorArtifact {
    pre: PreSig,
    tau: [u8; 32],
    input_index: usize,
    ring_indices: Vec<u64>,
    witness: SignerWitness,
    key_image: [u8; 32],
}

struct SigningInputState {
    ctx: ClsagCtx,
    witness: SignerWitness,
    ring_indices: Vec<u64>,
}

#[allow(clippy::too_many_arguments)]
fn build_signed_transaction(
    cli: &Cli,
    rpc: &MoneroRpc,
    plan: &monero_wallet_core::SpendPlan,
    owned_outputs: &[OwnedOutput],
    rings: &[Vec<u64>],
    ring_key_map: &BTreeMap<u64, RingMemberData>,
    monero_inputs: &tx_builder::Inputs,
    outputs: &tx_builder::Outputs,
    mut meta: tx_builder::RctMeta,
    sum_output_masks: Scalar,
) -> Result<SigningArtifacts> {
    if cli.make_pre_sig {
        ensure!(
            !cli.dry_run,
            "--make-pre-sig requires a non-dry-run invocation"
        );
    }

    let adaptor_index = if cli.make_pre_sig {
        Some(cli.input_index)
    } else {
        None
    };
    let mut adaptor_secret_override = if let Some(ref hex) = cli.adaptor_secret_hex {
        Some(parse_fixed_hex::<32>(hex, "adaptor secret hex")?)
    } else {
        None
    };
    if let Some(idx) = adaptor_index {
        ensure!(
            idx < plan.inputs.len(),
            "input-index {} out of range ({} inputs)",
            idx,
            plan.inputs.len()
        );
    }

    let message_bytes_cli = if let Some(message_hex) = cli.message_hex.as_ref() {
        Some(hex::decode(message_hex).context("decode message hex")?)
    } else {
        None
    };

    let swap_id_bytes = if adaptor_index.is_some() {
        Some(parse_fixed_hex::<32>(&cli.swap_id_hex, "swap id hex")?)
    } else {
        None
    };

    let position_key_bytes = if adaptor_index.is_some() {
        let bytes = hex::decode(&cli.position_key_hex).context("decode position key hex")?;
        ensure!(bytes.len() == 32, "position key must be 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    };

    let spend_key = parse_fixed_hex::<32>(&cli.spend_key_hex, "spend key hex")?;
    let view_key = parse_fixed_hex::<32>(&cli.view_key_hex, "view key hex")?;
    let wallet_cfg = build_wallet_config(cli)?;

    let mut signing_inputs = Vec::with_capacity(plan.inputs.len());
    for (idx, plan_input) in plan.inputs.iter().enumerate() {
        let ring = rings
            .get(idx)
            .ok_or_else(|| anyhow!("missing ring data for input {}", idx))?;
        let i_star = ring
            .iter()
            .position(|gi| *gi == plan_input.global_index)
            .ok_or_else(|| {
                anyhow!(
                    "real global index {} not found in ring {}",
                    plan_input.global_index,
                    idx
                )
            })?;

        let owned = owned_outputs
            .iter()
            .find(|o| o.global_index == plan_input.global_index)
            .ok_or_else(|| {
                anyhow!(
                    "owned output with global index {} not found",
                    plan_input.global_index
                )
            })?;

        let witness =
            derive_signer_witness(rpc, &wallet_cfg, owned, &spend_key, &view_key, i_star)?;

        let mut ring_keys = Vec::with_capacity(ring.len());
        let mut ring_commitments = Vec::with_capacity(ring.len());
        for gi in ring {
            let member = ring_key_map
                .get(gi)
                .ok_or_else(|| anyhow!("missing ring metadata for global index {gi}"))?;
            ring_keys.push(member.key);
            let commitment = OxCompressedPoint::from(member.commitment)
                .decompress()
                .ok_or_else(|| anyhow!("invalid ring commitment for global index {gi}"))?
                .compress()
                .to_bytes();
            ring_commitments.push(commitment);
        }

        let ctx = ClsagCtx {
            ring_keys,
            ring_commitments,
            key_image: plan_input.key_image,
            n: ring.len(),
        };

        signing_inputs.push(SigningInputState {
            ctx,
            witness,
            ring_indices: ring.clone(),
        });
    }

    let seed = if cli.deterministic {
        DETERMINISTIC_RNG_SEED
    } else {
        let mut seed_rng = ChaCha20Rng::from_entropy();
        seed_rng.gen::<[u8; 32]>()
    };

    let mut effective_message: Vec<u8> = message_bytes_cli.clone().unwrap_or_default();
    if effective_message.is_empty() {
        effective_message = vec![0u8; 32];
    }
    let mut message_hash = adaptor_clsag::transcript::message_hash(&effective_message);

    let first_results = sign_all_inputs(&signing_inputs, sum_output_masks, seed, message_hash)
        .context("initial CLSAG signing pass")?;

    let first_pseudo_outs: Vec<[u8; 32]> = first_results
        .iter()
        .map(|(_, pseudo)| pseudo.compress().to_bytes())
        .collect();

    if let monero_oxide::ringct::RctPrunable::Clsag {
        ref mut pseudo_outs,
        ..
    } = meta.proofs.prunable
    {
        ensure!(
            pseudo_outs.len() == first_pseudo_outs.len(),
            "pseudo_out count {} mismatch inputs {}",
            pseudo_outs.len(),
            first_pseudo_outs.len()
        );
        for (slot, bytes) in pseudo_outs.iter_mut().zip(first_pseudo_outs.iter()) {
            *slot = OxCompressedPoint::from(*bytes);
        }
    } else {
        return Err(anyhow!("transaction prunable data is not CLSAG"));
    }

    let mut tx_blob =
        assemble_unsigned_tx(monero_inputs, outputs, &meta).context("assemble unsigned tx")?;

    let tx_message =
        tx_builder::compute_clsag_message_hash(&tx_blob).context("compute CLSAG message hash")?;
    if message_bytes_cli.is_none() {
        effective_message = tx_message.to_vec();
    }
    message_hash = tx_message;

    let mut signing_results =
        sign_all_inputs(&signing_inputs, sum_output_masks, seed, message_hash)
            .context("final CLSAG signing pass")?;

    for ((_, pseudo), first_bytes) in signing_results.iter().zip(first_pseudo_outs.iter()) {
        let bytes = pseudo.compress().to_bytes();
        ensure!(
            bytes == *first_bytes,
            "pseudo_out mismatch between signing passes"
        );
    }

    tx_blob = assemble_unsigned_tx(monero_inputs, outputs, &meta)
        .context("assemble final unsigned tx")?;
    let regions =
        find_clsag_regions(&tx_blob).context("locate CLSAG regions in assembled transaction")?;
    ensure!(
        regions.len() == signing_results.len(),
        "CLSAG region count {} mismatch input count {}",
        regions.len(),
        signing_results.len()
    );

    let mut adaptor_artifact = None;
    for (idx, (clsag, pseudo_out)) in signing_results.iter_mut().enumerate() {
        let pseudo_bytes = pseudo_out.compress().to_bytes();
        replace_pseudo_out_at(&mut tx_blob, idx, OxCompressedPoint::from(pseudo_bytes))
            .with_context(|| format!("write pseudo_out for input {}", idx))?;

        if Some(idx) == adaptor_index {
            let swap_id =
                swap_id_bytes.ok_or_else(|| anyhow!("missing swap id for adaptor signing"))?;
            let position_key = position_key_bytes
                .as_ref()
                .ok_or_else(|| anyhow!("missing position key for adaptor signing"))?;

            let settlement_ctx = SettlementCtx {
                chain_tag: cli.chain_tag.clone(),
                position_key: position_key.clone(),
                settle_digest: plan.settle_digest,
            };

            let ring_hash = adaptor_clsag::transcript::ring_hash(&signing_inputs[idx].ctx);
            let settlement_hash = adaptor_clsag::transcript::settlement_hash(&settlement_ctx);
            let j = index::compute_designated_index(
                &ring_hash,
                &signing_inputs[idx].ctx.key_image,
                &message_hash,
                &swap_id,
                &settlement_hash,
                signing_inputs[idx].ctx.n,
            );

            let pre_hash = adaptor_clsag::transcript::pre_hash(
                &signing_inputs[idx].ctx,
                &effective_message,
                j,
                &swap_id,
                &settlement_ctx,
            );
            let tau_bytes = if let Some(secret) = adaptor_secret_override.take() {
                secret
            } else {
                tau::derive_tau(&settlement_ctx.settle_digest, &swap_id, &pre_hash, j as u32)
            };

            let mut responses: Vec<Scalar> = clsag.s.clone();
            let tau_scalar = Scalar::from_bytes_mod_order(tau_bytes);
            responses[j] += tau_scalar;
            let s_tilde = responses.iter().map(|s| s.to_bytes()).collect();

            let pre = PreSig {
                c1_tilde: clsag.c1.to_bytes(),
                s_tilde,
                d_tilde: clsag.D.to_bytes(),
                pseudo_out: pseudo_bytes,
                j,
                ctx: settlement_ctx.clone(),
                pre_hash,
            };

            let (_offset, region_len) = regions[idx];
            let region_bytes = presig_region::serialize_presig_region(&pre, region_len)
                .map_err(|e| anyhow!("serialize pre-sig region: {e:?}"))?;

            replace_clsag_at(&mut tx_blob, idx, 0, &region_bytes)
                .with_context(|| format!("inject pre-sig region for input {}", idx))?;

            adaptor_artifact = Some(AdaptorArtifact {
                pre,
                tau: tau_bytes,
                input_index: idx,
                ring_indices: signing_inputs[idx].ring_indices.clone(),
                witness: signing_inputs[idx].witness.clone(),
                key_image: signing_inputs[idx].ctx.key_image,
            });
        } else {
            let mut region_bytes = Vec::new();
            clsag
                .write(&mut region_bytes)
                .map_err(|e| anyhow!("serialize CLSAG for input {}: {e:?}", idx))?;
            replace_clsag_region(&mut tx_blob, idx, &region_bytes)
                .with_context(|| format!("write CLSAG for input {}", idx))?;
        }
    }

    if adaptor_index.is_some() && adaptor_artifact.is_none() {
        return Err(anyhow!(
            "failed to build adaptor artifact for input {}",
            adaptor_index.unwrap()
        ));
    }

    Ok(SigningArtifacts {
        blob: tx_blob,
        adaptor: adaptor_artifact,
    })
}

fn broadcast_transaction(rpc: &MoneroRpc, blob: &[u8], dry_run: bool) -> Result<()> {
    let submit = rpc
        .submit_raw_tx(blob, dry_run, false)
        .context("submit_raw_tx")?;
    if dry_run {
        println!(
            "Daemon accepted transaction {} in dry-run mode (status: {})",
            submit.tx_hash, submit.status
        );
    } else {
        println!(
            "Broadcast transaction {} (status: {})",
            submit.tx_hash, submit.status
        );
    }
    Ok(())
}

fn sign_all_inputs(
    inputs: &[SigningInputState],
    sum_outputs_masks: Scalar,
    seed: [u8; 32],
    message_hash: [u8; 32],
) -> Result<Vec<(monero_oxide::ringct::clsag::Clsag, EdwardsPoint)>> {
    use monero_oxide::ringct::clsag::ClsagContext;

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut signing: Vec<(Zeroizing<Scalar>, ClsagContext)> = Vec::with_capacity(inputs.len());

    for (idx, state) in inputs.iter().enumerate() {
        let ring_points = state.ctx.ring_edwards();
        let offsets = vec![0u64; ring_points.len()];
        let decoys = Decoys::new(offsets, state.witness.i_star as u8, ring_points)
            .ok_or_else(|| anyhow!("build decoys for input {}", idx))?;
        let commitment = state.witness.commitment();
        let context = ClsagContext::new(decoys, commitment)
            .map_err(|e| anyhow!("build CLSAG context for input {}: {e:?}", idx))?;
        let secret = Zeroizing::new(state.witness.secret_key());
        signing.push((secret, context));
    }

    monero_oxide::ringct::clsag::Clsag::sign(&mut rng, signing, sum_outputs_masks, message_hash)
        .map_err(|e| anyhow!("CLSAG signing failed: {e:?}"))
}

fn run_preflight_checks(blob: &[u8]) -> Result<()> {
    preflight_roundtrip(blob)?;
    preflight_balance(blob)?;
    Ok(())
}

fn preflight_roundtrip(blob: &[u8]) -> Result<()> {
    decompose_transaction(blob).context("roundtrip parse")?;
    Ok(())
}

fn preflight_balance(blob: &[u8]) -> Result<()> {
    use monero_oxide::{
        ringct::RctPrunable,
        transaction::{NotPruned, Transaction},
    };

    let mut slice = blob;
    let tx: Transaction<NotPruned> =
        Transaction::read(&mut slice).map_err(|e| anyhow!("preflight parse tx: {e:?}"))?;
    ensure!(
        slice.is_empty(),
        "preflight parse left trailing transaction bytes"
    );

    let proofs = match tx {
        Transaction::V2 {
            proofs: Some(proofs),
            ..
        } => proofs,
        _ => return Err(anyhow!("preflight expected CLSAG transaction with proofs")),
    };

    let pseudo_outs = match &proofs.prunable {
        RctPrunable::Clsag { pseudo_outs, .. } => pseudo_outs,
        _ => return Err(anyhow!("preflight transaction prunable data is not CLSAG")),
    };

    let pseudo_sum = pseudo_outs
        .iter()
        .try_fold(EdwardsPoint::identity(), |acc, cp| {
            let point = cp
                .decompress()
                .ok_or_else(|| anyhow!("pseudo_out failed to decompress"))?;
            Ok::<_, anyhow::Error>(acc + point)
        })?;

    let commitment_sum =
        proofs
            .base
            .commitments
            .iter()
            .try_fold(EdwardsPoint::identity(), |acc, cp| {
                let point = cp
                    .decompress()
                    .ok_or_else(|| anyhow!("commitment failed to decompress"))?;
                Ok::<_, anyhow::Error>(acc + point)
            })?;

    let fee_commitment = Commitment::new(Scalar::ZERO, proofs.base.fee).calculate();
    let expected = commitment_sum + fee_commitment;
    ensure!(
        pseudo_sum == expected,
        "balance equation check failed (pseudo_sum {:?} expected {:?})",
        pseudo_sum.compress().to_bytes(),
        expected.compress().to_bytes()
    );

    Ok(())
}

fn bytes_to_hex<T: AsRef<[u8]>>(data: T) -> String {
    hex::encode(data.as_ref())
}

fn tx_hash_hex_from_blob(blob: &[u8]) -> Result<String> {
    let mut slice = blob;
    let tx: OxTransaction<NotPruned> =
        OxTransaction::read(&mut slice).map_err(|e| anyhow!("parse tx blob: {e:?}"))?;
    Ok(hex::encode(tx.hash()))
}

fn drop_spent_outputs<'a>(
    rpc: &MoneroRpc,
    outputs: Vec<&'a OwnedOutput>,
) -> Result<Vec<&'a OwnedOutput>> {
    let mut key_images = Vec::new();
    let mut key_image_indices = Vec::new();
    for (idx, output) in outputs.iter().enumerate() {
        if let Some(ki) = output.key_image {
            key_images.push(ki.to_vec());
            key_image_indices.push(idx);
        }
    }

    if key_images.is_empty() {
        return Ok(outputs);
    }

    let statuses = match rpc.is_key_image_spent(&key_images) {
        Ok(status) => status,
        Err(RpcError::Node(msg))
            if msg.contains("HTTP 404") || msg.contains("Method not found") =>
        {
            return Ok(outputs);
        }
        Err(err) => {
            return Err(anyhow!("check key image spent status: {err}"));
        }
    };

    if statuses.len() != key_image_indices.len() {
        return Err(anyhow!(
            "daemon returned {} key image statuses for {} queries",
            statuses.len(),
            key_image_indices.len()
        ));
    }

    let mut status_by_index = HashMap::with_capacity(key_image_indices.len());
    for (region_idx, status) in key_image_indices.into_iter().zip(statuses.into_iter()) {
        status_by_index.insert(region_idx, status);
    }

    let mut retained = Vec::with_capacity(outputs.len());
    let mut dropped = 0usize;
    for (idx, output) in outputs.into_iter().enumerate() {
        if let Some(status) = status_by_index.get(&idx) {
            if *status != 0 {
                dropped += 1;
                continue;
            }
        }
        retained.push(output);
    }

    if dropped > 0 {
        println!("Filtered out {} spent output(s) before planning", dropped);
    }

    Ok(retained)
}

fn derive_signer_witness(
    rpc: &MoneroRpc,
    cfg: &WalletConfig,
    output: &OwnedOutput,
    spend_key: &[u8; 32],
    view_key: &[u8; 32],
    i_star: usize,
) -> Result<SignerWitness> {
    let spend_scalar = Scalar::from_bytes_mod_order(*spend_key);
    let view_scalar = Scalar::from_bytes_mod_order(*view_key);

    let key_offset = derive_key_offset(rpc, cfg, output, &view_scalar)?;
    let x_scalar = spend_scalar + key_offset;

    Ok(SignerWitness {
        x: x_scalar.to_bytes(),
        mask: output.mask,
        amount: output.amount,
        i_star,
    })
}

fn derive_key_offset(
    rpc: &MoneroRpc,
    cfg: &WalletConfig,
    output: &OwnedOutput,
    view_scalar: &Scalar,
) -> Result<Scalar> {
    let tx_hash_hex = hex::encode(output.txid);
    let resp = rpc
        .get_transactions(&GetTransactionsRequest {
            txs_hashes: vec![tx_hash_hex.clone()],
            decode_as_json: Some(true),
            prune: Some(false),
            ..Default::default()
        })
        .with_context(|| format!("fetch transaction {tx_hash_hex}"))?;

    if !resp.missed_tx.is_empty() {
        return Err(anyhow!(
            "daemon missing transaction data for {}",
            tx_hash_hex
        ));
    }

    let output_idx = output.out_index_in_tx as usize;
    let tx_entry = resp
        .txs
        .first()
        .ok_or_else(|| anyhow!("transaction metadata missing for {tx_hash_hex}"))?;
    let tx_value: serde_json::Value =
        serde_json::from_str(&tx_entry.as_json).context("parse transaction JSON")?;

    let extra_values = tx_value
        .get("extra")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("transaction missing extra field"))?;
    let mut extra_bytes = Vec::with_capacity(extra_values.len());
    for item in extra_values {
        let byte = item
            .as_u64()
            .ok_or_else(|| anyhow!("extra entry was not an integer"))?;
        ensure!(byte <= u8::MAX as u64, "extra value exceeded 8-bit range");
        extra_bytes.push(byte as u8);
    }
    let extra_keys =
        parse_extra_keys(&extra_bytes)?.ok_or_else(|| anyhow!("transaction missing extra keys"))?;

    let vouts = tx_value
        .get("vout")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("transaction missing vout array"))?;
    let vout = vouts
        .get(output_idx)
        .ok_or_else(|| anyhow!("output index {} out of range", output_idx))?;
    let target = vout
        .get("target")
        .and_then(|v| v.get("tagged_key"))
        .ok_or_else(|| anyhow!("vout missing tagged_key"))?;
    let key_hex = target
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("tagged_key missing key field"))?;
    let key_bytes = hex::decode(key_hex).context("decode tagged key")?;
    ensure!(
        key_bytes.len() == 32,
        "tagged key expected 32 bytes, got {}",
        key_bytes.len()
    );
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let output_point = OxCompressedPoint::from(key_array)
        .decompress()
        .ok_or_else(|| anyhow!("failed to decompress output key"))?;

    let view_tag_opt = target
        .get("view_tag")
        .and_then(|v| v.as_str())
        .map(|s| u8::from_str_radix(s, 16))
        .transpose()
        .map_err(|e| anyhow!("invalid view tag hex: {e}"))?;
    let mut candidates = extra_keys.primary;
    if let Some(additional) = extra_keys.additional {
        if let Some(extra) = additional.get(output_idx) {
            candidates.push(*extra);
        }
    }

    let spend_pub_point = CompressedEdwardsY(cfg.spend_pub)
        .decompress()
        .ok_or_else(|| anyhow!("invalid spend public key in wallet config"))?;
    let subaddr_map = build_subaddress_map(&cfg.subaddrs, &spend_pub_point, view_scalar);

    for key in candidates {
        let (shared_scalar, view_tag) = shared_scalar_with_view_tag(view_scalar, &key, output_idx)?;
        if let Some(expected) = view_tag_opt {
            if expected != view_tag {
                continue;
            }
        }

        let spend_candidate = output_point - (&shared_scalar * ED25519_BASEPOINT_TABLE);
        if let Some(entry) = subaddr_map.get(&spend_candidate.compress().to_bytes()) {
            let mut key_offset = shared_scalar;
            if let SubaddressEntry::Subaddress { derivation } = entry {
                key_offset += derivation;
            }
            return Ok(key_offset);
        }
    }

    Err(anyhow!(
        "failed to derive shared scalar for tx {} output {}",
        tx_hash_hex,
        output_idx
    ))
}

fn shared_scalar_with_view_tag(
    view_scalar: &Scalar,
    tx_key: &EdwardsPoint,
    output_idx: usize,
) -> Result<(Scalar, u8)> {
    let ecdh_point = view_scalar * tx_key;
    let mut derivation =
        Zeroizing::new(ecdh_point.mul_by_cofactor().compress().to_bytes().to_vec());
    {
        let derivation_vec: &mut Vec<u8> = derivation.as_mut();
        VarInt::write(&(output_idx as u64), derivation_vec)
            .expect("VarInt write to Vec should not fail");
    }

    let mut view_tag_input = Zeroizing::new(b"view_tag".to_vec());
    view_tag_input.extend(derivation.iter());
    let view_tag = keccak256(&view_tag_input)[0];

    let shared_scalar = keccak256_to_scalar(&derivation);
    Ok((shared_scalar, view_tag))
}

fn build_subaddress_map(
    configured: &[SubAddr],
    spend_pub: &EdwardsPoint,
    view_scalar: &Scalar,
) -> HashMap<[u8; 32], SubaddressEntry> {
    let mut map = HashMap::new();
    map.insert(spend_pub.compress().to_bytes(), SubaddressEntry::Primary);

    for sub in configured {
        let derivation = subaddress_derivation(view_scalar, sub.account, sub.index);
        let spend_point = spend_pub + (&derivation * ED25519_BASEPOINT_TABLE);
        let entry = if sub.account == 0 && sub.index == 0 {
            SubaddressEntry::Primary
        } else {
            SubaddressEntry::Subaddress { derivation }
        };
        map.insert(spend_point.compress().to_bytes(), entry);
    }

    map
}

fn subaddress_derivation(view_scalar: &Scalar, account: u32, index: u32) -> Scalar {
    let mut data = Zeroizing::new(Vec::new());
    data.extend_from_slice(b"SubAddr\0");
    data.extend_from_slice(&view_scalar.to_bytes());
    data.extend_from_slice(&account.to_le_bytes());
    data.extend_from_slice(&index.to_le_bytes());
    keccak256_to_scalar(data.as_slice())
}

#[derive(Debug)]
enum SubaddressEntry {
    Primary,
    Subaddress { derivation: Scalar },
}

#[derive(Debug)]
struct ExtraKeys {
    primary: Vec<EdwardsPoint>,
    additional: Option<Vec<EdwardsPoint>>,
}

fn parse_extra_keys(extra: &[u8]) -> Result<Option<ExtraKeys>> {
    let mut reader = extra;
    let mut keys = Vec::new();
    let mut additional: Option<Vec<EdwardsPoint>> = None;

    while !reader.is_empty() {
        let tag = match read_byte(&mut reader) {
            Ok(tag) => tag,
            Err(_) => break,
        };
        match tag {
            0 => {
                while let Some((&next, rest)) = reader.split_first() {
                    if next != 0 {
                        break;
                    }
                    reader = rest;
                }
            }
            1 => {
                let point = read_point(&mut reader)
                    .map_err(|e| anyhow!("failed to read tx public key: {e:?}"))?;
                keys.push(point);
            }
            2 => {
                let len: usize = VarInt::read(&mut reader)
                    .map_err(|e| anyhow!("failed to read extra nonce length: {e:?}"))?;
                if reader.len() < len {
                    return Err(anyhow!("extra nonce truncated"));
                }
                reader = &reader[len..];
            }
            3 => {
                let _height: u64 = VarInt::read(&mut reader)
                    .map_err(|e| anyhow!("failed to read extra nonce height: {e:?}"))?;
                if reader.len() < 32 {
                    return Err(anyhow!("extra nonce digest truncated"));
                }
                reader = &reader[32..];
            }
            4 => {
                let vec = read_vec(read_point, None, &mut reader)
                    .map_err(|e| anyhow!("failed to read additional tx keys: {e:?}"))?;
                if additional.is_none() {
                    additional = Some(vec);
                }
            }
            0xDE => {
                let data = read_vec(read_byte, None, &mut reader)
                    .map_err(|e| anyhow!("failed to read tx data: {e:?}"))?;
                if data.is_empty() {
                    continue;
                }
            }
            _ => break,
        }
    }

    if keys.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ExtraKeys {
            primary: keys,
            additional,
        }))
    }
}

#[derive(Clone)]
struct SendAddress {
    spend: EdwardsPoint,
    view: EdwardsPoint,
    is_subaddress: bool,
}

impl From<MoneroAddress> for SendAddress {
    fn from(addr: MoneroAddress) -> Self {
        SendAddress {
            spend: addr.spend(),
            view: addr.view(),
            is_subaddress: addr.is_subaddress(),
        }
    }
}

#[derive(Clone)]
struct OutputTarget {
    address: SendAddress,
    amount: u64,
}

fn build_output_artifacts(
    cli: &Cli,
    plan: &monero_wallet_core::SpendPlan,
    _inputs: &[MoneroInput],
    rng: &mut ChaCha20Rng,
) -> Result<(Vec<OutputSpec>, Vec<u8>, Vec<usize>)> {
    let network = parse_network_id(&cli.network)?;

    let mut targets = Vec::with_capacity(cli.destinations.len() + 1);
    for dest in &cli.destinations {
        let addr = MoneroAddress::from_str(network, &dest.address)
            .with_context(|| format!("parse destination address {}", dest.address))?;
        targets.push(OutputTarget {
            address: SendAddress::from(addr),
            amount: dest.amount,
        });
    }

    let mut change_indices = Vec::new();
    if let Some(change_amount) = plan.change {
        let change_address = derive_change_address(cli)?;
        targets.push(OutputTarget {
            address: change_address,
            amount: change_amount,
        });
        change_indices.push(targets.len() - 1);
    }

    ensure!(
        !targets.is_empty(),
        "spend plan produced no destination or change outputs"
    );

    if cli.destinations.is_empty() && change_indices.len() == 1 {
        let idx = change_indices.pop().expect("change index");
        let mut change_only = targets.remove(idx);
        ensure!(
            change_only.amount >= 2,
            "change amount {} too small to split into two outputs",
            change_only.amount
        );
        let first_amount = change_only.amount / 2;
        let second_amount = change_only.amount - first_amount;
        let mut first = change_only.clone();
        first.amount = first_amount;
        change_only.amount = second_amount;
        let first_index = targets.len();
        targets.push(first);
        change_indices.push(first_index);
        let second_index = targets.len();
        targets.push(change_only);
        change_indices.push(second_index);
    }

    let total_outputs = targets.len();

    let tx_scalar = Scalar::random(rng);
    let tx_pub_point = &tx_scalar * ED25519_BASEPOINT_TABLE;

    let use_additional_keys = targets.iter().any(|t| t.address.is_subaddress);
    let additional_scalars = if use_additional_keys {
        let mut scalars = Vec::with_capacity(total_outputs);
        for _ in 0..total_outputs {
            scalars.push(Scalar::random(rng));
        }
        Some(scalars)
    } else {
        None
    };

    let mut specs = Vec::with_capacity(total_outputs);
    for (idx, target) in targets.iter().enumerate() {
        let key_scalar = if target.address.is_subaddress {
            additional_scalars
                .as_ref()
                .map(|scalars| scalars[idx])
                .unwrap_or(tx_scalar)
        } else {
            tx_scalar
        };
        let (key, view_tag, shared_point) = derive_output_key(key_scalar, &target.address, idx)?;
        specs.push(OutputSpec {
            amount: target.amount,
            key,
            view_tag,
            shared_point,
        });
    }

    let mut extra_bytes = Vec::with_capacity(1 + 32);
    extra_bytes.push(1);
    extra_bytes.extend(tx_pub_point.compress().to_bytes());

    if let Some(scalars) = additional_scalars.as_ref() {
        if !scalars.is_empty() {
            let mut additional_points = Vec::with_capacity(total_outputs);
            for (idx, target) in targets.iter().enumerate() {
                let scalar = scalars[idx];
                let point = if target.address.is_subaddress {
                    target.address.spend * scalar
                } else {
                    &scalar * ED25519_BASEPOINT_TABLE
                };
                additional_points.push(point);
            }

            if !additional_points.is_empty() {
                extra_bytes.push(4);
                VarInt::write(&(additional_points.len() as u64), &mut extra_bytes)
                    .expect("VarInt write to Vec should not fail");
                for point in additional_points {
                    extra_bytes.extend(point.compress().to_bytes());
                }
            }
        }
    }

    Ok((specs, extra_bytes, change_indices))
}

fn derive_output_key(
    key_scalar: Scalar,
    address: &SendAddress,
    output_index: usize,
) -> Result<(OxCompressedPoint, u8, EdwardsPoint)> {
    let shared_point = address.view * key_scalar;
    let (view_tag, derivations) =
        tx_builder::ecdh::derive_view_tag_and_shared(shared_point, output_index);
    let shared_scalar = tx_builder::ecdh::shared_scalar(&derivations);
    let key_offset = &shared_scalar * ED25519_BASEPOINT_TABLE;
    let key_point = key_offset + address.spend;
    Ok((
        OxCompressedPoint::from(key_point.compress()),
        view_tag,
        shared_point,
    ))
}

fn parse_network_id(value: &str) -> Result<MoneroNetwork> {
    let lowered = value.to_ascii_lowercase();
    match lowered.as_str() {
        "mainnet" => Ok(MoneroNetwork::Mainnet),
        "stagenet" => Ok(MoneroNetwork::Stagenet),
        "testnet" => Ok(MoneroNetwork::Testnet),
        other => Err(anyhow!("unsupported network '{}'", other)),
    }
}

fn derive_change_address(cli: &Cli) -> Result<SendAddress> {
    let spend_key = parse_fixed_hex::<32>(&cli.spend_key_hex, "spend key hex")?;
    let view_key = parse_fixed_hex::<32>(&cli.view_key_hex, "view key hex")?;

    let spend_scalar = Scalar::from_bytes_mod_order(spend_key);
    let view_scalar = Scalar::from_bytes_mod_order(view_key);

    let spend_point = &spend_scalar * ED25519_BASEPOINT_TABLE;
    let view_point = &view_scalar * ED25519_BASEPOINT_TABLE;

    Ok(SendAddress {
        spend: spend_point,
        view: view_point,
        is_subaddress: false,
    })
}

fn mask_hex(value: &str, keep: usize) -> String {
    if value.len() <= keep {
        return value.to_string();
    }

    let (head, _) = value.split_at(keep);
    let masked = "*".repeat(value.len().saturating_sub(keep));
    format!("{head}…{masked} ({} chars total)", value.len())
}

fn parse_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("decode {label}"))?;
    anyhow::ensure!(
        bytes.len() == N,
        "{label} expected {N} bytes, got {}",
        bytes.len()
    );
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn load_owned_outputs(path: &Path) -> Result<Vec<OwnedOutput>> {
    let data = fs::read(path).with_context(|| format!("read owned outputs {}", path.display()))?;
    let outputs = serde_json::from_slice(&data)
        .with_context(|| format!("parse owned outputs {}", path.display()))?;
    Ok(outputs)
}

fn build_wallet_config(cli: &Cli) -> Result<WalletConfig> {
    let view_key = parse_fixed_hex::<32>(&cli.view_key_hex, "view key hex")?;
    let spend_key = parse_fixed_hex::<32>(&cli.spend_key_hex, "spend key hex")?;
    let spend_pub = if let Some(pub_hex) = cli.spend_pub_hex.as_ref() {
        parse_fixed_hex::<32>(pub_hex, "spend public key hex")?
    } else {
        derive_spend_pub(&spend_key)
    };
    let subaddrs = if cli.subaddresses.is_empty() {
        vec![SubAddr {
            account: 0,
            index: 0,
            label: None,
        }]
    } else {
        cli.subaddresses
            .iter()
            .map(|s| SubAddr {
                account: s.account,
                index: s.index,
                label: None,
            })
            .collect()
    };

    Ok(WalletConfig {
        view_key,
        spend_pub,
        spend_key: Some(spend_key),
        subaddrs,
        network: cli.network.clone(),
    })
}

fn derive_spend_pub(spend_key: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*spend_key);
    (ED25519_BASEPOINT_TABLE * &scalar).compress().to_bytes()
}

fn build_scan_params(cli: &Cli) -> ScanParams {
    ScanParams {
        start_height: cli.scan_start,
        end_height_inclusive: cli.scan_end.and_then(|end| end.checked_sub(1)),
    }
}

fn estimate_max_global_index(
    rpc: &MoneroRpc,
    chain_height: u64,
    lookback: u64,
) -> Result<Option<u64>> {
    if chain_height == 0 {
        return Ok(None);
    }

    let mut current_height = chain_height;
    let mut remaining = lookback.min(chain_height);
    let mut max_gi = None;

    while remaining > 0 && current_height > 0 {
        current_height -= 1;
        remaining -= 1;

        let block = rpc
            .get_block(&GetBlockParams {
                height: Some(current_height),
                ..Default::default()
            })
            .with_context(|| format!("get_block at height {}", current_height))?;
        if block.tx_hashes.is_empty() {
            continue;
        }

        let txs = rpc
            .get_transactions(&GetTransactionsRequest {
                txs_hashes: block.tx_hashes.clone(),
                ..Default::default()
            })
            .with_context(|| format!("get_transactions for block {}", current_height))?;
        if !txs.missed_tx.is_empty() {
            return Err(anyhow!("missing tx data for hashes: {:?}", txs.missed_tx));
        }

        for tx in txs.txs {
            if let Some(candidate) = tx.output_indices.iter().copied().max() {
                max_gi = Some(max_gi.map_or(candidate, |current: u64| current.max(candidate)));
            }
        }

        if max_gi.is_some() {
            break;
        }
    }

    Ok(max_gi)
}

fn build_ring_for_input(
    rng: &mut impl Rng,
    real_index: u64,
    max_global_index: u64,
    ring_size: usize,
) -> Result<(Vec<u64>, usize)> {
    ensure!(ring_size >= 2, "ring size must be at least 2");
    let pool_size = max_global_index
        .checked_add(1)
        .ok_or_else(|| anyhow!("global index overflow"))?;
    ensure!(
        pool_size >= ring_size as u64,
        "insufficient outputs ({pool_size}) to build ring of size {ring_size}"
    );

    let mut exclude_cutoff = pool_size.saturating_sub(DECOY_EXCLUDE_RECENT);
    let needed = ring_size - 1;

    for _pass in 0..DECOY_RESAMPLE_PASSES {
        let mut decoys = BTreeSet::new();
        let mut attempts = 0usize;
        let max_attempts = needed.saturating_mul(64).max(256);

        while decoys.len() < needed && attempts < max_attempts {
            let candidate = rng.gen_range(0..pool_size);
            attempts += 1;
            if candidate == real_index {
                continue;
            }
            if exclude_cutoff > 0 && candidate >= exclude_cutoff {
                continue;
            }
            decoys.insert(candidate);
        }

        if decoys.len() == needed {
            let mut ring: Vec<u64> = decoys.into_iter().collect();
            let insert_pos = match ring.binary_search(&real_index) {
                Ok(pos) => pos,
                Err(pos) => {
                    ring.insert(pos, real_index);
                    pos
                }
            };
            ensure!(
                ring.len() == ring_size,
                "ring length {} mismatch expected {}",
                ring.len(),
                ring_size
            );
            return Ok((ring, insert_pos));
        }

        if exclude_cutoff == 0 {
            break;
        }
        exclude_cutoff = 0;
    }

    Err(anyhow!(
        "unable to sample {} decoys (real gi {}, max_gi {}, exclude_recent {})",
        needed,
        real_index,
        max_global_index,
        DECOY_EXCLUDE_RECENT
    ))
}

fn rings_satisfy_sanity(rings: &[Vec<u64>], max_global_index: u64) -> bool {
    if rings.is_empty() {
        return true;
    }

    let mut unique = BTreeSet::new();
    let mut total = 0usize;
    for ring in rings {
        total += ring.len();
        for &idx in ring {
            unique.insert(idx);
        }
    }

    if total <= TX_SANITY_MIN_INDICES {
        return true;
    }
    if max_global_index < TX_SANITY_MIN_TOTAL_RCT {
        return true;
    }

    if unique.len() * TX_SANITY_MIN_UNIQUE_RATIO_DEN < total * TX_SANITY_MIN_UNIQUE_RATIO_NUM {
        return false;
    }

    let offsets: Vec<u64> = unique.into_iter().collect();
    if offsets.is_empty() {
        return true;
    }
    let median = if offsets.len().is_multiple_of(2) {
        let upper = offsets.len() / 2;
        let lower = upper - 1;
        offsets[lower]
            .saturating_add(offsets[upper])
            .saturating_div(2)
    } else {
        offsets[offsets.len() / 2]
    };

    let total_outputs = max_global_index.saturating_add(1);
    let threshold =
        total_outputs.saturating_mul(TX_SANITY_MEDIAN_RATIO_NUM) / TX_SANITY_MEDIAN_RATIO_DEN;
    median >= threshold
}

fn ensure_unlocked_decoys(
    rpc: &MoneroRpc,
    rng: &mut impl Rng,
    rings: &mut [Vec<u64>],
    ring_key_map: &mut BTreeMap<u64, RingMemberData>,
    plan: &monero_wallet_core::SpendPlan,
    max_global_index: u64,
) -> Result<bool> {
    for (ring_idx, ring) in rings.iter_mut().enumerate() {
        let real_index = plan.inputs[ring_idx].global_index;
        let mut present: BTreeSet<u64> = ring.iter().copied().collect();
        if !present.contains(&real_index) {
            if let Some(first) = ring.iter_mut().find(|gi| **gi != real_index) {
                *first = real_index;
            } else {
                ring.push(real_index);
            }
            present.insert(real_index);
        }

        for gi in ring.iter_mut() {
            let current = *gi;
            if current == real_index {
                continue;
            }
            let unlocked = ring_key_map
                .get(&current)
                .map(|entry| entry.unlocked)
                .unwrap_or(false);
            if unlocked {
                continue;
            }

            let mut replaced = false;
            for _ in 0..MAX_LOCKED_REPLACEMENT_ATTEMPTS {
                let candidate = rng.gen_range(0..=max_global_index);
                if candidate == real_index || present.contains(&candidate) {
                    continue;
                }
                let fetched = fetch_ring_keys_by_gi(rpc, &[candidate])
                    .context("fetch replacement decoy metadata")?;
                let entry = match fetched.get(&candidate) {
                    Some(data) => data.clone(),
                    None => continue,
                };
                if !entry.unlocked {
                    continue;
                }

                ring_key_map.remove(&current);
                ring_key_map.insert(candidate, entry);
                present.remove(&current);
                present.insert(candidate);
                *gi = candidate;
                replaced = true;
                break;
            }

            if !replaced {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
