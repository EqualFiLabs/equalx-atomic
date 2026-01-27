// SPDX-License-Identifier: Apache-2.0

//! Blocking Monero watcher that waits for a spend and extracts the adaptor
//! secret τ from the finalized CLSAG.

use std::{collections::BTreeMap, thread, time::Duration};

use adaptor_clsag::{extract_t, ClsagCtx, FinalSig, PreSig};
use anyhow::{anyhow, bail, ensure, Context, Result};
use monero_oxide::{
    ringct::RctPrunable,
    transaction::{Input as MoneroInput, NotPruned, Transaction},
};
use monero_rpc::{
    DaemonTransaction, GetOutsRequest, GetOutsResponse, GetTransactionsRequest,
    GetTransactionsResponse, MoneroRpc, OutputRef, RpcError,
};

/// Description of a single CLSAG spend we are interested in.
#[derive(Clone)]
pub struct WatchTarget {
    pub key_image: [u8; 32],
    pub tx_hash: String,
    pub input_index: usize,
    pub pre_sig: PreSig,
}

impl WatchTarget {
    pub fn new(
        key_image: [u8; 32],
        tx_hash: impl Into<String>,
        input_index: usize,
        pre_sig: PreSig,
    ) -> Self {
        Self {
            key_image,
            tx_hash: tx_hash.into(),
            input_index,
            pre_sig,
        }
    }
}

/// High-level status returned by `/is_key_image_spent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendState {
    Unspent,
    InPool,
    Confirmed,
    Unknown(u32),
}

impl SpendState {
    pub fn is_spent(self) -> bool {
        matches!(self, SpendState::Confirmed)
    }
}

impl From<u32> for SpendState {
    fn from(value: u32) -> Self {
        match value {
            0 => SpendState::Unspent,
            1 => SpendState::InPool,
            2 => SpendState::Confirmed,
            other => SpendState::Unknown(other),
        }
    }
}

impl std::str::FromStr for SpendState {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let normalized = s.trim().to_ascii_lowercase();
        Ok(match normalized.as_str() {
            "unspent" => SpendState::Unspent,
            "inpool" | "in_pool" | "pool" => SpendState::InPool,
            "confirmed" => SpendState::Confirmed,
            other => bail!("invalid spend state string: {other}"),
        })
    }
}

/// Event emitted once τ is extracted.
#[derive(Clone, Debug)]
pub struct TauEvent {
    pub key_image: [u8; 32],
    pub tx_hash: String,
    pub input_index: usize,
    pub tau: [u8; 32],
    pub spend_state: SpendState,
}

/// Abstraction over the subset of Monero RPC used by the watcher.
pub trait WatcherRpc: Send + Sync {
    fn is_key_image_spent(&self, key_images: &[Vec<u8>]) -> Result<Vec<u32>>;
    fn get_transactions(&self, request: &GetTransactionsRequest)
        -> Result<GetTransactionsResponse>;
    fn get_outs(&self, request: &GetOutsRequest) -> Result<GetOutsResponse>;
}

impl WatcherRpc for MoneroRpc {
    fn is_key_image_spent(&self, key_images: &[Vec<u8>]) -> Result<Vec<u32>> {
        MoneroRpc::is_key_image_spent(self, key_images).map_err(map_rpc_err)
    }

    fn get_transactions(
        &self,
        request: &GetTransactionsRequest,
    ) -> Result<GetTransactionsResponse> {
        MoneroRpc::get_transactions(self, request).map_err(map_rpc_err)
    }

    fn get_outs(&self, request: &GetOutsRequest) -> Result<GetOutsResponse> {
        MoneroRpc::get_outs(self, request).map_err(map_rpc_err)
    }
}

fn map_rpc_err(err: RpcError) -> anyhow::Error {
    anyhow!("monero rpc error: {err}")
}

/// Monero watcher that polls for key image spends and extracts τ upon detection.
pub struct MoneroWatcher<Rpc = MoneroRpc> {
    rpc: Rpc,
    targets: Vec<WatchTarget>,
    poll_interval: Duration,
}

impl MoneroWatcher<MoneroRpc> {
    pub fn new(rpc: MoneroRpc, targets: Vec<WatchTarget>) -> Self {
        Self::with_rpc(rpc, targets)
    }
}

impl<Rpc: WatcherRpc> MoneroWatcher<Rpc> {
    pub fn with_rpc(rpc: Rpc, targets: Vec<WatchTarget>) -> Self {
        Self {
            rpc,
            targets,
            poll_interval: Duration::from_secs(30),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Block until one of the targets is spent and τ is recovered.
    pub fn watch(&self) -> Result<TauEvent> {
        if self.targets.is_empty() {
            bail!("monero watcher requires at least one watch target");
        }
        loop {
            if let Some(event) = self.poll_once()? {
                return Ok(event);
            }
            thread::sleep(self.poll_interval);
        }
    }

    /// Perform a single poll cycle. Returns `Ok(Some(event))` if τ is available.
    pub fn poll_once(&self) -> Result<Option<TauEvent>> {
        if self.targets.is_empty() {
            return Ok(None);
        }

        let key_images: Vec<Vec<u8>> = self.targets.iter().map(|t| t.key_image.to_vec()).collect();
        let statuses = self
            .rpc
            .is_key_image_spent(&key_images)
            .context("call is_key_image_spent")?;
        ensure!(
            statuses.len() == self.targets.len(),
            "daemon returned {} statuses for {} key images",
            statuses.len(),
            self.targets.len()
        );

        for (target, code) in self.targets.iter().zip(statuses.into_iter()) {
            let state = SpendState::from(code);
            if state.is_spent() {
                let event = self.extract_tau_for_target(target, state)?;
                return Ok(Some(event));
            }
        }

        Ok(None)
    }

    fn extract_tau_for_target(
        &self,
        target: &WatchTarget,
        spend_state: SpendState,
    ) -> Result<TauEvent> {
        let tx_entry = self.fetch_tx_entry(&target.tx_hash)?;
        let tx_blob = hex::decode(tx_entry.as_hex.trim())
            .with_context(|| format!("decode tx hex for {}", target.tx_hash))?;
        let parsed = parse_tx_input(&tx_blob, target.input_index)?;
        ensure!(
            parsed.key_image == target.key_image,
            "key image mismatch for tx {} input {}",
            target.tx_hash,
            target.input_index
        );

        let ctx = build_clsag_ctx(&self.rpc, &parsed.absolute_ring_indices, parsed.key_image)
            .context("build clsag context for verification")?;
        ensure!(
            adaptor_clsag::verify(&ctx, &parsed.message_hash, &parsed.final_sig),
            "clsag verification failed for tx {} input {}",
            target.tx_hash,
            target.input_index
        );

        let tau = extract_t(&target.pre_sig, &parsed.final_sig);
        Ok(TauEvent {
            key_image: target.key_image,
            tx_hash: target.tx_hash.clone(),
            input_index: target.input_index,
            tau,
            spend_state,
        })
    }

    fn fetch_tx_entry(&self, tx_hash: &str) -> Result<DaemonTransaction> {
        let request = GetTransactionsRequest {
            txs_hashes: vec![tx_hash.to_string()],
            ..Default::default()
        };
        let response = self
            .rpc
            .get_transactions(&request)
            .with_context(|| format!("get_transactions for {tx_hash}"))?;
        if let Some(entry) = response
            .txs
            .into_iter()
            .find(|tx| tx.tx_hash.eq_ignore_ascii_case(tx_hash))
        {
            return Ok(entry);
        }
        if !response.missed_tx.is_empty() {
            bail!("transaction {tx_hash} missing from daemon response");
        }
        bail!("transaction {tx_hash} not returned by daemon");
    }
}

/// Parsed representation of the CLSAG input inside a transaction.
pub struct ParsedInput {
    pub final_sig: FinalSig,
    pub key_image: [u8; 32],
    pub absolute_ring_indices: Vec<u64>,
    pub message_hash: [u8; 32],
}

/// Parse a serialized transaction blob and extract the CLSAG for `input_index`.
pub fn parse_tx_input(blob: &[u8], input_index: usize) -> Result<ParsedInput> {
    let message_hash =
        tx_builder::compute_clsag_message_hash(blob).context("compute clsag message hash")?;

    let mut slice = blob;
    let tx: Transaction<NotPruned> =
        Transaction::read(&mut slice).map_err(|e| anyhow!("parse transaction: {e:?}"))?;
    ensure!(slice.is_empty(), "trailing bytes after transaction blob");

    let (inputs, proofs) = match tx {
        Transaction::V1 { .. } => return Err(anyhow!("expected CLSAG (v2) transaction")),
        Transaction::V2 { prefix, proofs } => {
            let proofs = proofs.ok_or_else(|| anyhow!("transaction missing RingCT proofs"))?;
            (prefix.inputs, proofs)
        }
    };

    ensure!(
        input_index < inputs.len(),
        "input index {} out of range (inputs={})",
        input_index,
        inputs.len()
    );

    let (key_offsets, key_image_cp) = match &inputs[input_index] {
        MoneroInput::ToKey {
            key_offsets,
            key_image,
            ..
        } => (key_offsets.clone(), *key_image),
        _ => return Err(anyhow!("input {input_index} is not a ToKey CLSAG input")),
    };

    let absolute_ring_indices = offsets_to_absolute(&key_offsets);
    ensure!(
        !absolute_ring_indices.is_empty(),
        "input {input_index} ring has no members"
    );

    let (clsags, pseudo_outs) = match proofs.prunable {
        RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            ..
        } => (clsags, pseudo_outs),
        _ => return Err(anyhow!("transaction prunable section is not CLSAG")),
    };

    ensure!(
        input_index < clsags.len(),
        "clsag entry missing for input {}",
        input_index
    );
    ensure!(
        input_index < pseudo_outs.len(),
        "pseudo_out entry missing for input {}",
        input_index
    );

    let clsag = clsags[input_index].clone();
    let pseudo_out = pseudo_outs[input_index].to_bytes();

    Ok(ParsedInput {
        final_sig: FinalSig { clsag, pseudo_out },
        key_image: key_image_cp.to_bytes(),
        absolute_ring_indices,
        message_hash,
    })
}

fn build_clsag_ctx<Rpc: WatcherRpc>(
    rpc: &Rpc,
    indices: &[u64],
    key_image: [u8; 32],
) -> Result<ClsagCtx> {
    let metadata = fetch_ring_metadata(rpc, indices).context("fetch ring metadata")?;
    let mut ring_keys = Vec::with_capacity(indices.len());
    let mut ring_commitments = Vec::with_capacity(indices.len());
    for gi in indices {
        let entry = metadata
            .get(gi)
            .with_context(|| format!("ring metadata missing for global index {gi}"))?;
        ring_keys.push(entry.key);
        ring_commitments.push(entry.commitment);
    }

    Ok(ClsagCtx {
        ring_keys,
        ring_commitments,
        key_image,
        n: indices.len(),
    })
}

const GET_OUTS_BATCH_LIMIT: usize = 96;

#[derive(Clone)]
struct RingMetadataEntry {
    key: [u8; 32],
    commitment: [u8; 32],
}

fn fetch_ring_metadata<Rpc: WatcherRpc>(
    rpc: &Rpc,
    indices: &[u64],
) -> Result<BTreeMap<u64, RingMetadataEntry>> {
    let mut out = BTreeMap::new();
    if indices.is_empty() {
        return Ok(out);
    }

    let mut unique = indices.to_vec();
    unique.sort_unstable();
    unique.dedup();

    for chunk in unique.chunks(GET_OUTS_BATCH_LIMIT.max(1)) {
        let outputs: Vec<OutputRef> = chunk
            .iter()
            .map(|&index| OutputRef { amount: 0, index })
            .collect();
        let request = GetOutsRequest {
            outputs,
            get_txid: false,
            client: None,
        };
        let response = rpc.get_outs(&request)?;
        ensure!(
            response.outs.len() == chunk.len(),
            "get_outs returned {} entries for {} indices",
            response.outs.len(),
            chunk.len()
        );

        for (&gi, entry) in chunk.iter().zip(response.outs.into_iter()) {
            let key = decode_hex32(&entry.key, "one-time key", gi)?;
            let commitment = decode_hex32(&entry.mask, "commitment mask", gi)?;
            out.insert(gi, RingMetadataEntry { key, commitment });
        }
    }

    Ok(out)
}

fn decode_hex32(value: &str, label: &str, gi: u64) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|e| anyhow!("decode {label} for gi {gi}: {e}"))?;
    ensure!(
        bytes.len() == 32,
        "{label} length {} invalid for gi {gi}",
        bytes.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Convert Monero key offsets into absolute global indices.
pub fn offsets_to_absolute(offsets: &[u64]) -> Vec<u64> {
    let mut result = Vec::with_capacity(offsets.len());
    let mut acc = 0u64;
    for offset in offsets {
        acc = acc.saturating_add(*offset);
        result.push(acc);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use adaptor_clsag::{
        complete, finalize_tx, make_pre_sig_into_tx, ClsagCtx, SettlementCtx, SignerWitness,
    };
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar, traits::Identity,
    };
    use monero_oxide::{
        io::CompressedPoint,
        primitives::Commitment,
        ringct::{
            bulletproofs::Bulletproof, clsag::Clsag, EncryptedAmount, RctBase, RctProofs,
            RctPrunable,
        },
        transaction::{Input, Output, Timelock},
    };
    use monero_rpc::{
        DaemonTransaction, GetOutsRequest, GetOutsResponse, GetTransactionsRequest,
        GetTransactionsResponse, OutputEntry,
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::sync::{Arc, Mutex};
    use tx_builder::{
        assemble_unsigned_tx, compute_clsag_message_hash, convert::key_offsets_from_global_indices,
        Inputs, Outputs, RctMeta,
    };

    #[test]
    fn watcher_extracts_tau_from_mock_rpc() {
        let fixture = Fixture::build();
        let rpc = MockRpc::new(&fixture);
        let watcher = MoneroWatcher::with_rpc(rpc, vec![fixture.target.clone()]);
        let event = watcher.poll_once().expect("poll").expect("event");
        assert_eq!(event.tau, fixture.tau);
        assert_eq!(event.key_image, fixture.target.key_image);
        assert_eq!(event.tx_hash, fixture.target.tx_hash);
        assert_eq!(event.spend_state, SpendState::Confirmed);
    }

    #[test]
    fn offsets_to_absolute_matches_helper() {
        let absolute = vec![3u64, 9, 12, 28];
        let offsets = key_offsets_from_global_indices(&absolute);
        assert_eq!(absolute, super::offsets_to_absolute(&offsets));
    }

    #[derive(Clone)]
    struct Fixture {
        target: WatchTarget,
        tau: [u8; 32],
        tx_hex: String,
        ring_map: BTreeMap<u64, ([u8; 32], [u8; 32])>,
    }

    impl Fixture {
        fn build() -> Self {
            let witness = sample_witness();
            let ctx = sample_clsag_ctx(&witness);
            let settlement = sample_settlement_ctx();

            let absolute_ring_indices = vec![7u64, 11, 18, 31, 49, 65, 86];
            let key_offsets = key_offsets_from_global_indices(&absolute_ring_indices);
            let (inputs, outputs, meta) = sample_tx_components(&witness, &ctx, key_offsets.clone());

            let blank_blob =
                assemble_unsigned_tx(&inputs, &outputs, &meta).expect("assemble fixture tx");
            let swap_id = [0xAB; 32];
            let (pre, tau, blob_with_pre) = make_pre_sig_into_tx(
                &ctx,
                &witness,
                &blank_blob,
                swap_id,
                settlement,
                &inputs,
                &outputs,
                &meta,
                0,
            )
            .expect("inject presig");
            let final_blob = finalize_tx(&pre, &tau, blob_with_pre, 0).expect("finalize");
            let final_sig = complete(&pre, &tau);
            // Sanity check verify path.
            let final_message_hash =
                compute_clsag_message_hash(&final_blob).expect("final message hash");
            assert!(adaptor_clsag::verify(&ctx, &final_message_hash, &final_sig));
            let tx_hex = hex::encode(final_blob);
            let tx_hash = "watcher-mock-hash".to_string();
            let key_image = ctx.key_image;
            let target = WatchTarget::new(key_image, &tx_hash, 0, pre);

            let mut ring_map = BTreeMap::new();
            for ((gi, key), commitment) in absolute_ring_indices
                .into_iter()
                .zip(ctx.ring_keys.into_iter())
                .zip(ctx.ring_commitments.into_iter())
            {
                ring_map.insert(gi, (key, commitment));
            }

            Fixture {
                target,
                tau,
                tx_hex,
                ring_map,
            }
        }
    }

    #[derive(Clone)]
    struct MockRpc {
        tx_hex: String,
        tx_hash: String,
        ring_map: BTreeMap<u64, ([u8; 32], [u8; 32])>,
    }

    impl MockRpc {
        fn new(fixture: &Fixture) -> Self {
            Self {
                tx_hex: fixture.tx_hex.clone(),
                tx_hash: fixture.target.tx_hash.clone(),
                ring_map: fixture.ring_map.clone(),
            }
        }
    }

    impl WatcherRpc for MockRpc {
        fn is_key_image_spent(&self, key_images: &[Vec<u8>]) -> Result<Vec<u32>> {
            ensure!(
                !key_images.is_empty(),
                "mock expects at least one key image"
            );
            Ok(vec![2])
        }

        fn get_transactions(
            &self,
            request: &GetTransactionsRequest,
        ) -> Result<GetTransactionsResponse> {
            ensure!(
                request
                    .txs_hashes
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(&self.tx_hash)),
                "mock requested tx hash mismatch"
            );
            let mut entry = DaemonTransaction::default();
            entry.as_hex = self.tx_hex.clone();
            entry.tx_hash = self.tx_hash.clone();
            entry.in_pool = false;
            entry.output_indices = self.ring_map.keys().copied().collect();
            let mut response = GetTransactionsResponse::default();
            response.txs = vec![entry];
            Ok(response)
        }

        fn get_outs(&self, request: &GetOutsRequest) -> Result<GetOutsResponse> {
            let mut response = GetOutsResponse::default();
            response.outs = request
                .outputs
                .iter()
                .map(|output| {
                    let entry = self
                        .ring_map
                        .get(&output.index)
                        .ok_or_else(|| anyhow!("ring member missing for gi {}", output.index))?;
                    Ok(OutputEntry {
                        height: 0,
                        key: hex::encode(entry.0),
                        mask: hex::encode(entry.1),
                        txid: String::new(),
                        unlocked: true,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(response)
        }
    }

    fn sample_witness() -> SignerWitness {
        let mut x = [0u8; 32];
        x[0] = 5;
        let mask = Scalar::from(11u64).to_bytes();
        SignerWitness {
            x,
            mask,
            amount: 19,
            i_star: 3,
        }
    }

    fn sample_clsag_ctx(witness: &SignerWitness) -> ClsagCtx {
        let n = 7;
        let mut ring_keys = Vec::with_capacity(n);
        let mut ring_commitments = Vec::with_capacity(n);
        for i in 0..n {
            if i == witness.i_star {
                let secret = Scalar::from_bytes_mod_order(witness.x);
                let public = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();
                let commitment_point = witness.commitment().calculate().compress().to_bytes();
                ring_keys.push(public);
                ring_commitments.push(commitment_point);
            } else {
                let secret = Scalar::from((i as u64) + 17);
                let public = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();
                let mask = Scalar::from((i as u64) + 21);
                let commitment = Commitment::new(mask, 0).calculate().compress().to_bytes();
                ring_keys.push(public);
                ring_commitments.push(commitment);
            }
        }

        ClsagCtx {
            ring_keys,
            ring_commitments,
            key_image: witness.key_image_bytes(),
            n,
        }
    }

    fn sample_settlement_ctx() -> SettlementCtx {
        SettlementCtx {
            chain_tag: "evm:8453".into(),
            position_key: [0xAA; 32],
            settle_digest: [0x11; 32],
        }
    }

    fn sample_tx_components(
        witness: &SignerWitness,
        ctx: &ClsagCtx,
        key_offsets: Vec<u64>,
    ) -> (Inputs, Outputs, RctMeta) {
        let inputs = vec![Input::ToKey {
            amount: None,
            key_offsets,
            key_image: CompressedPoint::from(ctx.key_image),
        }];

        let outputs = vec![Output {
            amount: None,
            key: CompressedPoint::from(ctx.ring_keys[0]),
            view_tag: Some(3),
        }];

        let output_commitment = Commitment::new(Scalar::from(5u64), witness.amount);
        let compressed_commitment = CompressedPoint::from(output_commitment.calculate().compress());
        let encrypted_amounts = vec![EncryptedAmount::Compact { amount: [0u8; 8] }];

        let pseudo_out_commitment = Commitment::new(Scalar::from(9u64), witness.amount)
            .calculate()
            .compress();

        let clsag_placeholder = Clsag {
            D: CompressedPoint::from(EdwardsPoint::identity().compress()),
            s: vec![Scalar::ZERO; ctx.n],
            c1: Scalar::ZERO,
        };

        let mut bp_rng = ChaCha20Rng::from_seed([9u8; 32]);
        let bulletproof = Bulletproof::prove_plus(&mut bp_rng, vec![output_commitment.clone()])
            .expect("bulletproof generation");

        let base = RctBase {
            fee: 0,
            pseudo_outs: vec![],
            encrypted_amounts,
            commitments: vec![compressed_commitment],
        };

        let prunable = RctPrunable::Clsag {
            clsags: vec![clsag_placeholder],
            pseudo_outs: vec![CompressedPoint::from(pseudo_out_commitment)],
            bulletproof,
        };

        let proofs = RctProofs { base, prunable };

        let meta = RctMeta {
            timelock: Timelock::None,
            extra: vec![0xAA],
            proofs,
        };

        (inputs, outputs, meta)
    }

    #[derive(Default)]
    struct InPoolRpc;

    impl WatcherRpc for InPoolRpc {
        fn is_key_image_spent(&self, key_images: &[Vec<u8>]) -> Result<Vec<u32>> {
            ensure!(
                !key_images.is_empty(),
                "mock expects at least one key image"
            );
            Ok(vec![1])
        }

        fn get_transactions(
            &self,
            _request: &GetTransactionsRequest,
        ) -> Result<GetTransactionsResponse> {
            unreachable!()
        }

        fn get_outs(&self, _request: &GetOutsRequest) -> Result<GetOutsResponse> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct MismatchStatusRpc;

    impl WatcherRpc for MismatchStatusRpc {
        fn is_key_image_spent(&self, _key_images: &[Vec<u8>]) -> Result<Vec<u32>> {
            Ok(vec![0, 2])
        }

        fn get_transactions(
            &self,
            _request: &GetTransactionsRequest,
        ) -> Result<GetTransactionsResponse> {
            unreachable!()
        }

        fn get_outs(&self, _request: &GetOutsRequest) -> Result<GetOutsResponse> {
            unreachable!()
        }
    }

    struct MissingTxRpc;

    impl WatcherRpc for MissingTxRpc {
        fn is_key_image_spent(&self, _key_images: &[Vec<u8>]) -> Result<Vec<u32>> {
            Ok(vec![2])
        }

        fn get_transactions(
            &self,
            _request: &GetTransactionsRequest,
        ) -> Result<GetTransactionsResponse> {
            Ok(GetTransactionsResponse::default())
        }

        fn get_outs(&self, _request: &GetOutsRequest) -> Result<GetOutsResponse> {
            unreachable!()
        }
    }

    #[derive(Default, Clone)]
    struct ChunkingRpc {
        calls: Arc<Mutex<Vec<Vec<u64>>>>,
    }

    impl ChunkingRpc {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl WatcherRpc for ChunkingRpc {
        fn is_key_image_spent(&self, _key_images: &[Vec<u8>]) -> Result<Vec<u32>> {
            unreachable!()
        }

        fn get_transactions(
            &self,
            _request: &GetTransactionsRequest,
        ) -> Result<GetTransactionsResponse> {
            unreachable!()
        }

        fn get_outs(&self, request: &GetOutsRequest) -> Result<GetOutsResponse> {
            self.calls
                .lock()
                .unwrap()
                .push(request.outputs.iter().map(|o| o.index).collect());
            let mut response = GetOutsResponse::default();
            response.outs = request
                .outputs
                .iter()
                .map(|output| OutputEntry {
                    height: 0,
                    key: hex::encode([0x11u8; 32]),
                    mask: hex::encode([0x22u8; 32]),
                    txid: format!("tx{}", output.index),
                    unlocked: true,
                })
                .collect();
            Ok(response)
        }
    }

    struct ShortGetOutsRpc;

    impl WatcherRpc for ShortGetOutsRpc {
        fn is_key_image_spent(&self, _key_images: &[Vec<u8>]) -> Result<Vec<u32>> {
            unreachable!()
        }

        fn get_transactions(
            &self,
            _request: &GetTransactionsRequest,
        ) -> Result<GetTransactionsResponse> {
            unreachable!()
        }

        fn get_outs(&self, request: &GetOutsRequest) -> Result<GetOutsResponse> {
            let mut response = GetOutsResponse::default();
            if !request.outputs.is_empty() {
                response.outs.push(OutputEntry {
                    height: 0,
                    key: hex::encode([0x33u8; 32]),
                    mask: hex::encode([0x44u8; 32]),
                    txid: "short".into(),
                    unlocked: true,
                });
            }
            Ok(response)
        }
    }

    fn sample_target() -> WatchTarget {
        Fixture::build().target
    }

    #[test]
    fn spend_state_unknown_and_in_pool_behaviour() {
        let unknown = SpendState::from(42u32);
        assert!(matches!(unknown, SpendState::Unknown(42)));
        assert!(!unknown.is_spent());

        let watcher = MoneroWatcher::with_rpc(InPoolRpc::default(), vec![sample_target()]);
        assert!(watcher.poll_once().expect("poll once").is_none());
    }

    #[test]
    fn watcher_errors_on_status_length_mismatch() {
        let watcher = MoneroWatcher::with_rpc(MismatchStatusRpc::default(), vec![sample_target()]);
        assert!(watcher.poll_once().is_err());
    }

    #[test]
    fn watcher_errors_when_transaction_missing() {
        let watcher = MoneroWatcher::with_rpc(MissingTxRpc, vec![sample_target()]);
        assert!(watcher.poll_once().is_err());
    }

    #[test]
    fn fetch_ring_metadata_batches_requests() {
        let rpc = ChunkingRpc::new();
        let limit = GET_OUTS_BATCH_LIMIT as u64;
        let indices: Vec<u64> = (0..(limit + 5)).collect();
        let metadata = fetch_ring_metadata(&rpc, &indices).expect("metadata");
        assert_eq!(metadata.len(), indices.len());
        let calls = rpc.calls.lock().unwrap();
        assert!(calls.len() >= 2);
        assert!(calls
            .iter()
            .all(|chunk| chunk.len() <= GET_OUTS_BATCH_LIMIT));
    }

    #[test]
    fn fetch_ring_metadata_rejects_short_response() {
        let indices = vec![1u64, 2u64];
        assert!(fetch_ring_metadata(&ShortGetOutsRpc, &indices).is_err());
    }
}
