//! convert.rs — helpers to derive Inputs/Outputs/RctMeta for tx assembly.
//!
//! These helpers intentionally avoid any policy decisions (like decoy selection).
//! They provide a thin, documented bridge between `monero-wallet-core` planning
//! and `tx_builder` assembly types.
//!
//! Note: Witness/CLSAG-ctx assembly and finalization are intentionally kept out
//! of `tx_builder` to avoid cyclic deps with `adaptor-clsag`.

use anyhow::{anyhow, ensure, Result};
use std::collections::BTreeMap;

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use monero_oxide::{
    io::CompressedPoint,
    primitives::Commitment,
    ringct::{bulletproofs::Bulletproof, clsag::Clsag, RctBase, RctProofs, RctPrunable},
    transaction::{Input, Output, Timelock},
};
use rand::rngs::OsRng;

use crate::ecdh;

/// Maximum outputs per `/get_outs` request tolerated by restricted daemons.
const GET_OUTS_BATCH_LIMIT: usize = 96;

/// Metadata for a ring member fetched via `/get_outs`.
#[derive(Clone, Debug)]
pub struct RingMemberData {
    pub key: [u8; 32],
    pub commitment: [u8; 32],
    pub height: u64,
    pub unlocked: bool,
}

/// Lookup one-time public keys and commitments for the provided global indices via `/get_outs`.
///
/// Returns a sorted map of `global_index -> RingMemberData`.
/// The request is chunked to accommodate restricted daemon limits (typically 100 entries).
pub fn fetch_ring_keys_by_gi(
    rpc: &monero_rpc::MoneroRpc,
    indices: &[u64],
) -> Result<BTreeMap<u64, RingMemberData>> {
    if indices.is_empty() {
        return Ok(BTreeMap::new());
    }

    let mut unique = indices.to_vec();
    unique.sort_unstable();
    unique.dedup();

    let mut out = BTreeMap::new();
    for chunk in unique.chunks(GET_OUTS_BATCH_LIMIT.max(1)) {
        let outputs = chunk
            .iter()
            .map(|&index| monero_rpc::OutputRef { amount: 0, index })
            .collect();
        let request = monero_rpc::GetOutsRequest {
            outputs,
            get_txid: false,
            client: None,
        };
        let response = rpc.get_outs(&request)?;
        if response.outs.len() != chunk.len() {
            return Err(anyhow!(
                "get_outs returned {} entries for {} indices",
                response.outs.len(),
                chunk.len()
            ));
        }

        for (&gi, entry) in chunk.iter().zip(response.outs.into_iter()) {
            let key_bytes = hex::decode(&entry.key)
                .map_err(|e| anyhow!("decode one-time key for gi {}: {e}", gi))?;
            ensure!(
                key_bytes.len() == 32,
                "unexpected key length {} for gi {}",
                key_bytes.len(),
                gi
            );
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let mask_bytes = hex::decode(&entry.mask)
                .map_err(|e| anyhow!("decode commitment mask for gi {}: {e}", gi))?;
            ensure!(
                mask_bytes.len() == 32,
                "unexpected mask length {} for gi {}",
                mask_bytes.len(),
                gi
            );
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&mask_bytes);

            out.insert(
                gi,
                RingMemberData {
                    key,
                    commitment,
                    height: entry.height,
                    unlocked: entry.unlocked,
                },
            );
        }
    }

    Ok(out)
}

/// Convert a list of absolute global indices into Monero key offsets.
///
/// - Sorts ascending
/// - Validates non-empty, strictly increasing
/// - Returns `[first_abs, diff_1, diff_2, ...]`
///
/// Panics if `ring` is empty or contains duplicates (i.e., not strictly increasing).
pub fn key_offsets_from_global_indices(ring: &[u64]) -> Vec<u64> {
    assert!(!ring.is_empty(), "ring must be non-empty");
    let mut gi = ring.to_vec();
    gi.sort_unstable();

    for i in 1..gi.len() {
        assert!(
            gi[i] > gi[i - 1],
            "ring indices must be strictly increasing"
        );
    }

    let mut key_offsets = Vec::with_capacity(gi.len());
    key_offsets.push(gi[0]);
    for i in 1..gi.len() {
        key_offsets.push(gi[i] - gi[i - 1]);
    }
    key_offsets
}

/// Build Inputs from a SpendPlan and caller-provided rings (global indices).
///
/// - One `rings[i]` per `plan.inputs[i]`
/// - Each ring is converted to key offsets (sorted, strictly increasing)
/// - `Input::ToKey` uses `amount=None` and the provided key image
pub fn inputs_from_plan_and_rings(
    plan: &monero_wallet_core::SpendPlan,
    rings: &[Vec<u64>],
) -> Result<crate::Inputs> {
    let n = plan.inputs.len();
    ensure!(
        rings.len() == n,
        "rings length {} != plan inputs {}",
        rings.len(),
        n
    );

    let mut inputs = Vec::with_capacity(n);
    for (idx, (inp, ring)) in plan.inputs.iter().zip(rings.iter()).enumerate() {
        let expected = inp.ring_member_count as usize;
        ensure!(
            ring.len() == expected,
            "ring[{}] member count {} != expected {}",
            idx,
            ring.len(),
            expected
        );
        let key_offsets = key_offsets_from_global_indices(ring);
        inputs.push(Input::ToKey {
            amount: None,
            key_offsets,
            key_image: CompressedPoint::from(inp.key_image),
        });
    }

    Ok(inputs)
}

/// Description for an output to include in the transaction.
#[derive(Clone)]
pub struct OutputSpec {
    pub amount: u64,
    pub key: CompressedPoint,
    pub view_tag: u8,
    pub shared_point: EdwardsPoint,
}

/// Build Outputs and RingCT metadata from `OutputSpec`s.
///
/// - Produces `Output`s directly from specs, verifying provided view tags
/// - Encrypts amounts/derives commitments via ECDH helpers
/// - Generates a Bulletproof across the output commitments using fresh entropy
/// - Returns CLSAG placeholders sized to the caller’s expected ring dimensions
pub fn outputs_and_meta_from_specs(
    specs: &[OutputSpec],
    fee: u64,
    extra: Vec<u8>,
    clsag_count: usize,
    ring_size: usize,
) -> Result<(crate::Outputs, crate::RctMeta, Scalar)> {
    ensure!(
        !specs.is_empty(),
        "outputs_and_meta_from_specs requires at least one output"
    );

    let mut outputs = Vec::with_capacity(specs.len());
    let mut commitments_for_bp = Vec::with_capacity(specs.len());
    let mut commitment_points = Vec::with_capacity(specs.len());
    let mut encrypted_amounts = Vec::with_capacity(specs.len());
    let mut mask_sum = Scalar::ZERO;

    for (idx, spec) in specs.iter().enumerate() {
        let (derived_view_tag, derivations) =
            ecdh::derive_view_tag_and_shared(spec.shared_point, idx);

        ensure!(
            derived_view_tag == spec.view_tag,
            "view tag mismatch for output {idx}"
        );

        let mask = ecdh::commitment_mask(&derivations);
        mask_sum += mask;
        let encrypted = ecdh::ecdh_encrypt_amount(&derivations, spec.amount);
        let commitment_point = ecdh::output_commitment(mask, spec.amount);
        let commitment = Commitment::new(mask, spec.amount);

        outputs.push(Output {
            amount: None,
            key: spec.key,
            view_tag: Some(spec.view_tag),
        });

        encrypted_amounts.push(encrypted);
        commitment_points.push(commitment_point);
        commitments_for_bp.push(commitment);
    }

    let mut bp_rng = OsRng;
    let bulletproof = Bulletproof::prove_plus(&mut bp_rng, commitments_for_bp)
        .map_err(|e| anyhow!("bulletproof generation failed: {e:?}"))?;

    let base = RctBase {
        fee,
        pseudo_outs: vec![],
        encrypted_amounts,
        commitments: commitment_points,
    };

    let clsag_placeholder = Clsag {
        D: CompressedPoint::from(EdwardsPoint::identity().compress()),
        s: vec![Scalar::ZERO; ring_size.max(1)],
        c1: Scalar::ZERO,
    };

    let clsag_entries = if clsag_count == 0 {
        Vec::new()
    } else {
        vec![clsag_placeholder; clsag_count]
    };

    let pseudo_outs = vec![CompressedPoint::from([0u8; 32]); clsag_entries.len()];

    let prunable = RctPrunable::Clsag {
        clsags: clsag_entries,
        pseudo_outs,
        bulletproof,
    };

    let meta = crate::RctMeta {
        timelock: Timelock::None,
        extra,
        proofs: RctProofs { base, prunable },
    };

    Ok((outputs, meta, mask_sum))
}
