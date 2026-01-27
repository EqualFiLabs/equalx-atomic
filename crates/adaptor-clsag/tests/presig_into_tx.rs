// SPDX-License-Identifier: Apache-2.0
#[path = "common/mod.rs"]
mod common;

use adaptor_clsag::{make_pre_sig_into_tx, presig_region, ClsagCtx, SignerWitness};
use common::{build_from_vector, load_roundtrip_vector};
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use monero_oxide::{
    io::CompressedPoint,
    primitives::Commitment,
    ringct::{
        bulletproofs::Bulletproof, clsag::Clsag, EncryptedAmount, RctBase, RctProofs, RctPrunable,
    },
    transaction::{Input, Output, Timelock},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use tx_builder::{find_clsag_regions, read_clsag_subrange, Inputs, Outputs, RctMeta};

fn mk_tx_components(witness: &SignerWitness, ctx: &ClsagCtx) -> (Inputs, Outputs, RctMeta) {
    let mut key_offsets = Vec::with_capacity(ctx.n);
    for i in 0..ctx.n {
        key_offsets.push((i as u64) + 1);
    }
    let inputs = vec![Input::ToKey {
        amount: None,
        key_offsets,
        key_image: CompressedPoint::from(ctx.key_image),
    }];

    let outputs = vec![Output {
        amount: None,
        key: CompressedPoint::from(ctx.ring_keys[0]),
        view_tag: Some(1),
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

    let mut bp_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let bulletproof =
        Bulletproof::prove_plus(&mut bp_rng, vec![output_commitment.clone()]).expect("bulletproof");

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
        extra: vec![0u8; 1],
        proofs,
    };

    (inputs, outputs, meta)
}

#[test]
fn make_presig_injects_into_real_moxide_blob() {
    let vector = load_roundtrip_vector();
    let (ctx, sctx, witness, message, swap_id) = build_from_vector(&vector);

    let (inputs, outputs, meta) = mk_tx_components(&witness, &ctx);

    let input_index = 0usize;

    let (pre, tau, blob) = make_pre_sig_into_tx(
        &ctx,
        &witness,
        &message,
        swap_id,
        sctx.clone(),
        &inputs,
        &outputs,
        &meta,
        input_index,
    )
    .expect("assemble+inject via monero-oxide");

    assert_eq!(hex::encode(pre.pre_hash), vector.expected.pre_hash_hex);
    assert_eq!(hex::encode(tau), vector.expected.tau_hex);

    let regions = find_clsag_regions(&blob).expect("regions");
    assert!(regions.len() > input_index, "at least one clsag region");
    let (_off, len) = regions[input_index];
    let region = read_clsag_subrange(&blob, input_index, 0, len).expect("read region");

    let expected = presig_region::serialize_presig_region(&pre, len).expect("serialize presig");
    assert_eq!(region, expected, "pre-sig bytes must match region bytes");
}
