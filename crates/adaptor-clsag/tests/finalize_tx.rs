// SPDX-License-Identifier: Apache-2.0
use adaptor_clsag::{
    complete, finalize_tx, make_pre_sig_into_tx, presig_region, ClsagCtx, FinalSig, SettlementCtx,
    SignerWitness,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar, traits::Identity,
};
use monero_oxide::{
    io::CompressedPoint,
    primitives::Commitment,
    ringct::{
        bulletproofs::Bulletproof, clsag::Clsag, EncryptedAmount, RctBase, RctProofs, RctPrunable,
    },
    transaction::{Input, Output, Timelock},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use tx_builder::{
    read_clsag_subrange, read_response_at, replace_pseudo_out_at, response_count, Inputs, Outputs,
    RctMeta, TxBlob,
};

fn mk_witness() -> SignerWitness {
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

fn mk_ring(n: usize, witness: &SignerWitness) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
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
    (ring_keys, ring_commitments)
}

fn mk_ctx(witness: &SignerWitness) -> ClsagCtx {
    let n = 7;
    let (ring_keys, ring_commitments) = mk_ring(n, witness);
    ClsagCtx {
        ring_keys,
        ring_commitments,
        key_image: witness.key_image_bytes(),
        n,
    }
}

fn mk_sctx() -> SettlementCtx {
    SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [77u8; 32],
    }
}

fn mk_tx_components(witness: &SignerWitness, ctx: &ClsagCtx) -> (Inputs, Outputs, RctMeta) {
    let key_offsets = (0..ctx.n).map(|i| (i as u64) + 1).collect();
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

fn parse_clsag_from_blob(blob: &TxBlob, idx: usize) -> Clsag {
    let mut slice = blob.as_slice();
    let tx = monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
        &mut slice,
    )
    .expect("parse tx");
    match tx {
        monero_oxide::transaction::Transaction::V2 {
            proofs: Some(proofs @ monero_oxide::ringct::RctProofs { .. }),
            ..
        } => match proofs.prunable {
            RctPrunable::Clsag { clsags, .. } => clsags[idx].clone(),
            _ => panic!("transaction not CLSAG"),
        },
        _ => panic!("transaction missing CLSAG proofs"),
    }
}

#[test]
fn finalize_replaces_only_sj_and_matches_complete() {
    let witness = mk_witness();
    let ctx = mk_ctx(&witness);
    let sctx = mk_sctx();
    let msg = b"unit-finalize-moxide";
    let swap_id = [12u8; 32];

    let (inputs, outputs, meta) = mk_tx_components(&witness, &ctx);

    let (pre, tau, blob_pre) = make_pre_sig_into_tx(
        &ctx, &witness, msg, swap_id, sctx, &inputs, &outputs, &meta, 0,
    )
    .expect("pre-sig injection");

    let response_total = response_count(&blob_pre, 0).expect("response count");
    let pre_responses: Vec<_> = (0..response_total)
        .map(|idx| read_response_at(&blob_pre, 0, idx).expect("read presig"))
        .collect();

    let final_blob = finalize_tx(&pre, &tau, blob_pre, 0).expect("finalize");

    let j = pre.j;
    for (idx, pre_resp) in pre_responses.iter().enumerate() {
        let after = read_response_at(&final_blob, 0, idx).expect("read final");
        if idx == j {
            assert_ne!(after, *pre_resp, "s_j must be updated");
        } else {
            assert_eq!(after, *pre_resp, "only s_j may change");
        }
    }

    let final_sig = complete(&pre, &tau);
    let parsed_clsag = parse_clsag_from_blob(&final_blob, 0);

    assert_eq!(parsed_clsag.s.len(), final_sig.clsag.s.len());
    for (parsed, expected) in parsed_clsag.s.iter().zip(final_sig.clsag.s.iter()) {
        assert_eq!(parsed.to_bytes(), expected.to_bytes());
    }
    assert_eq!(parsed_clsag.c1.to_bytes(), final_sig.clsag.c1.to_bytes());
    assert_eq!(parsed_clsag.D.to_bytes(), final_sig.clsag.D.to_bytes());

    let regions = tx_builder::find_clsag_regions(&final_blob).expect("regions");
    let (_offset, len) = regions[0];
    let mut expected_final =
        presig_region::serialize_presig_region(&pre, len).expect("serialize presig");
    let start = j * 32;
    expected_final[start..start + 32].copy_from_slice(&final_sig.clsag.s[j].to_bytes());
    let final_region = read_clsag_subrange(&final_blob, 0, 0, len).expect("read final region");
    assert_eq!(final_region, expected_final);
}

#[test]
fn finalize_tx_rejects_mismatched_region_bytes() {
    let witness = mk_witness();
    let ctx = mk_ctx(&witness);
    let sctx = mk_sctx();
    let msg = b"finalize-prehash-guard";
    let swap_id = [77u8; 32];

    let (inputs, outputs, meta) = mk_tx_components(&witness, &ctx);
    let (_pre, tau, mut blob_pre) = make_pre_sig_into_tx(
        &ctx, &witness, msg, swap_id, sctx, &inputs, &outputs, &meta, 0,
    )
    .expect("pre-sig injection");

    // Corrupt the CLSAG region by flipping the first byte
    let regions = tx_builder::find_clsag_regions(&blob_pre).expect("regions");
    let (off, _len) = regions[0];
    blob_pre[off] ^= 0x01;

    // finalize should now fail with PreHashMismatch due to region bytes mismatch
    let res = finalize_tx(&_pre, &tau, blob_pre, 0);
    assert!(matches!(
        res,
        Err(adaptor_clsag::EswpError::PreHashMismatch)
    ));
}

#[test]
fn finalize_tx_rejects_out_of_range_input_index() {
    let witness = mk_witness();
    let ctx = mk_ctx(&witness);
    let sctx = mk_sctx();
    let msg = b"finalize-oob-index";
    let swap_id = [88u8; 32];

    let (inputs, outputs, meta) = mk_tx_components(&witness, &ctx);
    let (pre, tau, blob_pre) = make_pre_sig_into_tx(
        &ctx, &witness, msg, swap_id, sctx, &inputs, &outputs, &meta, 0,
    )
    .expect("pre-sig injection");

    // Pass a bad input region index (there is only 1 region at index 0)
    let res = finalize_tx(&pre, &tau, blob_pre, 1);
    assert!(matches!(res, Err(adaptor_clsag::EswpError::RingInvalid)));
}

#[test]
fn finalize_tx_writes_pseudo_out_and_verifies() {
    let witness = mk_witness();
    let ctx = mk_ctx(&witness);
    let sctx = mk_sctx();
    let msg = b"finalize-pseudo-out";
    let swap_id = [0x33u8; 32];

    let (inputs, outputs, meta) = mk_tx_components(&witness, &ctx);

    let (pre, tau, mut blob_pre) = make_pre_sig_into_tx(
        &ctx, &witness, msg, swap_id, sctx, &inputs, &outputs, &meta, 0,
    )
    .expect("pre-sig injection");

    // Overwrite the pseudo_out with a placeholder so finalize_tx must restore it.
    let placeholder = CompressedPoint::from(EdwardsPoint::identity().compress());
    replace_pseudo_out_at(&mut blob_pre, 0, placeholder).expect("replace pseudo_out");

    let final_blob = finalize_tx(&pre, &tau, blob_pre, 0).expect("finalize");

    // Parse the finalized transaction and extract CLSAG + pseudo_out.
    let mut slice = final_blob.as_slice();
    let tx = monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(
        &mut slice,
    )
    .expect("parse final tx");
    let (clsag, pseudo_out) = match tx {
        monero_oxide::transaction::Transaction::V2 {
            proofs: Some(monero_oxide::ringct::RctProofs { prunable, .. }),
            ..
        } => match prunable {
            RctPrunable::Clsag {
                clsags,
                pseudo_outs,
                ..
            } => {
                let clsag = clsags.first().cloned().expect("clsag 0");
                let pseudo_out = pseudo_outs.first().cloned().expect("pseudo_out 0");
                (clsag, pseudo_out)
            }
            _ => panic!("transaction not CLSAG"),
        },
        _ => panic!("expected CLSAG transaction"),
    };

    let final_sig = complete(&pre, &tau);
    let pseudo_out_bytes = pseudo_out.to_bytes();
    assert_eq!(pseudo_out_bytes, final_sig.pseudo_out);

    let sig_from_blob = FinalSig {
        clsag,
        pseudo_out: pseudo_out_bytes,
    };
    assert!(adaptor_clsag::verify(&ctx, msg, &sig_from_blob));
}
