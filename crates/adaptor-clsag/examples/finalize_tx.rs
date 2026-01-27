use adaptor_clsag::{
    finalize_tx, make_pre_sig_into_tx, presig_region, ClsagCtx, SettlementCtx, SignerWitness,
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
use std::fs;
use std::path::Path;
use tx_builder::{find_clsag_regions, read_response_at, Inputs, Outputs, RctMeta};

fn mk_witness() -> SignerWitness {
    let mut x = [0u8; 32];
    x[0] = 7;
    let mask = Scalar::from(13u64).to_bytes();
    SignerWitness {
        x,
        mask,
        amount: 17,
        i_star: 1,
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
            let secret = Scalar::from((i as u64) + 19);
            let public = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();
            let mask = Scalar::from((i as u64) + 23);
            let commitment = Commitment::new(mask, 0).calculate().compress().to_bytes();
            ring_keys.push(public);
            ring_commitments.push(commitment);
        }
    }
    (ring_keys, ring_commitments)
}

fn mk_ctx(witness: &SignerWitness) -> ClsagCtx {
    let n = 6;
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
        settle_digest: [55u8; 32],
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
        view_tag: Some(2),
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

    let mut bp_rng = ChaCha20Rng::from_seed([3u8; 32]);
    let bulletproof = Bulletproof::prove_plus(&mut bp_rng, vec![output_commitment])
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
        extra: vec![0x42],
        proofs,
    };

    (inputs, outputs, meta)
}

fn main() {
    let witness = mk_witness();
    let ctx = mk_ctx(&witness);
    let sctx = mk_sctx();
    let msg = b"finalize example";
    let swap_id = [90u8; 32];

    let (inputs, outputs, meta) = mk_tx_components(&witness, &ctx);
    let (pre, tau, blob_with_presig) = make_pre_sig_into_tx(
        &ctx, &witness, msg, swap_id, sctx, &inputs, &outputs, &meta, 0,
    )
    .expect("pre-sig injection");

    let regions = find_clsag_regions(&blob_with_presig).expect("regions");
    println!("pre-sig regions: {:?}", regions);

    let final_blob = finalize_tx(&pre, &tau, blob_with_presig, 0).expect("finalize");

    let j = pre.j;
    let sj = read_response_at(&final_blob, 0, j).expect("read final s_j");
    let sj_hex = sj
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    println!("final s_j (index {}): {}", j, sj_hex);

    let out_dir = Path::new("out");
    fs::create_dir_all(out_dir).expect("create out/");
    fs::write(out_dir.join("final_tx.bin"), &final_blob).expect("write final_tx.bin");

    println!("final_tx.bin written ({} bytes)", final_blob.len());
    let expected_region =
        presig_region::serialize_presig_region(&pre, regions[0].1).expect("serialize presig");
    println!("pre region len: {}", expected_region.len());
}
