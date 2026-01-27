use adaptor_clsag::{
    make_pre_sig, ClsagCtx, EswpError, SettlementCtx, SignerWitness, SAMPLE_RING_COMMITMENTS,
    SAMPLE_RING_KEYS,
};
use monero_oxide::primitives::Commitment;

fn sample_ctx() -> (ClsagCtx, SettlementCtx) {
    let witness = witness_for_index(0);
    (
        ClsagCtx {
            ring_keys: SAMPLE_RING_KEYS.to_vec(),
            ring_commitments: SAMPLE_RING_COMMITMENTS.to_vec(),
            key_image: witness.key_image_bytes(),
            n: SAMPLE_RING_KEYS.len(),
        },
        SettlementCtx {
            chain_tag: "evm:84532".into(),
            position_key: [0u8; 32],
            settle_digest: [0u8; 32],
        },
    )
}

fn witness_for_index(i: usize) -> SignerWitness {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&((i + 1) as u64).to_le_bytes());
    let mut mask = [0u8; 32];
    mask[..8].copy_from_slice(&((i + 1) as u64).to_le_bytes());
    SignerWitness {
        x,
        mask,
        amount: 0,
        i_star: i,
    }
}

#[test]
fn make_pre_sig_rejects_noncanonical_scalar() {
    let (ctx, sctx) = sample_ctx();
    let bad_scalar = [0xffu8; 32];
    let mut mask = [0u8; 32];
    mask[0] = 1;
    let witness = SignerWitness {
        x: bad_scalar,
        mask,
        amount: 0,
        i_star: 0,
    };
    let swap_id = [0u8; 32];
    let res = make_pre_sig(&ctx, &witness, b"", &swap_id, sctx);
    assert!(matches!(res, Err(EswpError::EncodingNoncanonical)));
}

#[test]
fn make_pre_sig_rejects_duplicate_ring() {
    let (mut ctx, sctx) = sample_ctx();
    ctx.ring_keys = vec![SAMPLE_RING_KEYS[0]; SAMPLE_RING_KEYS.len()];
    let witness = witness_for_index(0);
    let swap_id = [0u8; 32];
    let res = make_pre_sig(&ctx, &witness, b"", &swap_id, sctx);
    assert!(matches!(res, Err(EswpError::RingInvalid)));
}

#[test]
fn make_pre_sig_rejects_commitment_len_mismatch() {
    // ring commitments wrong length but valid points
    let witness = witness_for_index(0);
    let ctx = ClsagCtx {
        ring_keys: SAMPLE_RING_KEYS.to_vec(),
        ring_commitments: vec![
            // valid commitment point but only 1 provided
            Commitment::zero().calculate().compress().to_bytes(),
        ],
        key_image: witness.key_image_bytes(),
        n: SAMPLE_RING_KEYS.len(),
    };
    // ensure we didn't accidentally make them empty
    assert_eq!(ctx.ring_commitments.len(), 1);
    let sctx = SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [0u8; 32],
    };
    let swap_id = [0u8; 32];
    let res = make_pre_sig(&ctx, &witness, b"", &swap_id, sctx);
    assert!(matches!(res, Err(EswpError::RingInvalid)));
}

#[test]
fn make_pre_sig_rejects_invalid_key_image() {
    // invalid compressed point for key image
    let witness = witness_for_index(0);
    let ctx = ClsagCtx {
        ring_keys: SAMPLE_RING_KEYS.to_vec(),
        ring_commitments: SAMPLE_RING_COMMITMENTS.to_vec(),
        key_image: [0xFFu8; 32],
        n: SAMPLE_RING_KEYS.len(),
    };
    let sctx = SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [0u8; 32],
    };
    let swap_id = [0u8; 32];
    let res = make_pre_sig(&ctx, &witness, b"", &swap_id, sctx);
    assert!(matches!(res, Err(EswpError::EncodingNoncanonical)));
}

#[test]
fn make_pre_sig_rejects_bad_n_and_len_mismatch() {
    // n < 5
    let witness = witness_for_index(0);
    let mut ctx = ClsagCtx {
        ring_keys: SAMPLE_RING_KEYS[..4].to_vec(),
        ring_commitments: Vec::new(),
        key_image: witness.key_image_bytes(),
        n: 4,
    };
    let sctx = SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [0u8; 32],
    };
    let swap_id = [0u8; 32];
    let res = make_pre_sig(&ctx, &witness, b"", &swap_id, sctx.clone());
    assert!(matches!(res, Err(EswpError::RingInvalid)));

    // len mismatch ring_keys vs n
    ctx.n = 5;
    let res2 = make_pre_sig(&ctx, &witness, b"", &swap_id, sctx);
    assert!(matches!(res2, Err(EswpError::RingInvalid)));
}
