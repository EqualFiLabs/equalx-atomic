use adaptor_clsag::{complete, extract_t, make_pre_sig, ClsagCtx, SettlementCtx, SignerWitness};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use monero_oxide::primitives::Commitment;

#[test]
fn extract_t_matches_tau() {
    // Build a small consistent ring
    let ring_size = 5;
    let mut secrets = Vec::with_capacity(ring_size);
    let mut masks = Vec::with_capacity(ring_size);
    let mut ring_keys = Vec::with_capacity(ring_size);
    let mut ring_commitments = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let secret = Scalar::from((i as u64) + 11);
        let mask = Scalar::from((i as u64) + 17);
        let public = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();
        let commitment = Commitment::new(mask, 0).calculate().compress().to_bytes();
        secrets.push(secret);
        masks.push(mask);
        ring_keys.push(public);
        ring_commitments.push(commitment);
    }

    let i_star = 2usize;
    let witness = SignerWitness {
        x: secrets[i_star].to_bytes(),
        mask: masks[i_star].to_bytes(),
        amount: 0,
        i_star,
    };
    // update the i* public to match secret exactly
    ring_keys[i_star] = (ED25519_BASEPOINT_TABLE * &secrets[i_star])
        .compress()
        .to_bytes();

    let ctx = ClsagCtx {
        ring_keys,
        ring_commitments,
        key_image: witness.key_image_bytes(),
        n: ring_size,
    };
    let sctx = SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [0u8; 32],
    };
    let swap_id = [0xABu8; 32];
    let (pre, tau) = make_pre_sig(&ctx, &witness, b"msg", &swap_id, sctx).expect("pre");
    let final_sig = complete(&pre, &tau);
    let t_extracted = extract_t(&pre, &final_sig);
    assert_eq!(t_extracted, tau, "extracted tau must match original bias");
}
