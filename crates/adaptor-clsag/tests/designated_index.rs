use adaptor_clsag::{index, transcript, ClsagCtx, SettlementCtx};

#[test]
fn designated_index_is_deterministic_and_bounded() {
    let sctx = SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0xAA; 32],
        settle_digest: [0x11; 32],
    };

    let ctx = ClsagCtx {
        ring_keys: vec![[0x22; 32]; 8],
        ring_commitments: Vec::new(),
        key_image: [0x33; 32],
        n: 8,
    };

    let swap_id = [0x44; 32];
    let message = b"adaptor-test-message";

    let ring_hash = transcript::ring_hash(&ctx);
    let message_hash = transcript::message_hash(message);
    let settlement_hash = transcript::settlement_hash(&sctx);

    let j1 = index::compute_designated_index(
        &ring_hash,
        &ctx.key_image,
        &message_hash,
        &swap_id,
        &settlement_hash,
        ctx.n,
    );

    let j2 = index::compute_designated_index(
        &ring_hash,
        &ctx.key_image,
        &message_hash,
        &swap_id,
        &settlement_hash,
        ctx.n,
    );

    assert_eq!(j1, j2, "designated index must be deterministic");
    assert!(j1 < ctx.n, "designated index must fall within ring size");
}
