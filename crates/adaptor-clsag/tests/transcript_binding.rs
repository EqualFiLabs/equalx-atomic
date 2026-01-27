#[path = "common/mod.rs"]
mod common;

use adaptor_clsag::derive_transcript;
use common::{build_from_vector, load_roundtrip_vector};
use hex::encode;

#[test]
fn transcript_binds_swap_and_settlement_digest() {
    let vector = load_roundtrip_vector();
    let (ctx, settlement, _witness, message, swap_id) = build_from_vector(&vector);
    let (_tr, t, _, pre_hash) =
        derive_transcript(&ctx, &message, vector.expected.j, &swap_id, &settlement);
    assert_eq!(encode(pre_hash), vector.expected.pre_hash_hex);

    let mut alt_swap = swap_id;
    alt_swap[0] ^= 0x01;
    let (_tr_alt, t_swap, _, hash_swap) =
        derive_transcript(&ctx, &message, vector.expected.j, &alt_swap, &settlement);
    assert_ne!(
        t, t_swap,
        "tau seed must change with swap id per docs/CLSAG-ADAPTOR-SPEC.md"
    );
    assert_ne!(pre_hash, hash_swap, "pre-hash must bind swap id");

    let mut other_ctx = settlement.clone();
    other_ctx.settle_digest[0] ^= 0xFE;
    let (_tr_ctx, t_ctx, _, hash_ctx) =
        derive_transcript(&ctx, &message, vector.expected.j, &swap_id, &other_ctx);
    assert_ne!(
        t, t_ctx,
        "tau seed must change with settlement digest per docs/CLSAG-ADAPTOR-SPEC.md"
    );
    assert_ne!(pre_hash, hash_ctx, "pre-hash must bind settlement digest");
}
