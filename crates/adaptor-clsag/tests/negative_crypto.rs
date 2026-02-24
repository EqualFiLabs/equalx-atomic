#[path = "common/mod.rs"]
mod common;

use adaptor_clsag::{
    complete, encoding::validate_presig, extract_t, make_pre_sig, verify, EswpError,
};
use common::{build_from_vector, load_roundtrip_vector};
use curve25519_dalek::scalar::Scalar;

#[test]
fn invalid_signature_is_rejected_by_verify() {
    let vector = load_roundtrip_vector();
    let (ctx, settlement, witness, message, swap_id) = build_from_vector(&vector);

    let (pre, tau) = make_pre_sig(&ctx, &witness, &message, &swap_id, settlement)
        .expect("make_pre_sig should succeed");
    let mut final_sig = complete(&pre, &tau);
    final_sig.clsag.c1 += Scalar::ONE;

    assert!(
        !verify(&ctx, &message, &final_sig),
        "tampered final signature must fail verification"
    );
}

#[test]
fn mismatched_settlement_digest_breaks_tau_consistency() {
    let vector = load_roundtrip_vector();
    let (ctx, settlement, witness, message, swap_id) = build_from_vector(&vector);

    let (pre, tau) = make_pre_sig(&ctx, &witness, &message, &swap_id, settlement.clone())
        .expect("make_pre_sig should succeed");
    let final_sig = complete(&pre, &tau);

    let mut other_settlement = settlement;
    other_settlement.settle_digest[0] ^= 0xA5;
    let (mismatched_pre, _) = make_pre_sig(&ctx, &witness, &message, &swap_id, other_settlement)
        .expect("make_pre_sig with alternate settlement should succeed");

    let extracted = extract_t(&mismatched_pre, &final_sig);
    assert_ne!(
        extracted, tau,
        "extracted tau must not match when settlement digest differs"
    );
}

#[test]
fn noncanonical_presig_encoding_is_rejected() {
    let vector = load_roundtrip_vector();
    let (ctx, settlement, witness, message, swap_id) = build_from_vector(&vector);

    let (mut pre, _) = make_pre_sig(&ctx, &witness, &message, &swap_id, settlement)
        .expect("make_pre_sig should succeed");
    pre.s_tilde[0] = [0xFF; 32];

    assert!(matches!(
        validate_presig(&pre),
        Err(EswpError::EncodingNoncanonical)
    ));
}
