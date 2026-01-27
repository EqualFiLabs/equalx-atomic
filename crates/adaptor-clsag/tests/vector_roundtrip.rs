#[path = "common/mod.rs"]
mod common;

use adaptor_clsag::{complete, extract_t, make_pre_sig, verify};
use common::{build_from_vector, load_roundtrip_vector};
use curve25519_dalek::scalar::Scalar;
use monero_oxide::io::CompressedPoint;

fn scalar_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

fn compressed_hex(point: &CompressedPoint) -> String {
    hex::encode(point.to_bytes())
}

#[test]
fn roundtrip_vector_happy_path() {
    let vector = load_roundtrip_vector();
    let (ctx, settlement, witness, message, swap_id) = build_from_vector(&vector);

    let (pre, tau) = make_pre_sig(&ctx, &witness, &message, &swap_id, settlement.clone())
        .expect("make_pre_sig should succeed");

    assert_eq!(pre.j, vector.expected.j, "designated index mismatch");
    assert_eq!(hex::encode(pre.pre_hash), vector.expected.pre_hash_hex);
    assert_eq!(hex::encode(tau), vector.expected.tau_hex);
    assert_eq!(pre.ctx.chain_tag, settlement.chain_tag);
    assert_eq!(pre.ctx.position_key, settlement.position_key);
    assert_eq!(pre.ctx.settle_digest, settlement.settle_digest);
    assert_eq!(
        hex::encode(pre.c1_tilde),
        vector.expected.pre_sig.c1_tilde_hex
    );
    let pre_s_hex: Vec<String> = pre.s_tilde.iter().map(hex::encode).collect();
    assert_eq!(pre_s_hex, vector.expected.pre_sig.s_tilde_hex);
    assert_eq!(
        hex::encode(pre.d_tilde),
        vector.expected.pre_sig.d_tilde_hex
    );
    assert_eq!(
        hex::encode(pre.pseudo_out),
        vector.expected.pre_sig.pseudo_out_hex
    );

    let final_sig = complete(&pre, &tau);
    assert_eq!(
        hex::encode(final_sig.clsag.c1.to_bytes()),
        vector.expected.final_sig.c1_hex
    );
    let final_s_hex: Vec<String> = final_sig.clsag.s.iter().map(scalar_hex).collect();
    assert_eq!(final_s_hex, vector.expected.final_sig.s_hex);
    assert_eq!(
        compressed_hex(&final_sig.clsag.D),
        vector.expected.final_sig.d_hex
    );
    assert_eq!(
        hex::encode(final_sig.pseudo_out),
        vector.expected.final_sig.pseudo_out_hex
    );

    assert!(
        verify(&ctx, &message, &final_sig),
        "final signature must verify"
    );

    let extracted = extract_t(&pre, &final_sig);
    assert_eq!(hex::encode(extracted), vector.expected.extracted_t_hex);
}

#[test]
fn roundtrip_vector_detects_tampering() {
    let vector = load_roundtrip_vector();
    let (ctx, settlement, witness, message, swap_id) = build_from_vector(&vector);

    let (pre, tau) = make_pre_sig(&ctx, &witness, &message, &swap_id, settlement)
        .expect("make_pre_sig should succeed");

    let mut bad_tau = tau;
    bad_tau[0] ^= 0x01;
    let tampered_sig = complete(&pre, &bad_tau);
    assert!(
        !verify(&ctx, &message, &tampered_sig),
        "tampered signature should fail verification"
    );

    let extracted = extract_t(&pre, &tampered_sig);
    assert_eq!(extracted, bad_tau, "extraction should recover tampered tau");
    assert_ne!(hex::encode(extracted), vector.expected.extracted_t_hex);
}
