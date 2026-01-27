use adaptor_clsag::wire::ClsagFinalSigContainer;
use adaptor_clsag::{
    complete as adaptor_complete, make_pre_sig as adaptor_make_pre_sig, ClsagCtx, SettlementCtx,
    SignerWitness, SAMPLE_RING_COMMITMENTS, SAMPLE_RING_KEYS,
};
use ffi_wasm::{
    eswp_clsag_complete_js, eswp_clsag_extract_t_js, eswp_clsag_make_pre_sig_js,
    eswp_wire_version_js,
};
use monero_oxide::ringct::clsag::Clsag;
use std::io::Cursor;
use wasm_bindgen_test::*;

fn sample_fixture() -> (ClsagCtx, SettlementCtx, SignerWitness, Vec<u8>, [u8; 32]) {
    let mut x = [0u8; 32];
    x[0] = 5;
    let mut mask = [0u8; 32];
    mask[0] = 9;
    let witness = SignerWitness {
        x,
        mask,
        amount: 0,
        i_star: 1,
    };
    let ctx = ClsagCtx {
        ring_keys: SAMPLE_RING_KEYS.to_vec(),
        ring_commitments: SAMPLE_RING_COMMITMENTS.to_vec(),
        key_image: witness.key_image_bytes(),
        n: SAMPLE_RING_KEYS.len(),
    };
    let settlement = SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [0x33u8; 32],
    };
    let message = b"ffi-wasm-roundtrip".to_vec();
    let mut swap_id = [0u8; 32];
    swap_id[0] = 0x42;
    (ctx, settlement, witness, message, swap_id)
}

fn encode_ctx_bytes(ctx: &SettlementCtx) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ctx.chain_tag.len() as u8);
    out.extend_from_slice(ctx.chain_tag.as_bytes());
    out.push(ctx.position_key.len() as u8);
    out.extend_from_slice(&ctx.position_key);
    out.push(ctx.settle_digest.len() as u8);
    out.extend_from_slice(&ctx.settle_digest);
    out
}

fn encode_ring_bytes(ctx: &ClsagCtx) -> Vec<u8> {
    ctx.ring_keys
        .iter()
        .zip(ctx.ring_commitments.iter())
        .flat_map(|(k, c)| k.iter().chain(c.iter()).copied())
        .collect()
}

fn decode_final_bytes(bytes: &[u8], decoys: usize) -> (ClsagFinalSigContainer, Clsag, [u8; 32]) {
    let container = ClsagFinalSigContainer::decode(bytes).expect("decode final container");
    assert!(
        container.final_sig.len() > 32,
        "final signature must contain pseudo_out"
    );
    let split = container.final_sig.len() - 32;
    let (clsag_bytes, pseudo) = container.final_sig.split_at(split);
    let mut cursor = Cursor::new(clsag_bytes);
    let clsag =
        Clsag::read(decoys, &mut cursor).expect("monero-oxide CLSAG decoding from wasm payload");
    let mut pseudo_out = [0u8; 32];
    pseudo_out.copy_from_slice(pseudo);
    (container, clsag, pseudo_out)
}

#[wasm_bindgen_test]
fn wire_version_exposed() {
    assert!(eswp_wire_version_js() > 0);
}

#[wasm_bindgen_test]
fn clsag_complete_and_extract_roundtrip_via_js_exports() {
    let (ctx, settlement, witness, message, swap_id) = sample_fixture();
    let ring_bytes = encode_ring_bytes(&ctx);
    let ctx_bytes = encode_ctx_bytes(&settlement);
    let pre_bytes = eswp_clsag_make_pre_sig_js(
        &message,
        &ring_bytes,
        witness.i_star as u32,
        &swap_id,
        &ctx_bytes,
    )
    .expect("js presig builder");

    let (pre, tau) =
        adaptor_make_pre_sig(&ctx, &witness, &message, &swap_id, settlement.clone()).unwrap();
    let final_bytes = eswp_clsag_complete_js(&pre_bytes, &tau).expect("js completion");
    let (container, clsag_from_js, pseudo_out) = decode_final_bytes(&final_bytes, ctx.n as usize);

    assert_eq!(container.resp_index as usize, pre.j);
    assert_eq!(container.pre_hash, pre.pre_hash);
    assert_eq!(container.ctx, settlement);

    let expected_final = adaptor_complete(&pre, &tau);
    assert_eq!(
        clsag_from_js.c1.to_bytes(),
        expected_final.clsag.c1.to_bytes()
    );
    assert_eq!(
        clsag_from_js.D.to_bytes(),
        expected_final.clsag.D.to_bytes()
    );
    assert_eq!(pseudo_out, expected_final.pseudo_out);
    assert_eq!(
        clsag_from_js.s.len(),
        expected_final.clsag.s.len(),
        "response counts must match"
    );
    for (got, expected) in clsag_from_js.s.iter().zip(expected_final.clsag.s.iter()) {
        assert_eq!(got.to_bytes(), expected.to_bytes());
    }

    let extracted = eswp_clsag_extract_t_js(&pre_bytes, &final_bytes).expect("js tau extraction");
    assert_eq!(extracted, tau);
}
