use adaptor_clsag::wire::{ClsagFinalSigContainer, ClsagPreSig, MAGIC_CLSAG_PRESIG};
use adaptor_clsag::{
    complete as adaptor_complete, make_pre_sig as adaptor_make_pre_sig, ClsagCtx, SettlementCtx,
    SignerWitness, BACKEND_ID_CLSAG, SAMPLE_RING_COMMITMENTS, SAMPLE_RING_KEYS, WIRE_VERSION,
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

fn encode_ring_keys_only(ctx: &ClsagCtx) -> Vec<u8> {
    ctx.ring_keys
        .iter()
        .flat_map(|key| key.iter().copied())
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

fn encode_pre_bytes_for_test(
    msg: &[u8],
    ctx: &ClsagCtx,
    pre: &adaptor_clsag::PreSig,
    swap_id: &[u8; 32],
    legacy_tau: Option<&[u8; 32]>,
) -> Vec<u8> {
    let ring_size = u8::try_from(ctx.n).expect("ring size fits u8");
    let ring_bytes: Vec<u8> = ctx.ring_keys.iter().flat_map(|key| key.to_vec()).collect();

    let commitments_len = u32::try_from(ctx.ring_commitments.len()).expect("commitments fit u32");
    let responses_len = u32::try_from(pre.s_tilde.len()).expect("responses fit u32");

    let mut proof = Vec::new();
    proof.extend_from_slice(swap_id);
    proof.extend_from_slice(&ctx.key_image);
    proof.extend_from_slice(&commitments_len.to_le_bytes());
    for commitment in &ctx.ring_commitments {
        proof.extend_from_slice(commitment);
    }
    proof.extend_from_slice(&pre.c1_tilde);
    proof.extend_from_slice(&pre.d_tilde);
    proof.extend_from_slice(&pre.pseudo_out);
    proof.extend_from_slice(&responses_len.to_le_bytes());
    for response in &pre.s_tilde {
        proof.extend_from_slice(response);
    }
    if let Some(tau) = legacy_tau {
        proof.extend_from_slice(&(32u32).to_le_bytes());
        proof.extend_from_slice(tau);
    }

    let container = ClsagPreSig {
        magic: MAGIC_CLSAG_PRESIG,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        ring_size,
        resp_index: u8::try_from(pre.j).expect("response index fits u8"),
        reserved0: 0,
        m: msg.to_vec(),
        ring_bytes,
        pre_hash: pre.pre_hash,
        ctx: pre.ctx.clone(),
        proof_bytes_sans_resp: proof,
    };
    container.encode().expect("encode test presig")
}

#[wasm_bindgen_test]
fn wire_version_exposed() {
    assert!(eswp_wire_version_js() > 0);
}

#[wasm_bindgen_test]
fn make_pre_sig_uses_entropy_and_omits_tau() {
    let (ctx, settlement, witness, message, swap_id) = sample_fixture();
    let ring_bytes = encode_ring_keys_only(&ctx);
    let ctx_bytes = encode_ctx_bytes(&settlement);
    let pre_a = eswp_clsag_make_pre_sig_js(
        &message,
        &ring_bytes,
        witness.i_star as u32,
        &swap_id,
        &ctx_bytes,
    )
    .expect("js presig builder");
    let pre_b = eswp_clsag_make_pre_sig_js(
        &message,
        &ring_bytes,
        witness.i_star as u32,
        &swap_id,
        &ctx_bytes,
    )
    .expect("js presig builder");
    assert_ne!(pre_a, pre_b, "presig output must not be deterministic");

    let container = ClsagPreSig::decode(&pre_a).expect("decode generated presig");
    let expected_proof_len =
        32 + 32 + 4 + (ctx.ring_commitments.len() * 32) + 32 + 32 + 32 + 4 + (ctx.n * 32);
    assert_eq!(
        container.proof_bytes_sans_resp.len(),
        expected_proof_len,
        "presig proof must omit embedded tau"
    );
}

#[wasm_bindgen_test]
fn clsag_complete_and_extract_roundtrip_via_js_exports() {
    let (ctx, settlement, witness, message, swap_id) = sample_fixture();
    let (pre, tau) =
        adaptor_make_pre_sig(&ctx, &witness, &message, &swap_id, settlement.clone()).unwrap();
    let pre_bytes = encode_pre_bytes_for_test(&message, &ctx, &pre, &swap_id, None);
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

#[wasm_bindgen_test]
fn clsag_complete_accepts_legacy_pre_payload() {
    let (ctx, settlement, witness, message, swap_id) = sample_fixture();
    let (pre, tau) =
        adaptor_make_pre_sig(&ctx, &witness, &message, &swap_id, settlement.clone()).unwrap();
    let legacy_pre = encode_pre_bytes_for_test(&message, &ctx, &pre, &swap_id, Some(&tau));

    let secret = [0x5Au8; 32];
    let final_bytes = eswp_clsag_complete_js(&legacy_pre, &secret).expect("complete legacy");
    let extracted =
        eswp_clsag_extract_t_js(&legacy_pre, &final_bytes).expect("extract from legacy payload");
    assert_eq!(extracted, secret);
}
