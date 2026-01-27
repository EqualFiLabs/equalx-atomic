use adaptor_clsag::{
    tau,
    wire::{ClsagFinalSigContainer, ClsagPreSig, MAGIC_CLSAG_FINAL, MAGIC_CLSAG_PRESIG},
    SettlementCtx, BACKEND_ID_CLSAG, SAMPLE_RING_KEYS, WIRE_VERSION,
};

fn sample_ctx() -> SettlementCtx {
    SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [1u8; 32],
    }
}

#[test]
fn presig_roundtrip() {
    let ring_bytes: Vec<u8> = SAMPLE_RING_KEYS.iter().flat_map(|b| b.to_vec()).collect();
    let presig = ClsagPreSig {
        magic: MAGIC_CLSAG_PRESIG,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        ring_size: SAMPLE_RING_KEYS.len() as u8,
        resp_index: 1,
        reserved0: 0,
        m: b"hello".to_vec(),
        ring_bytes,
        pre_hash: [2u8; 32],
        ctx: sample_ctx(),
        proof_bytes_sans_resp: vec![3, 4, 5],
    };
    let encoded = presig.encode().expect("encode presig");
    let decoded = ClsagPreSig::decode(&encoded).expect("decode presig");
    assert_eq!(decoded.magic, presig.magic);
    assert_eq!(decoded.wire_version, presig.wire_version);
    assert_eq!(decoded.backend, presig.backend);
    assert_eq!(decoded.ring_size, presig.ring_size);
    assert_eq!(decoded.resp_index, presig.resp_index);
    assert_eq!(decoded.m, presig.m);
    assert_eq!(decoded.ring_bytes, presig.ring_bytes);
    assert_eq!(decoded.pre_hash, presig.pre_hash);
    assert_eq!(decoded.ctx.chain_tag, presig.ctx.chain_tag);
    assert_eq!(decoded.ctx.position_key, presig.ctx.position_key);
    assert_eq!(decoded.ctx.settle_digest, presig.ctx.settle_digest);
    assert_eq!(decoded.proof_bytes_sans_resp, presig.proof_bytes_sans_resp);
}

#[test]
fn final_roundtrip() {
    let final_sig = ClsagFinalSigContainer {
        magic: MAGIC_CLSAG_FINAL,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        resp_index: 2,
        final_sig: vec![9u8; 64],
        pre_hash: [4u8; 32],
        ctx: sample_ctx(),
    };
    let encoded = final_sig.encode().expect("encode final");
    let decoded = ClsagFinalSigContainer::decode(&encoded).expect("decode final");
    assert_eq!(decoded.magic, final_sig.magic);
    assert_eq!(decoded.wire_version, final_sig.wire_version);
    assert_eq!(decoded.backend, final_sig.backend);
    assert_eq!(decoded.resp_index, final_sig.resp_index);
    assert_eq!(decoded.final_sig, final_sig.final_sig);
    assert_eq!(decoded.pre_hash, final_sig.pre_hash);
    assert_eq!(decoded.ctx.chain_tag, final_sig.ctx.chain_tag);
    assert_eq!(decoded.ctx.position_key, final_sig.ctx.position_key);
    assert_eq!(decoded.ctx.settle_digest, final_sig.ctx.settle_digest);
}

#[test]
fn tau_derivation_hkdf_deterministic() {
    let hashlock = [0xAA; 32];
    let swap_id = [0xBB; 32];
    let stmt = b"prehash-binding";
    let tau1 = tau::derive_tau(&hashlock, &swap_id, stmt, 7);
    let tau2 = tau::derive_tau(&hashlock, &swap_id, stmt, 7);
    assert_eq!(tau1, tau2);

    let tau3 = tau::derive_tau(&hashlock, &swap_id, stmt, 8);
    assert_ne!(tau1, tau3);

    let tau4 = tau::derive_tau(&hashlock, &swap_id, b"different", 7);
    assert_ne!(tau1, tau4);
}
