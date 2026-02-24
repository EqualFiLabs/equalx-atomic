use adaptor_clsag::{
    tau,
    wire::{ClsagFinalSigContainer, ClsagPreSig, MAGIC_CLSAG_FINAL, MAGIC_CLSAG_PRESIG},
    SettlementCtx, BACKEND_ID_CLSAG, SAMPLE_RING_KEYS, WIRE_VERSION,
};
use std::convert::TryInto;

fn sample_ctx() -> SettlementCtx {
    SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [1u8; 32],
    }
}

fn canonical_proof_bytes(ring_size: usize) -> Vec<u8> {
    let mut proof = Vec::with_capacity((ring_size + 3) * 32);
    proof.extend_from_slice(&[0xC1; 32]); // c1_tilde
    for i in 0..ring_size {
        proof.extend_from_slice(&[i as u8 + 1; 32]); // s_tilde[i]
    }
    proof.extend_from_slice(&[0xD1; 32]); // d_tilde
    proof.extend_from_slice(&[0xE1; 32]); // pseudo_out
    proof
}

#[test]
fn presig_roundtrip() {
    let ring_bytes: Vec<u8> = SAMPLE_RING_KEYS.iter().flat_map(|b| b.to_vec()).collect();
    let ring_size = SAMPLE_RING_KEYS.len();
    let presig = ClsagPreSig {
        magic: MAGIC_CLSAG_PRESIG,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        ring_size: ring_size as u8,
        resp_index: 1,
        reserved0: 0,
        m: b"hello".to_vec(),
        ring_bytes,
        pre_hash: [2u8; 32],
        ctx: sample_ctx(),
        proof_bytes_sans_resp: canonical_proof_bytes(ring_size),
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
fn presig_encode_enforces_canonical_layout_sections() {
    let ring_size = SAMPLE_RING_KEYS.len();
    let ring_bytes: Vec<u8> = SAMPLE_RING_KEYS.iter().flat_map(|b| b.to_vec()).collect();
    let proof = canonical_proof_bytes(ring_size);
    let presig = ClsagPreSig {
        magic: MAGIC_CLSAG_PRESIG,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        ring_size: ring_size as u8,
        resp_index: 2,
        reserved0: 0,
        m: b"layout-check".to_vec(),
        ring_bytes: ring_bytes.clone(),
        pre_hash: [0xAA; 32],
        ctx: SettlementCtx {
            chain_tag: "evm:1".into(),
            position_key: [0xBB; 32],
            settle_digest: [0xCC; 32],
        },
        proof_bytes_sans_resp: proof.clone(),
    };

    let encoded = presig.encode().expect("encode presig");
    assert_eq!(&encoded[0..4], &MAGIC_CLSAG_PRESIG.to_le_bytes());
    assert_eq!(&encoded[4..6], &WIRE_VERSION.to_le_bytes());
    assert_eq!(encoded[6], BACKEND_ID_CLSAG);
    assert_eq!(encoded[7], ring_size as u8);
    assert_eq!(encoded[8], 2);
    assert_eq!(encoded[9], 0);

    let m_len = u32::from_le_bytes(encoded[10..14].try_into().expect("m_len")) as usize;
    let ring_len = u32::from_le_bytes(encoded[14..18].try_into().expect("ring_len")) as usize;
    let pre_hash_len = u32::from_le_bytes(encoded[18..22].try_into().expect("pre_hash_len"));
    assert_eq!(m_len, presig.m.len());
    assert_eq!(ring_len, ring_bytes.len());
    assert_eq!(pre_hash_len, 32);

    let mut cursor = 22usize;
    assert_eq!(&encoded[cursor..cursor + m_len], presig.m.as_slice());
    cursor += m_len;
    assert_eq!(&encoded[cursor..cursor + ring_len], ring_bytes.as_slice());
    cursor += ring_len;
    assert_eq!(&encoded[cursor..cursor + 32], &[0xAA; 32]);
    cursor += 32;

    let chain_len = encoded[cursor] as usize;
    cursor += 1;
    assert_eq!(&encoded[cursor..cursor + chain_len], b"evm:1");
    cursor += chain_len;

    let position_len = encoded[cursor] as usize;
    cursor += 1;
    assert_eq!(position_len, 32);
    assert_eq!(&encoded[cursor..cursor + 32], &[0xBB; 32]);
    cursor += 32;

    let settle_len = encoded[cursor] as usize;
    cursor += 1;
    assert_eq!(settle_len, 32);
    assert_eq!(&encoded[cursor..cursor + 32], &[0xCC; 32]);
    cursor += 32;

    let proof_section = &encoded[cursor..];
    assert_eq!(proof_section, proof.as_slice());
    assert_eq!(proof_section.len(), (ring_size + 3) * 32);
}

#[test]
fn presig_decode_accepts_fully_canonical_payload() {
    let ring_size = SAMPLE_RING_KEYS.len();
    let ring_bytes: Vec<u8> = SAMPLE_RING_KEYS.iter().flat_map(|k| k.to_vec()).collect();
    let message = b"canonical-payload".to_vec();
    let proof = canonical_proof_bytes(ring_size);

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&MAGIC_CLSAG_PRESIG.to_le_bytes());
    encoded.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    encoded.push(BACKEND_ID_CLSAG);
    encoded.push(ring_size as u8);
    encoded.push(1);
    encoded.push(0);
    encoded.extend_from_slice(&(message.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&(ring_bytes.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&(32u32).to_le_bytes());
    encoded.extend_from_slice(&message);
    encoded.extend_from_slice(&ring_bytes);
    encoded.extend_from_slice(&[0x11; 32]);

    let chain = b"evm:8453";
    encoded.push(chain.len() as u8);
    encoded.extend_from_slice(chain);
    encoded.push(32);
    encoded.extend_from_slice(&[0x22; 32]);
    encoded.push(32);
    encoded.extend_from_slice(&[0x33; 32]);
    encoded.extend_from_slice(&proof);

    let decoded = ClsagPreSig::decode(&encoded).expect("decode canonical payload");
    assert_eq!(decoded.magic, MAGIC_CLSAG_PRESIG);
    assert_eq!(decoded.wire_version, WIRE_VERSION);
    assert_eq!(decoded.backend, BACKEND_ID_CLSAG);
    assert_eq!(decoded.ring_size as usize, ring_size);
    assert_eq!(decoded.resp_index, 1);
    assert_eq!(decoded.m, message);
    assert_eq!(decoded.ring_bytes, ring_bytes);
    assert_eq!(decoded.pre_hash, [0x11; 32]);
    assert_eq!(decoded.ctx.chain_tag, "evm:8453");
    assert_eq!(decoded.ctx.position_key, [0x22; 32]);
    assert_eq!(decoded.ctx.settle_digest, [0x33; 32]);
    assert_eq!(decoded.proof_bytes_sans_resp, proof);
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
