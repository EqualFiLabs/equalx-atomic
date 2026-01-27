use adaptor_clsag::wire::{
    ClsagFinalSigContainer, ClsagPreSig, MAGIC_CLSAG_FINAL, MAGIC_CLSAG_PRESIG,
};
use adaptor_clsag::{EswpError, SettlementCtx, BACKEND_ID_CLSAG, SAMPLE_RING_KEYS, WIRE_VERSION};

fn sample_ctx() -> SettlementCtx {
    SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [0u8; 32],
    }
}

fn sample_presig_bytes() -> Vec<u8> {
    let presig = ClsagPreSig {
        magic: MAGIC_CLSAG_PRESIG,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        ring_size: 3,
        resp_index: 1,
        reserved0: 0,
        m: b"msg".to_vec(),
        ring_bytes: SAMPLE_RING_KEYS
            .iter()
            .take(3)
            .flat_map(|k| k.to_vec())
            .collect(),
        pre_hash: [7u8; 32],
        ctx: sample_ctx(),
        proof_bytes_sans_resp: vec![1, 2, 3],
    };
    presig.encode().unwrap()
}

fn sample_final_bytes() -> Vec<u8> {
    let final_sig = ClsagFinalSigContainer {
        magic: MAGIC_CLSAG_FINAL,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        resp_index: 2,
        final_sig: vec![9u8; 64],
        pre_hash: [4u8; 32],
        ctx: sample_ctx(),
    };
    final_sig.encode().unwrap()
}

#[test]
fn presig_decode_rejects_wrong_magic_version_backend_reserved() {
    let mut buf = sample_presig_bytes();
    // wrong magic
    buf[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::MagicMismatch)
    ));

    // wrong version
    let mut buf = sample_presig_bytes();
    buf[4..6].copy_from_slice(&(WIRE_VERSION + 1).to_le_bytes());
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::VersionUnsupported)
    ));

    // backend mismatch
    let mut buf = sample_presig_bytes();
    buf[6] = BACKEND_ID_CLSAG.wrapping_add(1);
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::BackendMismatch)
    ));

    // reserved0 non-zero
    let mut buf = sample_presig_bytes();
    buf[9] = 1;
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::EncodingNoncanonical)
    ));
}

#[test]
fn presig_decode_rejects_ring_len_and_resp_index() {
    // Set ring_size to 4 but keep ring_len == 3*32 so mismatch triggers RingInvalid
    let mut buf = sample_presig_bytes();
    buf[7] = 4; // ring_size position
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::RingInvalid)
    ));

    // resp_index >= ring_size
    let mut buf = sample_presig_bytes();
    buf[7] = 3; // ring_size
    buf[8] = 3; // resp_index == ring_size
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::RespIndexUnadmitted)
    ));
}

#[test]
fn presig_decode_rejects_bad_pre_hash_len_and_ctx_settle_len() {
    // pre_hash_len != 32
    let mut buf = sample_presig_bytes();
    // field layout: magic(4) ver(2) backend(1) ring(1) resp(1) res0(1) m_len(4) ring_len(4) pre_len(4)
    let pre_len_off = 4 + 2 + 1 + 1 + 1 + 1 + 4 + 4;
    buf[pre_len_off..pre_len_off + 4].copy_from_slice(&31u32.to_le_bytes());
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::PreHashMismatch)
    ));

    // ctx settle_len != 32 triggers CtxUnsupported
    let mut buf = sample_presig_bytes();
    // Skip to after pre_hash payloads: 3x u32 + m + ring + pre_hash
    let m_len = u32::from_le_bytes(buf[10..14].try_into().unwrap()) as usize;
    let ring_len = u32::from_le_bytes(buf[14..18].try_into().unwrap()) as usize;
    let pre_len = u32::from_le_bytes(buf[18..22].try_into().unwrap()) as usize;
    let mut cursor = 22 + m_len + ring_len + pre_len;
    // chain_tag_len is 1 byte at cursor, then chain_tag bytes, then board_len, then board bytes, then settle_len
    let chain_len = buf[cursor] as usize;
    cursor += 1 + chain_len;
    let board_len = buf[cursor] as usize;
    cursor += 1 + board_len;
    // Now at settle_len position
    buf[cursor] = 31; // set to 31 instead of 32
    assert!(matches!(
        ClsagPreSig::decode(&buf),
        Err(EswpError::CtxUnsupported)
    ));
}

#[test]
fn final_decode_rejects_wrong_magic_version_backend_and_pre_len() {
    let mut buf = sample_final_bytes();
    // wrong magic
    buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    assert!(matches!(
        ClsagFinalSigContainer::decode(&buf),
        Err(EswpError::MagicMismatch)
    ));

    // version bad
    let mut buf = sample_final_bytes();
    buf[4..6].copy_from_slice(&(WIRE_VERSION + 1).to_le_bytes());
    assert!(matches!(
        ClsagFinalSigContainer::decode(&buf),
        Err(EswpError::VersionUnsupported)
    ));

    // backend mismatch
    let mut buf = sample_final_bytes();
    buf[6] = BACKEND_ID_CLSAG.wrapping_add(1);
    assert!(matches!(
        ClsagFinalSigContainer::decode(&buf),
        Err(EswpError::BackendMismatch)
    ));

    // pre_hash_len != 32
    let mut buf = sample_final_bytes();
    // layout: magic(4) ver(2) backend(1) resp(1) sig_len(4) sig(sig_len) pre_len(4)
    let sig_len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    let pre_len_off = 12 + sig_len;
    buf[pre_len_off..pre_len_off + 4].copy_from_slice(&31u32.to_le_bytes());
    assert!(matches!(
        ClsagFinalSigContainer::decode(&buf),
        Err(EswpError::PreHashMismatch)
    ));
}
