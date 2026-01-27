use crate::{ClsagCtx, SettlementCtx};
use sha3::{Digest, Sha3_256};

pub fn ring_hash(ctx: &ClsagCtx) -> [u8; 32] {
    let ring_bytes_concat: Vec<u8> = ctx.ring_keys.iter().flat_map(|b| b.to_vec()).collect();
    Sha3_256::digest(&ring_bytes_concat).into()
}

pub fn message_hash(m: &[u8]) -> [u8; 32] {
    Sha3_256::digest(m).into()
}

pub fn settlement_hash(sctx: &SettlementCtx) -> [u8; 32] {
    let mut s = Vec::new();
    s.extend_from_slice(sctx.chain_tag.as_bytes());
    s.push(0);
    s.extend_from_slice(&(sctx.position_key.len() as u8).to_le_bytes());
    s.extend_from_slice(&sctx.position_key);
    s.extend_from_slice(&sctx.settle_digest);
    Sha3_256::digest(&s).into()
}

pub fn pre_hash(
    ctx: &ClsagCtx,
    m: &[u8],
    j: usize,
    swap_id: &[u8; 32],
    sctx: &SettlementCtx,
) -> [u8; 32] {
    let ring_hash = ring_hash(ctx);
    let message_hash = message_hash(m);
    let ctx_hash = settlement_hash(sctx);

    let j_bytes = (j as u32).to_le_bytes();
    let preimage = [
        ring_hash.as_ref(),
        message_hash.as_ref(),
        j_bytes.as_slice(),
        &swap_id[..],
        ctx_hash.as_ref(),
    ]
    .concat();

    Sha3_256::digest(preimage).into()
}
