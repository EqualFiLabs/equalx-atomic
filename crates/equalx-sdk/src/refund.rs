//! Helpers for preparing deterministic refund transactions for the Monero leg.

use sha3::{Digest, Sha3_256};

use crate::error::{ErrorCode, Result};
use crate::settlement::SettlementCtx;

/// Parameters influencing the refund transaction.
#[derive(Clone, Debug)]
pub struct RefundParams {
    pub swap_id: [u8; 32],
    pub xmr_lock_height: u64,
    pub eth_expiry: u64,
    pub delta: u64,
    pub template: Vec<u8>,
}

/// Output describing the refund transaction bytes and locktime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundData {
    pub tx_bytes: Vec<u8>,
    pub lock_time: u64,
}

/// Prepares a deterministic refund transaction respecting the settlement context.
pub fn prepare_refund(ctx: &SettlementCtx, params: RefundParams) -> Result<RefundData> {
    if params.xmr_lock_height + params.delta >= params.eth_expiry {
        return Err(ErrorCode::PolicyDeadlineOrder);
    }
    let lock_time = params.xmr_lock_height + params.delta;
    let mut hasher = Sha3_256::new();
    let binding = ctx.binding(params.swap_id, "refund");
    hasher.update(binding);
    hasher.update(lock_time.to_be_bytes());
    hasher.update(&params.template);
    let digest = hasher.finalize();

    let mut tx_bytes = params.template;
    tx_bytes.extend_from_slice(&digest);

    Ok(RefundData {
        tx_bytes,
        lock_time,
    })
}
