use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyImageInfo {
    pub key_image: [u8; 32],
    pub txid: [u8; 32],
    pub global_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedOutput {
    pub txid: [u8; 32],
    pub out_index_in_tx: u32,
    pub amount: u64,
    pub global_index: u64,
    pub mask: [u8; 32],
    pub one_time_pubkey: [u8; 32],
    pub subaddr_account: u32,
    pub subaddr_index: u32,
    pub unlock_time: u64,
    pub block_height: u64,
    /// Optional KI if spend key known.
    pub key_image: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendInput {
    pub txid: [u8; 32],
    pub global_index: u64,
    pub ring_member_count: u32,
    pub key_image: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyRef {
    pub global_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendPlan {
    pub inputs: Vec<SpendInput>,
    pub decoys: Vec<DecoyRef>, // by global index
    pub fee_estimate: u64,
    pub change: Option<u64>,
    /// Settlement digest (32 bytes) that MUST byte-equal the
    /// `SettlementCtx::settle_digest` used by adaptor pre-signing/finalization.
    /// The adaptor container binds to this canonical digest; mismatches are invalid.
    pub settle_digest: [u8; 32],
    /// Pre-adaptor metadata: admissible index or SA+L response-slot info are selected later by adaptor.
    pub resp_index_hint: Option<u32>,
}
