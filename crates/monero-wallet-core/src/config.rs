use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct SubAddr {
    pub account: u32,
    pub index: u32,
    /// Optional label for UX; not used in core logic.
    pub label: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Primary private view key (hex or 32B).
    pub view_key: [u8; 32],
    /// Primary public spend key (compressed Edwards Y coordinate).
    pub spend_pub: [u8; 32],
    /// Optional private spend key for key image derivation; may be None for view-only scan.
    pub spend_key: Option<[u8; 32]>,
    /// Tracked subaddresses (account,index). If empty, treat as (0,0) only.
    pub subaddrs: Vec<SubAddr>,
    /// Target network tag: \"mainnet\" | \"stagenet\" | \"testnet\"
    pub network: String,
}
