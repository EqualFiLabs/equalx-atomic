//! monero-wallet-core — lightweight wallet primitives for swap planning.
//!
//! Pieces:
//! - Config: view/spend keys, (sub)addresses to track
//! - Storage trait: persistence boundary (RocksDB/sled/in-memory supplied by caller)
//! - Scanner: walks blocks via monero-rpc, derives owned outputs with monero-oxide
//! - SpendableSet: filtering by confirms/unlock/amount
//! - FeeEstimator: pluggable (daemon RPC-backed or fixed)
//! - SpendPlan: deterministic selection output ready for adaptor signing
//!
//! This crate purposely avoids wallet-rpc; it binds to daemon RPC only.
pub mod config;
pub mod decoys;
pub mod fees;
pub mod model;
pub mod plan;
pub mod scanner;
pub mod spendable;
pub mod storage;
pub use config::{SubAddr, WalletConfig};
pub use decoys::{DecoyPicker, NoopDecoyPicker, RpcDecoyPicker};
pub use fees::{DaemonFeeEstimator, FeeEstimator, FeeHint};
pub use model::{DecoyRef, KeyImageInfo, OwnedOutput, SpendInput, SpendPlan};
pub use scanner::{ScanParams, Scanner, SharedKeyDerivations};
pub use spendable::{SpendFilter, SpendableSet};
pub use storage::{InMemoryStore, ScanCursor, WalletStore};

pub fn plan_simple<S: storage::WalletStore>(
    scanner: &scanner::Scanner<S>,
    tip: u64,
    settle_digest: [u8; 32],
    target_amount: u64,
    as_of_height: u64,
) -> anyhow::Result<model::SpendPlan> {
    let fee_est = fees::DaemonFeeEstimator {
        rpc: scanner.rpc.clone(),
    }
    .estimate()?;
    let owned = scanner.list_owned()?;
    let filtered = spendable::SpendableSet::filter(
        &owned,
        spendable::SpendFilter {
            min_confirmations: 10,
            min_amount: 1,
            as_of_height,
        },
    );
    let inputs_preview = plan::preview_inputs(&filtered, target_amount + tip, fee_est)?;
    let decoys = if inputs_preview.is_empty() || fee_est.ring_size <= 1 {
        Vec::new()
    } else {
        RpcDecoyPicker {
            rpc: scanner.rpc.clone(),
            ring_size: fee_est.ring_size,
        }
        .pick(&inputs_preview)?
    };
    plan::build_spend_plan(
        &filtered,
        target_amount + tip,
        fee_est,
        settle_digest,
        decoys,
    )
}
