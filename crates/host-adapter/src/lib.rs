//! Host adapter contracts for partner integrations.

use equalx_error::AdapterError;

/// Result alias used by host adapter traits.
pub type Result<T> = core::result::Result<T, AdapterError>;

/// EVM call payload and execution parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmCall {
    pub to: [u8; 20],
    pub data: Vec<u8>,
    pub value_wei: u128,
    pub gas_limit: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub nonce: Option<u64>,
}

/// EVM transaction receipt data required by orchestrator logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceipt {
    pub tx_hash: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub success: bool,
    pub gas_used: u64,
}

/// Log query filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFilter {
    pub addresses: Vec<[u8; 20]>,
    pub topics: Vec<[u8; 32]>,
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
}

/// EVM log entry used by decoder and watcher workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub tx_hash: [u8; 32],
    pub log_index: u64,
}

/// Monero key-image spend state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendState {
    Unspent,
    InPool,
    Spent,
}

/// Monero node health response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeHealth {
    Healthy { height: u64 },
    Degraded { reason: String },
    Unreachable { reason: String },
}

/// Blockchain identifier for lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Evm,
    Monero,
}

/// Host-action prompts emitted by orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAction {
    ApproveReservation,
    ConfirmMoneroBroadcast,
    ReviewRefund,
}

/// Terminal swap outcome classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapOutcome {
    Settled,
    Refunded,
    Failed {
        error_code: i32,
        reason: String,
        recoverable: bool,
    },
}

/// Structured lifecycle events consumed by host UX and telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapLifecycleEvent {
    StateTransition {
        from: String,
        to: String,
        reservation_id: [u8; 32],
    },
    DeadlineWarning {
        reservation_id: [u8; 32],
        deadline: u64,
        remaining_secs: u64,
    },
    DeadlineExceeded {
        reservation_id: [u8; 32],
        deadline: u64,
    },
    ErrorOccurred {
        reservation_id: [u8; 32],
        error_code: i32,
        message: String,
    },
    UserActionRequired {
        reservation_id: [u8; 32],
        action: UserAction,
    },
    TxSubmitted {
        reservation_id: [u8; 32],
        chain: Chain,
        tx_hash: [u8; 32],
    },
    TxConfirmed {
        reservation_id: [u8; 32],
        chain: Chain,
        tx_hash: [u8; 32],
        confirmations: u64,
    },
    SwapCompleted {
        reservation_id: [u8; 32],
        outcome: SwapOutcome,
    },
}

/// L4 key and identity operations.
///
/// Secret key material remains host-owned. This trait supports host-managed
/// signing and key-image operations without exporting secret keys over ABI.
pub trait KeyIdentityAdapter {
    fn evm_address(&self) -> Result<[u8; 20]>;
    fn sign_evm_message(&self, digest: [u8; 32]) -> Result<Vec<u8>>;
    fn monero_spend_public_key(&self) -> Result<[u8; 32]>;
    fn monero_view_public_key(&self) -> Result<[u8; 32]>;
    fn monero_derive_subaddress(&self, major: u32, minor: u32) -> Result<Vec<u8>>;
    fn monero_compute_key_image(
        &self,
        output_pubkey: &[u8; 32],
        output_index: u64,
    ) -> Result<[u8; 32]>;
}

/// L4 EVM execution operations.
pub trait EvmExecutionAdapter {
    fn send_raw_tx(&self, signed_tx: &[u8]) -> Result<[u8; 32]>;
    fn estimate_gas(&self, call: &EvmCall) -> Result<u64>;
    fn replace_tx(&self, original_hash: [u8; 32], new_gas: u64) -> Result<[u8; 32]>;
    fn get_receipt(&self, tx_hash: [u8; 32]) -> Result<Option<TxReceipt>>;
    fn get_logs(&self, filter: &LogFilter) -> Result<Vec<LogEntry>>;
    fn chain_id(&self) -> Result<u64>;
    fn block_number(&self) -> Result<u64>;
    fn gas_price(&self) -> Result<u128>;
}

/// L4 Monero execution operations.
pub trait MoneroExecutionAdapter {
    fn broadcast_tx(&self, tx_blob: &[u8]) -> Result<[u8; 32]>;
    fn is_key_image_spent(&self, key_images: &[[u8; 32]]) -> Result<Vec<SpendState>>;
    fn get_tx_confirmations(&self, tx_hash: &[u8; 32]) -> Result<Option<u64>>;
    fn node_health(&self) -> Result<NodeHealth>;
}

/// L4 persistence operations for checkpoints.
pub trait PersistenceAdapter {
    fn save_checkpoint(&self, reservation_id: &[u8; 32], state: &[u8]) -> Result<()>;
    fn load_checkpoint(&self, reservation_id: &[u8; 32]) -> Result<Option<Vec<u8>>>;
    fn list_active_swaps(&self) -> Result<Vec<[u8; 32]>>;
    fn delete_swap(&self, reservation_id: &[u8; 32]) -> Result<()>;
}

/// L4 time and network liveness operations.
pub trait TimeNetworkAdapter {
    fn current_block_number(&self) -> Result<u64>;
    fn current_timestamp(&self) -> Result<u64>;
    fn is_evm_reachable(&self) -> Result<bool>;
    fn is_monero_reachable(&self) -> Result<bool>;
}

/// L4 UX event callback sink.
pub trait UxEventAdapter {
    fn on_event(&self, event: SwapLifecycleEvent);
}

/// Host adapter super-trait used by orchestrator and conformance suites.
pub trait HostAdapters:
    KeyIdentityAdapter
    + EvmExecutionAdapter
    + MoneroExecutionAdapter
    + PersistenceAdapter
    + TimeNetworkAdapter
    + UxEventAdapter
{
}

impl<T> HostAdapters for T where
    T: KeyIdentityAdapter
        + EvmExecutionAdapter
        + MoneroExecutionAdapter
        + PersistenceAdapter
        + TimeNetworkAdapter
        + UxEventAdapter
{
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use equalx_error::{AdapterError, ErrorCode};

    use super::{
        EvmCall, EvmExecutionAdapter, HostAdapters, KeyIdentityAdapter, LogEntry, LogFilter,
        MoneroExecutionAdapter, NodeHealth, PersistenceAdapter, SpendState, SwapLifecycleEvent,
        TimeNetworkAdapter, TxReceipt, UxEventAdapter,
    };

    #[derive(Default)]
    struct MockAdapter {
        opaque_key_handle: u64,
        events: RefCell<Vec<SwapLifecycleEvent>>,
    }

    impl KeyIdentityAdapter for MockAdapter {
        fn evm_address(&self) -> super::Result<[u8; 20]> {
            Ok([0x11; 20])
        }

        fn sign_evm_message(&self, digest: [u8; 32]) -> super::Result<Vec<u8>> {
            Ok(digest.to_vec())
        }

        fn monero_spend_public_key(&self) -> super::Result<[u8; 32]> {
            Ok([0x22; 32])
        }

        fn monero_view_public_key(&self) -> super::Result<[u8; 32]> {
            Ok([0x33; 32])
        }

        fn monero_derive_subaddress(&self, major: u32, minor: u32) -> super::Result<Vec<u8>> {
            Ok(vec![(major & 0xFF) as u8, (minor & 0xFF) as u8])
        }

        fn monero_compute_key_image(
            &self,
            output_pubkey: &[u8; 32],
            output_index: u64,
        ) -> super::Result<[u8; 32]> {
            let mut image = *output_pubkey;
            image[0] ^= self.opaque_key_handle as u8;
            image[1] ^= output_index as u8;
            Ok(image)
        }
    }

    impl EvmExecutionAdapter for MockAdapter {
        fn send_raw_tx(&self, signed_tx: &[u8]) -> super::Result<[u8; 32]> {
            if signed_tx.is_empty() {
                return Err(AdapterError::new(
                    ErrorCode::AdapterCallFailed,
                    "empty signed transaction",
                ));
            }
            Ok([0x44; 32])
        }

        fn estimate_gas(&self, _call: &EvmCall) -> super::Result<u64> {
            Ok(21000)
        }

        fn replace_tx(&self, _original_hash: [u8; 32], _new_gas: u64) -> super::Result<[u8; 32]> {
            Ok([0x45; 32])
        }

        fn get_receipt(&self, tx_hash: [u8; 32]) -> super::Result<Option<TxReceipt>> {
            Ok(Some(TxReceipt {
                tx_hash,
                block_number: 1,
                block_hash: [0x46; 32],
                success: true,
                gas_used: 21000,
            }))
        }

        fn get_logs(&self, _filter: &LogFilter) -> super::Result<Vec<LogEntry>> {
            Ok(Vec::new())
        }

        fn chain_id(&self) -> super::Result<u64> {
            Ok(1)
        }

        fn block_number(&self) -> super::Result<u64> {
            Ok(100)
        }

        fn gas_price(&self) -> super::Result<u128> {
            Ok(1_000_000_000)
        }
    }

    impl MoneroExecutionAdapter for MockAdapter {
        fn broadcast_tx(&self, _tx_blob: &[u8]) -> super::Result<[u8; 32]> {
            Ok([0x55; 32])
        }

        fn is_key_image_spent(&self, key_images: &[[u8; 32]]) -> super::Result<Vec<SpendState>> {
            Ok(vec![SpendState::Unspent; key_images.len()])
        }

        fn get_tx_confirmations(&self, _tx_hash: &[u8; 32]) -> super::Result<Option<u64>> {
            Ok(Some(10))
        }

        fn node_health(&self) -> super::Result<NodeHealth> {
            Ok(NodeHealth::Healthy { height: 3_000_000 })
        }
    }

    impl PersistenceAdapter for MockAdapter {
        fn save_checkpoint(&self, _reservation_id: &[u8; 32], _state: &[u8]) -> super::Result<()> {
            Ok(())
        }

        fn load_checkpoint(&self, _reservation_id: &[u8; 32]) -> super::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn list_active_swaps(&self) -> super::Result<Vec<[u8; 32]>> {
            Ok(Vec::new())
        }

        fn delete_swap(&self, _reservation_id: &[u8; 32]) -> super::Result<()> {
            Ok(())
        }
    }

    impl TimeNetworkAdapter for MockAdapter {
        fn current_block_number(&self) -> super::Result<u64> {
            Ok(100)
        }

        fn current_timestamp(&self) -> super::Result<u64> {
            Ok(1_700_000_000)
        }

        fn is_evm_reachable(&self) -> super::Result<bool> {
            Ok(true)
        }

        fn is_monero_reachable(&self) -> super::Result<bool> {
            Ok(true)
        }
    }

    impl UxEventAdapter for MockAdapter {
        fn on_event(&self, event: SwapLifecycleEvent) {
            self.events.borrow_mut().push(event);
        }
    }

    fn assert_host_adapters_impl<T: HostAdapters>(_adapter: &T) {}

    #[test]
    fn host_adapters_super_trait_is_satisfied() {
        let adapter = MockAdapter {
            opaque_key_handle: 7,
            ..MockAdapter::default()
        };
        assert_host_adapters_impl(&adapter);
    }

    #[test]
    fn key_identity_adapter_supports_opaque_host_key_handling() {
        let adapter = MockAdapter {
            opaque_key_handle: 42,
            ..MockAdapter::default()
        };
        let pubkey = [0xAA; 32];
        let image = adapter
            .monero_compute_key_image(&pubkey, 9)
            .expect("compute key image");
        assert_ne!(image, pubkey);
    }

    #[test]
    fn ux_event_callback_accepts_structured_events() {
        let adapter = MockAdapter::default();
        let event = SwapLifecycleEvent::DeadlineExceeded {
            reservation_id: [0xCC; 32],
            deadline: 123,
        };
        adapter.on_event(event);
        assert_eq!(adapter.events.borrow().len(), 1);
    }
}
