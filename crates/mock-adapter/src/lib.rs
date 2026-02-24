//! In-memory host adapter implementation for deterministic testing.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use equalx_error::{AdapterError, ErrorCode};
use host_adapter::{
    self, EvmCall, EvmExecutionAdapter, KeyIdentityAdapter, LogEntry, LogFilter,
    MoneroExecutionAdapter, NodeHealth, PersistenceAdapter, SpendState, SwapLifecycleEvent,
    TimeNetworkAdapter, TxReceipt, UxEventAdapter,
};

pub type ReservationId = [u8; 32];

type MethodKey = (String, String);

#[derive(Clone, Default)]
pub struct MockAdapter {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    now: u64,
    checkpoints: HashMap<ReservationId, Vec<u8>>,
    events: Vec<SwapLifecycleEvent>,
    injected_errors: HashMap<MethodKey, VecDeque<AdapterError>>,
    evm_send_calls: u64,
    monero_broadcast_calls: u64,
}

impl MockAdapter {
    /// Inject a one-shot error for a specific trait method.
    pub fn inject_error(&self, trait_name: &str, method_name: &str, error: AdapterError) {
        let key = (trait_name.to_string(), method_name.to_string());
        let mut inner = self.inner.lock().expect("mock adapter mutex poisoned");
        inner
            .injected_errors
            .entry(key)
            .or_default()
            .push_back(error);
    }

    /// Set the mock clock used by `current_timestamp`.
    pub fn set_clock(&self, timestamp: u64) {
        self.inner.lock().expect("mock adapter mutex poisoned").now = timestamp;
    }

    pub fn clock(&self) -> u64 {
        self.inner.lock().expect("mock adapter mutex poisoned").now
    }

    pub fn checkpoint_count(&self) -> usize {
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .checkpoints
            .len()
    }

    pub fn checkpoint(&self, reservation_id: &ReservationId) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .checkpoints
            .get(reservation_id)
            .cloned()
    }

    pub fn events(&self) -> Vec<SwapLifecycleEvent> {
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .events
            .clone()
    }

    pub fn evm_send_calls(&self) -> u64 {
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .evm_send_calls
    }

    pub fn monero_broadcast_calls(&self) -> u64 {
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .monero_broadcast_calls
    }

    fn maybe_fail(&self, trait_name: &str, method_name: &str) -> host_adapter::Result<()> {
        let key = (trait_name.to_string(), method_name.to_string());
        let mut inner = self.inner.lock().expect("mock adapter mutex poisoned");
        if let Some(queue) = inner.injected_errors.get_mut(&key) {
            if let Some(err) = queue.pop_front() {
                return Err(err);
            }
        }
        Ok(())
    }

    fn make_hash(marker: u8, counter: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = marker;
        out[1..9].copy_from_slice(&counter.to_le_bytes());
        out
    }
}

impl KeyIdentityAdapter for MockAdapter {
    fn evm_address(&self) -> host_adapter::Result<[u8; 20]> {
        self.maybe_fail("KeyIdentityAdapter", "evm_address")?;
        Ok([0x11; 20])
    }

    fn sign_evm_message(&self, digest: [u8; 32]) -> host_adapter::Result<Vec<u8>> {
        self.maybe_fail("KeyIdentityAdapter", "sign_evm_message")?;
        Ok(digest.to_vec())
    }

    fn monero_spend_public_key(&self) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail("KeyIdentityAdapter", "monero_spend_public_key")?;
        Ok([0x22; 32])
    }

    fn monero_view_public_key(&self) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail("KeyIdentityAdapter", "monero_view_public_key")?;
        Ok([0x33; 32])
    }

    fn monero_derive_subaddress(&self, major: u32, minor: u32) -> host_adapter::Result<Vec<u8>> {
        self.maybe_fail("KeyIdentityAdapter", "monero_derive_subaddress")?;
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&major.to_le_bytes());
        out.extend_from_slice(&minor.to_le_bytes());
        Ok(out)
    }

    fn monero_compute_key_image(
        &self,
        output_pubkey: &[u8; 32],
        output_index: u64,
    ) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail("KeyIdentityAdapter", "monero_compute_key_image")?;
        let mut out = *output_pubkey;
        out[0] ^= output_index as u8;
        Ok(out)
    }
}

impl EvmExecutionAdapter for MockAdapter {
    fn send_raw_tx(&self, signed_tx: &[u8]) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail("EvmExecutionAdapter", "send_raw_tx")?;
        if signed_tx.is_empty() {
            return Err(AdapterError::new(
                ErrorCode::AdapterCallFailed,
                "empty signed transaction",
            ));
        }
        let mut inner = self.inner.lock().expect("mock adapter mutex poisoned");
        inner.evm_send_calls += 1;
        Ok(Self::make_hash(0xE1, inner.evm_send_calls))
    }

    fn estimate_gas(&self, call: &EvmCall) -> host_adapter::Result<u64> {
        self.maybe_fail("EvmExecutionAdapter", "estimate_gas")?;
        Ok(21_000 + call.data.len() as u64)
    }

    fn replace_tx(&self, original_hash: [u8; 32], new_gas: u64) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail("EvmExecutionAdapter", "replace_tx")?;
        let mut out = original_hash;
        out[..8].copy_from_slice(&new_gas.to_le_bytes());
        out[31] ^= 0x44;
        Ok(out)
    }

    fn get_receipt(&self, tx_hash: [u8; 32]) -> host_adapter::Result<Option<TxReceipt>> {
        self.maybe_fail("EvmExecutionAdapter", "get_receipt")?;
        let block_number = self.clock() / 12 + 1;
        let mut block_hash = [0u8; 32];
        block_hash[..8].copy_from_slice(&block_number.to_le_bytes());
        Ok(Some(TxReceipt {
            tx_hash,
            block_number,
            block_hash,
            success: true,
            gas_used: 21_000,
        }))
    }

    fn get_logs(&self, _filter: &LogFilter) -> host_adapter::Result<Vec<LogEntry>> {
        self.maybe_fail("EvmExecutionAdapter", "get_logs")?;
        Ok(Vec::new())
    }

    fn chain_id(&self) -> host_adapter::Result<u64> {
        self.maybe_fail("EvmExecutionAdapter", "chain_id")?;
        Ok(1)
    }

    fn block_number(&self) -> host_adapter::Result<u64> {
        self.maybe_fail("EvmExecutionAdapter", "block_number")?;
        Ok(self.clock() / 12 + 1)
    }

    fn gas_price(&self) -> host_adapter::Result<u128> {
        self.maybe_fail("EvmExecutionAdapter", "gas_price")?;
        Ok(1_000_000_000)
    }
}

impl MoneroExecutionAdapter for MockAdapter {
    fn broadcast_tx(&self, tx_blob: &[u8]) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail("MoneroExecutionAdapter", "broadcast_tx")?;
        if tx_blob.is_empty() {
            return Err(AdapterError::new(
                ErrorCode::AdapterCallFailed,
                "empty Monero transaction",
            ));
        }
        let mut inner = self.inner.lock().expect("mock adapter mutex poisoned");
        inner.monero_broadcast_calls += 1;
        Ok(Self::make_hash(0xAA, inner.monero_broadcast_calls))
    }

    fn is_key_image_spent(&self, key_images: &[[u8; 32]]) -> host_adapter::Result<Vec<SpendState>> {
        self.maybe_fail("MoneroExecutionAdapter", "is_key_image_spent")?;
        Ok(vec![SpendState::Unspent; key_images.len()])
    }

    fn get_tx_confirmations(&self, _tx_hash: &[u8; 32]) -> host_adapter::Result<Option<u64>> {
        self.maybe_fail("MoneroExecutionAdapter", "get_tx_confirmations")?;
        Ok(Some(1))
    }

    fn node_health(&self) -> host_adapter::Result<NodeHealth> {
        self.maybe_fail("MoneroExecutionAdapter", "node_health")?;
        Ok(NodeHealth::Healthy {
            height: self.clock() / 120 + 1,
        })
    }
}

impl PersistenceAdapter for MockAdapter {
    fn save_checkpoint(&self, reservation_id: &[u8; 32], state: &[u8]) -> host_adapter::Result<()> {
        self.maybe_fail("PersistenceAdapter", "save_checkpoint")?;
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .checkpoints
            .insert(*reservation_id, state.to_vec());
        Ok(())
    }

    fn load_checkpoint(&self, reservation_id: &[u8; 32]) -> host_adapter::Result<Option<Vec<u8>>> {
        self.maybe_fail("PersistenceAdapter", "load_checkpoint")?;
        Ok(self
            .inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .checkpoints
            .get(reservation_id)
            .cloned())
    }

    fn list_active_swaps(&self) -> host_adapter::Result<Vec<[u8; 32]>> {
        self.maybe_fail("PersistenceAdapter", "list_active_swaps")?;
        let mut keys: Vec<_> = self
            .inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .checkpoints
            .keys()
            .copied()
            .collect();
        keys.sort_unstable();
        Ok(keys)
    }

    fn delete_swap(&self, reservation_id: &[u8; 32]) -> host_adapter::Result<()> {
        self.maybe_fail("PersistenceAdapter", "delete_swap")?;
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .checkpoints
            .remove(reservation_id);
        Ok(())
    }
}

impl TimeNetworkAdapter for MockAdapter {
    fn current_block_number(&self) -> host_adapter::Result<u64> {
        self.maybe_fail("TimeNetworkAdapter", "current_block_number")?;
        Ok(self.clock() / 12 + 1)
    }

    fn current_timestamp(&self) -> host_adapter::Result<u64> {
        self.maybe_fail("TimeNetworkAdapter", "current_timestamp")?;
        Ok(self.clock())
    }

    fn is_evm_reachable(&self) -> host_adapter::Result<bool> {
        self.maybe_fail("TimeNetworkAdapter", "is_evm_reachable")?;
        Ok(true)
    }

    fn is_monero_reachable(&self) -> host_adapter::Result<bool> {
        self.maybe_fail("TimeNetworkAdapter", "is_monero_reachable")?;
        Ok(true)
    }
}

impl UxEventAdapter for MockAdapter {
    fn on_event(&self, event: SwapLifecycleEvent) {
        self.inner
            .lock()
            .expect("mock adapter mutex poisoned")
            .events
            .push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_clock_updates_timestamp() {
        let adapter = MockAdapter::default();
        adapter.set_clock(42);
        assert_eq!(adapter.current_timestamp().expect("timestamp"), 42);
    }

    #[test]
    fn injected_error_is_consumed_once() {
        let adapter = MockAdapter::default();
        adapter.inject_error(
            "EvmExecutionAdapter",
            "send_raw_tx",
            AdapterError::new(ErrorCode::AdapterTimeout, "timeout"),
        );

        let first = adapter.send_raw_tx(b"tx");
        assert!(matches!(
            first,
            Err(AdapterError {
                code: ErrorCode::AdapterTimeout,
                ..
            })
        ));

        let second = adapter.send_raw_tx(b"tx").expect("second call succeeds");
        assert_eq!(second[0], 0xE1);
    }

    #[test]
    fn persistence_round_trip_works() {
        let adapter = MockAdapter::default();
        let mut reservation = [0u8; 32];
        reservation[0] = 9;
        let payload = vec![1, 2, 3, 4];
        adapter
            .save_checkpoint(&reservation, &payload)
            .expect("save checkpoint");

        let loaded = adapter
            .load_checkpoint(&reservation)
            .expect("load checkpoint")
            .expect("checkpoint present");
        assert_eq!(loaded, payload);
        assert_eq!(adapter.checkpoint_count(), 1);
    }
}
