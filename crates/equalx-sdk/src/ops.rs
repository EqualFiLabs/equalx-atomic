//! Operational helpers for gas policy, RPC fallback, confirmations, and reorg handling.

use std::collections::BTreeSet;

use alloy_primitives::U256;

use crate::error::{ErrorCode, Result};

/// Canonical basis-points denominator.
pub const BPS_DENOMINATOR: u16 = 10_000;

/// EIP-1559 fee parameters used by transaction submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eip1559FeeParams {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// Gas policy for recommending EIP-1559 fees and replacement bumps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasPolicy {
    /// Multiplier applied to base fee when suggesting `max_fee_per_gas` in basis points.
    pub base_fee_multiplier_bps: u16,
    /// Baseline tip suggestion.
    pub priority_fee_per_gas: u128,
    /// Optional cap for suggested priority fee.
    pub max_priority_fee_per_gas: Option<u128>,
    /// Replacement bump percentage used for speed-up transactions.
    pub replacement_bump_percent: u16,
}

impl Default for GasPolicy {
    fn default() -> Self {
        Self {
            base_fee_multiplier_bps: 12_500,
            priority_fee_per_gas: 1_500_000_000,
            max_priority_fee_per_gas: Some(3_000_000_000),
            replacement_bump_percent: 12,
        }
    }
}

impl GasPolicy {
    /// Recommend EIP-1559 fee parameters from a base fee observation.
    pub fn recommend_fee(&self, base_fee_per_gas: u128) -> Eip1559FeeParams {
        let mut tip = self.priority_fee_per_gas;
        if let Some(max_tip) = self.max_priority_fee_per_gas {
            tip = tip.min(max_tip);
        }
        let scaled_base = scale_by_bps(base_fee_per_gas, self.base_fee_multiplier_bps);
        let max_fee = scaled_base.saturating_add(tip).max(base_fee_per_gas);
        Eip1559FeeParams {
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip.min(max_fee),
        }
    }

    /// Compute replacement parameters that satisfy configured bump requirements.
    pub fn replacement_params(
        &self,
        original: Eip1559FeeParams,
        latest_base_fee_per_gas: u128,
    ) -> Eip1559FeeParams {
        let bumped_max_fee =
            apply_percent_bump(original.max_fee_per_gas, self.replacement_bump_percent);
        let bumped_tip = apply_percent_bump(
            original.max_priority_fee_per_gas,
            self.replacement_bump_percent,
        );
        let recommended = self.recommend_fee(latest_base_fee_per_gas);

        let mut max_fee = bumped_max_fee
            .max(recommended.max_fee_per_gas)
            .max(latest_base_fee_per_gas);
        let mut max_priority = bumped_tip.max(recommended.max_priority_fee_per_gas);
        if max_priority > max_fee {
            max_fee = max_priority;
        }
        max_priority = max_priority.min(max_fee);

        Eip1559FeeParams {
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: max_priority,
        }
    }
}

fn scale_by_bps(value: u128, bps: u16) -> u128 {
    value.saturating_mul(bps as u128).saturating_add(9_999) / 10_000
}

fn apply_percent_bump(value: u128, percent: u16) -> u128 {
    let delta = value.saturating_mul(percent as u128).saturating_add(99) / 100;
    value.saturating_add(delta)
}

/// Compute minimum acceptable settlement amount from expected output and slippage policy.
///
/// Uses floor rounding:
/// `min_received = expected_out * (10_000 - slippage_bps) / 10_000`.
pub fn min_received_with_slippage(expected_out: U256, slippage_bps: u16) -> Result<U256> {
    if slippage_bps > BPS_DENOMINATOR {
        return Err(ErrorCode::PolicySlippageBps);
    }
    let keep_bps = U256::from((BPS_DENOMINATOR - slippage_bps) as u64);
    let denominator = U256::from(BPS_DENOMINATOR as u64);
    Ok(expected_out.saturating_mul(keep_bps) / denominator)
}

/// Confirmation policy for finalizing EVM transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmationPolicy {
    pub min_confirmations: u64,
}

impl Default for ConfirmationPolicy {
    fn default() -> Self {
        Self {
            min_confirmations: 1,
        }
    }
}

impl ConfirmationPolicy {
    /// Return observed confirmations given inclusion and current head.
    pub fn confirmations(&self, inclusion_block: u64, current_block: u64) -> u64 {
        if current_block < inclusion_block {
            return 0;
        }
        current_block
            .saturating_sub(inclusion_block)
            .saturating_add(1)
    }

    /// Whether transaction is final under the policy.
    pub fn is_finalized(&self, inclusion_block: u64, current_block: u64) -> bool {
        self.confirmations(inclusion_block, current_block) >= self.min_confirmations
    }
}

/// RPC fallback configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcFallbackConfig {
    pub endpoints: Vec<String>,
    pub max_attempts: Option<usize>,
}

impl RpcFallbackConfig {
    pub fn new(primary: impl Into<String>, fallbacks: impl IntoIterator<Item = String>) -> Self {
        let mut endpoints = vec![primary.into()];
        endpoints.extend(fallbacks);
        Self {
            endpoints,
            max_attempts: None,
        }
    }

    pub fn from_endpoints(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            max_attempts: None,
        }
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = Some(max_attempts);
        self
    }

    fn endpoint_slice(&self) -> &[String] {
        let Some(max_attempts) = self.max_attempts else {
            return &self.endpoints;
        };
        let end = max_attempts.min(self.endpoints.len());
        &self.endpoints[..end]
    }
}

/// Generic RPC endpoint caller used by [`RpcFallbackClient`].
pub trait RpcEndpointClient {
    type Request;
    type Response;

    fn call_endpoint(&self, endpoint: &str, request: &Self::Request) -> Result<Self::Response>;
}

/// Successful fallback execution metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcFallbackOutcome<T> {
    pub value: T,
    pub successful_endpoint: String,
    pub attempted_endpoints: Vec<String>,
}

/// Wrapper that retries configured RPC endpoints in order.
#[derive(Clone, Debug)]
pub struct RpcFallbackClient<C> {
    config: RpcFallbackConfig,
    client: C,
}

impl<C> RpcFallbackClient<C> {
    pub fn new(config: RpcFallbackConfig, client: C) -> Self {
        Self { config, client }
    }
}

impl<C> RpcFallbackClient<C>
where
    C: RpcEndpointClient,
{
    pub fn call(&self, request: &C::Request) -> Result<C::Response> {
        self.call_with_trace(request).map(|outcome| outcome.value)
    }

    pub fn call_with_trace(&self, request: &C::Request) -> Result<RpcFallbackOutcome<C::Response>> {
        let endpoints = self.config.endpoint_slice();
        if endpoints.is_empty() {
            return Err(ErrorCode::BridgeTransportEvm);
        }

        let mut attempted = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            attempted.push(endpoint.clone());
            if let Ok(value) = self.client.call_endpoint(endpoint, request) {
                return Ok(RpcFallbackOutcome {
                    value,
                    successful_endpoint: endpoint.clone(),
                    attempted_endpoints: attempted,
                });
            }
        }

        Err(ErrorCode::BridgeTransportEvm)
    }
}

/// Transaction receipt snapshot used for reorg tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptSnapshot {
    pub tx_hash: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
}

/// Reorg reason classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReorgReasonKind {
    ReceiptDisappeared,
    BlockHashChanged,
}

/// Detailed reorg reason information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReorgReason {
    ReceiptDisappeared,
    BlockHashChanged {
        expected_block_hash: [u8; 32],
        observed_block_hash: [u8; 32],
    },
}

impl ReorgReason {
    pub fn kind(self) -> ReorgReasonKind {
        match self {
            ReorgReason::ReceiptDisappeared => ReorgReasonKind::ReceiptDisappeared,
            ReorgReason::BlockHashChanged { .. } => ReorgReasonKind::BlockHashChanged,
        }
    }
}

/// Reorg-aware transaction reconciliation state.
#[derive(Clone, Debug)]
pub struct ReconciliationState {
    pub tracked_tx: ReceiptSnapshot,
    pub allow_resubmit: bool,
    handled_reorgs: BTreeSet<ReorgReasonKind>,
}

impl ReconciliationState {
    pub fn new(tracked_tx: ReceiptSnapshot) -> Self {
        Self {
            tracked_tx,
            allow_resubmit: true,
            handled_reorgs: BTreeSet::new(),
        }
    }

    pub fn handled_reorgs(&self) -> &BTreeSet<ReorgReasonKind> {
        &self.handled_reorgs
    }
}

/// Callback interface required by reorg reconciliation.
pub trait ReorgRpc {
    fn get_receipt(&self, tx_hash: [u8; 32]) -> Result<Option<ReceiptSnapshot>>;
    fn resubmit(&self, tx_hash: [u8; 32]) -> Result<[u8; 32]>;
}

/// Reconciliation outcome for one reorg evaluation cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    Stable,
    AlreadyHandled {
        reason: ReorgReason,
    },
    Resubmitted {
        reason: ReorgReason,
        old_tx_hash: [u8; 32],
        new_tx_hash: [u8; 32],
    },
    NeedsCompensatingPath {
        reason: ReorgReason,
    },
}

/// Detect whether observed receipt implies an EVM reorg.
pub fn detect_reorg(
    expected: &ReceiptSnapshot,
    observed: Option<&ReceiptSnapshot>,
) -> Option<ReorgReason> {
    let observed = observed?;
    if observed.block_hash != expected.block_hash {
        return Some(ReorgReason::BlockHashChanged {
            expected_block_hash: expected.block_hash,
            observed_block_hash: observed.block_hash,
        });
    }
    if observed.block_number != expected.block_number {
        return Some(ReorgReason::BlockHashChanged {
            expected_block_hash: expected.block_hash,
            observed_block_hash: observed.block_hash,
        });
    }
    None
}

/// Reconcile tracked EVM transaction against live receipts and handle reorg paths.
pub fn reconcile_reorg<R: ReorgRpc>(
    state: &mut ReconciliationState,
    rpc: &R,
) -> Result<ReconciliationOutcome> {
    let observed = rpc.get_receipt(state.tracked_tx.tx_hash)?;
    let reason = match observed {
        None => Some(ReorgReason::ReceiptDisappeared),
        Some(ref receipt) => detect_reorg(&state.tracked_tx, Some(receipt)),
    };

    let Some(reason) = reason else {
        return Ok(ReconciliationOutcome::Stable);
    };

    if !state.handled_reorgs.insert(reason.kind()) {
        return Ok(ReconciliationOutcome::AlreadyHandled { reason });
    }

    if !state.allow_resubmit {
        return Ok(ReconciliationOutcome::NeedsCompensatingPath { reason });
    }

    let old_tx_hash = state.tracked_tx.tx_hash;
    let new_tx_hash = rpc.resubmit(old_tx_hash)?;
    state.tracked_tx.tx_hash = new_tx_hash;
    state.tracked_tx.block_number = 0;
    state.tracked_tx.block_hash = [0u8; 32];
    Ok(ReconciliationOutcome::Resubmitted {
        reason,
        old_tx_hash,
        new_tx_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    #[test]
    fn confirmation_policy_counts_blocks() {
        let policy = ConfirmationPolicy {
            min_confirmations: 3,
        };
        assert_eq!(policy.confirmations(100, 100), 1);
        assert_eq!(policy.confirmations(100, 101), 2);
        assert!(policy.is_finalized(100, 102));
        assert!(!policy.is_finalized(100, 101));
    }

    #[test]
    fn detect_reorg_marks_disappeared_receipts() {
        let expected = ReceiptSnapshot {
            tx_hash: [0x11; 32],
            block_number: 55,
            block_hash: [0x22; 32],
        };
        assert!(detect_reorg(&expected, None).is_none());
        let observed = ReceiptSnapshot {
            tx_hash: [0x11; 32],
            block_number: 55,
            block_hash: [0x33; 32],
        };
        assert!(matches!(
            detect_reorg(&expected, Some(&observed)),
            Some(ReorgReason::BlockHashChanged { .. })
        ));
    }

    #[test]
    fn min_received_helper_computes_floor_and_bounds() {
        let expected = U256::from(1_000u64);
        assert_eq!(
            min_received_with_slippage(expected, 0).expect("no slippage"),
            U256::from(1_000u64)
        );
        assert_eq!(
            min_received_with_slippage(expected, 100).expect("1% slippage"),
            U256::from(990u64)
        );
        assert_eq!(
            min_received_with_slippage(expected, BPS_DENOMINATOR).expect("100% slippage"),
            U256::ZERO
        );
    }

    #[test]
    fn min_received_helper_rejects_invalid_slippage_bps() {
        let err = min_received_with_slippage(U256::from(1_000u64), BPS_DENOMINATOR + 1)
            .expect_err("invalid bps");
        assert_eq!(err, ErrorCode::PolicySlippageBps);
    }

    #[derive(Clone)]
    struct MockRpcClient {
        success_endpoint: String,
        attempts: Arc<Mutex<Vec<String>>>,
    }

    impl MockRpcClient {
        fn new(success_endpoint: String) -> Self {
            Self {
                success_endpoint,
                attempts: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl RpcEndpointClient for MockRpcClient {
        type Request = ();
        type Response = String;

        fn call_endpoint(
            &self,
            endpoint: &str,
            _request: &Self::Request,
        ) -> Result<Self::Response> {
            self.attempts.lock().unwrap().push(endpoint.to_string());
            if endpoint == self.success_endpoint {
                return Ok(endpoint.to_string());
            }
            Err(ErrorCode::BridgeTransportEvm)
        }
    }

    #[derive(Clone)]
    struct MockReorgRpc {
        receipts: Arc<Mutex<VecDeque<Option<ReceiptSnapshot>>>>,
        resubmits: Arc<Mutex<Vec<[u8; 32]>>>,
        nonce: Arc<Mutex<u8>>,
    }

    impl MockReorgRpc {
        fn new(receipts: Vec<Option<ReceiptSnapshot>>) -> Self {
            Self {
                receipts: Arc::new(Mutex::new(VecDeque::from(receipts))),
                resubmits: Arc::new(Mutex::new(Vec::new())),
                nonce: Arc::new(Mutex::new(1)),
            }
        }
    }

    impl ReorgRpc for MockReorgRpc {
        fn get_receipt(&self, tx_hash: [u8; 32]) -> Result<Option<ReceiptSnapshot>> {
            let next = self.receipts.lock().unwrap().pop_front().flatten();
            Ok(match next {
                Some(receipt) if receipt.tx_hash == tx_hash => Some(receipt),
                Some(_) => None,
                None => None,
            })
        }

        fn resubmit(&self, tx_hash: [u8; 32]) -> Result<[u8; 32]> {
            self.resubmits.lock().unwrap().push(tx_hash);
            let mut nonce = self.nonce.lock().unwrap();
            let mut next = [0u8; 32];
            next[0] = *nonce;
            *nonce = nonce.wrapping_add(1);
            Ok(next)
        }
    }

    fn base_state() -> ReconciliationState {
        ReconciliationState::new(ReceiptSnapshot {
            tx_hash: [0xAA; 32],
            block_number: 100,
            block_hash: [0xBB; 32],
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100,
            .. ProptestConfig::default()
        })]

        /// Property 25: Gas policy fee computation.
        #[test]
        fn property25_gas_policy_fee_computation(
            base_fee in 0u64..1_000_000_000_000u64,
            priority_fee in 0u64..100_000_000_000u64,
            bump in 1u16..50u16,
            multiplier in 10_000u16..30_000u16,
        ) {
            let policy = GasPolicy {
                base_fee_multiplier_bps: multiplier,
                priority_fee_per_gas: priority_fee as u128,
                max_priority_fee_per_gas: Some((priority_fee as u128).saturating_add(10_000_000)),
                replacement_bump_percent: bump,
            };
            let recommended = policy.recommend_fee(base_fee as u128);
            prop_assert!(recommended.max_fee_per_gas >= base_fee as u128);

            let original = Eip1559FeeParams {
                max_fee_per_gas: recommended.max_fee_per_gas.max(1),
                max_priority_fee_per_gas: recommended.max_priority_fee_per_gas,
            };
            let replacement = policy.replacement_params(original, base_fee as u128);
            let minimum_bumped = apply_percent_bump(original.max_fee_per_gas, bump);

            prop_assert!(replacement.max_fee_per_gas >= base_fee as u128);
            prop_assert!(replacement.max_fee_per_gas >= minimum_bumped);
            prop_assert!(replacement.max_priority_fee_per_gas <= replacement.max_fee_per_gas);
        }

        /// Property 26: RPC fallback.
        #[test]
        fn property26_rpc_fallback(
            endpoint_count in 1usize..10usize,
            fail_first in 0usize..10usize,
        ) {
            let endpoints: Vec<String> = (0..endpoint_count)
                .map(|i| format!("https://rpc-{i}.example"))
                .collect();
            let success_index = fail_first % endpoint_count;
            let success_endpoint = endpoints[success_index].clone();

            let client = MockRpcClient::new(success_endpoint.clone());
            let wrapper = RpcFallbackClient::new(
                RpcFallbackConfig::from_endpoints(endpoints.clone()),
                client.clone(),
            );

            let outcome = wrapper.call_with_trace(&()).expect("must succeed");
            prop_assert_eq!(outcome.successful_endpoint, success_endpoint.clone());
            prop_assert_eq!(outcome.attempted_endpoints, endpoints[..=success_index].to_vec());
            prop_assert_eq!(outcome.value, success_endpoint);
        }

        /// Property 27: Reorg handling and state re-evaluation.
        #[test]
        fn property27_reorg_handling_and_state_re_evaluation(pattern in prop::collection::vec(0u8..3u8, 1..24)) {
            let original = ReceiptSnapshot {
                tx_hash: [0xAA; 32],
                block_number: 100,
                block_hash: [0xBB; 32],
            };
            let changed = ReceiptSnapshot {
                tx_hash: [0xAA; 32],
                block_number: 100,
                block_hash: [0xCC; 32],
            };

            let responses: Vec<Option<ReceiptSnapshot>> = pattern
                .iter()
                .map(|kind| match kind {
                    0 => Some(original),
                    1 => None,
                    _ => Some(changed),
                })
                .collect();

            let rpc = MockReorgRpc::new(responses);
            let mut state = base_state();

            for _ in 0..pattern.len() {
                let _ = reconcile_reorg(&mut state, &rpc).expect("reconcile");
            }

            let handled = state.handled_reorgs().len();
            let side_effects = rpc.resubmits.lock().unwrap().len();
            prop_assert_eq!(side_effects, handled);
            prop_assert!(handled <= 2);
            if pattern.iter().all(|k| *k == 0) {
                prop_assert_eq!(handled, 0);
            }
        }
    }
}
