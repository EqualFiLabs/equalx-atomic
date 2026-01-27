//! Automation helpers that bridge Monero watcher events with EVM settlement flows.

use std::collections::HashMap;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::info;
use monero_rpc::MoneroRpc;
use watcher::monero::{MoneroWatcher, TauEvent, WatchTarget};

use crate::{
    contracts::TxHash,
    error::{ErrorCode, Result},
    escrow::{EscrowClient, RefundArgs, SettleArgs},
    transport::EvmTransport,
};

/// Describes a watch target bound to a specific swap identifier.
#[derive(Clone)]
pub struct SettlementTarget {
    pub swap_id: [u8; 32],
    pub watch: WatchTarget,
}

/// Result returned when a settlement transaction is dispatched.
#[derive(Clone, Debug)]
pub struct SettlementOutcome {
    pub event: TauEvent,
    pub tx_hash: TxHash,
}

/// Configuration for automatic refunds.
#[derive(Clone, Debug)]
pub struct AutoRefundConfig {
    pub swap_id: [u8; 32],
    /// ETH expiry timestamp (seconds since Unix epoch).
    pub eth_expiry: u64,
    /// Additional buffer to wait after expiry before refunding.
    pub buffer_secs: u64,
    /// Poll interval while waiting for the deadline.
    pub poll_interval: Duration,
    pub gas_limit: Option<u64>,
}

impl AutoRefundConfig {
    fn earliest_refund_time(&self) -> u64 {
        self.eth_expiry.saturating_add(self.buffer_secs)
    }

    fn normalized_poll(&self) -> Duration {
        if self.poll_interval.is_zero() {
            Duration::from_secs(1)
        } else {
            self.poll_interval
        }
    }
}

/// Waits for a spend event and settles immediately once τ is extracted.
pub fn await_settle<E: EvmTransport>(
    rpc: MoneroRpc,
    targets: Vec<SettlementTarget>,
    escrow: &EscrowClient<E>,
) -> Result<SettlementOutcome> {
    let bindings = BindingMap::new(&targets)?;
    let watcher_targets = targets.into_iter().map(|t| t.watch).collect();
    let watcher = MoneroWatcher::new(rpc, watcher_targets);
    await_with_watcher(&watcher, &bindings, escrow)
}

/// Performs a single poll cycle and settles if τ is already available.
pub fn trigger_settlement<E: EvmTransport>(
    rpc: MoneroRpc,
    targets: Vec<SettlementTarget>,
    escrow: &EscrowClient<E>,
) -> Result<Option<SettlementOutcome>> {
    let bindings = BindingMap::new(&targets)?;
    let watcher_targets = targets.into_iter().map(|t| t.watch).collect();
    let watcher = MoneroWatcher::new(rpc, watcher_targets);
    trigger_with_watcher(&watcher, &bindings, escrow)
}

/// Waits until the refund window opens (expiry + buffer) and then calls `refund`.
pub fn auto_refund<E: EvmTransport>(
    escrow: &EscrowClient<E>,
    config: AutoRefundConfig,
) -> Result<TxHash> {
    let timer = SystemTimer;
    auto_refund_with_timer(escrow, config, &timer)
}

struct BindingMap {
    by_key_image: HashMap<[u8; 32], [u8; 32]>,
}

impl BindingMap {
    fn new(targets: &[SettlementTarget]) -> Result<Self> {
        let mut map = HashMap::new();
        for target in targets {
            if map.insert(target.watch.key_image, target.swap_id).is_some() {
                return Err(ErrorCode::BridgeTransportMonero);
            }
        }
        if map.is_empty() {
            return Err(ErrorCode::BridgeTransportMonero);
        }
        Ok(Self { by_key_image: map })
    }

    fn lookup(&self, key_image: &[u8; 32]) -> Result<[u8; 32]> {
        self.by_key_image
            .get(key_image)
            .copied()
            .ok_or(ErrorCode::BridgeTransportMonero)
    }
}

fn settle_with_event<E: EvmTransport>(
    event: TauEvent,
    bindings: &BindingMap,
    escrow: &EscrowClient<E>,
) -> Result<SettlementOutcome> {
    let swap_id = bindings.lookup(&event.key_image)?;
    let tx_hash = escrow.settle(SettleArgs {
        swap_id,
        adaptor_secret: event.tau,
        gas_limit: None,
    })?;
    Ok(SettlementOutcome { event, tx_hash })
}

trait TauWatcher {
    fn watch(&self) -> Result<TauEvent>;
    fn poll_once(&self) -> Result<Option<TauEvent>>;
}

impl TauWatcher for MoneroWatcher {
    fn watch(&self) -> Result<TauEvent> {
        MoneroWatcher::watch(self).map_err(|_| ErrorCode::BridgeTransportMonero)
    }

    fn poll_once(&self) -> Result<Option<TauEvent>> {
        MoneroWatcher::poll_once(self).map_err(|_| ErrorCode::BridgeTransportMonero)
    }
}

fn await_with_watcher<E: EvmTransport, W: TauWatcher>(
    watcher: &W,
    bindings: &BindingMap,
    escrow: &EscrowClient<E>,
) -> Result<SettlementOutcome> {
    let event = watcher.watch()?;
    settle_with_event(event, bindings, escrow)
}

fn trigger_with_watcher<E: EvmTransport, W: TauWatcher>(
    watcher: &W,
    bindings: &BindingMap,
    escrow: &EscrowClient<E>,
) -> Result<Option<SettlementOutcome>> {
    if let Some(event) = watcher.poll_once()? {
        let outcome = settle_with_event(event, bindings, escrow)?;
        Ok(Some(outcome))
    } else {
        Ok(None)
    }
}

fn auto_refund_with_timer<E: EvmTransport, T: RefundTimer>(
    escrow: &EscrowClient<E>,
    config: AutoRefundConfig,
    timer: &T,
) -> Result<TxHash> {
    let earliest = config.earliest_refund_time();
    info!(
        "auto_refund: monitoring expiry={} buffer={}s (earliest={})",
        config.eth_expiry, config.buffer_secs, earliest
    );

    let poll = config.normalized_poll();
    loop {
        let now = timer.now();
        if now >= earliest {
            info!("auto_refund: deadline satisfied (now={now})");
            break;
        }
        let remaining = earliest - now;
        let poll_secs = poll.as_secs().max(1);
        let sleep_secs = remaining.min(poll_secs);
        info!(
            "auto_refund: {}s remaining, sleeping {}s",
            remaining, sleep_secs
        );
        timer.sleep(Duration::from_secs(sleep_secs));
    }

    escrow.refund(RefundArgs {
        swap_id: config.swap_id,
        gas_limit: config.gas_limit,
    })
}

trait RefundTimer: Send + Sync {
    fn now(&self) -> u64;
    fn sleep(&self, duration: Duration);
}

struct SystemTimer;

impl RefundTimer for SystemTimer {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs()
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::TxHash;
    use crate::transport::{EvmCall, EvmMessageSigner};
    use adaptor_clsag::PreSig;
    use alloy_primitives::{Address, Bytes, B256};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use watcher::monero::WatchTarget;

    #[derive(Clone, Default)]
    struct MockTransport {
        calls: Arc<Mutex<Vec<EvmCall>>>,
    }

    impl EvmTransport for MockTransport {
        fn send(&self, call: EvmCall) -> Result<B256> {
            self.calls.lock().unwrap().push(call);
            Ok(B256::from([0xAA; 32]))
        }
    }

    impl EvmMessageSigner for MockTransport {
        fn sign_hash(&self, digest: B256) -> Result<Bytes> {
            Ok(Bytes::from(digest.to_vec()))
        }

        fn signer_address(&self) -> Address {
            Address::ZERO
        }
    }

    struct MockWatcher {
        event: Option<TauEvent>,
    }

    impl TauWatcher for MockWatcher {
        fn watch(&self) -> Result<TauEvent> {
            self.event.clone().ok_or(ErrorCode::BridgeTransportMonero)
        }

        fn poll_once(&self) -> Result<Option<TauEvent>> {
            Ok(self.event.clone())
        }
    }

    fn mock_bindings() -> (
        BindingMap,
        EscrowClient<MockTransport>,
        TauEvent,
        MockTransport,
    ) {
        let watch = WatchTarget::new([0x11; 32], "tx", 0, sample_presig());
        let target = SettlementTarget {
            swap_id: [0x22; 32],
            watch,
        };
        let bindings = BindingMap::new(&[target]).unwrap();
        let transport = MockTransport::default();
        let escrow = EscrowClient::new(Address::ZERO, transport.clone());
        let event = TauEvent {
            key_image: [0x11; 32],
            tx_hash: "tx".into(),
            input_index: 0,
            tau: [0x33; 32],
            spend_state: watcher::monero::SpendState::Confirmed,
        };
        (bindings, escrow, event, transport)
    }

    fn mock_escrow_client() -> (EscrowClient<MockTransport>, MockTransport) {
        let transport = MockTransport::default();
        let escrow = EscrowClient::new(Address::ZERO, transport.clone());
        (escrow, transport)
    }

    fn sample_presig() -> PreSig {
        use adaptor_clsag::{SettlementCtx as AdaptorSettlement, SAMPLE_RING_KEYS};
        PreSig {
            c1_tilde: SAMPLE_RING_KEYS[0],
            s_tilde: vec![SAMPLE_RING_KEYS[0]; SAMPLE_RING_KEYS.len()],
            d_tilde: SAMPLE_RING_KEYS[1],
            pseudo_out: SAMPLE_RING_KEYS[2],
            j: 0,
            ctx: AdaptorSettlement {
                chain_tag: "evm:8453".into(),
                position_key: [0xAA; 32],
                settle_digest: [0x44; 32],
            },
            pre_hash: [0x55; 32],
        }
    }

    fn sample_target(key_image: [u8; 32], swap_id: [u8; 32]) -> SettlementTarget {
        let watch = WatchTarget::new(key_image, "tx", 0, sample_presig());
        SettlementTarget { swap_id, watch }
    }

    fn dummy_rpc() -> MoneroRpc {
        MoneroRpc::new("http://127.0.0.1:18081", None).expect("rpc init")
    }

    #[test]
    fn settle_with_mock_watcher() {
        let (bindings, escrow, event, transport) = mock_bindings();
        let watcher = MockWatcher {
            event: Some(event.clone()),
        };
        let outcome = await_with_watcher(&watcher, &bindings, &escrow).expect("await outcome");
        assert_eq!(outcome.event.tau, event.tau);
        assert_eq!(outcome.tx_hash, TxHash(B256::from([0xAA; 32])));
        assert_eq!(transport.calls.lock().unwrap().len(), 1);

        let trigger = trigger_with_watcher(&watcher, &bindings, &escrow).unwrap();
        assert!(trigger.is_some());
    }

    #[test]
    fn auto_refund_waits_until_deadline() {
        let (escrow, transport) = mock_escrow_client();
        let timer = MockTimer::new(100);
        let config = AutoRefundConfig {
            swap_id: [0x33; 32],
            eth_expiry: 110,
            buffer_secs: 15,
            poll_interval: Duration::from_secs(5),
            gas_limit: Some(250_000),
        };
        let hash = auto_refund_with_timer(&escrow, config, &timer).expect("auto refund");
        assert_eq!(hash, TxHash(B256::from([0xAA; 32])));
        assert!(!timer.sleeps.lock().unwrap().is_empty());
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn auto_refund_immediate_when_past_deadline() {
        let (escrow, transport) = mock_escrow_client();
        let timer = MockTimer::new(500);
        let config = AutoRefundConfig {
            swap_id: [0x44; 32],
            eth_expiry: 100,
            buffer_secs: 10,
            poll_interval: Duration::from_secs(10),
            gas_limit: None,
        };
        let _ = auto_refund_with_timer(&escrow, config, &timer).expect("auto refund");
        assert!(timer.sleeps.lock().unwrap().is_empty());
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }

    #[derive(Clone)]
    struct MockTimer {
        now: Arc<Mutex<u64>>,
        sleeps: Arc<Mutex<Vec<Duration>>>,
    }

    impl MockTimer {
        fn new(start: u64) -> Self {
            Self {
                now: Arc::new(Mutex::new(start)),
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl RefundTimer for MockTimer {
        fn now(&self) -> u64 {
            *self.now.lock().unwrap()
        }

        fn sleep(&self, duration: Duration) {
            self.sleeps.lock().unwrap().push(duration);
            let mut guard = self.now.lock().unwrap();
            *guard += duration.as_secs();
        }
    }

    #[test]
    fn await_settle_rejects_empty_targets() {
        let (escrow, _) = mock_escrow_client();
        let rpc = dummy_rpc();
        let err = await_settle(rpc, Vec::new(), &escrow).expect_err("empty targets");
        assert_eq!(err, ErrorCode::BridgeTransportMonero);
    }

    #[test]
    fn await_settle_rejects_duplicate_key_images() {
        let (escrow, _) = mock_escrow_client();
        let rpc = dummy_rpc();
        let targets = vec![
            sample_target([0x01; 32], [0xAA; 32]),
            sample_target([0x01; 32], [0xBB; 32]),
        ];
        let err = await_settle(rpc, targets, &escrow).expect_err("duplicate targets");
        assert_eq!(err, ErrorCode::BridgeTransportMonero);
    }

    #[test]
    fn trigger_settlement_rejects_empty_targets() {
        let (escrow, _) = mock_escrow_client();
        let rpc = dummy_rpc();
        let err = trigger_settlement(rpc, Vec::new(), &escrow).expect_err("empty targets");
        assert_eq!(err, ErrorCode::BridgeTransportMonero);
    }

    #[test]
    fn trigger_settlement_rejects_duplicate_key_images() {
        let (escrow, _) = mock_escrow_client();
        let rpc = dummy_rpc();
        let targets = vec![
            sample_target([0x02; 32], [0x11; 32]),
            sample_target([0x02; 32], [0x22; 32]),
        ];
        let err = trigger_settlement(rpc, targets, &escrow).expect_err("duplicate key images");
        assert_eq!(err, ErrorCode::BridgeTransportMonero);
    }
}
