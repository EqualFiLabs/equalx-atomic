use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use equalx_error::{AdapterError, ErrorCode};
use host_adapter::{
    EvmCall, EvmExecutionAdapter, KeyIdentityAdapter, LogEntry, LogFilter, MoneroExecutionAdapter,
    NodeHealth, PersistenceAdapter, SpendState, SwapLifecycleEvent, SwapOutcome,
    TimeNetworkAdapter, TxReceipt, UxEventAdapter,
};
use orchestrator::{
    DeadlineEvent, MakerState, MoneroContext, OrchestratorConfig, OrchestratorError, ReservationId,
    ReservationParams, SideEffectKind, SideEffectRecord, SwapCheckpoint, SwapOrchestrator,
    SwapRole, SwapState, TakerState,
};
use proptest::prelude::*;

#[derive(Clone, Debug)]
enum FailurePoint {
    SendRawTx,
    BroadcastTx,
    CurrentTimestamp,
    BlockNumber,
}

#[derive(Clone, Debug)]
struct InjectedFailure {
    point: FailurePoint,
    error: AdapterError,
}

#[derive(Clone, Debug)]
struct MockAdapterConfig {
    now: u64,
    failures: Vec<InjectedFailure>,
}

impl Default for MockAdapterConfig {
    fn default() -> Self {
        Self {
            now: 1_000,
            failures: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
struct MockAdapter {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    now: u64,
    checkpoints: HashMap<ReservationId, Vec<u8>>,
    save_count: usize,
    events: Vec<SwapLifecycleEvent>,
    evm_send_calls: usize,
    monero_broadcast_calls: usize,
    failures: VecDeque<InjectedFailure>,
}

impl MockAdapter {
    fn from_config(config: MockAdapterConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                now: config.now,
                failures: VecDeque::from(config.failures),
                ..Inner::default()
            })),
        }
    }

    fn set_now(&self, now: u64) {
        self.inner.lock().expect("mutex poisoned").now = now;
    }

    fn insert_checkpoint(&self, reservation_id: ReservationId, checkpoint_bytes: Vec<u8>) {
        self.inner
            .lock()
            .expect("mutex poisoned")
            .checkpoints
            .insert(reservation_id, checkpoint_bytes);
    }

    fn save_count(&self) -> usize {
        self.inner.lock().expect("mutex poisoned").save_count
    }

    fn evm_send_calls(&self) -> usize {
        self.inner.lock().expect("mutex poisoned").evm_send_calls
    }

    fn monero_broadcast_calls(&self) -> usize {
        self.inner
            .lock()
            .expect("mutex poisoned")
            .monero_broadcast_calls
    }

    fn events(&self) -> Vec<SwapLifecycleEvent> {
        self.inner.lock().expect("mutex poisoned").events.clone()
    }

    fn maybe_fail(&self, point: FailurePoint) -> host_adapter::Result<()> {
        let mut inner = self.inner.lock().expect("mutex poisoned");
        if let Some(index) = inner.failures.iter().position(|entry| {
            matches!(
                (&entry.point, &point),
                (FailurePoint::SendRawTx, FailurePoint::SendRawTx)
                    | (FailurePoint::BroadcastTx, FailurePoint::BroadcastTx)
                    | (
                        FailurePoint::CurrentTimestamp,
                        FailurePoint::CurrentTimestamp
                    )
                    | (FailurePoint::BlockNumber, FailurePoint::BlockNumber)
            )
        }) {
            let failure = inner.failures.remove(index).expect("index exists");
            return Err(failure.error);
        }
        Ok(())
    }
}

impl KeyIdentityAdapter for MockAdapter {
    fn evm_address(&self) -> host_adapter::Result<[u8; 20]> {
        Ok([0x11; 20])
    }

    fn sign_evm_message(&self, digest: [u8; 32]) -> host_adapter::Result<Vec<u8>> {
        Ok(digest.to_vec())
    }

    fn monero_spend_public_key(&self) -> host_adapter::Result<[u8; 32]> {
        Ok([0x22; 32])
    }

    fn monero_view_public_key(&self) -> host_adapter::Result<[u8; 32]> {
        Ok([0x33; 32])
    }

    fn monero_derive_subaddress(&self, major: u32, minor: u32) -> host_adapter::Result<Vec<u8>> {
        Ok(vec![major as u8, minor as u8])
    }

    fn monero_compute_key_image(
        &self,
        output_pubkey: &[u8; 32],
        output_index: u64,
    ) -> host_adapter::Result<[u8; 32]> {
        let mut out = *output_pubkey;
        out[0] ^= output_index as u8;
        Ok(out)
    }
}

impl EvmExecutionAdapter for MockAdapter {
    fn send_raw_tx(&self, _signed_tx: &[u8]) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail(FailurePoint::SendRawTx)?;
        let mut inner = self.inner.lock().expect("mutex poisoned");
        inner.evm_send_calls += 1;
        let mut hash = [0u8; 32];
        hash[0] = inner.evm_send_calls as u8;
        Ok(hash)
    }

    fn estimate_gas(&self, _call: &EvmCall) -> host_adapter::Result<u64> {
        Ok(21_000)
    }

    fn replace_tx(
        &self,
        _original_hash: [u8; 32],
        _new_gas: u64,
    ) -> host_adapter::Result<[u8; 32]> {
        Ok([0x44; 32])
    }

    fn get_receipt(&self, tx_hash: [u8; 32]) -> host_adapter::Result<Option<TxReceipt>> {
        Ok(Some(TxReceipt {
            tx_hash,
            block_number: 100,
            block_hash: [0x55; 32],
            success: true,
            gas_used: 21_000,
        }))
    }

    fn get_logs(&self, _filter: &LogFilter) -> host_adapter::Result<Vec<LogEntry>> {
        Ok(Vec::new())
    }

    fn chain_id(&self) -> host_adapter::Result<u64> {
        Ok(1)
    }

    fn block_number(&self) -> host_adapter::Result<u64> {
        self.maybe_fail(FailurePoint::BlockNumber)?;
        Ok(1_000)
    }

    fn gas_price(&self) -> host_adapter::Result<u128> {
        Ok(1_000_000_000)
    }
}

impl MoneroExecutionAdapter for MockAdapter {
    fn broadcast_tx(&self, _tx_blob: &[u8]) -> host_adapter::Result<[u8; 32]> {
        self.maybe_fail(FailurePoint::BroadcastTx)?;
        let mut inner = self.inner.lock().expect("mutex poisoned");
        inner.monero_broadcast_calls += 1;
        let mut tx = [0u8; 32];
        tx[0] = inner.monero_broadcast_calls as u8;
        tx[1] = 0xAA;
        Ok(tx)
    }

    fn is_key_image_spent(&self, key_images: &[[u8; 32]]) -> host_adapter::Result<Vec<SpendState>> {
        Ok(vec![SpendState::Unspent; key_images.len()])
    }

    fn get_tx_confirmations(&self, _tx_hash: &[u8; 32]) -> host_adapter::Result<Option<u64>> {
        Ok(Some(1))
    }

    fn node_health(&self) -> host_adapter::Result<NodeHealth> {
        Ok(NodeHealth::Healthy { height: 1_000_000 })
    }
}

impl PersistenceAdapter for MockAdapter {
    fn save_checkpoint(&self, reservation_id: &[u8; 32], state: &[u8]) -> host_adapter::Result<()> {
        let mut inner = self.inner.lock().expect("mutex poisoned");
        inner.checkpoints.insert(*reservation_id, state.to_vec());
        inner.save_count += 1;
        Ok(())
    }

    fn load_checkpoint(&self, reservation_id: &[u8; 32]) -> host_adapter::Result<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .expect("mutex poisoned")
            .checkpoints
            .get(reservation_id)
            .cloned())
    }

    fn list_active_swaps(&self) -> host_adapter::Result<Vec<[u8; 32]>> {
        Ok(self
            .inner
            .lock()
            .expect("mutex poisoned")
            .checkpoints
            .keys()
            .copied()
            .collect())
    }

    fn delete_swap(&self, reservation_id: &[u8; 32]) -> host_adapter::Result<()> {
        self.inner
            .lock()
            .expect("mutex poisoned")
            .checkpoints
            .remove(reservation_id);
        Ok(())
    }
}

impl TimeNetworkAdapter for MockAdapter {
    fn current_block_number(&self) -> host_adapter::Result<u64> {
        Ok(1_000)
    }

    fn current_timestamp(&self) -> host_adapter::Result<u64> {
        self.maybe_fail(FailurePoint::CurrentTimestamp)?;
        Ok(self.inner.lock().expect("mutex poisoned").now)
    }

    fn is_evm_reachable(&self) -> host_adapter::Result<bool> {
        Ok(true)
    }

    fn is_monero_reachable(&self) -> host_adapter::Result<bool> {
        Ok(true)
    }
}

impl UxEventAdapter for MockAdapter {
    fn on_event(&self, event: SwapLifecycleEvent) {
        self.inner
            .lock()
            .expect("mutex poisoned")
            .events
            .push(event);
    }
}

#[derive(Clone, Copy, Debug)]
enum FlowPrefix {
    Maker(usize),
    Taker(usize),
}

#[derive(Clone, Copy, Debug)]
enum InvalidCommand {
    MakerSettle,
    TakerPublishFinalSig,
}

#[derive(Clone, Debug)]
struct InvalidCase {
    reservation_id: ReservationId,
    role: SwapRole,
    state: SwapState,
    command: InvalidCommand,
}

#[derive(Clone, Debug)]
struct DeadlineCase {
    reservation_id: ReservationId,
    state: SwapState,
    config: OrchestratorConfig,
    now: u64,
}

#[derive(Clone, Debug)]
struct GeneratedCheckpoint {
    reservation_id: ReservationId,
    checkpoint: SwapCheckpoint,
    expected_state: SwapState,
}

fn reservation(id: u8) -> ReservationId {
    let mut out = [0u8; 32];
    out[0] = id;
    out
}

fn sample_context() -> MoneroContext {
    MoneroContext {
        context_hash: [0x77; 32],
        wire_version: adaptor_clsag::WIRE_VERSION,
        envelope: None,
    }
}

fn checkpoint_bytes_for_state(
    role: SwapRole,
    reservation_id: ReservationId,
    state: &SwapState,
    timestamp: u64,
    sequence: u64,
    side_effects_log: Vec<SideEffectRecord>,
) -> Vec<u8> {
    let state_bytes = match state {
        SwapState::Maker(maker) => bincode::serialize(maker).expect("serialize maker"),
        SwapState::Taker(taker) => bincode::serialize(taker).expect("serialize taker"),
    };
    let checkpoint = SwapCheckpoint {
        version: 1,
        role,
        reservation_id,
        state: state_bytes,
        timestamp,
        sequence,
        side_effects_log,
    };
    bincode::serialize(&checkpoint).expect("serialize checkpoint")
}

fn transition_count_from_events(events: &[SwapLifecycleEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, SwapLifecycleEvent::StateTransition { .. }))
        .count()
}

fn expected_transitions(prefix: FlowPrefix) -> usize {
    match prefix {
        FlowPrefix::Maker(len) => match len {
            1 => 1,
            2 => 2,
            3 => 3,
            4 => 4,
            5 => 5,
            6 => 7,
            _ => 0,
        },
        FlowPrefix::Taker(len) => match len {
            1 => 1,
            2 => 2,
            3 => 3,
            4 => 5,
            5 => 6,
            _ => 0,
        },
    }
}

fn execute_valid_prefix(
    orchestrator: &SwapOrchestrator<MockAdapter>,
    reservation_id: ReservationId,
    prefix: FlowPrefix,
) -> Option<[u8; 32]> {
    match prefix {
        FlowPrefix::Maker(len) => {
            if len >= 1 {
                orchestrator
                    .maker_create_reservation(ReservationParams {
                        reservation_id,
                        created_at: Some(100),
                    })
                    .expect("maker_create_reservation");
            }
            if len >= 2 {
                orchestrator
                    .maker_set_hashlock(reservation_id)
                    .expect("maker_set_hashlock");
            }
            if len >= 3 {
                orchestrator
                    .maker_handle_context(reservation_id)
                    .expect("maker_handle_context");
            }
            if len >= 4 {
                orchestrator
                    .maker_publish_presig(reservation_id)
                    .expect("maker_publish_presig");
            }
            if len >= 5 {
                orchestrator
                    .maker_handle_final_sig(reservation_id)
                    .expect("maker_handle_final_sig");
            }
            if len >= 6 {
                orchestrator
                    .maker_settle(reservation_id)
                    .expect("maker_settle");
            }
            None
        }
        FlowPrefix::Taker(len) => {
            let mut monero_tx = None;
            if len >= 1 {
                orchestrator
                    .taker_accept_reservation(reservation_id)
                    .expect("taker_accept_reservation");
            }
            if len >= 2 {
                orchestrator
                    .taker_publish_context(reservation_id, sample_context())
                    .expect("taker_publish_context");
            }
            if len >= 3 {
                orchestrator
                    .taker_handle_presig(reservation_id)
                    .expect("taker_handle_presig");
            }
            if len >= 4 {
                monero_tx = Some(
                    orchestrator
                        .taker_complete_and_broadcast(reservation_id)
                        .expect("taker_complete_and_broadcast"),
                );
            }
            if len >= 5 {
                orchestrator
                    .taker_publish_final_sig(
                        reservation_id,
                        monero_tx.expect("monero tx id from prior step"),
                    )
                    .expect("taker_publish_final_sig");
            }
            monero_tx
        }
    }
}

fn replay_last_command(
    orchestrator: &SwapOrchestrator<MockAdapter>,
    reservation_id: ReservationId,
    prefix: FlowPrefix,
    monero_tx: Option<[u8; 32]>,
) {
    match prefix {
        FlowPrefix::Maker(1) => {
            orchestrator
                .maker_create_reservation(ReservationParams {
                    reservation_id,
                    created_at: Some(100),
                })
                .expect("idempotent maker create");
        }
        FlowPrefix::Maker(2) => {
            orchestrator
                .maker_set_hashlock(reservation_id)
                .expect("idempotent maker hashlock");
        }
        FlowPrefix::Maker(3) => {
            orchestrator
                .maker_handle_context(reservation_id)
                .expect("idempotent maker context");
        }
        FlowPrefix::Maker(4) => {
            orchestrator
                .maker_publish_presig(reservation_id)
                .expect("idempotent maker presig");
        }
        FlowPrefix::Maker(5) => {
            orchestrator
                .maker_handle_final_sig(reservation_id)
                .expect("idempotent maker final sig");
        }
        FlowPrefix::Maker(6) => {
            orchestrator
                .maker_settle(reservation_id)
                .expect("idempotent maker settle");
        }
        FlowPrefix::Taker(1) => {
            orchestrator
                .taker_accept_reservation(reservation_id)
                .expect("idempotent taker accept");
        }
        FlowPrefix::Taker(2) => {
            orchestrator
                .taker_publish_context(reservation_id, sample_context())
                .expect("idempotent taker context");
        }
        FlowPrefix::Taker(3) => {
            orchestrator
                .taker_handle_presig(reservation_id)
                .expect("idempotent taker presig");
        }
        FlowPrefix::Taker(4) => {
            let _ = orchestrator
                .taker_complete_and_broadcast(reservation_id)
                .expect("idempotent taker broadcast");
        }
        FlowPrefix::Taker(5) => {
            orchestrator
                .taker_publish_final_sig(reservation_id, monero_tx.expect("monero tx"))
                .expect("idempotent taker final sig");
        }
        _ => {}
    }
}

fn arb_error_code() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![
        Just(ErrorCode::AdapterCallFailed),
        Just(ErrorCode::AdapterTimeout),
        Just(ErrorCode::NetworkUnreachable),
        Just(ErrorCode::RpcError),
    ]
}

fn arb_side_effect_kind() -> impl Strategy<Value = SideEffectKind> {
    prop_oneof![
        Just(SideEffectKind::EvmTxSubmitted),
        Just(SideEffectKind::MoneroTxBroadcast),
        Just(SideEffectKind::MailboxPublish),
        Just(SideEffectKind::HashlockSet),
    ]
}

fn arb_side_effect_record() -> impl Strategy<Value = SideEffectRecord> {
    (
        arb_side_effect_kind(),
        prop::option::of(any::<[u8; 32]>()),
        any::<bool>(),
    )
        .prop_map(|(kind, tx_hash, completed)| SideEffectRecord {
            kind,
            tx_hash,
            completed,
        })
}

fn arb_maker_state() -> impl Strategy<Value = MakerState> {
    let reason = proptest::string::string_regex("[a-zA-Z0-9 _-]{1,40}").expect("regex");
    prop_oneof![
        Just(MakerState::Idle),
        (any::<[u8; 32]>(), any::<u64>()).prop_map(|(reservation_id, created_at)| {
            MakerState::ReservationCreated {
                reservation_id,
                created_at,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, hashlock)| {
            MakerState::HashlockSet {
                reservation_id,
                hashlock,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, context_hash)| {
            MakerState::ContextReceived {
                reservation_id,
                context_hash,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, presig_hash)| {
            MakerState::PresigPublished {
                reservation_id,
                presig_hash,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, monero_tx_id)| {
            MakerState::FinalSigReceived {
                reservation_id,
                monero_tx_id,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, tau)| {
            MakerState::TauExtracted {
                reservation_id,
                tau,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, settle_tx)| {
            MakerState::Settled {
                reservation_id,
                settle_tx,
            }
        }),
        any::<[u8; 32]>().prop_map(|reservation_id| MakerState::Refunded { reservation_id }),
        (any::<[u8; 32]>(), any::<i32>(), reason, any::<bool>()).prop_map(
            |(reservation_id, error_code, reason, recoverable)| MakerState::Failed {
                reservation_id,
                error_code,
                reason,
                recoverable,
            }
        ),
    ]
}

fn arb_taker_state() -> impl Strategy<Value = TakerState> {
    let reason = proptest::string::string_regex("[a-zA-Z0-9 _-]{1,40}").expect("regex");
    prop_oneof![
        Just(TakerState::Idle),
        (any::<[u8; 32]>(), any::<u64>()).prop_map(|(reservation_id, expiry)| {
            TakerState::ReservationAccepted {
                reservation_id,
                expiry,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, context_hash)| {
            TakerState::ContextPublished {
                reservation_id,
                context_hash,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, presig_hash)| {
            TakerState::PresigReceived {
                reservation_id,
                presig_hash,
            }
        }),
        any::<[u8; 32]>()
            .prop_map(|reservation_id| TakerState::SignatureCompleted { reservation_id }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, monero_tx_id)| {
            TakerState::MoneroTxBroadcast {
                reservation_id,
                monero_tx_id,
            }
        }),
        any::<[u8; 32]>()
            .prop_map(|reservation_id| TakerState::FinalSigPublished { reservation_id }),
        any::<[u8; 32]>().prop_map(|reservation_id| TakerState::Settled { reservation_id }),
        any::<[u8; 32]>().prop_map(|reservation_id| TakerState::Refunded { reservation_id }),
        (any::<[u8; 32]>(), any::<i32>(), reason, any::<bool>()).prop_map(
            |(reservation_id, error_code, reason, recoverable)| TakerState::Failed {
                reservation_id,
                error_code,
                reason,
                recoverable,
            }
        ),
    ]
}

fn arb_generated_checkpoint() -> impl Strategy<Value = GeneratedCheckpoint> {
    (
        any::<[u8; 32]>(),
        any::<bool>(),
        prop::collection::vec(arb_side_effect_record(), 0..8),
        any::<u64>(),
        any::<u64>(),
        prop_oneof![
            arb_maker_state().prop_map(SwapState::Maker),
            arb_taker_state().prop_map(SwapState::Taker)
        ],
    )
        .prop_map(
            |(
                reservation_id,
                force_maker,
                side_effects_log,
                timestamp,
                sequence,
                generated_state,
            )| {
                let (role, expected_state) = match generated_state {
                    SwapState::Maker(state) if !force_maker => {
                        (SwapRole::Maker, SwapState::Maker(state))
                    }
                    SwapState::Maker(state) => (SwapRole::Maker, SwapState::Maker(state)),
                    SwapState::Taker(state) if force_maker => {
                        (SwapRole::Taker, SwapState::Taker(state))
                    }
                    SwapState::Taker(state) => (SwapRole::Taker, SwapState::Taker(state)),
                };
                let state_bytes = match &expected_state {
                    SwapState::Maker(state) => bincode::serialize(state).expect("serialize maker"),
                    SwapState::Taker(state) => bincode::serialize(state).expect("serialize taker"),
                };
                let checkpoint = SwapCheckpoint {
                    version: 1,
                    role,
                    reservation_id,
                    state: state_bytes,
                    timestamp,
                    sequence,
                    side_effects_log,
                };
                GeneratedCheckpoint {
                    reservation_id,
                    checkpoint,
                    expected_state,
                }
            },
        )
}

fn arb_flow_prefix() -> impl Strategy<Value = FlowPrefix> {
    prop_oneof![
        (1usize..7usize).prop_map(FlowPrefix::Maker),
        (1usize..6usize).prop_map(FlowPrefix::Taker),
    ]
}

fn arb_invalid_case() -> impl Strategy<Value = InvalidCase> {
    let maker_invalid_state = prop_oneof![
        Just(MakerState::Idle),
        (any::<[u8; 32]>(), any::<u64>()).prop_map(|(reservation_id, created_at)| {
            MakerState::ReservationCreated {
                reservation_id,
                created_at,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, hashlock)| {
            MakerState::HashlockSet {
                reservation_id,
                hashlock,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, context_hash)| {
            MakerState::ContextReceived {
                reservation_id,
                context_hash,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, presig_hash)| {
            MakerState::PresigPublished {
                reservation_id,
                presig_hash,
            }
        }),
    ];
    let taker_invalid_state = prop_oneof![
        Just(TakerState::Idle),
        (any::<[u8; 32]>(), any::<u64>()).prop_map(|(reservation_id, expiry)| {
            TakerState::ReservationAccepted {
                reservation_id,
                expiry,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, context_hash)| {
            TakerState::ContextPublished {
                reservation_id,
                context_hash,
            }
        }),
        (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, presig_hash)| {
            TakerState::PresigReceived {
                reservation_id,
                presig_hash,
            }
        }),
        any::<[u8; 32]>()
            .prop_map(|reservation_id| TakerState::SignatureCompleted { reservation_id }),
    ];

    prop_oneof![
        (any::<[u8; 32]>(), maker_invalid_state).prop_map(|(reservation_id, state)| InvalidCase {
            reservation_id,
            role: SwapRole::Maker,
            state: SwapState::Maker(state),
            command: InvalidCommand::MakerSettle,
        }),
        (any::<[u8; 32]>(), taker_invalid_state).prop_map(|(reservation_id, state)| InvalidCase {
            reservation_id,
            role: SwapRole::Taker,
            state: SwapState::Taker(state),
            command: InvalidCommand::TakerPublishFinalSig,
        }),
    ]
}

fn arb_deadline_case() -> impl Strategy<Value = DeadlineCase> {
    prop_oneof![
        (
            any::<[u8; 32]>(),
            0u64..10_000u64,
            1u64..5_000u64,
            1u64..5_000u64
        )
            .prop_map(|(reservation_id, created_at, timeout_secs, offset_secs)| {
                let now = created_at
                    .saturating_add(timeout_secs)
                    .saturating_add(offset_secs);
                DeadlineCase {
                    reservation_id,
                    state: SwapState::Maker(MakerState::ReservationCreated {
                        reservation_id,
                        created_at,
                    }),
                    config: OrchestratorConfig {
                        checkpoint_version: 1,
                        maker_timeout_secs: timeout_secs,
                        taker_timeout_secs: 3600,
                    },
                    now,
                }
            }),
        (any::<[u8; 32]>(), 0u64..10_000u64, 1u64..5_000u64).prop_map(
            |(reservation_id, expiry, offset_secs)| {
                let now = expiry.saturating_add(offset_secs);
                DeadlineCase {
                    reservation_id,
                    state: SwapState::Taker(TakerState::ReservationAccepted {
                        reservation_id,
                        expiry,
                    }),
                    config: OrchestratorConfig {
                        checkpoint_version: 1,
                        maker_timeout_secs: 3600,
                        taker_timeout_secs: 3600,
                    },
                    now,
                }
            }
        ),
    ]
}

fn arb_adapter_error() -> impl Strategy<Value = AdapterError> {
    (
        arb_error_code(),
        proptest::string::string_regex("[a-zA-Z0-9 _-]{1,40}").expect("regex"),
        prop::option::of(any::<i32>()),
    )
        .prop_map(|(code, message, adapter_code)| {
            let error = AdapterError::new(code, message);
            if let Some(adapter_code) = adapter_code {
                error.with_adapter_code(adapter_code)
            } else {
                error
            }
        })
}

fn arb_mock_adapter_config() -> impl Strategy<Value = MockAdapterConfig> {
    (
        0u64..10_000u64,
        prop::collection::vec(
            (
                prop_oneof![
                    Just(FailurePoint::SendRawTx),
                    Just(FailurePoint::BroadcastTx),
                    Just(FailurePoint::CurrentTimestamp),
                    Just(FailurePoint::BlockNumber)
                ],
                arb_adapter_error(),
            )
                .prop_map(|(point, error)| InjectedFailure { point, error }),
            0..4,
        ),
    )
        .prop_map(|(now, failures)| MockAdapterConfig { now, failures })
}

fn make_orchestrator(
    config: MockAdapterConfig,
    orch_config: OrchestratorConfig,
) -> (MockAdapter, SwapOrchestrator<MockAdapter>) {
    let adapter = MockAdapter::from_config(config);
    let orchestrator = SwapOrchestrator::new(adapter.clone(), orch_config);
    (adapter, orchestrator)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100,
        .. ProptestConfig::default()
    })]

    /// Property 8: swap state serialization round-trip (maker).
    #[test]
    fn property8_swap_state_roundtrip_maker(state in arb_maker_state()) {
        let encoded = bincode::serialize(&state).expect("serialize");
        let decoded: MakerState = bincode::deserialize(&encoded).expect("deserialize");
        prop_assert_eq!(decoded, state);
    }

    /// Property 8: swap state serialization round-trip (taker).
    #[test]
    fn property8_swap_state_roundtrip_taker(state in arb_taker_state()) {
        let encoded = bincode::serialize(&state).expect("serialize");
        let decoded: TakerState = bincode::deserialize(&encoded).expect("deserialize");
        prop_assert_eq!(decoded, state);
    }

    /// Property 3: checkpoint persistence on every state transition.
    #[test]
    fn property3_checkpoint_persistence(prefix in arb_flow_prefix(), reservation_id in any::<[u8; 32]>()) {
        let (adapter, orchestrator) = make_orchestrator(MockAdapterConfig::default(), OrchestratorConfig::default());
        let _ = execute_valid_prefix(&orchestrator, reservation_id, prefix);
        let saves = adapter.save_count();
        let transitions = transition_count_from_events(&adapter.events());
        prop_assert_eq!(saves, transitions);
        prop_assert_eq!(saves, expected_transitions(prefix));
    }

    /// Property 4: crash recovery preserves state.
    #[test]
    fn property4_crash_recovery_preserves_state(generated in arb_generated_checkpoint()) {
        let adapter = MockAdapter::from_config(MockAdapterConfig::default());
        let bytes = bincode::serialize(&generated.checkpoint).expect("checkpoint serialize");
        adapter.insert_checkpoint(generated.reservation_id, bytes);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let resumed = orchestrator.resume(generated.reservation_id).expect("resume");

        prop_assert_eq!(resumed, generated.expected_state);
        prop_assert_eq!(adapter.evm_send_calls(), 0);
        prop_assert_eq!(adapter.monero_broadcast_calls(), 0);
    }

    /// Property 5: invalid state transition rejection.
    #[test]
    fn property5_invalid_transition_rejection(case in arb_invalid_case()) {
        let adapter = MockAdapter::from_config(MockAdapterConfig::default());
        let bytes = checkpoint_bytes_for_state(
            case.role,
            case.reservation_id,
            &case.state,
            100,
            1,
            vec![],
        );
        adapter.insert_checkpoint(case.reservation_id, bytes);

        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let resumed = orchestrator.resume(case.reservation_id).expect("resume");
        prop_assert_eq!(resumed, case.state.clone());

        let before = orchestrator.state(case.reservation_id).expect("before state");
        let result = match case.command {
            InvalidCommand::MakerSettle => orchestrator.maker_settle(case.reservation_id),
            InvalidCommand::TakerPublishFinalSig => {
                orchestrator.taker_publish_final_sig(case.reservation_id, [0xAA; 32])
            }
        };
        let err = result.expect_err("must reject invalid transition");
        prop_assert_eq!(
            matches!(err, OrchestratorError::InvalidTransition { .. }),
            true
        );
        let after = orchestrator.state(case.reservation_id).expect("after state");
        prop_assert_eq!(before, after);
    }

    /// Property 6: deadline enforcement.
    #[test]
    fn property6_deadline_enforcement(case in arb_deadline_case()) {
        let adapter = MockAdapter::from_config(MockAdapterConfig::default());
        let role = match &case.state {
            SwapState::Maker(_) => SwapRole::Maker,
            SwapState::Taker(_) => SwapRole::Taker,
        };
        let bytes = checkpoint_bytes_for_state(role, case.reservation_id, &case.state, 10, 1, vec![]);
        adapter.insert_checkpoint(case.reservation_id, bytes);
        adapter.set_now(case.now);

        let orchestrator = SwapOrchestrator::new(adapter.clone(), case.config.clone());
        let _ = orchestrator.resume(case.reservation_id).expect("resume");
        let events: Vec<DeadlineEvent> = orchestrator.check_deadlines().expect("check deadlines");

        prop_assert!(!events.is_empty());
        prop_assert!(events.iter().any(|event| event.reservation_id == case.reservation_id));
        let emitted = adapter.events();
        prop_assert_eq!(
            emitted.iter().any(|event| matches!(
                event,
                SwapLifecycleEvent::DeadlineExceeded { reservation_id, .. } if *reservation_id == case.reservation_id
            )),
            true
        );
        let state = orchestrator.state(case.reservation_id).expect("state");
        prop_assert_eq!(
            matches!(
                state,
                SwapState::Maker(MakerState::Refunded { .. })
                    | SwapState::Taker(TakerState::Refunded { .. })
            ),
            true
        );
    }

    /// Property 7: command idempotence.
    #[test]
    fn property7_command_idempotence(prefix in arb_flow_prefix(), reservation_id in any::<[u8; 32]>()) {
        let (adapter, orchestrator) = make_orchestrator(MockAdapterConfig::default(), OrchestratorConfig::default());
        let monero_tx = execute_valid_prefix(&orchestrator, reservation_id, prefix);

        let before_saves = adapter.save_count();
        let before_evm_calls = adapter.evm_send_calls();
        let before_monero_calls = adapter.monero_broadcast_calls();
        let before_effects = orchestrator
            .side_effects(reservation_id)
            .unwrap_or_default()
            .len();

        replay_last_command(&orchestrator, reservation_id, prefix, monero_tx);

        let after_saves = adapter.save_count();
        let after_evm_calls = adapter.evm_send_calls();
        let after_monero_calls = adapter.monero_broadcast_calls();
        let after_effects = orchestrator
            .side_effects(reservation_id)
            .unwrap_or_default()
            .len();

        prop_assert_eq!(after_saves, before_saves);
        prop_assert_eq!(after_evm_calls, before_evm_calls);
        prop_assert_eq!(after_monero_calls, before_monero_calls);
        prop_assert_eq!(after_effects, before_effects);
    }

    /// Property 2: adapter error propagation.
    #[test]
    fn property2_adapter_error_propagation(error in arb_adapter_error(), reservation_id in any::<[u8; 32]>()) {
        let config = MockAdapterConfig {
            now: 1_000,
            failures: vec![InjectedFailure {
                point: FailurePoint::SendRawTx,
                error: error.clone(),
            }],
        };
        let (adapter, orchestrator) = make_orchestrator(config, OrchestratorConfig::default());
        let result = orchestrator.maker_create_reservation(ReservationParams {
            reservation_id,
            created_at: Some(10),
        });
        let err = result.expect_err("must surface adapter error");
        match err {
            OrchestratorError::Adapter { context, source } => {
                prop_assert!(context.contains("maker_create_reservation/send_raw_tx"));
                prop_assert_eq!(source.code, error.code);
                prop_assert_eq!(source.message.as_str(), error.message.as_str());
                prop_assert_eq!(source.adapter_code, error.adapter_code);
            }
            other => prop_assert!(false, "unexpected error variant: {other:?}"),
        }

        let state = orchestrator.state(reservation_id).expect("failed state");
        prop_assert_eq!(
            matches!(state, SwapState::Maker(MakerState::Failed { .. })),
            true
        );
        let events = adapter.events();
        prop_assert_eq!(
            events.iter().any(|event| matches!(
                event,
                SwapLifecycleEvent::ErrorOccurred { reservation_id: rid, message, .. }
                    if *rid == reservation_id && message.contains(&error.message)
            )),
            true
        );
    }

    /// Failed-state payload integrity for unrecoverable/internal failures.
    #[test]
    fn property11_9_failed_state_payload_integrity(error in arb_adapter_error(), reservation_id in any::<[u8; 32]>()) {
        let config = MockAdapterConfig {
            now: 1_000,
            failures: vec![InjectedFailure {
                point: FailurePoint::SendRawTx,
                error: error.clone(),
            }],
        };
        let (_adapter, orchestrator) = make_orchestrator(config, OrchestratorConfig::default());
        let _ = orchestrator.maker_create_reservation(ReservationParams {
            reservation_id,
            created_at: Some(10),
        });
        let state = orchestrator.state(reservation_id).expect("state");
        let expected_recoverable = matches!(
            error.code,
            ErrorCode::AdapterTimeout | ErrorCode::NetworkUnreachable
        );
        match state {
            SwapState::Maker(MakerState::Failed {
                error_code,
                reason,
                recoverable,
                ..
            }) => {
                prop_assert_eq!(error_code, error.code as i32);
                prop_assert!(reason.contains(&error.message));
                prop_assert_eq!(recoverable, expected_recoverable);
            }
            other => prop_assert!(false, "expected failed maker state, got {other:?}"),
        }
    }

    /// Timeout/economic outcomes transition to Refunded, never Failed.
    #[test]
    fn property11_9_timeout_paths_never_failed(case in arb_deadline_case()) {
        let adapter = MockAdapter::from_config(MockAdapterConfig::default());
        let role = match &case.state {
            SwapState::Maker(_) => SwapRole::Maker,
            SwapState::Taker(_) => SwapRole::Taker,
        };
        let bytes = checkpoint_bytes_for_state(role, case.reservation_id, &case.state, 10, 1, vec![]);
        adapter.insert_checkpoint(case.reservation_id, bytes);
        adapter.set_now(case.now);

        let orchestrator = SwapOrchestrator::new(adapter.clone(), case.config);
        let _ = orchestrator.resume(case.reservation_id).expect("resume");
        let _ = orchestrator.check_deadlines().expect("deadlines");
        let state = orchestrator.state(case.reservation_id).expect("state");
        prop_assert_eq!(
            matches!(
                state,
                SwapState::Maker(MakerState::Refunded { .. })
                    | SwapState::Taker(TakerState::Refunded { .. })
            ),
            true
        );
        prop_assert_eq!(
            matches!(
                state,
                SwapState::Maker(MakerState::Failed { .. })
                    | SwapState::Taker(TakerState::Failed { .. })
            ),
            false
        );
    }

    /// Generator sanity: checkpoint and mock config generators are well-formed.
    #[test]
    fn generators_produce_well_formed_values(
        generated in arb_generated_checkpoint(),
        config in arb_mock_adapter_config(),
    ) {
        let encoded = bincode::serialize(&generated.checkpoint).expect("serialize checkpoint");
        let decoded: SwapCheckpoint = bincode::deserialize(&encoded).expect("deserialize checkpoint");
        prop_assert_eq!(decoded.reservation_id, generated.reservation_id);
        prop_assert!(config.now <= 10_000);
        prop_assert!(config.failures.len() <= 4);
    }
}

#[test]
fn completion_event_contains_outcome_payload() {
    let reservation_id = reservation(0x55);
    let config = MockAdapterConfig::default();
    let adapter = MockAdapter::from_config(config);
    let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());

    execute_valid_prefix(&orchestrator, reservation_id, FlowPrefix::Maker(6));
    let events = adapter.events();
    assert!(events.iter().any(|event| matches!(
        event,
        SwapLifecycleEvent::SwapCompleted {
            reservation_id: rid,
            outcome: SwapOutcome::Settled,
        } if *rid == reservation_id
    )));
}
