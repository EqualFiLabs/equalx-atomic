//! Deterministic L2 swap orchestration with checkpointing and recovery.

use std::collections::HashMap;
use std::sync::Mutex;

use equalx_error::{AdapterError, ErrorCode};
use host_adapter::{Chain, HostAdapters, SwapLifecycleEvent, SwapOutcome};
use serde::{Deserialize, Serialize};

pub type ReservationId = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MakerState {
    Idle,
    ReservationCreated {
        reservation_id: ReservationId,
        created_at: u64,
    },
    HashlockSet {
        reservation_id: ReservationId,
        hashlock: [u8; 32],
    },
    ContextReceived {
        reservation_id: ReservationId,
        context_hash: [u8; 32],
    },
    PresigPublished {
        reservation_id: ReservationId,
        presig_hash: [u8; 32],
    },
    FinalSigReceived {
        reservation_id: ReservationId,
        monero_tx_id: [u8; 32],
    },
    TauExtracted {
        reservation_id: ReservationId,
        tau: [u8; 32],
    },
    Settled {
        reservation_id: ReservationId,
        settle_tx: [u8; 32],
    },
    Refunded {
        reservation_id: ReservationId,
    },
    Failed {
        reservation_id: ReservationId,
        error_code: i32,
        reason: String,
        recoverable: bool,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TakerState {
    Idle,
    ReservationAccepted {
        reservation_id: ReservationId,
        expiry: u64,
    },
    ContextPublished {
        reservation_id: ReservationId,
        context_hash: [u8; 32],
    },
    PresigReceived {
        reservation_id: ReservationId,
        presig_hash: [u8; 32],
    },
    SignatureCompleted {
        reservation_id: ReservationId,
    },
    MoneroTxBroadcast {
        reservation_id: ReservationId,
        monero_tx_id: [u8; 32],
    },
    FinalSigPublished {
        reservation_id: ReservationId,
    },
    Settled {
        reservation_id: ReservationId,
    },
    Refunded {
        reservation_id: ReservationId,
    },
    Failed {
        reservation_id: ReservationId,
        error_code: i32,
        reason: String,
        recoverable: bool,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapRole {
    Maker,
    Taker,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideEffectKind {
    EvmTxSubmitted,
    MoneroTxBroadcast,
    MailboxPublish,
    HashlockSet,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SideEffectRecord {
    pub kind: SideEffectKind,
    pub tx_hash: Option<[u8; 32]>,
    pub completed: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SwapCheckpoint {
    pub version: u8,
    pub role: SwapRole,
    pub reservation_id: ReservationId,
    pub state: Vec<u8>,
    pub timestamp: u64,
    pub sequence: u64,
    pub side_effects_log: Vec<SideEffectRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapState {
    Maker(MakerState),
    Taker(TakerState),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadlineEvent {
    pub reservation_id: ReservationId,
    pub deadline: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationParams {
    pub reservation_id: ReservationId,
    pub created_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoneroContext {
    pub context_hash: [u8; 32],
    pub wire_version: u16,
    pub envelope: Option<presig_envelope::Envelope>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchestratorConfig {
    pub checkpoint_version: u8,
    pub maker_timeout_secs: u64,
    pub taker_timeout_secs: u64,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            checkpoint_version: 1,
            maker_timeout_secs: 3600,
            taker_timeout_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestratorError {
    Adapter {
        context: String,
        source: AdapterError,
    },
    InvalidTransition {
        reservation_id: ReservationId,
        current_state: String,
        attempted: String,
    },
    SwapNotFound {
        reservation_id: ReservationId,
    },
    CheckpointCorrupted {
        reason: String,
    },
    Serialization {
        reason: String,
    },
}

impl OrchestratorError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Adapter { source, .. } => source.code,
            Self::InvalidTransition { .. } => ErrorCode::InvalidStateTransition,
            Self::SwapNotFound { .. } => ErrorCode::SwapNotFound,
            Self::CheckpointCorrupted { .. } => ErrorCode::CheckpointCorrupted,
            Self::Serialization { .. } => ErrorCode::CheckpointCorrupted,
        }
    }
}

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adapter { context, source } => {
                write!(f, "adapter error during {context}: {source}")
            }
            Self::InvalidTransition {
                reservation_id,
                current_state,
                attempted,
            } => write!(
                f,
                "invalid transition for reservation {}: state={current_state}, attempted={attempted}",
                hex::encode(reservation_id),
            ),
            Self::SwapNotFound { reservation_id } => {
                write!(f, "swap not found: {}", hex::encode(reservation_id))
            }
            Self::CheckpointCorrupted { reason } => write!(f, "checkpoint corrupted: {reason}"),
            Self::Serialization { reason } => write!(f, "serialization error: {reason}"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

type Result<T> = std::result::Result<T, OrchestratorError>;

#[derive(Clone, Debug)]
struct RuntimeSwap {
    role: SwapRole,
    state: SwapState,
    sequence: u64,
    side_effects_log: Vec<SideEffectRecord>,
    timestamp: u64,
}

impl RuntimeSwap {
    fn maker() -> Self {
        Self {
            role: SwapRole::Maker,
            state: SwapState::Maker(MakerState::Idle),
            sequence: 0,
            side_effects_log: Vec::new(),
            timestamp: 0,
        }
    }

    fn taker() -> Self {
        Self {
            role: SwapRole::Taker,
            state: SwapState::Taker(TakerState::Idle),
            sequence: 0,
            side_effects_log: Vec::new(),
            timestamp: 0,
        }
    }
}

pub struct SwapOrchestrator<A: HostAdapters> {
    adapters: A,
    config: OrchestratorConfig,
    swaps: Mutex<HashMap<ReservationId, RuntimeSwap>>,
}

impl<A: HostAdapters> SwapOrchestrator<A> {
    pub fn new(adapters: A, config: OrchestratorConfig) -> Self {
        Self {
            adapters,
            config,
            swaps: Mutex::new(HashMap::new()),
        }
    }

    pub fn state(&self, reservation_id: ReservationId) -> Option<SwapState> {
        let swaps = self.swaps.lock().expect("mutex poisoned");
        swaps.get(&reservation_id).map(|entry| entry.state.clone())
    }

    pub fn side_effects(&self, reservation_id: ReservationId) -> Option<Vec<SideEffectRecord>> {
        let swaps = self.swaps.lock().expect("mutex poisoned");
        swaps
            .get(&reservation_id)
            .map(|entry| entry.side_effects_log.clone())
    }

    pub fn maker_create_reservation(&self, params: ReservationParams) -> Result<ReservationId> {
        let reservation_id = params.reservation_id;
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .entry(reservation_id)
            .or_insert_with(RuntimeSwap::maker);
        if runtime.role != SwapRole::Maker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_create_reservation",
            ));
        }

        let current_stage = match &runtime.state {
            SwapState::Maker(state) => maker_stage(state),
            _ => 0,
        };
        if current_stage >= 1 {
            return Ok(reservation_id);
        }
        if !matches!(runtime.state, SwapState::Maker(MakerState::Idle)) {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_create_reservation",
            ));
        }

        let created_at = match params.created_at {
            Some(ts) => ts,
            None => self.adapters.current_timestamp().map_err(|err| {
                self.wrap_adapter("maker_create_reservation/current_timestamp", err)
            })?,
        };
        let tx_payload = command_payload("maker_create_reservation", reservation_id, None);
        let tx_hash = match self.adapters.send_raw_tx(&tx_payload) {
            Ok(tx_hash) => tx_hash,
            Err(err) => {
                self.fail_swap(
                    reservation_id,
                    runtime,
                    "maker_create_reservation/send_raw_tx",
                    err.clone(),
                );
                return Err(self.wrap_adapter("maker_create_reservation/send_raw_tx", err));
            }
        };
        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
            reservation_id,
            chain: Chain::Evm,
            tx_hash,
        });

        let next = SwapState::Maker(MakerState::ReservationCreated {
            reservation_id,
            created_at,
        });
        self.transition(
            reservation_id,
            runtime,
            next,
            Some(SideEffectRecord {
                kind: SideEffectKind::EvmTxSubmitted,
                tx_hash: Some(tx_hash),
                completed: true,
            }),
        )?;
        Ok(reservation_id)
    }

    pub fn maker_set_hashlock(&self, reservation_id: ReservationId) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Maker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_set_hashlock",
            ));
        }
        let stage = match &runtime.state {
            SwapState::Maker(state) => maker_stage(state),
            _ => 0,
        };
        if stage >= 2 {
            return Ok(());
        }
        if stage != 1 {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_set_hashlock",
            ));
        }

        let tau = derive_tau_for_reservation(reservation_id);
        let hashlock = equalx_sdk::compute_hashlock(&tau);
        let tx_payload = command_payload("maker_set_hashlock", reservation_id, Some(&hashlock));
        let tx_hash = match self.adapters.send_raw_tx(&tx_payload) {
            Ok(tx_hash) => tx_hash,
            Err(err) => {
                self.fail_swap(
                    reservation_id,
                    runtime,
                    "maker_set_hashlock/send_raw_tx",
                    err.clone(),
                );
                return Err(self.wrap_adapter("maker_set_hashlock/send_raw_tx", err));
            }
        };
        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
            reservation_id,
            chain: Chain::Evm,
            tx_hash,
        });
        let next = SwapState::Maker(MakerState::HashlockSet {
            reservation_id,
            hashlock,
        });
        self.transition(
            reservation_id,
            runtime,
            next,
            Some(SideEffectRecord {
                kind: SideEffectKind::HashlockSet,
                tx_hash: Some(tx_hash),
                completed: true,
            }),
        )
    }

    pub fn maker_handle_context(&self, reservation_id: ReservationId) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Maker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_handle_context",
            ));
        }

        let stage = match &runtime.state {
            SwapState::Maker(state) => maker_stage(state),
            _ => 0,
        };
        if stage >= 3 {
            return Ok(());
        }
        if stage != 2 {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_handle_context",
            ));
        }

        if let Err(err) = self.adapters.block_number() {
            self.fail_swap(
                reservation_id,
                runtime,
                "maker_handle_context/block_number",
                err.clone(),
            );
            return Err(self.wrap_adapter("maker_handle_context/block_number", err));
        }
        let context_hash = derive_tagged_hash(reservation_id, b"context");
        let next = SwapState::Maker(MakerState::ContextReceived {
            reservation_id,
            context_hash,
        });
        self.transition(reservation_id, runtime, next, None)
    }

    pub fn maker_publish_presig(&self, reservation_id: ReservationId) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Maker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_publish_presig",
            ));
        }

        let stage = match &runtime.state {
            SwapState::Maker(state) => maker_stage(state),
            _ => 0,
        };
        if stage >= 4 {
            return Ok(());
        }
        if stage != 3 {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_publish_presig",
            ));
        }

        let mut seed = [0u8; 32];
        seed[..2].copy_from_slice(&adaptor_clsag::WIRE_VERSION.to_be_bytes());
        seed[2..].copy_from_slice(&reservation_id[..30]);
        let tx_payload = command_payload("maker_publish_presig", reservation_id, Some(&seed));
        let tx_hash = match self.adapters.send_raw_tx(&tx_payload) {
            Ok(tx_hash) => tx_hash,
            Err(err) => {
                self.fail_swap(
                    reservation_id,
                    runtime,
                    "maker_publish_presig/send_raw_tx",
                    err.clone(),
                );
                return Err(self.wrap_adapter("maker_publish_presig/send_raw_tx", err));
            }
        };
        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
            reservation_id,
            chain: Chain::Evm,
            tx_hash,
        });
        let next = SwapState::Maker(MakerState::PresigPublished {
            reservation_id,
            presig_hash: seed,
        });
        self.transition(
            reservation_id,
            runtime,
            next,
            Some(SideEffectRecord {
                kind: SideEffectKind::MailboxPublish,
                tx_hash: Some(tx_hash),
                completed: true,
            }),
        )
    }

    pub fn maker_handle_final_sig(&self, reservation_id: ReservationId) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Maker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_handle_final_sig",
            ));
        }

        let stage = match &runtime.state {
            SwapState::Maker(state) => maker_stage(state),
            _ => 0,
        };
        if stage >= 5 {
            return Ok(());
        }
        if stage != 4 {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "maker_handle_final_sig",
            ));
        }

        if let Err(err) = self.adapters.node_health() {
            self.fail_swap(
                reservation_id,
                runtime,
                "maker_handle_final_sig/node_health",
                err.clone(),
            );
            return Err(self.wrap_adapter("maker_handle_final_sig/node_health", err));
        }
        let monero_tx_id = derive_tagged_hash(reservation_id, b"monero-final");
        let next = SwapState::Maker(MakerState::FinalSigReceived {
            reservation_id,
            monero_tx_id,
        });
        self.transition(reservation_id, runtime, next, None)
    }

    pub fn maker_settle(&self, reservation_id: ReservationId) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Maker {
            return Err(self.invalid_transition(reservation_id, &runtime.state, "maker_settle"));
        }

        loop {
            let stage = match &runtime.state {
                SwapState::Maker(state) => maker_stage(state),
                _ => 0,
            };
            if stage >= 7 {
                return Ok(());
            }
            if stage < 5 {
                return Err(self.invalid_transition(
                    reservation_id,
                    &runtime.state,
                    "maker_settle",
                ));
            }
            if stage == 5 {
                let tau = derive_tau_for_reservation(reservation_id);
                let next = SwapState::Maker(MakerState::TauExtracted {
                    reservation_id,
                    tau,
                });
                self.transition(reservation_id, runtime, next, None)?;
                continue;
            }

            let tau = match &runtime.state {
                SwapState::Maker(MakerState::TauExtracted { tau, .. }) => *tau,
                _ => [0u8; 32],
            };
            let tx_payload = command_payload("maker_settle", reservation_id, Some(&tau));
            let tx_hash = match self.adapters.send_raw_tx(&tx_payload) {
                Ok(tx_hash) => tx_hash,
                Err(err) => {
                    self.fail_swap(
                        reservation_id,
                        runtime,
                        "maker_settle/send_raw_tx",
                        err.clone(),
                    );
                    return Err(self.wrap_adapter("maker_settle/send_raw_tx", err));
                }
            };
            self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
                reservation_id,
                chain: Chain::Evm,
                tx_hash,
            });
            let next = SwapState::Maker(MakerState::Settled {
                reservation_id,
                settle_tx: tx_hash,
            });
            self.transition(
                reservation_id,
                runtime,
                next,
                Some(SideEffectRecord {
                    kind: SideEffectKind::EvmTxSubmitted,
                    tx_hash: Some(tx_hash),
                    completed: true,
                }),
            )?;
            return Ok(());
        }
    }

    pub fn taker_accept_reservation(&self, reservation_id: ReservationId) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .entry(reservation_id)
            .or_insert_with(RuntimeSwap::taker);
        if runtime.role != SwapRole::Taker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_accept_reservation",
            ));
        }

        let stage = match &runtime.state {
            SwapState::Taker(state) => taker_stage(state),
            _ => 0,
        };
        if stage >= 1 {
            return Ok(());
        }
        if !matches!(runtime.state, SwapState::Taker(TakerState::Idle)) {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_accept_reservation",
            ));
        }

        let now = self
            .adapters
            .current_timestamp()
            .map_err(|err| self.wrap_adapter("taker_accept_reservation/current_timestamp", err))?;
        let expiry = now.saturating_add(self.config.taker_timeout_secs);
        let tx_payload = command_payload("taker_accept_reservation", reservation_id, None);
        let tx_hash = match self.adapters.send_raw_tx(&tx_payload) {
            Ok(tx_hash) => tx_hash,
            Err(err) => {
                self.fail_swap(
                    reservation_id,
                    runtime,
                    "taker_accept_reservation/send_raw_tx",
                    err.clone(),
                );
                return Err(self.wrap_adapter("taker_accept_reservation/send_raw_tx", err));
            }
        };
        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
            reservation_id,
            chain: Chain::Evm,
            tx_hash,
        });
        let next = SwapState::Taker(TakerState::ReservationAccepted {
            reservation_id,
            expiry,
        });
        self.transition(
            reservation_id,
            runtime,
            next,
            Some(SideEffectRecord {
                kind: SideEffectKind::EvmTxSubmitted,
                tx_hash: Some(tx_hash),
                completed: true,
            }),
        )
    }

    pub fn taker_publish_context(
        &self,
        reservation_id: ReservationId,
        context: MoneroContext,
    ) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Taker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_publish_context",
            ));
        }
        let stage = match &runtime.state {
            SwapState::Taker(state) => taker_stage(state),
            _ => 0,
        };
        if stage >= 2 {
            return Ok(());
        }
        if stage != 1 {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_publish_context",
            ));
        }

        let tx_payload = command_payload(
            "taker_publish_context",
            reservation_id,
            Some(&context.context_hash),
        );
        let tx_hash = match self.adapters.send_raw_tx(&tx_payload) {
            Ok(tx_hash) => tx_hash,
            Err(err) => {
                self.fail_swap(
                    reservation_id,
                    runtime,
                    "taker_publish_context/send_raw_tx",
                    err.clone(),
                );
                return Err(self.wrap_adapter("taker_publish_context/send_raw_tx", err));
            }
        };
        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
            reservation_id,
            chain: Chain::Evm,
            tx_hash,
        });
        let next = SwapState::Taker(TakerState::ContextPublished {
            reservation_id,
            context_hash: context.context_hash,
        });
        self.transition(
            reservation_id,
            runtime,
            next,
            Some(SideEffectRecord {
                kind: SideEffectKind::MailboxPublish,
                tx_hash: Some(tx_hash),
                completed: true,
            }),
        )
    }

    pub fn taker_handle_presig(&self, reservation_id: ReservationId) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Taker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_handle_presig",
            ));
        }
        let stage = match &runtime.state {
            SwapState::Taker(state) => taker_stage(state),
            _ => 0,
        };
        if stage >= 3 {
            return Ok(());
        }
        if stage != 2 {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_handle_presig",
            ));
        }

        if let Err(err) = self.adapters.block_number() {
            self.fail_swap(
                reservation_id,
                runtime,
                "taker_handle_presig/block_number",
                err.clone(),
            );
            return Err(self.wrap_adapter("taker_handle_presig/block_number", err));
        }
        let mut presig_hash = [0u8; 32];
        presig_hash[..2].copy_from_slice(&adaptor_clsag::WIRE_VERSION.to_be_bytes());
        presig_hash[2..].copy_from_slice(&reservation_id[..30]);
        let next = SwapState::Taker(TakerState::PresigReceived {
            reservation_id,
            presig_hash,
        });
        self.transition(reservation_id, runtime, next, None)
    }

    pub fn taker_complete_and_broadcast(&self, reservation_id: ReservationId) -> Result<[u8; 32]> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Taker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_complete_and_broadcast",
            ));
        }

        loop {
            let stage = match &runtime.state {
                SwapState::Taker(state) => taker_stage(state),
                _ => 0,
            };
            if stage >= 5 {
                let broadcasted = monero_tx_for_state(&runtime.state)
                    .or_else(|| {
                        runtime.side_effects_log.iter().rev().find_map(|r| {
                            if r.kind == SideEffectKind::MoneroTxBroadcast {
                                r.tx_hash
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or([0u8; 32]);
                return Ok(broadcasted);
            }
            if stage < 3 {
                return Err(self.invalid_transition(
                    reservation_id,
                    &runtime.state,
                    "taker_complete_and_broadcast",
                ));
            }
            if stage == 3 {
                let next = SwapState::Taker(TakerState::SignatureCompleted { reservation_id });
                self.transition(reservation_id, runtime, next, None)?;
                continue;
            }

            let payload = command_payload("taker_complete_and_broadcast", reservation_id, None);
            let tx_hash = match self.adapters.broadcast_tx(&payload) {
                Ok(tx_hash) => tx_hash,
                Err(err) => {
                    self.fail_swap(
                        reservation_id,
                        runtime,
                        "taker_complete_and_broadcast/broadcast_tx",
                        err.clone(),
                    );
                    return Err(self.wrap_adapter("taker_complete_and_broadcast/broadcast_tx", err));
                }
            };
            self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
                reservation_id,
                chain: Chain::Monero,
                tx_hash,
            });
            let next = SwapState::Taker(TakerState::MoneroTxBroadcast {
                reservation_id,
                monero_tx_id: tx_hash,
            });
            self.transition(
                reservation_id,
                runtime,
                next,
                Some(SideEffectRecord {
                    kind: SideEffectKind::MoneroTxBroadcast,
                    tx_hash: Some(tx_hash),
                    completed: true,
                }),
            )?;
            return Ok(tx_hash);
        }
    }

    pub fn taker_publish_final_sig(
        &self,
        reservation_id: ReservationId,
        monero_tx_id: [u8; 32],
    ) -> Result<()> {
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let runtime = swaps
            .get_mut(&reservation_id)
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        if runtime.role != SwapRole::Taker {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_publish_final_sig",
            ));
        }
        let stage = match &runtime.state {
            SwapState::Taker(state) => taker_stage(state),
            _ => 0,
        };
        if stage >= 6 {
            return Ok(());
        }
        if stage != 5 {
            return Err(self.invalid_transition(
                reservation_id,
                &runtime.state,
                "taker_publish_final_sig",
            ));
        }

        let payload = command_payload(
            "taker_publish_final_sig",
            reservation_id,
            Some(&monero_tx_id),
        );
        let tx_hash = match self.adapters.send_raw_tx(&payload) {
            Ok(tx_hash) => tx_hash,
            Err(err) => {
                self.fail_swap(
                    reservation_id,
                    runtime,
                    "taker_publish_final_sig/send_raw_tx",
                    err.clone(),
                );
                return Err(self.wrap_adapter("taker_publish_final_sig/send_raw_tx", err));
            }
        };
        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
            reservation_id,
            chain: Chain::Evm,
            tx_hash,
        });
        let next = SwapState::Taker(TakerState::FinalSigPublished { reservation_id });
        self.transition(
            reservation_id,
            runtime,
            next,
            Some(SideEffectRecord {
                kind: SideEffectKind::MailboxPublish,
                tx_hash: Some(tx_hash),
                completed: true,
            }),
        )
    }

    pub fn resume(&self, reservation_id: ReservationId) -> Result<SwapState> {
        let bytes = self
            .adapters
            .load_checkpoint(&reservation_id)
            .map_err(|err| self.wrap_adapter("resume/load_checkpoint", err))?
            .ok_or(OrchestratorError::SwapNotFound { reservation_id })?;
        let checkpoint: SwapCheckpoint =
            bincode::deserialize(&bytes).map_err(|err| OrchestratorError::CheckpointCorrupted {
                reason: err.to_string(),
            })?;
        if checkpoint.reservation_id != reservation_id {
            return Err(OrchestratorError::CheckpointCorrupted {
                reason: "reservation id mismatch in checkpoint".into(),
            });
        }
        let state = decode_state(checkpoint.role, &checkpoint.state)?;
        let runtime = RuntimeSwap {
            role: checkpoint.role,
            state: state.clone(),
            sequence: checkpoint.sequence,
            side_effects_log: checkpoint.side_effects_log,
            timestamp: checkpoint.timestamp,
        };
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        swaps.insert(reservation_id, runtime);
        Ok(state)
    }

    pub fn check_deadlines(&self) -> Result<Vec<DeadlineEvent>> {
        let now = self
            .adapters
            .current_timestamp()
            .map_err(|err| self.wrap_adapter("check_deadlines/current_timestamp", err))?;
        let mut swaps = self.swaps.lock().expect("mutex poisoned");
        let mut events = Vec::new();
        let ids: Vec<ReservationId> = swaps.keys().copied().collect();

        for reservation_id in ids {
            let Some(runtime) = swaps.get_mut(&reservation_id) else {
                continue;
            };
            match runtime.state.clone() {
                SwapState::Maker(MakerState::ReservationCreated { created_at, .. }) => {
                    let deadline = created_at.saturating_add(self.config.maker_timeout_secs);
                    if now > deadline {
                        let tx_payload = command_payload("maker_refund", reservation_id, None);
                        let tx_hash = self.adapters.send_raw_tx(&tx_payload).map_err(|err| {
                            self.wrap_adapter("check_deadlines/maker_refund/send_raw_tx", err)
                        })?;
                        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
                            reservation_id,
                            chain: Chain::Evm,
                            tx_hash,
                        });
                        self.adapters
                            .on_event(SwapLifecycleEvent::DeadlineExceeded {
                                reservation_id,
                                deadline,
                            });
                        events.push(DeadlineEvent {
                            reservation_id,
                            deadline,
                        });
                        let next = SwapState::Maker(MakerState::Refunded { reservation_id });
                        self.transition(
                            reservation_id,
                            runtime,
                            next,
                            Some(SideEffectRecord {
                                kind: SideEffectKind::EvmTxSubmitted,
                                tx_hash: Some(tx_hash),
                                completed: true,
                            }),
                        )?;
                    }
                }
                SwapState::Taker(TakerState::ReservationAccepted { expiry, .. }) => {
                    if now > expiry {
                        let tx_payload = command_payload("taker_refund", reservation_id, None);
                        let tx_hash = self.adapters.send_raw_tx(&tx_payload).map_err(|err| {
                            self.wrap_adapter("check_deadlines/taker_refund/send_raw_tx", err)
                        })?;
                        self.adapters.on_event(SwapLifecycleEvent::TxSubmitted {
                            reservation_id,
                            chain: Chain::Evm,
                            tx_hash,
                        });
                        self.adapters
                            .on_event(SwapLifecycleEvent::DeadlineExceeded {
                                reservation_id,
                                deadline: expiry,
                            });
                        events.push(DeadlineEvent {
                            reservation_id,
                            deadline: expiry,
                        });
                        let next = SwapState::Taker(TakerState::Refunded { reservation_id });
                        self.transition(
                            reservation_id,
                            runtime,
                            next,
                            Some(SideEffectRecord {
                                kind: SideEffectKind::EvmTxSubmitted,
                                tx_hash: Some(tx_hash),
                                completed: true,
                            }),
                        )?;
                    }
                }
                _ => {}
            }
        }
        Ok(events)
    }

    fn transition(
        &self,
        reservation_id: ReservationId,
        runtime: &mut RuntimeSwap,
        next_state: SwapState,
        side_effect: Option<SideEffectRecord>,
    ) -> Result<()> {
        let from = state_name(&runtime.state).to_string();
        let to = state_name(&next_state).to_string();
        let mut side_effects = runtime.side_effects_log.clone();
        if let Some(effect) = side_effect {
            side_effects.push(effect);
        }
        let timestamp = self
            .adapters
            .current_timestamp()
            .map_err(|err| self.wrap_adapter("transition/current_timestamp", err))?;
        let sequence = runtime.sequence.saturating_add(1);
        let state_bytes = encode_state(&next_state)?;
        let checkpoint = SwapCheckpoint {
            version: self.config.checkpoint_version,
            role: runtime.role,
            reservation_id,
            state: state_bytes,
            timestamp,
            sequence,
            side_effects_log: side_effects.clone(),
        };
        let checkpoint_bytes =
            bincode::serialize(&checkpoint).map_err(|err| OrchestratorError::Serialization {
                reason: err.to_string(),
            })?;
        self.adapters
            .save_checkpoint(&reservation_id, &checkpoint_bytes)
            .map_err(|err| self.wrap_adapter("transition/save_checkpoint", err))?;

        runtime.state = next_state;
        runtime.sequence = sequence;
        runtime.timestamp = timestamp;
        runtime.side_effects_log = side_effects;
        self.adapters.on_event(SwapLifecycleEvent::StateTransition {
            from,
            to,
            reservation_id,
        });
        if let Some(outcome) = terminal_outcome(&runtime.state) {
            self.adapters.on_event(SwapLifecycleEvent::SwapCompleted {
                reservation_id,
                outcome,
            });
        }
        Ok(())
    }

    fn invalid_transition(
        &self,
        reservation_id: ReservationId,
        state: &SwapState,
        attempted: &str,
    ) -> OrchestratorError {
        OrchestratorError::InvalidTransition {
            reservation_id,
            current_state: state_name(state).to_string(),
            attempted: attempted.to_string(),
        }
    }

    fn wrap_adapter(&self, context: &str, source: AdapterError) -> OrchestratorError {
        OrchestratorError::Adapter {
            context: context.to_string(),
            source,
        }
    }

    fn fail_swap(
        &self,
        reservation_id: ReservationId,
        runtime: &mut RuntimeSwap,
        context: &str,
        source: AdapterError,
    ) {
        self.adapters.on_event(SwapLifecycleEvent::ErrorOccurred {
            reservation_id,
            error_code: source.code as i32,
            message: format!("{context}: {}", source.message),
        });
        let recoverable = matches!(
            source.code,
            ErrorCode::AdapterTimeout | ErrorCode::NetworkUnreachable
        );
        let failed_state = match runtime.role {
            SwapRole::Maker => SwapState::Maker(MakerState::Failed {
                reservation_id,
                error_code: source.code as i32,
                reason: format!("{context}: {}", source.message),
                recoverable,
            }),
            SwapRole::Taker => SwapState::Taker(TakerState::Failed {
                reservation_id,
                error_code: source.code as i32,
                reason: format!("{context}: {}", source.message),
                recoverable,
            }),
        };
        let _ = self.transition(reservation_id, runtime, failed_state, None);
    }
}

fn encode_state(state: &SwapState) -> Result<Vec<u8>> {
    match state {
        SwapState::Maker(state) => {
            bincode::serialize(state).map_err(|err| OrchestratorError::Serialization {
                reason: err.to_string(),
            })
        }
        SwapState::Taker(state) => {
            bincode::serialize(state).map_err(|err| OrchestratorError::Serialization {
                reason: err.to_string(),
            })
        }
    }
}

fn decode_state(role: SwapRole, bytes: &[u8]) -> Result<SwapState> {
    match role {
        SwapRole::Maker => {
            let state: MakerState = bincode::deserialize(bytes).map_err(|err| {
                OrchestratorError::CheckpointCorrupted {
                    reason: err.to_string(),
                }
            })?;
            Ok(SwapState::Maker(state))
        }
        SwapRole::Taker => {
            let state: TakerState = bincode::deserialize(bytes).map_err(|err| {
                OrchestratorError::CheckpointCorrupted {
                    reason: err.to_string(),
                }
            })?;
            Ok(SwapState::Taker(state))
        }
    }
}

fn state_name(state: &SwapState) -> &'static str {
    match state {
        SwapState::Maker(MakerState::Idle) => "Idle",
        SwapState::Maker(MakerState::ReservationCreated { .. }) => "ReservationCreated",
        SwapState::Maker(MakerState::HashlockSet { .. }) => "HashlockSet",
        SwapState::Maker(MakerState::ContextReceived { .. }) => "ContextReceived",
        SwapState::Maker(MakerState::PresigPublished { .. }) => "PresigPublished",
        SwapState::Maker(MakerState::FinalSigReceived { .. }) => "FinalSigReceived",
        SwapState::Maker(MakerState::TauExtracted { .. }) => "TauExtracted",
        SwapState::Maker(MakerState::Settled { .. }) => "Settled",
        SwapState::Maker(MakerState::Refunded { .. }) => "Refunded",
        SwapState::Maker(MakerState::Failed { .. }) => "Failed",
        SwapState::Taker(TakerState::Idle) => "Idle",
        SwapState::Taker(TakerState::ReservationAccepted { .. }) => "ReservationAccepted",
        SwapState::Taker(TakerState::ContextPublished { .. }) => "ContextPublished",
        SwapState::Taker(TakerState::PresigReceived { .. }) => "PresigReceived",
        SwapState::Taker(TakerState::SignatureCompleted { .. }) => "SignatureCompleted",
        SwapState::Taker(TakerState::MoneroTxBroadcast { .. }) => "MoneroTxBroadcast",
        SwapState::Taker(TakerState::FinalSigPublished { .. }) => "FinalSigPublished",
        SwapState::Taker(TakerState::Settled { .. }) => "Settled",
        SwapState::Taker(TakerState::Refunded { .. }) => "Refunded",
        SwapState::Taker(TakerState::Failed { .. }) => "Failed",
    }
}

fn maker_stage(state: &MakerState) -> u8 {
    match state {
        MakerState::Idle => 0,
        MakerState::ReservationCreated { .. } => 1,
        MakerState::HashlockSet { .. } => 2,
        MakerState::ContextReceived { .. } => 3,
        MakerState::PresigPublished { .. } => 4,
        MakerState::FinalSigReceived { .. } => 5,
        MakerState::TauExtracted { .. } => 6,
        MakerState::Settled { .. } => 7,
        MakerState::Refunded { .. } => 8,
        MakerState::Failed { .. } => 9,
    }
}

fn taker_stage(state: &TakerState) -> u8 {
    match state {
        TakerState::Idle => 0,
        TakerState::ReservationAccepted { .. } => 1,
        TakerState::ContextPublished { .. } => 2,
        TakerState::PresigReceived { .. } => 3,
        TakerState::SignatureCompleted { .. } => 4,
        TakerState::MoneroTxBroadcast { .. } => 5,
        TakerState::FinalSigPublished { .. } => 6,
        TakerState::Settled { .. } => 7,
        TakerState::Refunded { .. } => 8,
        TakerState::Failed { .. } => 9,
    }
}

fn monero_tx_for_state(state: &SwapState) -> Option<[u8; 32]> {
    match state {
        SwapState::Taker(TakerState::MoneroTxBroadcast { monero_tx_id, .. }) => Some(*monero_tx_id),
        _ => None,
    }
}

fn terminal_outcome(state: &SwapState) -> Option<SwapOutcome> {
    match state {
        SwapState::Maker(MakerState::Settled { .. })
        | SwapState::Taker(TakerState::Settled { .. }) => Some(SwapOutcome::Settled),
        SwapState::Maker(MakerState::Refunded { .. })
        | SwapState::Taker(TakerState::Refunded { .. }) => Some(SwapOutcome::Refunded),
        SwapState::Maker(MakerState::Failed {
            error_code,
            reason,
            recoverable,
            ..
        })
        | SwapState::Taker(TakerState::Failed {
            error_code,
            reason,
            recoverable,
            ..
        }) => Some(SwapOutcome::Failed {
            error_code: *error_code,
            reason: reason.clone(),
            recoverable: *recoverable,
        }),
        _ => None,
    }
}

fn command_payload(
    command: &str,
    reservation_id: ReservationId,
    suffix: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(command.len() + 64);
    out.extend_from_slice(command.as_bytes());
    out.extend_from_slice(&reservation_id);
    if let Some(suffix) = suffix {
        out.extend_from_slice(suffix);
    }
    out
}

fn derive_tagged_hash(seed: [u8; 32], tag: &[u8]) -> [u8; 32] {
    let mut out = seed;
    for (index, byte) in tag.iter().enumerate() {
        out[index % 32] ^= *byte;
    }
    out
}

fn derive_tau_for_reservation(reservation_id: ReservationId) -> [u8; 32] {
    derive_tagged_hash(reservation_id, b"tau")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use host_adapter::{
        EvmCall, EvmExecutionAdapter, KeyIdentityAdapter, LogEntry, LogFilter,
        MoneroExecutionAdapter, NodeHealth, PersistenceAdapter, SpendState, TimeNetworkAdapter,
        TxReceipt, UxEventAdapter,
    };

    #[derive(Clone, Default)]
    struct MockAdapter {
        inner: Arc<Mutex<Inner>>,
    }

    #[derive(Default)]
    struct Inner {
        now: u64,
        checkpoints: HashMap<ReservationId, Vec<u8>>,
        events: Vec<SwapLifecycleEvent>,
        evm_send_calls: usize,
        evm_payloads: Vec<Vec<u8>>,
        monero_broadcast_calls: usize,
        fail_next_send: Option<AdapterError>,
    }

    impl MockAdapter {
        fn with_time(now: u64) -> Self {
            Self {
                inner: Arc::new(Mutex::new(Inner {
                    now,
                    ..Inner::default()
                })),
            }
        }

        fn set_time(&self, now: u64) {
            self.inner.lock().expect("mutex").now = now;
        }

        fn fail_next_send(&self, err: AdapterError) {
            self.inner.lock().expect("mutex").fail_next_send = Some(err);
        }

        fn evm_send_calls(&self) -> usize {
            self.inner.lock().expect("mutex").evm_send_calls
        }

        fn evm_payloads(&self) -> Vec<Vec<u8>> {
            self.inner.lock().expect("mutex").evm_payloads.clone()
        }

        fn monero_broadcast_calls(&self) -> usize {
            self.inner.lock().expect("mutex").monero_broadcast_calls
        }

        fn events(&self) -> Vec<SwapLifecycleEvent> {
            self.inner.lock().expect("mutex").events.clone()
        }

        fn checkpoint_bytes(&self, reservation_id: ReservationId) -> Vec<u8> {
            self.inner
                .lock()
                .expect("mutex")
                .checkpoints
                .get(&reservation_id)
                .cloned()
                .expect("checkpoint")
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

        fn monero_derive_subaddress(
            &self,
            major: u32,
            minor: u32,
        ) -> host_adapter::Result<Vec<u8>> {
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
        fn send_raw_tx(&self, signed_tx: &[u8]) -> host_adapter::Result<[u8; 32]> {
            let mut inner = self.inner.lock().expect("mutex");
            if let Some(err) = inner.fail_next_send.take() {
                return Err(err);
            }
            inner.evm_send_calls += 1;
            inner.evm_payloads.push(signed_tx.to_vec());
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
            Ok(500)
        }

        fn gas_price(&self) -> host_adapter::Result<u128> {
            Ok(1_000_000_000)
        }
    }

    impl MoneroExecutionAdapter for MockAdapter {
        fn broadcast_tx(&self, _tx_blob: &[u8]) -> host_adapter::Result<[u8; 32]> {
            let mut inner = self.inner.lock().expect("mutex");
            inner.monero_broadcast_calls += 1;
            let mut hash = [0u8; 32];
            hash[0] = inner.monero_broadcast_calls as u8;
            hash[1] = 0xAA;
            Ok(hash)
        }

        fn is_key_image_spent(
            &self,
            key_images: &[[u8; 32]],
        ) -> host_adapter::Result<Vec<SpendState>> {
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
        fn save_checkpoint(
            &self,
            reservation_id: &[u8; 32],
            state: &[u8],
        ) -> host_adapter::Result<()> {
            self.inner
                .lock()
                .expect("mutex")
                .checkpoints
                .insert(*reservation_id, state.to_vec());
            Ok(())
        }

        fn load_checkpoint(
            &self,
            reservation_id: &[u8; 32],
        ) -> host_adapter::Result<Option<Vec<u8>>> {
            Ok(self
                .inner
                .lock()
                .expect("mutex")
                .checkpoints
                .get(reservation_id)
                .cloned())
        }

        fn list_active_swaps(&self) -> host_adapter::Result<Vec<[u8; 32]>> {
            Ok(self
                .inner
                .lock()
                .expect("mutex")
                .checkpoints
                .keys()
                .copied()
                .collect())
        }

        fn delete_swap(&self, reservation_id: &[u8; 32]) -> host_adapter::Result<()> {
            self.inner
                .lock()
                .expect("mutex")
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
            Ok(self.inner.lock().expect("mutex").now)
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
            self.inner.lock().expect("mutex").events.push(event);
        }
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

    #[test]
    fn maker_flow_transitions_and_persists() {
        let adapter = MockAdapter::with_time(1_000);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let rid = reservation(1);

        orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(100),
            })
            .expect("create");
        orchestrator.maker_set_hashlock(rid).expect("hashlock");
        orchestrator.maker_handle_context(rid).expect("context");
        orchestrator.maker_publish_presig(rid).expect("presig");
        orchestrator.maker_handle_final_sig(rid).expect("final sig");
        orchestrator.maker_settle(rid).expect("settle");

        let state = orchestrator.state(rid).expect("state");
        assert!(matches!(
            state,
            SwapState::Maker(MakerState::Settled { .. })
        ));
        assert!(adapter.evm_send_calls() >= 4);

        let checkpoint_bytes = adapter.checkpoint_bytes(rid);
        let checkpoint: SwapCheckpoint =
            bincode::deserialize(&checkpoint_bytes).expect("checkpoint");
        assert_eq!(checkpoint.role, SwapRole::Maker);
        assert!(checkpoint.sequence >= 7);
        assert!(checkpoint.side_effects_log.len() >= 4);
    }

    #[test]
    fn maker_hashlock_and_settle_use_same_tau_preimage() {
        let adapter = MockAdapter::with_time(1_000);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let rid = reservation(0x21);
        let expected_tau = derive_tau_for_reservation(rid);
        let expected_hashlock = equalx_sdk::compute_hashlock(&expected_tau);

        orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(100),
            })
            .expect("create");
        orchestrator.maker_set_hashlock(rid).expect("hashlock");

        let state_after_hashlock = orchestrator.state(rid).expect("state after hashlock");
        assert!(matches!(
            state_after_hashlock,
            SwapState::Maker(MakerState::HashlockSet { hashlock, .. }) if hashlock == expected_hashlock
        ));

        orchestrator.maker_handle_context(rid).expect("context");
        orchestrator.maker_publish_presig(rid).expect("presig");
        orchestrator.maker_handle_final_sig(rid).expect("final sig");
        orchestrator.maker_settle(rid).expect("settle");

        let payloads = adapter.evm_payloads();
        let hashlock_payload = payloads
            .iter()
            .find(|payload| payload.starts_with(b"maker_set_hashlock"))
            .expect("maker_set_hashlock payload");
        assert!(
            hashlock_payload.ends_with(&expected_hashlock),
            "hashlock payload must embed keccak256(tau)"
        );
        let settle_payload = payloads
            .iter()
            .find(|payload| payload.starts_with(b"maker_settle"))
            .expect("maker_settle payload");
        assert!(
            settle_payload.ends_with(&expected_tau),
            "settle payload must embed same tau preimage used by hashlock"
        );
    }

    #[test]
    fn taker_flow_is_idempotent_on_replay() {
        let adapter = MockAdapter::with_time(1_000);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let rid = reservation(2);

        orchestrator.taker_accept_reservation(rid).expect("accept");
        orchestrator
            .taker_publish_context(rid, sample_context())
            .expect("publish context");
        orchestrator.taker_handle_presig(rid).expect("presig");
        let monero_tx = orchestrator
            .taker_complete_and_broadcast(rid)
            .expect("broadcast");
        orchestrator
            .taker_publish_final_sig(rid, monero_tx)
            .expect("publish final sig");

        let evm_calls_before = adapter.evm_send_calls();
        let monero_calls_before = adapter.monero_broadcast_calls();
        orchestrator
            .taker_publish_final_sig(rid, monero_tx)
            .expect("idempotent replay");
        assert_eq!(adapter.evm_send_calls(), evm_calls_before);
        assert_eq!(adapter.monero_broadcast_calls(), monero_calls_before);
    }

    #[test]
    fn resume_reconstructs_state_from_checkpoint() {
        let adapter = MockAdapter::with_time(2_000);
        let rid = reservation(3);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(200),
            })
            .expect("create");
        orchestrator.maker_set_hashlock(rid).expect("hashlock");

        let restarted = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let resumed = restarted.resume(rid).expect("resume");
        assert!(matches!(
            resumed,
            SwapState::Maker(MakerState::HashlockSet { .. })
        ));
    }

    #[test]
    fn check_deadlines_refunds_and_never_fails_timeout_paths() {
        let adapter = MockAdapter::with_time(100);
        let config = OrchestratorConfig {
            maker_timeout_secs: 10,
            taker_timeout_secs: 10,
            ..OrchestratorConfig::default()
        };
        let orchestrator = SwapOrchestrator::new(adapter.clone(), config);
        let rid = reservation(4);

        orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(1),
            })
            .expect("create");

        adapter.set_time(1000);
        let events = orchestrator.check_deadlines().expect("deadlines");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reservation_id, rid);
        let state = orchestrator.state(rid).expect("state");
        assert!(matches!(
            state,
            SwapState::Maker(MakerState::Refunded { .. })
        ));
        assert!(!matches!(
            state,
            SwapState::Maker(MakerState::Failed { .. })
        ));
    }

    #[test]
    fn maker_deadline_refund_submits_refund_tx() {
        let adapter = MockAdapter::with_time(100);
        let config = OrchestratorConfig {
            maker_timeout_secs: 10,
            ..OrchestratorConfig::default()
        };
        let orchestrator = SwapOrchestrator::new(adapter.clone(), config);
        let rid = reservation(0x31);

        orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(1),
            })
            .expect("create");
        assert_eq!(adapter.evm_send_calls(), 1, "create submits one tx");

        adapter.set_time(1_000);
        let events = orchestrator.check_deadlines().expect("deadlines");
        assert_eq!(events.len(), 1);
        assert_eq!(adapter.evm_send_calls(), 2, "deadline refund submits tx");
        let payloads = adapter.evm_payloads();
        assert!(
            payloads
                .last()
                .is_some_and(|payload| payload.starts_with(b"maker_refund")),
            "deadline path must submit maker_refund payload"
        );
        assert!(matches!(
            orchestrator.state(rid),
            Some(SwapState::Maker(MakerState::Refunded { .. }))
        ));
    }

    #[test]
    fn taker_deadline_refund_submits_refund_tx() {
        let adapter = MockAdapter::with_time(200);
        let config = OrchestratorConfig {
            taker_timeout_secs: 10,
            ..OrchestratorConfig::default()
        };
        let orchestrator = SwapOrchestrator::new(adapter.clone(), config);
        let rid = reservation(0x32);

        orchestrator
            .taker_accept_reservation(rid)
            .expect("accept reservation");
        assert_eq!(adapter.evm_send_calls(), 1, "accept submits one tx");

        adapter.set_time(1_000);
        let events = orchestrator.check_deadlines().expect("deadlines");
        assert_eq!(events.len(), 1);
        assert_eq!(adapter.evm_send_calls(), 2, "deadline refund submits tx");
        let payloads = adapter.evm_payloads();
        assert!(
            payloads
                .last()
                .is_some_and(|payload| payload.starts_with(b"taker_refund")),
            "deadline path must submit taker_refund payload"
        );
        assert!(matches!(
            orchestrator.state(rid),
            Some(SwapState::Taker(TakerState::Refunded { .. }))
        ));
    }

    #[test]
    fn adapter_error_propagates_context_and_marks_failed() {
        let adapter = MockAdapter::with_time(1_000);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let rid = reservation(5);
        adapter.fail_next_send(
            AdapterError::new(ErrorCode::AdapterCallFailed, "boom").with_adapter_code(77),
        );
        let err = orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(55),
            })
            .expect_err("must fail");
        match err {
            OrchestratorError::Adapter { context, source } => {
                assert!(context.contains("maker_create_reservation/send_raw_tx"));
                assert_eq!(source.code, ErrorCode::AdapterCallFailed);
                assert_eq!(source.adapter_code, Some(77));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        let state = orchestrator.state(rid).expect("state");
        match state {
            SwapState::Maker(MakerState::Failed {
                error_code,
                recoverable,
                ..
            }) => {
                assert_eq!(error_code, ErrorCode::AdapterCallFailed as i32);
                assert!(!recoverable);
            }
            other => panic!("expected failed state, got {other:?}"),
        }
    }

    #[test]
    fn invalid_transition_reports_current_state_and_command() {
        let adapter = MockAdapter::with_time(1_000);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let rid = reservation(6);
        orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(10),
            })
            .expect("create");

        let err = orchestrator
            .maker_publish_presig(rid)
            .expect_err("invalid transition");
        match err {
            OrchestratorError::InvalidTransition {
                current_state,
                attempted,
                ..
            } => {
                assert_eq!(current_state, "ReservationCreated");
                assert_eq!(attempted, "maker_publish_presig");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn emits_transition_tx_and_completion_events() {
        let adapter = MockAdapter::with_time(1_000);
        let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());
        let rid = reservation(7);

        orchestrator
            .maker_create_reservation(ReservationParams {
                reservation_id: rid,
                created_at: Some(20),
            })
            .expect("create");
        orchestrator.maker_set_hashlock(rid).expect("hashlock");
        orchestrator.maker_handle_context(rid).expect("context");
        orchestrator.maker_publish_presig(rid).expect("presig");
        orchestrator.maker_handle_final_sig(rid).expect("final sig");
        orchestrator.maker_settle(rid).expect("settle");

        let events = adapter.events();
        assert!(events.iter().any(|evt| matches!(
            evt,
            SwapLifecycleEvent::StateTransition { reservation_id, .. } if *reservation_id == rid
        )));
        assert!(events.iter().any(|evt| matches!(
            evt,
            SwapLifecycleEvent::TxSubmitted { reservation_id, chain: Chain::Evm, .. } if *reservation_id == rid
        )));
        assert!(events.iter().any(|evt| matches!(
            evt,
            SwapLifecycleEvent::SwapCompleted { reservation_id, outcome: SwapOutcome::Settled } if *reservation_id == rid
        )));
    }

    #[test]
    fn state_models_round_trip_serialize_deserialize() {
        let maker = MakerState::Failed {
            reservation_id: reservation(8),
            error_code: 123,
            reason: "reason".to_string(),
            recoverable: false,
        };
        let taker = TakerState::MoneroTxBroadcast {
            reservation_id: reservation(9),
            monero_tx_id: [0xAA; 32],
        };
        let maker_bytes = bincode::serialize(&maker).expect("serialize maker");
        let taker_bytes = bincode::serialize(&taker).expect("serialize taker");
        let maker_rt: MakerState = bincode::deserialize(&maker_bytes).expect("deserialize maker");
        let taker_rt: TakerState = bincode::deserialize(&taker_bytes).expect("deserialize taker");
        assert_eq!(maker, maker_rt);
        assert_eq!(taker, taker_rt);
    }
}
