//! Conformance scenarios for host adapter integrations.

use host_adapter::HostAdapters;
use orchestrator::{
    MakerState, MoneroContext, OrchestratorConfig, ReservationId, ReservationParams,
    SwapOrchestrator, SwapState, TakerState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub scenario: &'static str,
    pub passed: bool,
    pub checks: Vec<ConformanceCheck>,
}

impl ConformanceReport {
    fn new(scenario: &'static str) -> Self {
        Self {
            scenario,
            passed: true,
            checks: Vec::new(),
        }
    }

    fn pass(&mut self, name: &'static str, detail: impl Into<String>) {
        self.checks.push(ConformanceCheck {
            name,
            passed: true,
            detail: detail.into(),
        });
    }

    fn fail(&mut self, name: &'static str, detail: impl Into<String>) {
        self.passed = false;
        self.checks.push(ConformanceCheck {
            name,
            passed: false,
            detail: detail.into(),
        });
    }
}

/// Runs maker-lifecycle conformance checks against a host adapter implementation.
pub fn run_maker_conformance<A: HostAdapters + Clone>(adapters: A) -> ConformanceReport {
    let mut report = ConformanceReport::new("maker");
    let orchestrator = SwapOrchestrator::new(adapters, OrchestratorConfig::default());
    let rid = reservation(0xA1);

    if let Err(err) = orchestrator.maker_create_reservation(ReservationParams {
        reservation_id: rid,
        created_at: Some(10),
    }) {
        report.fail("maker_create_reservation", err.to_string());
        return report;
    }
    report.pass("maker_create_reservation", "reservation created");

    if let Err(err) = orchestrator.maker_set_hashlock(rid) {
        report.fail("maker_set_hashlock", err.to_string());
        return report;
    }
    report.pass("maker_set_hashlock", "hashlock set");

    if let Err(err) = orchestrator.maker_handle_context(rid) {
        report.fail("maker_handle_context", err.to_string());
        return report;
    }
    report.pass("maker_handle_context", "context handled");

    if let Err(err) = orchestrator.maker_publish_presig(rid) {
        report.fail("maker_publish_presig", err.to_string());
        return report;
    }
    report.pass("maker_publish_presig", "presig published");

    if let Err(err) = orchestrator.maker_handle_final_sig(rid, sample_monero_tx(rid)) {
        report.fail("maker_handle_final_sig", err.to_string());
        return report;
    }
    report.pass("maker_handle_final_sig", "final signature handled");

    if let Err(err) = orchestrator.maker_settle(rid) {
        report.fail("maker_settle", err.to_string());
        return report;
    }
    report.pass("maker_settle", "maker settled");

    match orchestrator.state(rid) {
        Some(SwapState::Maker(MakerState::Settled { .. })) => {
            report.pass("maker_terminal_state", "state is Settled")
        }
        other => report.fail(
            "maker_terminal_state",
            format!("expected maker settled, got {other:?}"),
        ),
    }

    let side_effects = orchestrator.side_effects(rid).unwrap_or_default();
    if side_effects.is_empty() {
        report.fail("maker_side_effects", "no side effects recorded");
    } else {
        report.pass(
            "maker_side_effects",
            format!("{} side effects recorded", side_effects.len()),
        );
    }

    report
}

/// Runs taker-lifecycle conformance checks against a host adapter implementation.
pub fn run_taker_conformance<A: HostAdapters + Clone>(adapters: A) -> ConformanceReport {
    let mut report = ConformanceReport::new("taker");
    let orchestrator = SwapOrchestrator::new(adapters, OrchestratorConfig::default());
    let rid = reservation(0xB2);

    if let Err(err) = orchestrator.taker_accept_reservation(rid) {
        report.fail("taker_accept_reservation", err.to_string());
        return report;
    }
    report.pass("taker_accept_reservation", "reservation accepted");

    if let Err(err) = orchestrator.taker_publish_context(rid, sample_context(rid)) {
        report.fail("taker_publish_context", err.to_string());
        return report;
    }
    report.pass("taker_publish_context", "context published");

    if let Err(err) = orchestrator.taker_handle_presig(rid) {
        report.fail("taker_handle_presig", err.to_string());
        return report;
    }
    report.pass("taker_handle_presig", "presig handled");

    let monero_tx_id = match orchestrator.taker_complete_and_broadcast(rid) {
        Ok(tx) => {
            report.pass("taker_complete_and_broadcast", "monero tx broadcasted");
            tx
        }
        Err(err) => {
            report.fail("taker_complete_and_broadcast", err.to_string());
            return report;
        }
    };

    if monero_tx_id.iter().all(|byte| *byte == 0) {
        report.fail("taker_monero_tx_id", "broadcast tx id must be non-zero");
    } else {
        report.pass("taker_monero_tx_id", "broadcast tx id captured");
    }

    if let Err(err) = orchestrator.taker_publish_final_sig(rid, monero_tx_id) {
        report.fail("taker_publish_final_sig", err.to_string());
        return report;
    }
    report.pass("taker_publish_final_sig", "final signature published");

    match orchestrator.state(rid) {
        Some(SwapState::Taker(TakerState::FinalSigPublished { .. }))
        | Some(SwapState::Taker(TakerState::Settled { .. })) => report.pass(
            "taker_terminal_state",
            "state progressed to final publishing stage",
        ),
        other => report.fail(
            "taker_terminal_state",
            format!("expected final sig published/settled, got {other:?}"),
        ),
    }

    report
}

/// Runs deadline/refund-path conformance checks.
pub fn run_refund_conformance<A: HostAdapters + Clone>(adapters: A) -> ConformanceReport {
    let mut report = ConformanceReport::new("refund");
    let config = OrchestratorConfig {
        maker_timeout_secs: 1,
        taker_timeout_secs: 1,
        ..OrchestratorConfig::default()
    };
    let orchestrator = SwapOrchestrator::new(adapters, config);
    let rid = reservation(0xC3);

    if let Err(err) = orchestrator.maker_create_reservation(ReservationParams {
        reservation_id: rid,
        created_at: Some(0),
    }) {
        report.fail("maker_create_reservation", err.to_string());
        return report;
    }
    report.pass("maker_create_reservation", "reservation created");

    let deadline_events = match orchestrator.check_deadlines() {
        Ok(events) => events,
        Err(err) => {
            report.fail("check_deadlines", err.to_string());
            return report;
        }
    };

    if deadline_events.is_empty() {
        report.fail(
            "deadline_event",
            "no deadline event emitted (clock may not be advanced)",
        );
    } else {
        report.pass(
            "deadline_event",
            format!("{} deadline events emitted", deadline_events.len()),
        );
    }

    match orchestrator.state(rid) {
        Some(SwapState::Maker(MakerState::RefundPending { .. })) => report.pass(
            "refund_state_pending",
            "maker submitted refund and is awaiting receipt",
        ),
        Some(SwapState::Maker(MakerState::Refunded { .. })) => {
            report.pass("refund_state", "maker moved to Refunded")
        }
        other => report.fail(
            "refund_state",
            format!("expected maker refund pending/refunded, got {other:?}"),
        ),
    }

    if let Err(err) = orchestrator.check_deadlines() {
        report.fail("check_deadlines_confirm", err.to_string());
        return report;
    }
    match orchestrator.state(rid) {
        Some(SwapState::Maker(MakerState::Refunded { .. })) => {
            report.pass("refund_confirmed", "maker refund confirmed")
        }
        other => report.fail(
            "refund_confirmed",
            format!("expected maker refunded after confirmation poll, got {other:?}"),
        ),
    }

    report
}

/// Runs recovery conformance checks (checkpoint save + resume).
pub fn run_recovery_conformance<A: HostAdapters + Clone>(adapters: A) -> ConformanceReport {
    let mut report = ConformanceReport::new("recovery");
    let rid = reservation(0xD4);

    let orchestrator = SwapOrchestrator::new(adapters.clone(), OrchestratorConfig::default());
    if let Err(err) = orchestrator.maker_create_reservation(ReservationParams {
        reservation_id: rid,
        created_at: Some(10),
    }) {
        report.fail("maker_create_reservation", err.to_string());
        return report;
    }
    if let Err(err) = orchestrator.maker_set_hashlock(rid) {
        report.fail("maker_set_hashlock", err.to_string());
        return report;
    }
    report.pass("checkpointed_progress", "maker advanced to HashlockSet");

    let restarted = SwapOrchestrator::new(adapters, OrchestratorConfig::default());
    let resumed = match restarted.resume(rid) {
        Ok(state) => state,
        Err(err) => {
            report.fail("resume", err.to_string());
            return report;
        }
    };

    match resumed {
        SwapState::Maker(MakerState::HashlockSet { .. }) => {
            report.pass("resumed_state", "resume reconstructed HashlockSet state")
        }
        other => report.fail(
            "resumed_state",
            format!("expected HashlockSet after resume, got {other:?}"),
        ),
    }

    report
}

/// Runs idempotency conformance checks for replayed commands.
pub fn run_idempotency_conformance<A: HostAdapters + Clone>(adapters: A) -> ConformanceReport {
    let mut report = ConformanceReport::new("idempotency");
    let orchestrator = SwapOrchestrator::new(adapters, OrchestratorConfig::default());
    let rid = reservation(0xE5);

    if let Err(err) = orchestrator.maker_create_reservation(ReservationParams {
        reservation_id: rid,
        created_at: Some(10),
    }) {
        report.fail("maker_create_reservation", err.to_string());
        return report;
    }
    if let Err(err) = orchestrator.maker_set_hashlock(rid) {
        report.fail("maker_set_hashlock", err.to_string());
        return report;
    }

    let before = orchestrator.side_effects(rid).unwrap_or_default().len();

    if let Err(err) = orchestrator.maker_set_hashlock(rid) {
        report.fail("replay_maker_set_hashlock", err.to_string());
        return report;
    }

    let after = orchestrator.side_effects(rid).unwrap_or_default().len();
    if before == after {
        report.pass(
            "replay_side_effects",
            format!("side effects unchanged at {after}"),
        );
    } else {
        report.fail(
            "replay_side_effects",
            format!("expected unchanged side effects, before={before}, after={after}"),
        );
    }

    report
}

fn reservation(seed: u8) -> ReservationId {
    let mut rid = [0u8; 32];
    rid[0] = seed;
    rid
}

fn sample_context(seed: ReservationId) -> MoneroContext {
    MoneroContext {
        context_hash: seed,
        wire_version: 1,
        envelope: None,
    }
}

fn sample_monero_tx(seed: ReservationId) -> [u8; 32] {
    let mut monero_tx = [0xA5; 32];
    monero_tx[0] = seed[0];
    monero_tx
}
