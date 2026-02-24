use conformance::{
    run_idempotency_conformance, run_maker_conformance, run_recovery_conformance,
    run_refund_conformance, run_taker_conformance,
};
use mock_adapter::MockAdapter;

#[test]
fn maker_conformance_passes_with_mock_adapter() {
    let adapter = MockAdapter::default();
    adapter.set_clock(100);
    let report = run_maker_conformance(adapter);
    assert!(report.passed, "maker conformance failed: {report:?}");
}

#[test]
fn taker_conformance_passes_with_mock_adapter() {
    let adapter = MockAdapter::default();
    adapter.set_clock(100);
    let report = run_taker_conformance(adapter);
    assert!(report.passed, "taker conformance failed: {report:?}");
}

#[test]
fn refund_conformance_passes_with_mock_adapter() {
    let adapter = MockAdapter::default();
    adapter.set_clock(100);
    let report = run_refund_conformance(adapter);
    assert!(report.passed, "refund conformance failed: {report:?}");
}

#[test]
fn recovery_conformance_passes_with_mock_adapter() {
    let adapter = MockAdapter::default();
    adapter.set_clock(100);
    let report = run_recovery_conformance(adapter);
    assert!(report.passed, "recovery conformance failed: {report:?}");
}

#[test]
fn idempotency_conformance_passes_with_mock_adapter() {
    let adapter = MockAdapter::default();
    adapter.set_clock(100);
    let report = run_idempotency_conformance(adapter);
    assert!(report.passed, "idempotency conformance failed: {report:?}");
}
