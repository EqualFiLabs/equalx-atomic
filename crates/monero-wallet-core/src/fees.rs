pub trait FeeEstimator: Send + Sync {
    fn estimate(&self) -> anyhow::Result<FeeHint>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FeeHint {
    pub fee_per_byte: u64,
    pub ring_size: u32,
}

pub struct DaemonFeeEstimator {
    pub rpc: monero_rpc::MoneroRpc,
}

impl FeeEstimator for DaemonFeeEstimator {
    fn estimate(&self) -> anyhow::Result<FeeHint> {
        let resp = self.rpc.get_fee_estimate(None)?;
        // Fallbacks to safe-ish defaults if the node is coy.
        let per_byte = if resp.fee == 0 { 200 } else { resp.fee };
        Ok(FeeHint {
            fee_per_byte: per_byte,
            ring_size: 16,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use monero_rpc::MoneroRpc;
    use serde_json::json;

    fn mock_fee_response(fee: u64) -> serde_json::Value {
        json!({
            "result": {
                "fee": fee,
                "fees": [fee, fee, fee, fee],
                "quantization_mask": 1,
                "status": "OK",
                "top_hash": "",
                "credits": 0,
                "untrusted": false
            }
        })
    }

    #[test]
    fn fee_estimator_uses_node_fee_when_nonzero() {
        let server = MockServer::start();
        let body = mock_fee_response(3_000);
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/json_rpc")
                .body_contains("get_fee_estimate");
            then.status(200)
                .header("content-type", "application/json")
                .body(body.to_string());
        });
        let rpc = MoneroRpc::new(&server.base_url(), None).unwrap();
        let estimator = DaemonFeeEstimator { rpc };
        let hint = estimator.estimate().expect("fee estimate");
        mock.assert();
        assert_eq!(hint.fee_per_byte, 3_000);
        assert_eq!(hint.ring_size, 16);
    }

    #[test]
    fn fee_estimator_falls_back_when_node_reports_zero() {
        let server = MockServer::start();
        let body = mock_fee_response(0);
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/json_rpc")
                .body_contains("get_fee_estimate");
            then.status(200)
                .header("content-type", "application/json")
                .body(body.to_string());
        });
        let rpc = MoneroRpc::new(&server.base_url(), None).unwrap();
        let estimator = DaemonFeeEstimator { rpc };
        let hint = estimator.estimate().expect("fee estimate");
        mock.assert();
        assert_eq!(hint.fee_per_byte, 200, "fallback fee is 200 piconero/byte");
    }
}
