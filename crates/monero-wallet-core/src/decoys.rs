// SPDX-License-Identifier: Apache-2.0
//! Decoy selection helpers for spend planning.

use std::collections::HashSet;

use crate::model::{DecoyRef, SpendInput};
use anyhow::{anyhow, ensure, Result};
use monero_rpc::{GetOutsRequest, MoneroRpc, OutputRef};
use rand::{seq::SliceRandom, thread_rng};

/// Maximum number of outputs to request per batch for `/get_outs`.
const GET_OUTS_BATCH_LIMIT: usize = 96;
/// Default window (in global indices) to search when sampling decoys.
const SAMPLE_WINDOW: u64 = 512;

pub trait DecoyPicker {
    fn pick(&self, inputs: &[SpendInput], ring_size: u32) -> Result<Vec<DecoyRef>>;
}

/// No-op picker useful for tests; returns zero decoys.
pub struct NoopDecoyPicker;

impl DecoyPicker for NoopDecoyPicker {
    fn pick(&self, _inputs: &[SpendInput], _ring_size: u32) -> Result<Vec<DecoyRef>> {
        Ok(vec![])
    }
}

/// RPC-backed decoy picker. Samples neighbours around each real input,
/// filters out owned indices, and verifies existence via `/get_outs`.
pub struct RpcDecoyPicker {
    pub rpc: MoneroRpc,
    pub ring_size: u32,
}

impl RpcDecoyPicker {
    pub fn pick(&self, inputs: &[SpendInput]) -> Result<Vec<DecoyRef>> {
        self.pick_with_ring(inputs, self.ring_size)
    }

    fn pick_with_ring(&self, inputs: &[SpendInput], ring_size: u32) -> Result<Vec<DecoyRef>> {
        if inputs.is_empty() || ring_size <= 1 {
            return Ok(vec![]);
        }

        let per_input = ring_size
            .checked_sub(1)
            .ok_or_else(|| anyhow!("ring_size must be at least 1"))?
            as usize;
        if per_input == 0 {
            return Ok(vec![]);
        }

        let owned: HashSet<u64> = inputs.iter().map(|inp| inp.global_index).collect();
        let mut selections: Vec<Vec<u64>> = Vec::with_capacity(inputs.len());
        let mut unique_indices = HashSet::new();
        let mut rng = thread_rng();

        for input in inputs {
            let picks = Self::sample_for_input(input.global_index, per_input, &owned, &mut rng)?;
            unique_indices.extend(picks.iter().copied());
            selections.push(picks);
        }

        self.ensure_indices_exist(&unique_indices)?;

        let mut decoys = Vec::with_capacity(per_input * inputs.len());
        for picks in selections {
            for idx in picks {
                decoys.push(DecoyRef { global_index: idx });
            }
        }
        Ok(decoys)
    }

    fn sample_for_input(
        global_index: u64,
        needed: usize,
        owned: &HashSet<u64>,
        rng: &mut rand::rngs::ThreadRng,
    ) -> Result<Vec<u64>> {
        if needed == 0 {
            return Ok(vec![]);
        }

        let mut candidates = Vec::new();
        let start = global_index.saturating_sub(SAMPLE_WINDOW);
        for idx in start..global_index {
            if !owned.contains(&idx) {
                candidates.push(idx);
            }
        }

        let mut above = global_index.checked_add(1);
        while candidates.len() < needed {
            let Some(idx) = above else {
                break;
            };
            if !owned.contains(&idx) {
                candidates.push(idx);
            }
            if idx == u64::MAX {
                break;
            }
            let distance = idx.saturating_sub(global_index);
            if distance >= SAMPLE_WINDOW {
                break;
            } else {
                above = idx.checked_add(1);
            }
        }

        candidates.sort_unstable();
        candidates.dedup();

        ensure!(
            candidates.len() >= needed,
            "insufficient decoy candidates near global index {} (needed {}, have {})",
            global_index,
            needed,
            candidates.len()
        );

        candidates.shuffle(rng);
        Ok(candidates.into_iter().take(needed).collect())
    }

    fn ensure_indices_exist(&self, indices: &HashSet<u64>) -> Result<()> {
        if indices.is_empty() {
            return Ok(());
        }

        let mut ordered: Vec<u64> = indices.iter().copied().collect();
        ordered.sort_unstable();

        for chunk in ordered.chunks(GET_OUTS_BATCH_LIMIT.max(1)) {
            let outputs: Vec<OutputRef> = chunk
                .iter()
                .map(|&index| OutputRef { amount: 0, index })
                .collect();
            let request = GetOutsRequest {
                outputs,
                get_txid: false,
                client: None,
            };
            let response = self.rpc.get_outs(&request)?;
            ensure!(
                response.outs.len() == chunk.len(),
                "get_outs returned {} entries for {} indices",
                response.outs.len(),
                chunk.len()
            );
        }

        Ok(())
    }
}

impl DecoyPicker for RpcDecoyPicker {
    fn pick(&self, inputs: &[SpendInput], ring_size: u32) -> Result<Vec<DecoyRef>> {
        self.pick_with_ring(inputs, ring_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use monero_rpc::MoneroRpc;
    use serde_json::json;
    use std::collections::HashSet;

    fn outs_payload(indices: &[u64]) -> serde_json::Value {
        let outs: Vec<_> = indices
            .iter()
            .map(|idx| {
                json!({
                    "height": 1,
                    "key": format!("{idx:064x}"),
                    "mask": format!("{idx:064x}"),
                    "txid": format!("{idx:064x}"),
                    "unlocked": true
                })
            })
            .collect();
        json!({
            "credits": 0,
            "outs": outs,
            "status": "OK",
            "top_hash": "",
            "untrusted": false
        })
    }

    #[test]
    fn ensure_indices_exist_hits_get_outs() {
        let server = MockServer::start();
        let mut indices = HashSet::new();
        indices.insert(42);
        indices.insert(43);
        let ordered: Vec<u64> = {
            let mut v: Vec<u64> = indices.iter().copied().collect();
            v.sort_unstable();
            v
        };
        let response_body = outs_payload(&ordered);
        let response_json = response_body.to_string();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/get_outs");
            then.status(200)
                .header("content-type", "application/json")
                .body(response_json.clone());
        });
        let rpc = MoneroRpc::new(&server.base_url(), None).unwrap();
        let picker = RpcDecoyPicker { rpc, ring_size: 16 };
        picker
            .ensure_indices_exist(&indices)
            .expect("indices exist");
        mock.assert();
    }
}
