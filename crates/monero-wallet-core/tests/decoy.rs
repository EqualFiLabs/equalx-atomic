// SPDX-License-Identifier: Apache-2.0

use monero_wallet_core::{plan, DecoyRef, FeeHint, OwnedOutput};

fn owned_output(global_index: u64, amount: u64, key_byte: u8) -> OwnedOutput {
    OwnedOutput {
        txid: [key_byte; 32],
        out_index_in_tx: 0,
        amount,
        global_index,
        mask: [0u8; 32],
        one_time_pubkey: [1u8; 32],
        subaddr_account: 0,
        subaddr_index: 0,
        unlock_time: 0,
        block_height: global_index,
        key_image: Some([key_byte; 32]),
    }
}

#[test]
fn decoy_count_matches_ring_size() {
    let owned = vec![owned_output(10, 100_000, 1), owned_output(20, 100_000, 2)];
    let refs: Vec<&OwnedOutput> = owned.iter().collect();

    let fee = FeeHint {
        fee_per_byte: 200,
        ring_size: 8,
    };
    let target_amount = 180_000;
    let preview = plan::preview_inputs(&refs, target_amount, fee).unwrap();
    let expected_decoys = (fee.ring_size as usize - 1) * preview.len();
    let decoys: Vec<DecoyRef> = (0..expected_decoys)
        .map(|i| DecoyRef {
            global_index: (1000 + i as u64),
        })
        .collect();

    let plan =
        plan::build_spend_plan(&refs, target_amount, fee, [0u8; 32], decoys.clone()).unwrap();
    assert_eq!(plan.inputs.len(), preview.len());
    assert_eq!(plan.decoys.len(), expected_decoys);
}
