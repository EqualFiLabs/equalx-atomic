use crate::{
    fees::FeeHint,
    model::{DecoyRef, OwnedOutput, SpendInput, SpendPlan},
};
use anyhow::ensure;

fn select_inputs_internal(
    owned: &[&OwnedOutput],
    target_amount: u64,
    fee: FeeHint,
) -> anyhow::Result<(Vec<SpendInput>, u64)> {
    let mut sorted = owned.to_vec();
    sorted.sort_by_key(|o| (o.block_height, o.global_index));

    let mut total = 0u64;
    let mut inputs = Vec::new();
    for o in sorted {
        let ki = o
            .key_image
            .ok_or_else(|| anyhow::anyhow!("missing key image; spend key required"))?;
        inputs.push(SpendInput {
            txid: o.txid,
            global_index: o.global_index,
            ring_member_count: fee.ring_size,
            key_image: ki,
        });
        total = total.saturating_add(o.amount);
        if total >= target_amount {
            break;
        }
    }
    ensure!(total >= target_amount, "insufficient funds");

    Ok((inputs, total))
}

pub fn preview_inputs(
    owned: &[&OwnedOutput],
    target_amount: u64,
    fee: FeeHint,
) -> anyhow::Result<Vec<SpendInput>> {
    let (inputs, _) = select_inputs_internal(owned, target_amount, fee)?;
    Ok(inputs)
}

pub fn build_spend_plan(
    owned: &[&OwnedOutput],
    target_amount: u64,
    fee: FeeHint,
    settle_digest: [u8; 32],
    decoys: Vec<DecoyRef>,
) -> anyhow::Result<SpendPlan> {
    let (inputs, total) = select_inputs_internal(owned, target_amount, fee)?;

    let per_input = fee.ring_size.checked_sub(1).unwrap_or_default() as usize;
    let expected_decoys = inputs.len().checked_mul(per_input).unwrap_or_default();
    if expected_decoys == 0 {
        ensure!(
            decoys.is_empty(),
            "expected no decoys for ring size {}, received {}",
            fee.ring_size,
            decoys.len()
        );
    } else {
        ensure!(
            decoys.len() == expected_decoys,
            "expected {} decoys ({} per input), received {}",
            expected_decoys,
            per_input,
            decoys.len()
        );
    }

    // Naive fee: linear per-byte approx (caller may re-run once size is known)
    let est_fee = fee
        .fee_per_byte
        .saturating_mul(180 + 80 * inputs.len() as u64);

    let change = total.saturating_sub(target_amount + est_fee);
    Ok(SpendPlan {
        inputs,
        decoys,
        fee_estimate: est_fee,
        change: (change > 0).then_some(change),
        settle_digest,
        resp_index_hint: None,
    })
}
