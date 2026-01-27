// SPDX-License-Identifier: Apache-2.0

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar};
use monero_oxide::transaction::{NotPruned, Transaction};
use tx_builder::{
    assemble_unsigned_tx,
    convert::{outputs_and_meta_from_specs, OutputSpec},
    Inputs,
};

fn sample_point_from_scalar(bytes: [u8; 32]) -> EdwardsPoint {
    let scalar = Scalar::from_bytes_mod_order(bytes);
    &scalar * ED25519_BASEPOINT_TABLE
}

#[test]
fn encrypted_amounts_are_non_zero() {
    // Deterministic scalars for reproducibility.
    let spend_point = sample_point_from_scalar([1u8; 32]);
    let view_point = sample_point_from_scalar([2u8; 32]);
    let tx_point = sample_point_from_scalar([3u8; 32]);

    let shared_point = view_point * Scalar::from_bytes_mod_order([3u8; 32]);
    let (view_tag, derivations) = tx_builder::ecdh::derive_view_tag_and_shared(shared_point, 0);
    let shared_scalar = tx_builder::ecdh::shared_scalar(&derivations);
    let key_point = (&shared_scalar * ED25519_BASEPOINT_TABLE) + spend_point;

    let specs = vec![OutputSpec {
        amount: 1_000_000_000_000,
        key: monero_oxide::io::CompressedPoint::from(key_point.compress()),
        view_tag,
        shared_point,
    }];

    let (outputs, meta, _) = outputs_and_meta_from_specs(
        &specs,
        10_000,
        {
            let mut extra = vec![1u8];
            extra.extend_from_slice(tx_point.compress().as_bytes());
            extra
        },
        1,
        16,
    )
    .expect("outputs and meta conversion");

    let inputs: Inputs = vec![monero_oxide::transaction::Input::ToKey {
        amount: None,
        key_offsets: vec![1],
        key_image: monero_oxide::io::CompressedPoint::from(
            sample_point_from_scalar([4u8; 32]).compress(),
        ),
    }];

    let blob =
        assemble_unsigned_tx(&inputs, &outputs, &meta).expect("assemble unsigned transaction");

    let mut slice = blob.as_slice();
    let tx: Transaction<NotPruned> =
        Transaction::read(&mut slice).expect("parse unsigned transaction");

    let proofs = match &tx {
        Transaction::V2 {
            proofs: Some(proofs),
            ..
        } => proofs,
        _ => panic!("expected ringct v2 transaction"),
    };

    assert!(
        proofs.base.encrypted_amounts.iter().all(|enc| match enc {
            monero_oxide::ringct::EncryptedAmount::Compact { amount } => {
                amount.iter().any(|byte| *byte != 0)
            }
            monero_oxide::ringct::EncryptedAmount::Original { mask, amount } => {
                mask.iter().any(|byte| *byte != 0) || amount.iter().any(|byte| *byte != 0)
            }
        }),
        "expected all encrypted amounts to be non-zero"
    );
}
