use anyhow::{anyhow, bail, ensure, Result};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar, traits::Identity,
};
use monero_oxide::{
    io::CompressedPoint,
    primitives::Commitment,
    ringct::{
        bulletproofs::Bulletproof, clsag::Clsag, EncryptedAmount, RctBase, RctProofs, RctPrunable,
    },
    transaction::{Input, NotPruned, Output, Timelock, Transaction},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use tx_builder::{assemble_unsigned_tx, replace_pseudo_out_at, RctMeta};

#[test]
fn pseudo_out_balance_holds_after_injection() -> Result<()> {
    let amount_in = 7u64;
    let amount_out = 5u64;
    let fee = amount_in - amount_out;
    let mask = Scalar::from(11u64);

    let pseudo_commitment = Commitment::new(mask, amount_in);
    let pseudo_point = CompressedPoint::from(pseudo_commitment.calculate().compress());

    let output_commitment = Commitment::new(mask, amount_out);
    let output_point = CompressedPoint::from(output_commitment.calculate().compress());

    let inputs = vec![Input::ToKey {
        amount: None,
        key_offsets: vec![1, 2, 3],
        key_image: CompressedPoint::from((ED25519_BASEPOINT_POINT * Scalar::from(3u64)).compress()),
    }];

    let outputs = vec![Output {
        amount: None,
        key: CompressedPoint::from((ED25519_BASEPOINT_POINT * Scalar::from(5u64)).compress()),
        view_tag: Some(1),
    }];

    let clsag_placeholder = Clsag {
        D: CompressedPoint::from(EdwardsPoint::identity().compress()),
        s: vec![Scalar::ZERO; 3],
        c1: Scalar::ZERO,
    };

    let mut bp_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let bulletproof = Bulletproof::prove_plus(&mut bp_rng, vec![output_commitment.clone()])
        .map_err(|e| anyhow!("bulletproof generation failed: {e:?}"))?;

    let base = RctBase {
        fee,
        pseudo_outs: vec![],
        encrypted_amounts: vec![EncryptedAmount::Compact { amount: [0u8; 8] }],
        commitments: vec![output_point],
    };

    let prunable = RctPrunable::Clsag {
        clsags: vec![clsag_placeholder],
        pseudo_outs: vec![CompressedPoint::from([0u8; 32])],
        bulletproof,
    };

    let meta = RctMeta {
        timelock: Timelock::None,
        extra: vec![],
        proofs: RctProofs { base, prunable },
    };

    let mut blob = assemble_unsigned_tx(&inputs, &outputs, &meta)?;

    replace_pseudo_out_at(&mut blob, 0, pseudo_point)?;

    let mut slice = blob.as_slice();
    let tx: Transaction<NotPruned> =
        Transaction::read(&mut slice).map_err(|e| anyhow!("parse tx: {e:?}"))?;
    ensure!(
        slice.is_empty(),
        "unexpected trailing bytes after transaction"
    );

    let proofs = match tx {
        Transaction::V2 {
            proofs: Some(proofs),
            ..
        } => proofs,
        _ => bail!("expected CLSAG transaction with proofs"),
    };

    let RctProofs { base, prunable } = proofs;
    let pseudo_outs = match prunable {
        RctPrunable::Clsag { pseudo_outs, .. } => pseudo_outs,
        _ => bail!("transaction prunable data is not CLSAG"),
    };

    assert_eq!(pseudo_outs.len(), 1, "pseudo outs count mismatch");
    assert_eq!(
        pseudo_outs[0].to_bytes(),
        pseudo_point.to_bytes(),
        "pseudo out bytes mismatch"
    );

    let pseudo_sum = pseudo_outs
        .into_iter()
        .fold(EdwardsPoint::identity(), |acc, cp| {
            acc + cp.decompress().expect("pseudo_out must decompress")
        });

    let output_sum = base
        .commitments
        .into_iter()
        .fold(EdwardsPoint::identity(), |acc, cp| {
            acc + cp.decompress().expect("commitment must decompress")
        });

    let fee_commitment = Commitment::new(Scalar::ZERO, fee).calculate();
    assert_eq!(pseudo_sum, output_sum + fee_commitment, "balance equation");

    Ok(())
}
