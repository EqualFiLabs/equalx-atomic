use adaptor_clsag::{
    complete,
    encoding::{ensure_unique_ring, validate_point_le, validate_presig, validate_scalar_le},
    make_pre_sig,
    tau::derive_tau,
    verify, ClsagCtx, EswpError, PreSig, SettlementCtx, SignerWitness,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar, traits::Identity,
};
use monero_oxide::{io::CompressedPoint, primitives::Commitment};
use proptest::prelude::*;

#[derive(Clone, Debug)]
struct ValidCase {
    ctx: ClsagCtx,
    witness: SignerWitness,
    settlement: SettlementCtx,
    message: Vec<u8>,
    swap_id: [u8; 32],
}

/// Arbitrary generator: settlement context.
fn arb_settlement_ctx() -> impl Strategy<Value = SettlementCtx> {
    (any::<u32>(), any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(
        |(chain_id, position_key, settle_digest)| SettlementCtx {
            chain_tag: format!("evm:{chain_id}"),
            position_key,
            settle_digest,
        },
    )
}

/// Arbitrary generator: ring key and commitment arrays.
fn arb_ring_arrays() -> impl Strategy<Value = (Vec<[u8; 32]>, Vec<[u8; 32]>)> {
    (5usize..9, any::<u64>()).prop_map(|(n, seed)| {
        let mut ring_keys = Vec::with_capacity(n);
        let mut ring_commitments = Vec::with_capacity(n);
        for i in 0..n {
            let secret = Scalar::from(seed.wrapping_add(i as u64 + 1));
            let mask = Scalar::from(seed.rotate_left(13).wrapping_add(i as u64 + 17));
            ring_keys.push((ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes());
            ring_commitments.push(Commitment::new(mask, 0).calculate().compress().to_bytes());
        }
        (ring_keys, ring_commitments)
    })
}

fn valid_case_strategy() -> impl Strategy<Value = ValidCase> {
    (
        5usize..9,
        any::<u64>(),
        any::<usize>(),
        arb_settlement_ctx(),
    )
        .prop_flat_map(|(n, seed, i_seed, settlement)| {
            (
                Just(n),
                Just(seed),
                Just(settlement),
                Just(i_seed % n),
                prop::collection::vec(any::<u8>(), 1..96),
                any::<[u8; 32]>(),
            )
        })
        .prop_map(|(n, seed, settlement, i_star, message, swap_id)| {
            let mut ring_keys = Vec::with_capacity(n);
            let mut ring_commitments = Vec::with_capacity(n);
            let mut witness_x = [0u8; 32];
            let mut witness_mask = [0u8; 32];

            for i in 0..n {
                let secret = Scalar::from(seed.wrapping_add(i as u64 + 1));
                let mask = Scalar::from(seed.rotate_left(7).wrapping_add(i as u64 + 11));
                let pk = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();
                let com = Commitment::new(mask, 0).calculate().compress().to_bytes();
                if i == i_star {
                    witness_x = secret.to_bytes();
                    witness_mask = mask.to_bytes();
                }
                ring_keys.push(pk);
                ring_commitments.push(com);
            }

            let witness = SignerWitness {
                x: witness_x,
                mask: witness_mask,
                amount: 0,
                i_star,
            };
            let ctx = ClsagCtx {
                ring_keys,
                ring_commitments,
                key_image: witness.key_image_bytes(),
                n,
            };
            ValidCase {
                ctx,
                witness,
                settlement,
                message,
                swap_id,
            }
        })
}

/// Arbitrary generator: ClsagCtx.
fn arb_clsag_ctx() -> impl Strategy<Value = ClsagCtx> {
    valid_case_strategy().prop_map(|case| case.ctx)
}

/// Arbitrary generator: SignerWitness.
fn arb_signer_witness() -> impl Strategy<Value = SignerWitness> {
    valid_case_strategy().prop_map(|case| case.witness)
}

/// Arbitrary generator: PreSig.
fn arb_presig() -> impl Strategy<Value = PreSig> {
    valid_case_strategy().prop_filter_map("valid presig generation", |case| {
        make_pre_sig(
            &case.ctx,
            &case.witness,
            &case.message,
            &case.swap_id,
            case.settlement,
        )
        .ok()
        .map(|(pre, _tau)| pre)
    })
}

fn arb_non_reduced_scalar() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("non-canonical scalar", |bytes| {
        bool::from(Scalar::from_canonical_bytes(*bytes).is_none())
    })
}

fn arb_non_canonical_point() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("non-canonical point", |bytes| {
        CompressedPoint::from(*bytes).decompress().is_none()
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    /// Property 15: Cryptographic input validation.
    #[test]
    fn prop15_cryptographic_input_validation(
        bad_scalar in arb_non_reduced_scalar(),
        bad_point in arb_non_canonical_point(),
        (mut ring_keys, _ring_commitments) in arb_ring_arrays(),
    ) {
        prop_assert!(matches!(
            validate_scalar_le(&bad_scalar),
            Err(EswpError::EncodingNoncanonical)
        ));
        prop_assert!(matches!(
            validate_point_le(&bad_point),
            Err(EswpError::EncodingNoncanonical)
        ));

        let last = ring_keys.len() - 1;
        ring_keys[last] = ring_keys[0];
        prop_assert!(matches!(
            ensure_unique_ring(&ring_keys),
            Err(EswpError::RingInvalid)
        ));
    }

    /// Property 17: Tau derivation non-zero output.
    #[test]
    fn prop17_tau_derivation_non_zero(
        hashlock in any::<[u8; 32]>(),
        swap_id in any::<[u8; 32]>(),
        stmt in prop::collection::vec(any::<u8>(), 0..256),
        j in any::<u32>(),
    ) {
        let tau = derive_tau(&hashlock, &swap_id, &stmt, j);
        prop_assert_ne!(Scalar::from_bytes_mod_order(tau), Scalar::ZERO);
    }

    /// Property 16: Presig generation rejects invalid inputs.
    #[test]
    fn prop16_presig_generation_rejects_invalid_inputs(case in valid_case_strategy()) {
        let mut zero_scalar_witness = case.witness.clone();
        zero_scalar_witness.x = [0u8; 32];
        prop_assert!(matches!(
            make_pre_sig(
                &case.ctx,
                &zero_scalar_witness,
                &case.message,
                &case.swap_id,
                case.settlement.clone(),
            ),
            Err(EswpError::EncodingNoncanonical)
        ));

        let mut identity_ctx = case.ctx.clone();
        identity_ctx.ring_keys[0] = EdwardsPoint::identity().compress().to_bytes();
        prop_assert!(matches!(
            make_pre_sig(
                &identity_ctx,
                &case.witness,
                &case.message,
                &case.swap_id,
                case.settlement.clone(),
            ),
            Err(EswpError::EncodingNoncanonical)
        ));

        let mut duplicate_ring_ctx = case.ctx.clone();
        duplicate_ring_ctx.ring_keys[1] = duplicate_ring_ctx.ring_keys[0];
        prop_assert!(matches!(
            make_pre_sig(
                &duplicate_ring_ctx,
                &case.witness,
                &case.message,
                &case.swap_id,
                case.settlement.clone(),
            ),
            Err(EswpError::RingInvalid)
        ));

        let mut len_mismatch_ctx = case.ctx.clone();
        len_mismatch_ctx.ring_commitments.pop();
        prop_assert!(matches!(
            make_pre_sig(
                &len_mismatch_ctx,
                &case.witness,
                &case.message,
                &case.swap_id,
                case.settlement,
            ),
            Err(EswpError::RingInvalid)
        ));
    }

    /// Property 18: Complete then verify.
    #[test]
    fn prop18_clsag_complete_then_verify(case in valid_case_strategy()) {
        let pre_and_tau = make_pre_sig(
            &case.ctx,
            &case.witness,
            &case.message,
            &case.swap_id,
            case.settlement,
        );
        prop_assert!(pre_and_tau.is_ok());
        let (pre, tau) = pre_and_tau.expect("checked above");
        let final_sig = complete(&pre, &tau);
        prop_assert!(verify(&case.ctx, &case.message, &final_sig));
    }

    #[test]
    fn generated_presig_is_structurally_valid(pre in arb_presig()) {
        prop_assert!(validate_presig(&pre).is_ok());
    }

    #[test]
    fn generated_types_are_well_formed(
        ctx in arb_clsag_ctx(),
        witness in arb_signer_witness(),
        settlement in arb_settlement_ctx(),
    ) {
        prop_assert!(ctx.n >= 5);
        prop_assert_eq!(ctx.ring_keys.len(), ctx.n);
        prop_assert_eq!(ctx.ring_commitments.len(), ctx.n);
        prop_assert!(witness.i_star < 9);
        prop_assert!(!settlement.chain_tag.is_empty());
    }
}
