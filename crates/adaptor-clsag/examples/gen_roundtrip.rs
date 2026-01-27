use adaptor_clsag::{complete, extract_t, make_pre_sig, ClsagCtx, SettlementCtx, SignerWitness};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use monero_oxide::primitives::Commitment;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use serde::Serialize;

#[derive(Serialize)]
struct RoundTripVector {
    message_hex: String,
    swap_id_hex: String,
    settlement: SettlementVector,
    clsag_ctx: ClsagCtxVector,
    witness: WitnessVector,
    expected: ExpectedVector,
}

#[derive(Serialize)]
struct SettlementVector {
    chain_tag: String,
    position_key_hex: String,
    settle_digest_hex: String,
}

#[derive(Serialize)]
struct ClsagCtxVector {
    ring_keys_hex: Vec<String>,
    ring_commitments_hex: Vec<String>,
    key_image_hex: String,
    n: usize,
}

#[derive(Serialize)]
struct WitnessVector {
    x_hex: String,
    mask_hex: String,
    amount: u64,
    i_star: usize,
}

#[derive(Serialize)]
struct ExpectedVector {
    j: usize,
    pre_hash_hex: String,
    tau_hex: String,
    pre_sig: PreSigVector,
    final_sig: FinalSigVector,
    extracted_t_hex: String,
}

#[derive(Serialize)]
struct PreSigVector {
    c1_tilde_hex: String,
    s_tilde_hex: Vec<String>,
    d_tilde_hex: String,
    pseudo_out_hex: String,
}

#[derive(Serialize)]
struct FinalSigVector {
    c1_hex: String,
    s_hex: Vec<String>,
    d_hex: String,
    pseudo_out_hex: String,
}

fn main() {
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let ring_size = 5;

    let mut ring_keys = Vec::with_capacity(ring_size);
    let mut ring_commitments = Vec::with_capacity(ring_size);
    let mut secrets = Vec::with_capacity(ring_size);
    let mut masks = Vec::with_capacity(ring_size);

    for _ in 0..ring_size {
        let mut secret_seed = [0u8; 64];
        rng.fill_bytes(&mut secret_seed);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_seed);
        let public = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();

        let mut mask_seed = [0u8; 64];
        rng.fill_bytes(&mut mask_seed);
        let mask = Scalar::from_bytes_mod_order_wide(&mask_seed);
        let commitment = Commitment::new(mask, 0).calculate().compress().to_bytes();

        ring_keys.push(public);
        ring_commitments.push(commitment);
        secrets.push(secret);
        masks.push(mask);
    }

    let i_star = 2usize;
    let secret = secrets[i_star];
    ring_keys[i_star] = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();

    let message = b"clsag roundtrip vector message".to_vec();
    let swap_id = [0x42u8; 32];
    let settlement = SettlementCtx {
        chain_tag: "evm:84532".to_string(),
        position_key: [0x11; 32],
        settle_digest: [0u8; 32],
    };

    let witness = SignerWitness {
        x: secret.to_bytes(),
        mask: masks[i_star].to_bytes(),
        amount: 0,
        i_star,
    };

    let clsag_ctx = ClsagCtx {
        ring_keys: ring_keys.clone(),
        ring_commitments: ring_commitments.clone(),
        key_image: witness.key_image_bytes(),
        n: ring_size,
    };

    let (pre, tau) = make_pre_sig(&clsag_ctx, &witness, &message, &swap_id, settlement.clone())
        .expect("make_pre_sig failed");
    let final_sig = complete(&pre, &tau);
    let extracted = extract_t(&pre, &final_sig);

    let vector = RoundTripVector {
        message_hex: hex::encode(&message),
        swap_id_hex: hex::encode(swap_id),
        settlement: SettlementVector {
            chain_tag: settlement.chain_tag.clone(),
            position_key_hex: hex::encode(settlement.position_key),
            settle_digest_hex: hex::encode(settlement.settle_digest),
        },
        clsag_ctx: ClsagCtxVector {
            ring_keys_hex: ring_keys.iter().map(hex::encode).collect(),
            ring_commitments_hex: ring_commitments.iter().map(hex::encode).collect(),
            key_image_hex: hex::encode(clsag_ctx.key_image),
            n: ring_size,
        },
        witness: WitnessVector {
            x_hex: hex::encode(witness.x),
            mask_hex: hex::encode(witness.mask),
            amount: witness.amount,
            i_star: witness.i_star,
        },
        expected: ExpectedVector {
            j: pre.j,
            pre_hash_hex: hex::encode(pre.pre_hash),
            tau_hex: hex::encode(tau),
            pre_sig: PreSigVector {
                c1_tilde_hex: hex::encode(pre.c1_tilde),
                s_tilde_hex: pre.s_tilde.iter().map(hex::encode).collect(),
                d_tilde_hex: hex::encode(pre.d_tilde),
                pseudo_out_hex: hex::encode(pre.pseudo_out),
            },
            final_sig: FinalSigVector {
                c1_hex: hex::encode(final_sig.clsag.c1.to_bytes()),
                s_hex: final_sig
                    .clsag
                    .s
                    .iter()
                    .map(|s| hex::encode(s.to_bytes()))
                    .collect(),
                d_hex: hex::encode(final_sig.clsag.D.to_bytes()),
                pseudo_out_hex: hex::encode(final_sig.pseudo_out),
            },
            extracted_t_hex: hex::encode(extracted),
        },
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&vector).expect("vector serialization failed")
    );
}
