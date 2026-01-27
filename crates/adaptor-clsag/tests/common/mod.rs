use adaptor_clsag::{ClsagCtx, SettlementCtx, SignerWitness};
use serde::Deserialize;
use std::path::PathBuf;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct RoundTripVector {
    pub message_hex: String,
    pub swap_id_hex: String,
    pub settlement: SettlementVector,
    pub clsag_ctx: ClsagCtxVector,
    pub witness: WitnessVector,
    pub expected: ExpectedVector,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SettlementVector {
    pub chain_tag: String,
    pub position_key_hex: String,
    pub settle_digest_hex: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ClsagCtxVector {
    pub ring_keys_hex: Vec<String>,
    pub ring_commitments_hex: Vec<String>,
    pub key_image_hex: String,
    pub n: usize,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct WitnessVector {
    pub x_hex: String,
    pub mask_hex: String,
    pub amount: u64,
    pub i_star: usize,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ExpectedVector {
    pub j: usize,
    pub pre_hash_hex: String,
    pub tau_hex: String,
    pub pre_sig: PreSigVector,
    pub final_sig: FinalSigVector,
    pub extracted_t_hex: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PreSigVector {
    pub c1_tilde_hex: String,
    pub s_tilde_hex: Vec<String>,
    pub d_tilde_hex: String,
    pub pseudo_out_hex: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct FinalSigVector {
    pub c1_hex: String,
    pub s_hex: Vec<String>,
    pub d_hex: String,
    pub pseudo_out_hex: String,
}

pub fn load_roundtrip_vector() -> RoundTripVector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/clsag/roundtrip.json");
    let json = std::fs::read_to_string(path).expect("roundtrip vector readable");
    serde_json::from_str(&json).expect("roundtrip vector decodes")
}

pub fn build_from_vector(
    vector: &RoundTripVector,
) -> (ClsagCtx, SettlementCtx, SignerWitness, Vec<u8>, [u8; 32]) {
    let settlement = SettlementCtx {
        chain_tag: vector.settlement.chain_tag.clone(),
        position_key: hex_to_array(&vector.settlement.position_key_hex),
        settle_digest: hex_to_array(&vector.settlement.settle_digest_hex),
    };

    let ctx = ClsagCtx {
        ring_keys: vector
            .clsag_ctx
            .ring_keys_hex
            .iter()
            .map(|h| hex_to_array::<32>(h))
            .collect(),
        ring_commitments: vector
            .clsag_ctx
            .ring_commitments_hex
            .iter()
            .map(|h| hex_to_array::<32>(h))
            .collect(),
        key_image: hex_to_array::<32>(&vector.clsag_ctx.key_image_hex),
        n: vector.clsag_ctx.n,
    };

    let witness = SignerWitness {
        x: hex_to_array::<32>(&vector.witness.x_hex),
        mask: hex_to_array::<32>(&vector.witness.mask_hex),
        amount: vector.witness.amount,
        i_star: vector.witness.i_star,
    };

    let message = hex_to_vec(&vector.message_hex);
    let swap_id = hex_to_array::<32>(&vector.swap_id_hex);

    (ctx, settlement, witness, message, swap_id)
}

pub fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("hex decode")
}

pub fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex_to_vec(hex);
    assert_eq!(bytes.len(), N, "expected {N} bytes");
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}
