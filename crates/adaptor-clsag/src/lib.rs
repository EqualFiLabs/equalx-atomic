//! EqualX • CLSAG Adaptor (core lib)
//! Implementation notes: container bytes, transcript, admissible j, extract, verify.

pub mod encoding;
pub mod error;
pub mod finalsig_region;
pub mod index;
pub mod presig_region;
pub mod tau;
pub mod transcript;
pub mod wire;

pub use error::EswpError;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar};
use hkdf::Hkdf;
use merlin::Transcript;
use monero_generators::biased_hash_to_point;
use monero_oxide::{
    io::CompressedPoint,
    primitives::{Commitment, Decoys},
    ringct::clsag::{Clsag, ClsagContext},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha3::{Digest, Sha3_256};
use tx_builder::{
    find_clsag_regions, read_clsag_subrange, replace_clsag_region, replace_pseudo_out_at,
    response_count, TxBlob,
};
use zeroize::Zeroizing;

/// 32B scalar/point encodings; use concrete types once monero_oxide is linked.
/// We keep a minimal, compile-safe skeleton with opaque bytes to unblock FFI & CLI work.
pub const BACKEND_ID_CLSAG: u8 = 0x01;
pub const WIRE_VERSION: u16 = 1;

pub const SAMPLE_RING_KEYS: [[u8; 32]; 5] = [
    [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ],
    [
        0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f, 0x39,
        0x97, 0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09, 0xf3, 0xcd,
        0x60, 0x22,
    ],
    [
        0xd4, 0xb4, 0xf5, 0x78, 0x48, 0x68, 0xc3, 0x02, 0x04, 0x03, 0x24, 0x67, 0x17, 0xec, 0x16,
        0x9f, 0xf7, 0x9e, 0x26, 0x60, 0x8e, 0xa1, 0x26, 0xa1, 0xab, 0x69, 0xee, 0x77, 0xd1, 0xb1,
        0x67, 0x12,
    ],
    [
        0x2f, 0x11, 0x32, 0xca, 0x61, 0xab, 0x38, 0xdf, 0xf0, 0x0f, 0x2f, 0xea, 0x32, 0x28, 0xf2,
        0x4c, 0x6c, 0x71, 0xd5, 0x80, 0x85, 0xb8, 0x0e, 0x47, 0xe1, 0x95, 0x15, 0xcb, 0x27, 0xe8,
        0xd0, 0x47,
    ],
    [
        0xed, 0xc8, 0x76, 0xd6, 0x83, 0x1f, 0xd2, 0x10, 0x5d, 0x0b, 0x43, 0x89, 0xca, 0x2e, 0x28,
        0x31, 0x66, 0x46, 0x92, 0x89, 0x14, 0x6e, 0x2c, 0xe0, 0x6f, 0xae, 0xfe, 0x98, 0xb2, 0x25,
        0x48, 0xdf,
    ],
];

pub const SAMPLE_RING_COMMITMENTS: [[u8; 32]; 5] = SAMPLE_RING_KEYS;

/// Chain-agnostic settlement binding (see §1.2)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementCtx {
    pub chain_tag: String, // e.g. "evm:84532"
    pub position_key: [u8; 32], // Position NFT-derived key (bytes32)
    pub settle_digest: [u8; 32],
}

/// Immutable context for CLSAG (public ring + key image)
#[derive(Clone, Debug)]
pub struct ClsagCtx {
    pub ring_keys: Vec<[u8; 32]>,
    pub ring_commitments: Vec<[u8; 32]>,
    pub key_image: [u8; 32],
    pub n: usize,
}

/// Pre-signature container (library-facing); mirrors spec concepts.
#[derive(Clone, Debug)]
pub struct PreSig {
    pub c1_tilde: [u8; 32],
    pub s_tilde: Vec<[u8; 32]>, // length == n
    pub d_tilde: [u8; 32],
    pub pseudo_out: [u8; 32],
    pub j: usize,
    pub ctx: SettlementCtx,
    pub pre_hash: [u8; 32],
}

/// Canonical CLSAG bytes (opaque to this layer).
#[derive(Clone, Debug)]
pub struct FinalSig {
    pub clsag: Clsag,
    pub pseudo_out: [u8; 32],
}

/// Signer witness (private x, true index i_star).
#[derive(Clone, Debug)]
pub struct SignerWitness {
    pub x: [u8; 32], // scalar LE (reduced)
    pub mask: [u8; 32],
    pub amount: u64,
    pub i_star: usize,
}

impl ClsagCtx {
    fn default_commitment_bytes() -> [u8; 32] {
        CompressedPoint::from(Commitment::zero().calculate().compress()).to_bytes()
    }

    pub fn ring_edwards(&self) -> Vec<[EdwardsPoint; 2]> {
        let commitment_bytes = if self.ring_commitments.is_empty() {
            vec![Self::default_commitment_bytes(); self.n]
        } else {
            assert_eq!(self.ring_commitments.len(), self.n);
            self.ring_commitments.clone()
        };

        self.ring_keys
            .iter()
            .zip(commitment_bytes.iter())
            .map(|(key_bytes, commitment_bytes)| {
                let key = CompressedPoint::from(*key_bytes)
                    .decompress()
                    .expect("invalid ring key");
                let commitment = CompressedPoint::from(*commitment_bytes)
                    .decompress()
                    .expect("invalid ring commitment");
                [key, commitment]
            })
            .collect()
    }

    pub fn ring_compressed(&self) -> Vec<[CompressedPoint; 2]> {
        let commitment_bytes = if self.ring_commitments.is_empty() {
            vec![Self::default_commitment_bytes(); self.n]
        } else {
            assert_eq!(self.ring_commitments.len(), self.n);
            self.ring_commitments.clone()
        };

        self.ring_keys
            .iter()
            .zip(commitment_bytes.iter())
            .map(|(key_bytes, commitment_bytes)| {
                [
                    CompressedPoint::from(*key_bytes),
                    CompressedPoint::from(*commitment_bytes),
                ]
            })
            .collect()
    }

    pub fn key_image(&self) -> CompressedPoint {
        CompressedPoint::from(self.key_image)
    }
}

impl SignerWitness {
    pub fn secret_key(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.x)
    }

    pub fn commitment(&self) -> Commitment {
        Commitment::new(Scalar::from_bytes_mod_order(self.mask), self.amount)
    }

    pub fn key_image_bytes(&self) -> [u8; 32] {
        let secret = self.secret_key();
        let public = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();
        let hashed = biased_hash_to_point(public);
        (hashed * secret).compress().to_bytes()
    }
}

/// Deterministic transcript per spec (bindings §7), returns (t, per-member r, pre_hash).
pub fn derive_transcript(
    ctx: &ClsagCtx,
    m: &[u8],
    j: usize,
    swap_id: &[u8; 32],
    sctx: &SettlementCtx,
) -> (Transcript, [u8; 32], Vec<[u8; 32]>, [u8; 32]) {
    let ring_hash = crate::transcript::ring_hash(ctx);
    let message_hash = crate::transcript::message_hash(m);
    let settlement_hash = crate::transcript::settlement_hash(sctx);

    let mut tr = Transcript::new(b"EqualX/0.0.1/CLSAG-Adaptor");
    tr.append_message(b"ring_hash", &ring_hash);
    tr.append_message(b"key_image", &ctx.key_image);
    tr.append_message(b"message_hash", &message_hash);
    tr.append_message(b"designated_index", &(j as u32).to_le_bytes());
    tr.append_message(b"swap_id", swap_id);
    tr.append_message(b"chain_tag", sctx.chain_tag.as_bytes());
    tr.append_message(b"position_key", &sctx.position_key);
    tr.append_message(b"settle_digest", &sctx.settle_digest);

    let j_bytes = (j as u32).to_le_bytes();
    let hkdf_ikm = [
        ring_hash.as_ref(),
        message_hash.as_ref(),
        ctx.key_image.as_ref(),
        &swap_id[..],
        j_bytes.as_slice(),
    ]
    .concat();
    let hk = Hkdf::<Sha3_256>::new(Some(settlement_hash.as_ref()), &hkdf_ikm);

    let mut t = [0u8; 32];
    hk.expand(b"clsag/t", &mut t).expect("hkdf expand for t");

    let mut r = Vec::with_capacity(ctx.n);
    for idx in 0..ctx.n {
        let mut scalar_bytes = [0u8; 32];
        let mut info = [0u8; 11];
        info[..7].copy_from_slice(b"clsag/r");
        info[7..].copy_from_slice(&(idx as u32).to_le_bytes());
        hk.expand(&info, &mut scalar_bytes)
            .expect("hkdf expand for r_i");
        r.push(scalar_bytes);
    }

    // Exported pre_hash (bind ring/message/j/swap/ctx deterministically)
    let preimage = [
        ring_hash.as_ref(),
        message_hash.as_ref(),
        j_bytes.as_slice(),
        &swap_id[..],
        settlement_hash.as_ref(),
    ]
    .concat();
    let pre_hash: [u8; 32] = Sha3_256::digest(preimage).into();

    (tr, t, r, pre_hash)
}

/// make_pre_sig: skeleton that returns shaped data; real math deferred to Phase 1.
pub fn make_pre_sig(
    ctx: &ClsagCtx,
    witness: &SignerWitness,
    m: &[u8],
    swap_id: &[u8; 32],
    sctx: SettlementCtx,
) -> Result<(PreSig, [u8; 32]), EswpError> {
    encoding::validate_scalar_le(&witness.x)?;
    encoding::validate_scalar_le(&witness.mask)?;
    if ctx.ring_keys.len() != ctx.n {
        return Err(EswpError::RingInvalid);
    }
    if ctx.n < 5 {
        return Err(EswpError::RingInvalid);
    }
    encoding::ensure_unique_ring(&ctx.ring_keys)?;
    for key in &ctx.ring_keys {
        encoding::validate_point_le(key)?;
    }
    if !ctx.ring_commitments.is_empty() {
        if ctx.ring_commitments.len() != ctx.n {
            return Err(EswpError::RingInvalid);
        }
        for commitment in &ctx.ring_commitments {
            encoding::validate_point_le(commitment)?;
        }
    }
    encoding::validate_point_le(&ctx.key_image)?;

    let ring_hash = crate::transcript::ring_hash(ctx);

    let message_hash = if m.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(m);
        arr
    } else if let Ok(hash) = tx_builder::compute_clsag_message_hash(m) {
        hash
    } else {
        crate::transcript::message_hash(m)
    };
    let settlement_hash = crate::transcript::settlement_hash(&sctx);
    let j = index::compute_designated_index(
        &ring_hash,
        &ctx.key_image,
        &message_hash,
        swap_id,
        &settlement_hash,
        ctx.n,
    );

    let (_tr, _tau_placeholder, _r, pre_hash) = derive_transcript(ctx, m, j, swap_id, &sctx);
    let tau_bytes = tau::derive_tau(&sctx.settle_digest, swap_id, &pre_hash, j as u32);

    let ring_points = ctx.ring_edwards();
    let offsets = vec![0u64; ring_points.len()];
    let decoys = Decoys::new(offsets, witness.i_star as u8, ring_points)
        .expect("invalid ring configuration");
    let commitment = witness.commitment();
    let clsag_ctx =
        ClsagContext::new(decoys, commitment.clone()).expect("failed to build CLSAG context");

    // Use deterministic RNG to keep vector fixtures stable until transcript-derived randomness lands.
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let inputs = vec![(Zeroizing::new(witness.secret_key()), clsag_ctx)];
    let msg_hash = message_hash;
    let mut clsag_outputs =
        Clsag::sign(&mut rng, inputs, Scalar::ZERO, msg_hash).expect("CLSAG signing failed");
    let (mut clsag, pseudo_out) = clsag_outputs.pop().expect("missing CLSAG output");

    let tau_scalar = Scalar::from_bytes_mod_order(tau_bytes);
    clsag.s[j] += tau_scalar;
    let tau_bytes = tau_scalar.to_bytes();

    let pre = PreSig {
        c1_tilde: clsag.c1.to_bytes(),
        s_tilde: clsag.s.iter().map(|x| x.to_bytes()).collect(),
        d_tilde: clsag.D.to_bytes(),
        pseudo_out: CompressedPoint::from(pseudo_out.compress()).to_bytes(),
        j,
        ctx: sctx,
        pre_hash,
    };
    Ok((pre, tau_bytes))
}

pub fn complete(pre: &PreSig, tau: &[u8; 32]) -> FinalSig {
    let mut responses: Vec<Scalar> = pre
        .s_tilde
        .iter()
        .map(|bytes| {
            Scalar::from_canonical_bytes(*bytes)
                .unwrap_or_else(|| Scalar::from_bytes_mod_order(*bytes))
        })
        .collect();

    let t = Scalar::from_bytes_mod_order(*tau);
    let j = pre.j;
    responses[j] -= t;

    let clsag = Clsag {
        D: CompressedPoint::from(pre.d_tilde),
        s: responses,
        c1: Scalar::from_canonical_bytes(pre.c1_tilde)
            .unwrap_or_else(|| Scalar::from_bytes_mod_order(pre.c1_tilde)),
    };

    FinalSig {
        clsag,
        pseudo_out: pre.pseudo_out,
    }
}

/// Replace the biased response `s_j` in-place inside a pre-signed transaction blob,
/// yielding a fully formed CLSAG ready for broadcast.
pub fn finalize_tx(
    pre: &PreSig,
    tau: &[u8; 32],
    mut blob_with_presig: TxBlob,
    input_region_index: usize,
) -> Result<TxBlob, EswpError> {
    encoding::validate_presig(pre)?;
    let regions =
        find_clsag_regions(&blob_with_presig).map_err(|_| EswpError::EncodingNoncanonical)?;
    if input_region_index >= regions.len() {
        return Err(EswpError::RingInvalid);
    }
    let (_off, region_len) = regions[input_region_index];

    let region_bytes = read_clsag_subrange(&blob_with_presig, input_region_index, 0, region_len)
        .map_err(|_| EswpError::EncodingNoncanonical)?;
    let expected = crate::presig_region::serialize_presig_region(pre, region_len)?;
    if region_bytes != expected {
        return Err(EswpError::PreHashMismatch);
    }

    let final_sig = complete(pre, tau);
    let response_total = response_count(&blob_with_presig, input_region_index)
        .map_err(|_| EswpError::EncodingNoncanonical)?;
    let j = pre.j;
    if j >= response_total {
        return Err(EswpError::RingInvalid);
    }

    let mut final_region = Vec::with_capacity(region_len);
    final_sig
        .clsag
        .write(&mut final_region)
        .map_err(|_| EswpError::EncodingNoncanonical)?;
    if final_region.len() != region_len {
        return Err(EswpError::EncodingNoncanonical);
    }

    replace_clsag_region(&mut blob_with_presig, input_region_index, &final_region)
        .map_err(|_| EswpError::EncodingNoncanonical)?;

    let pseudo_out = CompressedPoint::from(final_sig.pseudo_out);
    replace_pseudo_out_at(&mut blob_with_presig, input_region_index, pseudo_out)
        .map_err(|_| EswpError::EncodingNoncanonical)?;

    Ok(blob_with_presig)
}

pub fn verify(ctx: &ClsagCtx, m: &[u8], sig: &FinalSig) -> bool {
    let ring = ctx.ring_compressed();
    let key_image = ctx.key_image();
    let pseudo_out = CompressedPoint::from(sig.pseudo_out);
    let msg_hash = if m.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(m);
        arr
    } else if let Ok(hash) = tx_builder::compute_clsag_message_hash(m) {
        hash
    } else {
        crate::transcript::message_hash(m)
    };

    sig.clsag
        .verify(ring, &key_image, &pseudo_out, &msg_hash)
        .is_ok()
}

pub fn extract_t(pre: &PreSig, final_sig: &FinalSig) -> [u8; 32] {
    let j = pre.j;
    let s_pre = Scalar::from_canonical_bytes(pre.s_tilde[j])
        .unwrap_or_else(|| Scalar::from_bytes_mod_order(pre.s_tilde[j]));
    let s_final = final_sig.clsag.s[j];
    (s_pre - s_final).to_bytes()
}

/// Build a pre-signature and inject it into a freshly assembled unsigned tx blob.
/// Returns (pre_sig, tau, tx_blob_with_presig).
#[allow(clippy::too_many_arguments)]
pub fn make_pre_sig_into_tx(
    ctx: &ClsagCtx,
    witness: &SignerWitness,
    m: &[u8],
    swap_id: [u8; 32],
    sctx: SettlementCtx,
    inputs: &tx_builder::Inputs,
    outputs: &tx_builder::Outputs,
    meta: &tx_builder::RctMeta,
    input_index: usize,
) -> Result<(PreSig, [u8; 32], TxBlob), EswpError> {
    use tx_builder::{
        assemble_unsigned_tx, find_clsag_regions, read_clsag_subrange, replace_clsag_at,
    };

    // 1) Build the biased pre-signature and tau as usual
    let (pre, tau) = make_pre_sig(ctx, witness, m, &swap_id, sctx)?;

    // 2) Assemble an unsigned tx blob using the real monero-oxide path
    let mut blob =
        assemble_unsigned_tx(inputs, outputs, meta).map_err(|_| EswpError::EncodingNoncanonical)?;

    // 3) Resolve CLSAG regions and locate the designated input
    let regions = find_clsag_regions(&blob).map_err(|_| EswpError::EncodingNoncanonical)?;
    if input_index >= regions.len() {
        return Err(EswpError::RingInvalid);
    }
    let (_off, reg_len) = regions[input_index];

    // 4) Serialize the PreSig into a buffer sized exactly to the region
    let region_bytes = crate::presig_region::serialize_presig_region(&pre, reg_len)?;

    // 5) Inject bytes in-place for the entire CLSAG region
    replace_clsag_at(&mut blob, input_index, 0, &region_bytes)
        .map_err(|_| EswpError::EncodingNoncanonical)?;

    // 6) Verify the write for determinism
    let back = read_clsag_subrange(&blob, input_index, 0, reg_len)
        .map_err(|_| EswpError::EncodingNoncanonical)?;
    if back != region_bytes {
        return Err(EswpError::EncodingNoncanonical);
    }

    Ok((pre, tau, blob))
}
