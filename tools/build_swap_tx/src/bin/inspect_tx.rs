use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use monero_oxide::{
    io::CompressedPoint as OxCompressedPoint,
    primitives::Commitment,
    ringct::{clsag::Clsag, RctPrunable},
    transaction::{Input as MoneroInput, NotPruned, Transaction},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use tx_builder::convert::{fetch_ring_keys_by_gi, RingMemberData};

#[derive(Debug, Parser)]
struct Args {
    /// Path to the serialized transaction blob (e.g. out/final_tx.bin)
    #[arg(long)]
    tx_file: PathBuf,

    /// Daemon RPC endpoint used to resolve ring members
    #[arg(long, default_value = "http://127.0.0.1:58081")]
    daemon_url: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let blob =
        std::fs::read(&args.tx_file).with_context(|| format!("read {}", args.tx_file.display()))?;

    let msg_hash =
        tx_builder::compute_clsag_message_hash(&blob).context("compute clsag message hash")?;

    let mut slice = blob.as_slice();
    let tx: Transaction<NotPruned> =
        Transaction::read(&mut slice).map_err(|e| anyhow!("parse transaction: {e:?}"))?;
    if !slice.is_empty() {
        return Err(anyhow!("trailing bytes after transaction blob"));
    }

    let (inputs, proofs) = match tx {
        Transaction::V1 { .. } => return Err(anyhow!("expected v2 transaction")),
        Transaction::V2 { prefix, proofs } => {
            let proofs = proofs.ok_or_else(|| anyhow!("transaction missing RingCT proofs"))?;
            (prefix.inputs, proofs)
        }
    };

    println!("Rct type: {:?}", proofs.rct_type());

    println!(
        "RctBase pseudo_outs: {} | commitments: {}",
        proofs.base.pseudo_outs.len(),
        proofs.base.commitments.len()
    );

    let commitments = proofs.base.commitments.clone();

    let (clsags, pseudo_outs, bulletproof) = match proofs.prunable {
        RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            bulletproof,
            ..
        } => (clsags, pseudo_outs, bulletproof),
        _ => return Err(anyhow!("transaction prunable data is not CLSAG")),
    };
    println!("Prunable pseudo_outs: {}", pseudo_outs.len());

    if clsags.len() != inputs.len() || pseudo_outs.len() != inputs.len() {
        return Err(anyhow!(
            "input/prunable mismatch: inputs={} clsags={} pseudo_outs={}",
            inputs.len(),
            clsags.len(),
            pseudo_outs.len()
        ));
    }

    let rpc = monero_rpc::MoneroRpc::new(&args.daemon_url, None)?;

    for (index, input) in inputs.iter().enumerate() {
        let (key_offsets, key_image) = match input {
            MoneroInput::ToKey {
                key_offsets,
                key_image,
                ..
            } => (key_offsets.clone(), *key_image),
            _ => {
                println!("Input {index}: non-ToKey input (skipping)");
                continue;
            }
        };

        let absolute = offsets_to_absolute(&key_offsets);
        let members = fetch_ring_keys_by_gi(&rpc, &absolute).with_context(|| {
            format!("fetch ring members for input {index} (indices={absolute:?})")
        })?;

        let mut ring = Vec::with_capacity(absolute.len());
        let mut ctx_keys = Vec::with_capacity(absolute.len());
        let mut ctx_commitments = Vec::with_capacity(absolute.len());
        for gi in &absolute {
            let RingMemberData {
                key, commitment, ..
            } = members.get(gi).ok_or_else(|| {
                anyhow!(
                    "ring metadata for input {} missing global index {}",
                    index,
                    gi
                )
            })?;
            ctx_keys.push(*key);
            ctx_commitments.push(*commitment);
            let key_cp = OxCompressedPoint::from(*key);
            let comm_cp = OxCompressedPoint::from(*commitment);
            ring.push([key_cp, comm_cp]);
        }

        let ctx = adaptor_clsag::ClsagCtx {
            ring_keys: ctx_keys,
            ring_commitments: ctx_commitments,
            key_image: key_image.to_bytes(),
            n: ring.len(),
        };

        let clsag = clsags[index].clone();
        let pseudo_out = pseudo_outs[index];

        match verify_clsag(&clsag, &ring, &key_image, &pseudo_out, &msg_hash) {
            Ok(()) => {
                println!(
                    "Input {index}: CLSAG verification OK (ring size {})",
                    ring.len()
                );
            }
            Err(err) => {
                println!("Input {index}: CLSAG verification FAILED: {err}");
            }
        }

        let final_sig = adaptor_clsag::FinalSig {
            clsag,
            pseudo_out: pseudo_out.to_bytes(),
        };
        let ok = adaptor_clsag::verify(&ctx, &msg_hash, &final_sig);
        println!(
            "Input {index}: adaptor verify -> {}",
            if ok { "success" } else { "failure" }
        );
    }

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let bp_ok = bulletproof.verify(&mut rng, &commitments);
    println!(
        "Bulletproof verification: {}",
        if bp_ok { "success" } else { "failure" }
    );

    let sum_commitments = commitments
        .iter()
        .try_fold(EdwardsPoint::identity(), |acc, cp| {
            let point = cp
                .decompress()
                .ok_or_else(|| anyhow!("output commitment failed to decompress"))?;
            Ok::<_, anyhow::Error>(acc + point)
        })?;
    let sum_pseudo = pseudo_outs
        .iter()
        .try_fold(EdwardsPoint::identity(), |acc, cp| {
            let point = cp
                .decompress()
                .ok_or_else(|| anyhow!("pseudo_out failed to decompress"))?;
            Ok::<_, anyhow::Error>(acc + point)
        })?;
    let fee_commitment = Commitment::new(Scalar::ZERO, proofs.base.fee).calculate();
    let expected = sum_commitments + fee_commitment;
    println!(
        "Pseudo sum == commitments + fee? {}",
        if sum_pseudo == expected { "yes" } else { "no" }
    );

    Ok(())
}

fn offsets_to_absolute(offsets: &[u64]) -> Vec<u64> {
    let mut result = Vec::with_capacity(offsets.len());
    let mut sum = 0u64;
    for offset in offsets {
        sum = sum.saturating_add(*offset);
        result.push(sum);
    }
    result
}

fn verify_clsag(
    clsag: &Clsag,
    ring: &[[OxCompressedPoint; 2]],
    key_image: &OxCompressedPoint,
    pseudo_out: &OxCompressedPoint,
    msg_hash: &[u8; 32],
) -> Result<(), String> {
    let ring_vec = ring.to_vec();
    clsag
        .verify(ring_vec, key_image, pseudo_out, msg_hash)
        .map_err(|e| format!("{e:?}"))
}
