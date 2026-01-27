//! serial.rs — helpers for inspecting and mutating CLSAG regions within a
//! serialized Monero transaction blob. The utilities here provide both:
//!   * a stub layout (for lightweight tests) keyed by MAGIC 0xA5A5_A5A5; and
//!   * a canonical path that round-trips real transactions via monero-oxide.
//!
//! All mutation helpers validate bounds and lengths before writing into the
//! byte buffer to ensure that callers cannot accidentally corrupt unrelated
//! transaction data.

use std::io::Write;

use anyhow::{anyhow, ensure, Result};

use crate::{ClsagRegions, TxBlob};

pub(crate) fn ensure_canonical_clsag_region(bytes: &[u8]) -> Result<()> {
    use curve25519_dalek::scalar::Scalar;
    use monero_oxide::io::CompressedPoint;

    if bytes.len() < 96 || !bytes.len().is_multiple_of(32) {
        anyhow::bail!("clsag region length {} invalid", bytes.len());
    }
    let chunk_count = bytes.len() / 32;
    let scalar_count = chunk_count - 2;
    for chunk in bytes[..scalar_count * 32].chunks_exact(32) {
        let arr: [u8; 32] = chunk.try_into().unwrap();
        if Scalar::from_canonical_bytes(arr).is_none().into() {
            anyhow::bail!("clsag response not canonical");
        }
    }
    let c1: [u8; 32] = bytes[scalar_count * 32..(scalar_count + 1) * 32]
        .try_into()
        .unwrap();
    if Scalar::from_canonical_bytes(c1).is_none().into() {
        anyhow::bail!("clsag challenge not canonical");
    }
    let d_bytes: [u8; 32] = bytes[(scalar_count + 1) * 32..].try_into().unwrap();
    if CompressedPoint::from(d_bytes).decompress().is_none() {
        anyhow::bail!("clsag D point invalid");
    }
    Ok(())
}

/// Compute the canonical CLSAG message hash for a serialized transaction blob.
///
/// Parses the blob with monero-oxide, ensures canonical re-serialization, and
/// delegates to `Transaction::signature_hash()` which binds the prefix and
/// RingCT base (including bulletproof commitments).
pub fn compute_clsag_message_hash(blob: &[u8]) -> Result<[u8; 32]> {
    use monero_oxide::transaction::{NotPruned, Transaction};

    let mut slice = blob;
    let tx: Transaction<NotPruned> =
        Transaction::read(&mut slice).map_err(|e| anyhow!("parse_tx: {e:?}"))?;
    ensure!(slice.is_empty(), "trailing bytes after transaction");

    let canonical = tx.serialize();
    ensure!(
        canonical.as_slice() == blob,
        "serialized bytes mismatch provided blob"
    );

    tx.signature_hash()
        .ok_or_else(|| anyhow!("transaction missing signature hash"))
}

/// Find CLSAG regions inside a serialized tx blob.
///
/// Behavior:
/// - In stub mode (default): read the simple header written by assemble_unsigned_tx_stub.
/// - In moxide mode: attempt to parse the rct_signatures / CLSAG layout using monero-oxide APIs.
///   The moxide path currently contains clear TODO markers to be implemented once the exact
///   upstream serializer types are confirmed.
///
/// Returns a vector of (offset, length) pairs describing where CLSAG bytes live in the blob.
pub fn find_clsag_regions(blob: &TxBlob) -> Result<ClsagRegions> {
    // Fast failure
    if blob.len() < 8 {
        anyhow::bail!("blob too small");
    }

    // Detect stub magic used by assemble_unsigned_tx_stub: 0xA5A5_A5A5
    let magic = u32::from_le_bytes(blob[0..4].try_into().unwrap());
    if magic == 0xA5A5_A5A5 {
        // stub layout: [u32:magic][u32: count][ repeated: u32 offset, u32 len ]...
        let count = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as usize;
        let mut regions = Vec::with_capacity(count);
        let mut cursor = 8usize;
        for i in 0..count {
            if cursor + 8 > blob.len() {
                anyhow::bail!("stub header truncated at region {}", i);
            }
            let off = u32::from_le_bytes(blob[cursor..cursor + 4].try_into().unwrap()) as usize;
            let len = u32::from_le_bytes(blob[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
            // Validate bounds
            if !off
                .checked_add(len)
                .map(|x| x <= blob.len())
                .unwrap_or(false)
            {
                anyhow::bail!(
                    "stub region {} out of bounds (off {}, len {}, blob {})",
                    i,
                    off,
                    len,
                    blob.len()
                );
            }
            regions.push((off, len));
            cursor += 8;
        }
        return Ok(regions);
    }

    let mut slice = blob.as_slice();
    let tx = monero_oxide::transaction::Transaction::read(&mut slice)
        .map_err(|e| anyhow!("parse_tx: {e:?}"))?;
    ensure!(slice.is_empty(), "trailing bytes after transaction");

    let (serialized, regions) = serialize_with_clsag_offsets(&tx)?;
    ensure!(
        serialized.as_slice() == blob,
        "serialized bytes mismatch provided blob"
    );

    Ok(regions)
}

/// Inject `clsag_bytes` at the given region index (0-based).
/// - Enforces clsag_bytes.len() == region_length.
/// - Overwrites bytes in-place.
pub fn inject_clsag_at(blob: &mut TxBlob, region_index: usize, clsag_bytes: &[u8]) -> Result<()> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        anyhow::bail!(
            "region_index {} out of range (len {})",
            region_index,
            regions.len()
        );
    }
    let (off, len) = regions[region_index];
    if clsag_bytes.len() != len {
        anyhow::bail!(
            "clsag_bytes length {} != region length {}",
            clsag_bytes.len(),
            len
        );
    }
    blob[off..off + len].copy_from_slice(clsag_bytes);
    ensure_canonical_clsag_region(&blob[off..off + len])?;
    Ok(())
}

/// Replace a subrange within a CLSAG region.
/// Example: replace only the j-th 32-byte scalar inside the region.
/// - offset_in_region: start index within the region (must be <= len - new_bytes.len()).
pub fn replace_clsag_at(
    blob: &mut TxBlob,
    region_index: usize,
    offset_in_region: usize,
    new_bytes: &[u8],
) -> Result<()> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        anyhow::bail!(
            "region_index {} out of range (len {})",
            region_index,
            regions.len()
        );
    }
    let (off, len) = regions[region_index];
    if !offset_in_region
        .checked_add(new_bytes.len())
        .map(|x| x <= len)
        .unwrap_or(false)
    {
        anyhow::bail!(
            "replacement out of range: offset {} + new_bytes {} > region len {}",
            offset_in_region,
            new_bytes.len(),
            len
        );
    }
    let start = off + offset_in_region;
    let end = start + new_bytes.len();
    blob[start..end].copy_from_slice(new_bytes);
    ensure_canonical_clsag_region(&blob[off..off + len])?;
    Ok(())
}

/// Read a subrange within a CLSAG region (useful for verifying a particular s_j)
pub fn read_clsag_subrange(
    blob: &TxBlob,
    region_index: usize,
    offset_in_region: usize,
    length: usize,
) -> Result<Vec<u8>> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        anyhow::bail!(
            "region_index {} out of range (len {})",
            region_index,
            regions.len()
        );
    }
    let (off, len) = regions[region_index];
    if !offset_in_region
        .checked_add(length)
        .map(|x| x <= len)
        .unwrap_or(false)
    {
        anyhow::bail!(
            "read out of range: offset {} + length {} > region len {}",
            offset_in_region,
            length,
            len
        );
    }
    ensure_canonical_clsag_region(&blob[off..off + len])?;
    Ok(blob[off + offset_in_region..off + offset_in_region + length].to_vec())
}

/// Write `pseudo_out` into the CLSAG prunable section for the specified input.
/// Re-parses the transaction with monero-oxide, mutates the pseudo-outs vector,
/// and re-serializes to preserve canonical encoding.
pub fn write_pseudo_out_at(
    blob: &mut TxBlob,
    input_index: usize,
    pseudo_out: monero_oxide::io::CompressedPoint,
) -> Result<()> {
    use monero_oxide::{
        ringct::RctPrunable,
        transaction::{NotPruned, Transaction},
    };

    let mut slice = blob.as_slice();
    let mut tx: Transaction<NotPruned> =
        Transaction::read(&mut slice).map_err(|e| anyhow!("parse_tx: {e:?}"))?;
    ensure!(slice.is_empty(), "trailing bytes after transaction");

    let Transaction::V2 { proofs, .. } = &mut tx else {
        return Err(anyhow!("expected CLSAG transaction (v2)"));
    };
    let proofs: &mut monero_oxide::ringct::RctProofs = proofs
        .as_mut()
        .ok_or_else(|| anyhow!("transaction missing RingCT proofs"))?;

    let pseudo_outs = match &mut proofs.prunable {
        RctPrunable::Clsag { pseudo_outs, .. } => pseudo_outs,
        _ => return Err(anyhow!("transaction prunable data is not CLSAG")),
    };

    if input_index >= pseudo_outs.len() {
        return Err(anyhow!(
            "pseudo_out index {} out of range (len={})",
            input_index,
            pseudo_outs.len()
        ));
    }

    pseudo_outs[input_index] = pseudo_out;

    let reserialized = tx.serialize();
    ensure!(
        reserialized.len() == blob.len(),
        "reserialized transaction length mismatch (old {}, new {})",
        blob.len(),
        reserialized.len()
    );

    *blob = reserialized;
    Ok(())
}

fn write_prefix(
    prefix: &monero_oxide::transaction::TransactionPrefix,
    buf: &mut Vec<u8>,
) -> Result<()> {
    use monero_oxide::io::{write_vec, VarInt};
    use monero_oxide::transaction::{Input, Output};

    prefix
        .additional_timelock
        .write(buf)
        .map_err(|e| anyhow!("write timelock: {e:?}"))?;
    write_vec(Input::write, &prefix.inputs, buf).map_err(|e| anyhow!("write inputs: {e:?}"))?;
    write_vec(Output::write, &prefix.outputs, buf).map_err(|e| anyhow!("write outputs: {e:?}"))?;
    VarInt::write(&prefix.extra.len(), buf).map_err(|e| anyhow!("write extra len: {e:?}"))?;
    buf.write_all(&prefix.extra)
        .map_err(|e| anyhow!("write extra: {e:?}"))?;
    Ok(())
}

pub(crate) fn serialize_with_clsag_offsets(
    tx: &monero_oxide::transaction::Transaction,
) -> Result<(TxBlob, ClsagRegions)> {
    use monero_oxide::io::{write_raw_vec, VarInt};
    use monero_oxide::ringct::RctPrunable;

    let mut buf = Vec::new();
    let mut regions = Vec::new();

    match tx {
        monero_oxide::transaction::Transaction::V1 { .. } => {
            return Err(anyhow!("expected CLSAG transaction (v2)"));
        }
        monero_oxide::transaction::Transaction::V2 { prefix, proofs } => {
            VarInt::write(&2u64, &mut buf).map_err(|e| anyhow!("write version: {e:?}"))?;
            write_prefix(prefix, &mut buf)?;

            match proofs {
                None => {
                    buf.write_all(&[0])
                        .map_err(|e| anyhow!("write empty proofs: {e:?}"))?;
                }
                Some(proofs) => {
                    let rct_type = proofs.rct_type();
                    proofs
                        .base
                        .write(&mut buf, rct_type)
                        .map_err(|e| anyhow!("write rct base: {e:?}"))?;
                    match &proofs.prunable {
                        RctPrunable::Clsag {
                            bulletproof,
                            clsags,
                            pseudo_outs,
                        } => {
                            buf.write_all(&[1])
                                .map_err(|e| anyhow!("write bulletproof count: {e:?}"))?;
                            bulletproof
                                .write(&mut buf)
                                .map_err(|e| anyhow!("write bulletproof: {e:?}"))?;
                            for clsag in clsags {
                                let start = buf.len();
                                clsag
                                    .write(&mut buf)
                                    .map_err(|e| anyhow!("write clsag: {e:?}"))?;
                                regions.push((start, buf.len() - start));
                            }
                            write_raw_vec(
                                monero_oxide::io::CompressedPoint::write,
                                pseudo_outs,
                                &mut buf,
                            )
                            .map_err(|e| anyhow!("write pseudo outs: {e:?}"))?;
                        }
                        _ => return Err(anyhow!("transaction prunable data is not CLSAG")),
                    }
                }
            }
        }
    }

    let canonical = tx.serialize();
    if canonical != buf {
        return Err(anyhow!("internal serialization mismatch"));
    }

    Ok((canonical, regions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemble_unsigned_tx_stub;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use proptest::{array::uniform32, prelude::*};

    pub(super) fn canonical_region(len: usize) -> Vec<u8> {
        assert!(len >= 96 && len % 32 == 0);
        let chunk_count = len / 32;
        let scalar_count = chunk_count - 2;
        let scalar_bytes = Scalar::from(3u64).to_bytes();
        let mut out = Vec::with_capacity(len);
        for _ in 0..scalar_count {
            out.extend_from_slice(&scalar_bytes);
        }
        let c1_bytes = Scalar::from(7u64).to_bytes();
        out.extend_from_slice(&c1_bytes);
        let d_bytes = ED25519_BASEPOINT_POINT.compress().to_bytes();
        out.extend_from_slice(&d_bytes);
        out
    }

    #[test]
    fn stub_find_and_inject_roundtrip() {
        let inputs = vec![];
        let outputs = vec![];
        let mut blob = assemble_unsigned_tx_stub(&inputs, &outputs).expect("assemble");
        // get regions
        let regions = find_clsag_regions(&blob).expect("find");
        assert_eq!(regions.len(), 1);
        let (off, len) = regions[0];
        assert!(len > 0 && off + len <= blob.len());
        // create dummy bytes
        let dummy = canonical_region(len);
        inject_clsag_at(&mut blob, 0, &dummy).expect("inject");
        let read = read_clsag_subrange(&blob, 0, 0, len).expect("read");
        assert_eq!(read, dummy);
    }

    #[test]
    fn stub_replace_subrange() {
        let inputs = vec![];
        let outputs = vec![];
        let mut blob = assemble_unsigned_tx_stub(&inputs, &outputs).expect("assemble stub");
        let regions = find_clsag_regions(&blob).expect("find");
        let (_off, len) = regions[0];
        // build a region full of zeros then replace the middle 32 bytes
        let mut region = canonical_region(len);
        inject_clsag_at(&mut blob, 0, &region).expect("inject canonical");
        let replace_scalar = Scalar::from(42u64).to_bytes();
        // pick offset such that 32 bytes fit (safe in our stub)
        let offset_in_region = 32;
        replace_clsag_at(&mut blob, 0, offset_in_region, &replace_scalar).expect("replace");
        region[offset_in_region..offset_in_region + 32].copy_from_slice(&replace_scalar);
        let read_back = read_clsag_subrange(&blob, 0, offset_in_region, 32).expect("readback");
        assert_eq!(read_back, replace_scalar.to_vec());
    }

    #[test]
    fn stub_read_out_of_bounds_errors() {
        let inputs = vec![];
        let outputs = vec![];
        let blob = assemble_unsigned_tx_stub(&inputs, &outputs).expect("assemble stub");
        let regions = find_clsag_regions(&blob).expect("find");
        let (_off, len) = regions[0];
        // attempt to read beyond region length should error
        let res = read_clsag_subrange(&blob, 0, len, 1);
        assert!(res.is_err(), "expected out-of-bounds read to error");
    }

    #[test]
    fn stub_replace_region_index_oob_errors() {
        let inputs = vec![];
        let outputs = vec![];
        let mut blob = assemble_unsigned_tx_stub(&inputs, &outputs).expect("assemble stub");
        // region index 1 is out of range (only region 0 exists)
        let res = replace_clsag_at(&mut blob, 1, 0, &[0u8; 1]);
        assert!(res.is_err(), "expected region_index out-of-range to error");
    }

    proptest! {
        #[test]
        fn ensure_rejects_noncanonical_scalars(
            scalar_count in 3usize..8,
            scalar_index in 0usize..16,
            invalid_scalar in uniform32(any::<u8>()),
        ) {
            let len = (scalar_count + 2) * 32;
            let mut region = canonical_region(len);
            prop_assume!(bool::from(
                Scalar::from_canonical_bytes(invalid_scalar).is_none()
            ));
            let idx = scalar_index % scalar_count;
            let start = idx * 32;
            region[start..start + 32].copy_from_slice(&invalid_scalar);
            prop_assert!(ensure_canonical_clsag_region(&region).is_err());
        }
    }

    proptest! {
        #[test]
        fn ensure_rejects_invalid_points(
            scalar_count in 3usize..8,
            invalid_point in uniform32(any::<u8>()),
        ) {
            use monero_oxide::io::CompressedPoint;

            let len = (scalar_count + 2) * 32;
            let mut region = canonical_region(len);
            // Guard to only test bytes that fail decompression so the property is meaningful.
            prop_assume!(CompressedPoint::from(invalid_point).decompress().is_none());
            let start = len - 32;
            region[start..].copy_from_slice(&invalid_point);
            prop_assert!(ensure_canonical_clsag_region(&region).is_err());
        }
    }

    #[cfg(feature = "moxide")]
    mod moxide {
        use super::*;
        use crate::{
            assemble_unsigned_tx, read_clsag_subrange, replace_clsag_at, Inputs, Outputs, RctMeta,
        };
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
        use monero_oxide::{
            io::CompressedPoint,
            primitives::Commitment,
            ringct::{
                bulletproofs::Bulletproof, clsag::Clsag, EncryptedAmount, RctBase, RctProofs,
                RctPrunable,
            },
            transaction::{Input, NotPruned, Output, Timelock, Transaction},
        };
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

        fn load_production_blob() -> TxBlob {
            let hex_blob =
                include_str!("../../..//vectors/tx_builder/production_clsag_tx_hex.txt").trim();
            hex::decode(hex_blob).expect("decode production fixture")
        }

        fn multi_input_blob(input_count: usize, ring_size: usize) -> TxBlob {
            assert!(input_count >= 2);
            let mut rng = ChaCha20Rng::from_seed([9u8; 32]);

            let outputs: Outputs = vec![Output {
                amount: None,
                key: CompressedPoint::from(
                    (ED25519_BASEPOINT_POINT * Scalar::from(7u64)).compress(),
                ),
                view_tag: Some(1),
            }];

            let output_commitment = Commitment::new(Scalar::from(5u64), 2);
            let bulletproof = Bulletproof::prove_plus(&mut rng, vec![output_commitment.clone()])
                .expect("bulletproof generation");

            let base = RctBase {
                fee: 0,
                pseudo_outs: vec![],
                encrypted_amounts: vec![EncryptedAmount::Compact { amount: [0u8; 8] }],
                commitments: vec![CompressedPoint::from(
                    output_commitment.calculate().compress(),
                )],
            };

            let mut inputs: Inputs = Vec::with_capacity(input_count);
            let mut clsags = Vec::with_capacity(input_count);
            let mut pseudo_outs = Vec::with_capacity(input_count);
            for i in 0..input_count {
                inputs.push(Input::ToKey {
                    amount: None,
                    key_offsets: (1..=ring_size as u64).collect(),
                    key_image: CompressedPoint::from(
                        (ED25519_BASEPOINT_POINT * Scalar::from((50 + i) as u64)).compress(),
                    ),
                });

                let d_point = (ED25519_BASEPOINT_POINT * Scalar::from((i + 11) as u64)).compress();
                clsags.push(Clsag {
                    D: CompressedPoint::from(d_point),
                    s: vec![Scalar::from((20 + i) as u64); ring_size],
                    c1: Scalar::from((30 + i) as u64),
                });

                let pseudo_commitment =
                    Commitment::new(Scalar::from((40 + i) as u64), 2).calculate();
                pseudo_outs.push(CompressedPoint::from(pseudo_commitment.compress()));
            }

            let prunable = RctPrunable::Clsag {
                bulletproof,
                clsags,
                pseudo_outs,
            };

            let meta = RctMeta {
                timelock: Timelock::None,
                extra: vec![0u8; 2],
                proofs: RctProofs { base, prunable },
            };

            assemble_unsigned_tx(&inputs, &outputs, &meta).expect("assemble multi-input blob")
        }

        #[test]
        fn production_fixture_validates_region_and_pseudo_out_mutations() -> Result<()> {
            let mut blob = load_production_blob();
            let baseline = find_clsag_regions(&blob)?;
            assert!(
                !baseline.is_empty(),
                "production fixture must contain clsag regions"
            );

            let (_off, len) = baseline[0];
            let replacement = canonical_region(len);
            inject_clsag_at(&mut blob, 0, &replacement)?;
            let after_inject = find_clsag_regions(&blob)?;
            assert_eq!(baseline, after_inject, "offsets must stay stable");
            assert_eq!(
                read_clsag_subrange(&blob, 0, 0, len)?,
                replacement,
                "region bytes should match injected canonical data"
            );

            let new_pseudo =
                CompressedPoint::from((ED25519_BASEPOINT_POINT * Scalar::from(111u64)).compress());
            write_pseudo_out_at(&mut blob, 0, new_pseudo)?;

            let mut slice = blob.as_slice();
            let tx: Transaction<NotPruned> =
                Transaction::read(&mut slice).map_err(|e| anyhow!("parse_tx: {e:?}"))?;
            ensure!(slice.is_empty(), "trailing bytes after transaction");
            match tx {
                Transaction::V2 {
                    proofs: Some(proofs),
                    ..
                } => match proofs.prunable {
                    RctPrunable::Clsag { pseudo_outs, .. } => {
                        assert_eq!(pseudo_outs[0], new_pseudo, "pseudo out not rewritten");
                    }
                    _ => anyhow::bail!("expected clsag prunable section"),
                },
                _ => anyhow::bail!("fixture must be clsag v2 transaction"),
            }

            Ok(())
        }

        #[test]
        fn concurrent_region_mutations_preserve_offsets() -> Result<()> {
            let mut blob = multi_input_blob(3, 5);
            let baseline = find_clsag_regions(&blob)?;
            assert!(
                baseline.len() >= 2,
                "multi-input fixture should expose multiple regions"
            );

            for (idx, (_off, len)) in baseline.iter().copied().enumerate() {
                let mut replacement = canonical_region(len);
                replacement[0] = (idx as u8) + 1;
                inject_clsag_at(&mut blob, idx, &replacement)?;

                let scalar_override = Scalar::from((idx as u64) + 90).to_bytes();
                replace_clsag_at(&mut blob, idx, 32, &scalar_override)?;
                assert_eq!(
                    read_clsag_subrange(&blob, idx, 32, 32)?,
                    scalar_override.to_vec(),
                    "subrange replacement should take effect"
                );
            }

            let after = find_clsag_regions(&blob)?;
            assert_eq!(baseline, after, "region offsets must remain stable");
            Ok(())
        }
    }
}
