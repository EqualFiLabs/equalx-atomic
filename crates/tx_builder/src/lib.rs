//! tx_builder — thin adapter over monero-oxide for assembling a tx and locating CLSAG regions.

use anyhow::{anyhow, ensure, Result};

use crate::serial::ensure_canonical_clsag_region;

mod clsag;
#[cfg(not(target_arch = "wasm32"))]
pub mod convert;
#[cfg(not(target_arch = "wasm32"))]
pub mod ecdh;
pub mod serial;
#[cfg(not(target_arch = "wasm32"))]
pub mod wallet;

pub use clsag::{read_response_at, replace_response_at, response_count, response_offset};

pub type TxBlob = Vec<u8>;
pub type ClsagRegions = Vec<(usize, usize)>;

pub fn compute_clsag_message_hash(blob: &[u8]) -> anyhow::Result<[u8; 32]> {
    // Delegate to monero_oxide to compute message hash from parsed tx (prefix + RctBase)
    crate::serial::compute_clsag_message_hash(blob)
}

pub type Inputs = Vec<monero_oxide::transaction::Input>;
pub type Outputs = Vec<monero_oxide::transaction::Output>;

/// Metadata required to assemble the RingCT portion of a transaction.
#[derive(Clone)]
pub struct RctMeta {
    pub timelock: monero_oxide::transaction::Timelock,
    pub extra: Vec<u8>,
    pub proofs: monero_oxide::ringct::RctProofs,
}

/// Complete representation of a parsed RingCT transaction useful for adaptor signing flows.
pub struct TxSkeleton {
    pub inputs: Inputs,
    pub outputs: Outputs,
    pub meta: RctMeta,
}

/// Assemble an unsigned transaction using monero-oxide primitives.
///
/// Returns the serialized transaction blob if the provided metadata describes
/// a CLSAG transaction. Errors if any portion fails to serialize canonically.
pub fn assemble_unsigned_tx(inputs: &Inputs, outputs: &Outputs, meta: &RctMeta) -> Result<TxBlob> {
    use monero_oxide::transaction::{Transaction, TransactionPrefix};

    let prefix = TransactionPrefix {
        additional_timelock: meta.timelock,
        inputs: inputs.clone(),
        outputs: outputs.clone(),
        extra: meta.extra.clone(),
    };

    let tx = Transaction::V2 {
        prefix,
        proofs: Some(meta.proofs.clone()),
    };

    let (blob, _) = crate::serial::serialize_with_clsag_offsets(&tx)?;
    Ok(blob)
}

/// Locate CLSAG regions in a serialized tx blob (per input) using monero-oxide’s serializer/parser.
/// Returns a vector of (offset, length) for each CLSAG section.
pub fn find_clsag_regions(blob: &TxBlob) -> Result<ClsagRegions> {
    crate::serial::find_clsag_regions(blob)
}

/// Parse a serialized RingCT CLSAG transaction into its core components.
pub fn decompose_transaction(blob: &[u8]) -> Result<TxSkeleton> {
    use monero_oxide::transaction::Transaction;

    let mut slice = blob;
    let tx = Transaction::read(&mut slice).map_err(|e| anyhow!("parse_tx: {:?}", e))?;
    ensure!(slice.is_empty(), "trailing bytes after transaction");
    let (reencoded, _) = crate::serial::serialize_with_clsag_offsets(&tx)?;
    ensure!(
        reencoded.as_slice() == blob,
        "serialized bytes mismatch provided blob"
    );

    match tx {
        Transaction::V1 { .. } => Err(anyhow!("expected CLSAG transaction (v2)")),
        Transaction::V2 { prefix, proofs } => match proofs {
            None => Err(anyhow!("transaction missing RingCT proofs")),
            Some(proofs) => Ok(TxSkeleton {
                inputs: prefix.inputs,
                outputs: prefix.outputs,
                meta: RctMeta {
                    timelock: prefix.additional_timelock,
                    extra: prefix.extra,
                    proofs,
                },
            }),
        },
    }
}

/// Replace a subrange within a CLSAG region `region_index`.
/// Used to overwrite a single 32-byte s_j inside the response vector.
pub fn replace_clsag_at(
    blob: &mut TxBlob,
    region_index: usize,
    offset_in_region: usize,
    new_bytes: &[u8],
) -> Result<()> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        return Err(anyhow!("region_index out of range"));
    }
    let (off, len) = regions[region_index];
    if offset_in_region + new_bytes.len() > len {
        return Err(anyhow!("offset+len exceed region bound"));
    }
    let start = off + offset_in_region;
    let end = start + new_bytes.len();
    blob[start..end].copy_from_slice(new_bytes);
    ensure_canonical_clsag_region(&blob[off..off + len])?;
    Ok(())
}

/// Read back (offset,len) bytes from a CLSAG region — useful for verification.
pub fn read_clsag_subrange(
    blob: &TxBlob,
    region_index: usize,
    offset_in_region: usize,
    length: usize,
) -> Result<Vec<u8>> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        return Err(anyhow!("region_index out of range"));
    }
    let (off, len) = regions[region_index];
    if offset_in_region + length > len {
        return Err(anyhow!("offset+length exceed region bound"));
    }
    ensure_canonical_clsag_region(&blob[off..off + len])?;
    Ok(blob[off + offset_in_region..off + offset_in_region + length].to_vec())
}

/// Replace the full CLSAG region at `region_index` with `clsag_bytes`.
/// Ensures the replacement length matches the canonical region length.
pub fn replace_clsag_region(
    blob: &mut TxBlob,
    region_index: usize,
    clsag_bytes: &[u8],
) -> Result<()> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        return Err(anyhow!("region_index out of range"));
    }
    let (off, len) = regions[region_index];
    if clsag_bytes.len() != len {
        return Err(anyhow!(
            "clsag_bytes length {} != region length {}",
            clsag_bytes.len(),
            len
        ));
    }
    blob[off..off + len].copy_from_slice(clsag_bytes);
    ensure_canonical_clsag_region(&blob[off..off + len])?;
    Ok(())
}

pub fn replace_pseudo_out_at(
    blob: &mut TxBlob,
    input_index: usize,
    pseudo_out: monero_oxide::io::CompressedPoint,
) -> anyhow::Result<()> {
    // ensure the blob is a recognized CLSAG transaction before mutating pseudo outs
    let _ = find_clsag_regions(blob)?;
    crate::serial::write_pseudo_out_at(blob, input_index, pseudo_out)
}

#[cfg(test)]
pub fn assemble_unsigned_tx_stub(_inputs: &Inputs, _outputs: &Outputs) -> Result<TxBlob> {
    const MAGIC: u32 = 0xA5A5_A5A5;
    const REGION_COUNT: u32 = 1;
    const REGION_LEN: usize = 160;

    let header_len = 8 + (REGION_COUNT as usize) * 8;
    let region_offset = header_len;

    let mut blob = Vec::with_capacity(region_offset + REGION_LEN);
    blob.extend_from_slice(&MAGIC.to_le_bytes());
    blob.extend_from_slice(&REGION_COUNT.to_le_bytes());
    blob.extend_from_slice(&(region_offset as u32).to_le_bytes());
    blob.extend_from_slice(&(REGION_LEN as u32).to_le_bytes());
    blob.resize(region_offset + REGION_LEN, 0u8);
    Ok(blob)
}
