//! clsag.rs — helpers backed by monero-oxide to work with CLSAG regions.
//!
//! These helpers inspect a serialized transaction using monero-oxide's parser
//! to determine how many CLSAG responses exist for each input and where they
//! live within the serialized region. The layout strictly follows
//! `monero_oxide::ringct::clsag::Clsag::write`, which encodes the responses as
//! contiguous scalars followed by `c1` and `D`.

use anyhow::{anyhow, Result};

use crate::{find_clsag_regions, serial::ensure_canonical_clsag_region, TxBlob};

const SCALAR_SIZE: usize = 32;

fn parse_tx(blob: &TxBlob) -> Result<monero_oxide::transaction::Transaction> {
    let mut slice = blob.as_slice();
    monero_oxide::transaction::Transaction::read(&mut slice).map_err(|e| anyhow!("parse_tx: {e:?}"))
}

fn clsag_for_region(
    tx: &monero_oxide::transaction::Transaction,
    region_index: usize,
) -> Result<&monero_oxide::ringct::clsag::Clsag> {
    use monero_oxide::{ringct::RctPrunable, transaction::Transaction};

    let proofs = match tx {
        Transaction::V2 {
            proofs: Some(proofs),
            ..
        } => proofs,
        _ => return Err(anyhow!("transaction missing CLSAG proofs")),
    };

    let clsags = match &proofs.prunable {
        RctPrunable::Clsag { clsags, .. } => clsags,
        _ => return Err(anyhow!("transaction prunable data is not CLSAG")),
    };

    clsags
        .get(region_index)
        .ok_or_else(|| anyhow!("region_index {region_index} out of range"))
}

/// Return the number of 32-byte responses in the CLSAG at `region_index`.
pub fn response_count(blob: &TxBlob, region_index: usize) -> Result<usize> {
    let tx = parse_tx(blob)?;
    let clsag = clsag_for_region(&tx, region_index)?;
    let regions = find_clsag_regions(blob)?;
    let (off, len) = regions
        .get(region_index)
        .ok_or_else(|| anyhow!("region_index {region_index} out of range"))?;
    ensure_canonical_clsag_region(&blob[*off..*off + *len])?;
    Ok(clsag.s.len())
}

/// Return the byte offset (from start of the CLSAG region) for response index `j`.
///
/// monero-oxide serializes a CLSAG as `s[0] || ... || s[n-1] || c1 || D`. Each
/// response is a 32-byte scalar, so the offset is simply `j * 32`.
pub fn response_offset(blob: &TxBlob, region_index: usize, j: usize) -> Result<usize> {
    let count = response_count(blob, region_index)?;
    if j >= count {
        return Err(anyhow!("response index {j} out of range (count={count})"));
    }
    Ok(j * SCALAR_SIZE)
}

/// Replace `s_j` inside the region with a new 32-byte scalar (bounded & validated).
pub fn replace_response_at(
    blob: &mut TxBlob,
    region_index: usize,
    j: usize,
    s_j: &[u8; 32],
) -> Result<()> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        return Err(anyhow!("region_index {region_index} out of range"));
    }

    let (region_off, region_len) = regions[region_index];
    let count = response_count(blob, region_index)?;
    if j >= count {
        return Err(anyhow!("response index {j} out of range (count={count})"));
    }

    let offset_in_region = response_offset(blob, region_index, j)?;
    if offset_in_region + SCALAR_SIZE > region_len {
        return Err(anyhow!(
            "computed offset {} exceeds region length {}",
            offset_in_region,
            region_len
        ));
    }

    let start = region_off + offset_in_region;
    let end = start + SCALAR_SIZE;
    blob[start..end].copy_from_slice(s_j);
    Ok(())
}

/// Read back `s_j` (debug/verification).
pub fn read_response_at(blob: &TxBlob, region_index: usize, j: usize) -> Result<[u8; 32]> {
    let regions = find_clsag_regions(blob)?;
    if region_index >= regions.len() {
        return Err(anyhow!("region_index {region_index} out of range"));
    }

    let (region_off, region_len) = regions[region_index];
    let count = response_count(blob, region_index)?;
    if j >= count {
        return Err(anyhow!("response index {j} out of range (count={count})"));
    }

    let offset_in_region = response_offset(blob, region_index, j)?;
    if offset_in_region + SCALAR_SIZE > region_len {
        return Err(anyhow!(
            "computed offset {} exceeds region length {}",
            offset_in_region,
            region_len
        ));
    }

    let start = region_off + offset_in_region;
    let end = start + SCALAR_SIZE;
    let mut out = [0u8; 32];
    out.copy_from_slice(&blob[start..end]);
    Ok(out)
}
