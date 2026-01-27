use crate::{
    wire::{ClsagFinalSigContainer, ClsagPreSig},
    EswpError, PreSig,
};
use curve25519_dalek::scalar::Scalar;
use monero_oxide::io::CompressedPoint;
use std::collections::HashSet;

pub fn validate_scalar_le(bytes: &[u8; 32]) -> Result<(), EswpError> {
    if Scalar::from_canonical_bytes(*bytes).is_some().into() {
        Ok(())
    } else {
        Err(EswpError::EncodingNoncanonical)
    }
}

pub fn validate_point_le(bytes: &[u8; 32]) -> Result<(), EswpError> {
    CompressedPoint::from(*bytes)
        .decompress()
        .map(|_| ())
        .ok_or(EswpError::EncodingNoncanonical)
}

pub fn ensure_unique_ring(ring: &[[u8; 32]]) -> Result<(), EswpError> {
    let mut seen = HashSet::with_capacity(ring.len());
    for entry in ring {
        if !seen.insert(entry) {
            return Err(EswpError::RingInvalid);
        }
    }
    Ok(())
}

pub fn validate_presig_container(container: &ClsagPreSig) -> Result<(), EswpError> {
    if container.ring_size == 0 {
        return Err(EswpError::RingInvalid);
    }
    if container.resp_index as usize >= container.ring_size as usize {
        return Err(EswpError::RespIndexUnadmitted);
    }
    if container.ring_bytes.len() != container.ring_size as usize * 32 {
        return Err(EswpError::RingInvalid);
    }
    let mut ring = Vec::with_capacity(container.ring_size as usize);
    for chunk in container.ring_bytes.chunks_exact(32) {
        let mut entry = [0u8; 32];
        entry.copy_from_slice(chunk);
        validate_point_le(&entry)?;
        ring.push(entry);
    }
    ensure_unique_ring(&ring)?;
    Ok(())
}

pub fn validate_final_sig_container(container: &ClsagFinalSigContainer) -> Result<(), EswpError> {
    if container.final_sig.len() < 32 {
        return Err(EswpError::FinalSigInvalid);
    }
    Ok(())
}

pub fn validate_presig(pre: &PreSig) -> Result<(), EswpError> {
    for response in &pre.s_tilde {
        validate_scalar_le(response)?;
    }
    validate_scalar_le(&pre.c1_tilde)?;
    validate_point_le(&pre.d_tilde)?;
    validate_point_le(&pre.pseudo_out)?;
    Ok(())
}
