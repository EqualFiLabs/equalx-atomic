//! Adaptor signature orchestration for CLSAG backends.

use adaptor_clsag::{self, ClsagCtx, FinalSig, PreSig, SignerWitness};

use crate::{
    error::{ErrorCode, Result},
    settlement::SettlementCtx,
};

/// Supported adaptor backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Backend {
    Clsag = 0x01,
}

/// Inputs required to build a CLSAG pre-signature.
#[derive(Clone)]
pub struct PreAdaptorParams {
    pub clsag: ClsagCtx,
    pub witness: SignerWitness,
    pub message: Vec<u8>,
    pub swap_id: [u8; 32],
    pub settlement: SettlementCtx,
}

/// Result of building a pre-adaptor.
#[derive(Clone)]
pub struct PreAdaptorResult {
    pub backend: Backend,
    pub pre_sig: PreSig,
    pub adaptor_secret: [u8; 32],
    pub swap_id: [u8; 32],
}

/// Completed adaptor signature.
#[derive(Clone)]
pub struct FinalAdaptorSignature {
    pub backend: Backend,
    pub swap_id: [u8; 32],
    pub final_sig: FinalSig,
}

/// Builds a backend-specific pre-adaptor container.
pub fn make_pre_adaptor(params: PreAdaptorParams) -> Result<PreAdaptorResult> {
    if params.clsag.ring_keys.len() < 5 {
        return Err(ErrorCode::ClsagInvalidRing);
    }
    let settlement = params.settlement.to_adaptor();
    let (pre_sig, tau) = adaptor_clsag::make_pre_sig(
        &params.clsag,
        &params.witness,
        &params.message,
        &params.swap_id,
        settlement,
    )
    .map_err(|_| ErrorCode::ClsagResponseMismatch)?;

    Ok(PreAdaptorResult {
        backend: Backend::Clsag,
        pre_sig,
        adaptor_secret: tau,
        swap_id: params.swap_id,
    })
}

/// Completes a pre-adaptor by blinding it with the adaptor scalar.
pub fn complete(
    pre: &PreSig,
    swap_id: [u8; 32],
    secret_scalar: [u8; 32],
) -> Result<FinalAdaptorSignature> {
    let final_sig = adaptor_clsag::complete(pre, &secret_scalar);
    Ok(FinalAdaptorSignature {
        backend: Backend::Clsag,
        swap_id,
        final_sig,
    })
}

/// Verifies that a final adaptor signature is consistent with the specified CLSAG context.
pub fn verify(ctx: &ClsagCtx, message: &[u8], final_sig: &FinalAdaptorSignature) -> Result<bool> {
    match final_sig.backend {
        Backend::Clsag => Ok(adaptor_clsag::verify(ctx, message, &final_sig.final_sig)),
    }
}

/// Extracts the adaptor scalar from a pre/final pair.
pub fn extract_t(pre: &PreSig, final_sig: &FinalAdaptorSignature) -> Result<[u8; 32]> {
    match final_sig.backend {
        Backend::Clsag => Ok(adaptor_clsag::extract_t(pre, &final_sig.final_sig)),
    }
}
