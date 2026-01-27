//! finalsig_region.rs — helpers to inspect final CLSAG signatures using the
//! monero-oxide layout.

use crate::FinalSig;

/// Return the serialized bytes of `s_j` from the final signature.
///
/// The layout matches `Clsag::write`, so responses appear before `c1` and `D`.
pub fn finalsig_scalar_at_j(final_sig: &FinalSig, j: usize) -> [u8; 32] {
    let responses = &final_sig.clsag.s;
    assert!(j < responses.len(), "response index out of range");
    responses[j].to_bytes()
}
