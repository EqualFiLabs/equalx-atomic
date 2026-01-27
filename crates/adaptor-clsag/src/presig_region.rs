//! presig_region.rs — serialize PreSig to match monero-oxide's CLSAG layout.
//!
//! The wire format emitted by `monero_oxide::ringct::clsag::Clsag::write` is:
//!
//! ```text
//! region := s[0] || s[1] || ... || s[n-1] || c1 || D
//! ```
//!
//! Each element is 32 bytes. The helpers here mirror that layout exactly when
//! serializing a `PreSig` into the CLSAG region of a transaction blob.
use crate::{encoding, EswpError, PreSig};

/// Serialize a PreSig according to the monero-oxide CLSAG layout.
pub fn serialize_presig_region(pre: &PreSig, region_len: usize) -> Result<Vec<u8>, EswpError> {
    encoding::validate_presig(pre)?;

    let n = pre.s_tilde.len();
    let mut out = Vec::with_capacity((n + 2) * 32);

    for s in &pre.s_tilde {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&pre.c1_tilde);
    out.extend_from_slice(&pre.d_tilde);

    if out.len() != region_len {
        return Err(EswpError::EncodingNoncanonical);
    }

    Ok(out)
}
