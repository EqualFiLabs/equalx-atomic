//! ecdh.rs — helpers for deriving per-output shared secrets and compact amount encodings.
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use monero_oxide::{io::CompressedPoint, ringct::EncryptedAmount};
use monero_wallet_core::SharedKeyDerivations;
use zeroize::Zeroizing;

/// Final artifacts for a single output after ECDH derivations.
pub struct EcdhOut {
    pub encrypted: EncryptedAmount,
    pub commitment: CompressedPoint,
    pub view_tag: u8,
}

/// Hash the raw shared ECDH point for an output to obtain the view tag and shared scalar.
pub fn derive_view_tag_and_shared(
    shared_point: EdwardsPoint,
    output_index: usize,
) -> (u8, Zeroizing<SharedKeyDerivations>) {
    let derivations =
        SharedKeyDerivations::output_derivations(None, Zeroizing::new(shared_point), output_index);
    let view_tag = derivations.view_tag();
    (view_tag, derivations)
}

/// Derive the commitment mask used for a Pedersen commitment from the shared scalar.
pub fn commitment_mask(shared: &SharedKeyDerivations) -> Scalar {
    shared.commitment_mask()
}

/// Encode the amount using compact RingCT encryption (8-byte XOR) derived from the shared scalar.
pub fn ecdh_encrypt_amount(shared: &SharedKeyDerivations, amount: u64) -> EncryptedAmount {
    let encrypted = shared.compact_amount_encryption(amount);
    EncryptedAmount::Compact { amount: encrypted }
}

/// Produce the compressed commitment corresponding to `mask*G + amount*H`.
pub fn output_commitment(mask: Scalar, amount: u64) -> CompressedPoint {
    let commitment = monero_oxide::primitives::Commitment::new(mask, amount);
    CompressedPoint::from(commitment.calculate().compress())
}

/// Accessor for the shared scalar used when deriving an output key.
pub fn shared_scalar(shared: &SharedKeyDerivations) -> Scalar {
    *shared.shared_key()
}
