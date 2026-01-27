//! Deterministic key management helpers for Monero and EVM chains using the production primitives.

use alloy_primitives::{Address as EvmAddress, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar as DalekScalar};
use monero_address::{AddressType, MoneroAddress, Network as MoneroNetwork};
use monero_generators::biased_hash_to_point;
use monero_oxide::{io::CompressedPoint, primitives::keccak256_to_scalar};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::{ErrorCode, Result};

/// Type alias representing a 32-byte scalar in little-endian form.
pub type Scalar = [u8; 32];
/// Alias for the canonical EVM address type.
pub type Address = EvmAddress;

/// Generates a fresh Monero spend and view keypair using curve25519 scalars.
pub fn generate_monero_keypair() -> Result<(Scalar, Scalar)> {
    let mut rng = OsRng;
    let mut seed = [0u8; 64];
    rng.fill_bytes(&mut seed);
    let spend_scalar = DalekScalar::from_bytes_mod_order_wide(&seed);
    let spend = spend_scalar.to_bytes();

    let view_scalar = keccak256_to_scalar(spend);
    let view = view_scalar.to_bytes();
    Ok((spend, view))
}

/// Derives a deterministic subaddress (account 0, index `minor`) and the corresponding
/// spend scalar used for CLSAG signing.
pub fn derive_subaddress(
    view_key: &Scalar,
    private_key: &Scalar,
    index: u32,
) -> Result<(String, Scalar)> {
    let spend_scalar = DalekScalar::from_bytes_mod_order(*private_key);
    let view_scalar = DalekScalar::from_bytes_mod_order(*view_key);
    let spend_point = (&spend_scalar * ED25519_BASEPOINT_TABLE)
        .compress()
        .decompress()
        .ok_or(ErrorCode::BridgeBackendUnsupported)?;

    let derivation = subaddress_derivation(&view_scalar, index);
    let sub_spend_point = spend_point + (&derivation * ED25519_BASEPOINT_TABLE);
    let shared_view_point = view_scalar * sub_spend_point;

    let address = MoneroAddress::new(
        MoneroNetwork::Mainnet,
        AddressType::Subaddress,
        sub_spend_point,
        shared_view_point,
    )
    .to_string();

    let derived_spend_scalar = (spend_scalar + derivation).to_bytes();
    Ok((address, derived_spend_scalar))
}

/// Computes the key image for a given output and private spend key.
pub fn compute_key_image(
    tx_out_pub_key: &[u8; 32],
    private_spend_key: &Scalar,
) -> Result<[u8; 32]> {
    let spend_scalar = DalekScalar::from_bytes_mod_order(*private_spend_key);
    let output_point = CompressedPoint::from(*tx_out_pub_key)
        .decompress()
        .ok_or(ErrorCode::BridgeBackendUnsupported)?;
    let hashed_point = biased_hash_to_point(output_point.compress().to_bytes());
    let key_image = spend_scalar * hashed_point;
    Ok(key_image.compress().to_bytes())
}

/// Generates a secp256k1 keypair for the EVM leg using Alloy's local signer.
pub fn generate_evm_keypair() -> Result<(Scalar, Address)> {
    let signer = PrivateKeySigner::random();
    let priv_bytes: [u8; 32] = signer.to_bytes().into();
    Ok((priv_bytes, signer.address()))
}

/// Signs a 32-byte digest with an EVM private key using Alloy's signer implementation.
pub fn sign_evm_message(private_key: &Scalar, message: &[u8; 32]) -> Result<[u8; 65]> {
    let signer =
        PrivateKeySigner::from_slice(private_key).map_err(|_| ErrorCode::SignatureInvalid)?;
    let digest = B256::from(*message);
    let signature = signer
        .sign_hash_sync(&digest)
        .map_err(|_| ErrorCode::SignatureInvalid)?;
    Ok(signature.as_bytes())
}

fn subaddress_derivation(view_scalar: &DalekScalar, minor_index: u32) -> DalekScalar {
    let mut data = Vec::with_capacity(8 + 32 + 4 + 4);
    data.extend_from_slice(b"SubAddr\0");
    data.extend_from_slice(&view_scalar.to_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&minor_index.to_le_bytes());
    keccak256_to_scalar(&data)
}
