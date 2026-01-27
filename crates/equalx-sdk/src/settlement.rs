//! Settlement context helpers used to bind transcripts across chains.

use adaptor_clsag::SettlementCtx as ClsagSettlementCtx;
use alloy_primitives::{keccak256, Address, FixedBytes, U256};
use sha3::{Digest, Sha3_256};

use crate::error::{ErrorCode, Result};

/// Canonical settlement context as described in the SDK spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementCtx {
    chain_tag: String,
    position_key: [u8; 32],
    settle_digest: [u8; 32],
}

impl SettlementCtx {
    /// Constructs a settlement context after enforcing canonical constraints.
    pub fn new(
        chain_tag: impl Into<String>,
        position_key: [u8; 32],
        settle_digest: [u8; 32],
    ) -> Result<Self> {
        let chain_tag = chain_tag.into();
        if chain_tag.len() > u8::MAX as usize {
            return Err(ErrorCode::PolicyDigestLength);
        }

        Ok(Self {
            chain_tag,
            position_key,
            settle_digest,
        })
    }

    /// Returns the stored settlement digest.
    pub fn settle_digest(&self) -> [u8; 32] {
        self.settle_digest
    }

    /// Chain tag as a UTF-8 string.
    pub fn chain_tag(&self) -> &str {
        &self.chain_tag
    }

    /// Position key (bytes32).
    pub fn position_key(&self) -> [u8; 32] {
        self.position_key
    }

    /// Returns canonical bytes used in transcript binding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(2 + self.chain_tag.len() + self.position_key.len() + 32);
        bytes.extend_from_slice(self.chain_tag.as_bytes());
        bytes.push(0);
        bytes.push(self.position_key.len() as u8);
        bytes.extend_from_slice(&self.position_key);
        bytes.extend_from_slice(&self.settle_digest);
        bytes
    }

    /// Computes a deterministic binding for the provided swap id and domain.
    pub fn binding(&self, swap_id: [u8; 32], domain: &str) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.canonical_bytes());
        hasher.update(&swap_id);
        hasher.update(domain.as_bytes());
        hasher.finalize().into()
    }

    /// Converts into the adaptor-clsag settlement context representation.
    pub fn to_adaptor(&self) -> ClsagSettlementCtx {
        ClsagSettlementCtx {
            chain_tag: self.chain_tag.clone(),
            position_key: self.position_key,
            settle_digest: self.settle_digest,
        }
    }
}

/// Canonical EqualX settlement digest inputs (docs/CLSAG-ADAPTOR-SPEC §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementDigestInputs {
    pub chain_id: U256,
    // For Atomic Desk swaps, this is the global reservation counter.
    pub counter: U256,
    pub position_key: FixedBytes<32>,
    pub quote_token: Address,
    pub base_token: Address,
    pub taker: Address,
    pub desk: Address,
}

/// Computes the settlement digest binding the Monero transcript to an Atomic Desk reservation.
pub fn compute_settlement_digest(inputs: &SettlementDigestInputs) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 3 + 20 * 4);
    encoded.extend_from_slice(&inputs.counter.to_be_bytes::<32>());
    encoded.extend_from_slice(inputs.position_key.as_slice());
    encoded.extend_from_slice(inputs.quote_token.as_slice());
    encoded.extend_from_slice(inputs.base_token.as_slice());
    encoded.extend_from_slice(inputs.taker.as_slice());
    encoded.extend_from_slice(inputs.desk.as_slice());
    encoded.extend_from_slice(&inputs.chain_id.to_be_bytes::<32>());
    keccak256(encoded).into()
}

/// Computes the hashlock expected by SettlementEscrow (keccak256(tau)).
pub fn compute_hashlock(tau: &[u8; 32]) -> [u8; 32] {
    keccak256(tau).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, U256};

    #[test]
    fn settlement_digest_matches_spec_layout() {
        let inputs = SettlementDigestInputs {
            chain_id: U256::from(84532u64),
            counter: U256::from(42u64),
            position_key: FixedBytes::from_slice(&[0x11; 32]),
            quote_token: address!("0101010101010101010101010101010101010101"),
            base_token: address!("0202020202020202020202020202020202020202"),
            taker: address!("0303030303030303030303030303030303030303"),
            desk: address!("0404040404040404040404040404040404040404"),
        };

        let digest = compute_settlement_digest(&inputs);

        let mut manual = Vec::new();
        manual.extend_from_slice(&inputs.counter.to_be_bytes::<32>());
        manual.extend_from_slice(inputs.position_key.as_slice());
        manual.extend_from_slice(inputs.quote_token.as_slice());
        manual.extend_from_slice(inputs.base_token.as_slice());
        manual.extend_from_slice(inputs.taker.as_slice());
        manual.extend_from_slice(inputs.desk.as_slice());
        manual.extend_from_slice(&inputs.chain_id.to_be_bytes::<32>());

        let expected: [u8; 32] = keccak256(manual).into();
        assert_eq!(digest, expected);
    }

    #[test]
    fn hashlock_is_keccak_of_tau() {
        let tau = [0xABu8; 32];
        let expected: [u8; 32] = keccak256(tau).into();
        assert_eq!(compute_hashlock(&tau), expected);
    }
}
