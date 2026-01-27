//! Helpers for interacting with the on-chain encryption key registry.

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{sol, SolCall};

use crate::{
    contracts::TxHash,
    error::{ErrorCode, Result},
    transport::{EvmCall, EvmTransport, EvmViewTransport},
};

sol! {
    #[allow(non_camel_case_types)]
    contract KeyRegistry {
        function registerEncPub(bytes encPub);
        function getEncPub(address owner) view returns (bytes encPub);
        function isRegistered(address owner) view returns (bool registered);
    }
}

/// Client bound to a specific key registry contract.
#[derive(Clone)]
pub struct KeyRegistryClient<T: EvmTransport + EvmViewTransport> {
    registry: Address,
    transport: T,
}

impl<T: EvmTransport + EvmViewTransport> KeyRegistryClient<T> {
    pub fn new(registry: Address, transport: T) -> Self {
        Self {
            registry,
            transport,
        }
    }

    pub fn address(&self) -> Address {
        self.registry
    }

    /// Registers a compressed secp256k1 pubkey (33 bytes) for the caller.
    pub fn register_enc_pub(&self, pubkey: &[u8; 33], gas_limit: Option<u64>) -> Result<TxHash> {
        let calldata = KeyRegistry::registerEncPubCall {
            encPub: Bytes::from(pubkey.to_vec()),
        }
        .abi_encode();
        let call = EvmCall::new(self.registry, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    /// Fetches the registered pubkey for `owner` (empty vector if unset).
    pub fn get_enc_pub(&self, owner: Address) -> Result<Vec<u8>> {
        let calldata = KeyRegistry::getEncPubCall { owner }.abi_encode();
        let call = EvmCall::new(self.registry, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = KeyRegistry::getEncPubCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded.encPub.to_vec())
    }

    /// Returns true if the address has registered any pubkey.
    pub fn is_registered(&self, owner: Address) -> Result<bool> {
        let calldata = KeyRegistry::isRegisteredCall { owner }.abi_encode();
        let call = EvmCall::new(self.registry, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = KeyRegistry::isRegisteredCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded.registered)
    }
}
