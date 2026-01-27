//! Transport abstractions for EVM RPC interactions.

#[cfg(not(target_arch = "wasm32"))]
use alloy_network::EthereumWallet;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
#[cfg(not(target_arch = "wasm32"))]
use alloy_provider::{Provider, ProviderBuilder};
#[cfg(not(target_arch = "wasm32"))]
use alloy_rpc_types::eth::transaction::{TransactionInput, TransactionRequest};
#[cfg(not(target_arch = "wasm32"))]
use alloy_signer::{Signer, SignerSync};
#[cfg(not(target_arch = "wasm32"))]
use alloy_signer_local::PrivateKeySigner;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;

#[cfg(not(target_arch = "wasm32"))]
use crate::error::ErrorCode;
use crate::error::Result;

/// Encoded EVM call that can be dispatched via a transport.
#[derive(Clone, Debug)]
pub struct EvmCall {
    pub to: Address,
    pub data: Bytes,
    pub value: U256,
    pub gas_limit: Option<u64>,
}

impl EvmCall {
    pub fn new(to: Address, data: impl Into<Bytes>, value: U256) -> Self {
        Self {
            to,
            data: data.into(),
            value,
            gas_limit: None,
        }
    }

    pub fn with_gas_limit(mut self, gas: u64) -> Self {
        self.gas_limit = Some(gas);
        self
    }
}

/// Abstraction over sending signed EVM transactions.
pub trait EvmTransport: Send + Sync {
    fn send(&self, call: EvmCall) -> Result<B256>;
}

/// Abstraction over read-only `eth_call` style interactions.
pub trait EvmViewTransport: Send + Sync {
    fn call_view(&self, call: EvmCall) -> Result<Bytes>;
}

/// Trait for transports that can also sign arbitrary digests.
pub trait EvmMessageSigner {
    fn sign_hash(&self, digest: B256) -> Result<Bytes>;
    fn signer_address(&self) -> Address;
}

#[cfg(not(target_arch = "wasm32"))]
/// JSON-RPC transport backed by Alloy's provider stack and a local private key signer.
pub struct AlloyHttpTransport {
    rpc_url: reqwest::Url,
    wallet: PrivateKeySigner,
    runtime: Arc<Runtime>,
    default_gas: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl AlloyHttpTransport {
    /// Builds a new transport targeting `rpc_url` and signing with `private_key_hex`.
    pub fn new(rpc_url: &str, private_key_hex: &str) -> Result<Self> {
        let runtime = Runtime::new().map_err(|err| {
            eprintln!("transport init error (runtime): {err:?}");
            ErrorCode::BridgeTransportEvm
        })?;
        let url = reqwest::Url::parse(rpc_url).map_err(|err| {
            eprintln!("transport init error (url parse): {err:?}");
            ErrorCode::BridgeTransportEvm
        })?;

        let base_provider = ProviderBuilder::new().on_http(url.clone());
        let chain_id = runtime
            .block_on(base_provider.get_chain_id())
            .map_err(|err| {
                eprintln!("transport init error (chain_id): {err:?}");
                ErrorCode::BridgeTransportEvm
            })?;

        let mut wallet: PrivateKeySigner = private_key_hex
            .parse()
            .map_err(|_| ErrorCode::SignatureInvalid)?;
        wallet.set_chain_id(Some(chain_id));

        Ok(Self {
            rpc_url: url,
            wallet,
            runtime: Arc::new(runtime),
            default_gas: 500_000,
        })
    }

    fn build_transaction(&self, call: EvmCall) -> TransactionRequest {
        let mut tx = TransactionRequest::default()
            .from(self.wallet.address())
            .gas_limit(call.gas_limit.unwrap_or(self.default_gas))
            .input(TransactionInput::from(call.data.clone()))
            .value(call.value);
        tx.to = Some(alloy_primitives::TxKind::Call(call.to));
        tx
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl EvmTransport for AlloyHttpTransport {
    fn send(&self, call: EvmCall) -> Result<B256> {
        let tx = self.build_transaction(call);
        let rpc_url = self.rpc_url.clone();
        let wallet = self.wallet.clone();
        let fut = async move {
            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(EthereumWallet::new(wallet))
                .on_http(rpc_url);
            provider.send_transaction(tx).await
        };
        let pending = self
            .runtime
            .block_on(fut)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(*pending.tx_hash())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl EvmViewTransport for AlloyHttpTransport {
    fn call_view(&self, call: EvmCall) -> Result<Bytes> {
        let req = self.build_transaction(call);
        let rpc_url = self.rpc_url.clone();
        let fut = async move {
            let provider = ProviderBuilder::new().on_http(rpc_url);
            provider.call(&req).await
        };
        self.runtime.block_on(fut).map_err(|err| {
            eprintln!("provider error (call_view): {err:?}");
            ErrorCode::BridgeTransportEvm
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl EvmMessageSigner for AlloyHttpTransport {
    fn sign_hash(&self, digest: B256) -> Result<Bytes> {
        let signature = self
            .wallet
            .sign_hash_sync(&digest)
            .map_err(|_| ErrorCode::SignatureInvalid)?;
        Ok(Bytes::from(signature.as_bytes().to_vec()))
    }

    fn signer_address(&self) -> Address {
        self.wallet.address()
    }
}

/// Helper to compute the message preimage used when posting Monero tx hashes.
pub fn tx_hash_message(swap_id: [u8; 32], monero_tx_hash: [u8; 32], tau_pub: &[u8]) -> B256 {
    let mut payload = Vec::with_capacity(64 + tau_pub.len());
    payload.extend_from_slice(&swap_id);
    payload.extend_from_slice(&monero_tx_hash);
    payload.extend_from_slice(tau_pub);
    keccak256(payload)
}
