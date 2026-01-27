//! ADR-001 Monero transaction hash publication helpers.

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};

use crate::{
    error::{ErrorCode, Result},
    transport::{tx_hash_message, EvmCall, EvmMessageSigner, EvmTransport, EvmViewTransport},
    TxHash,
};

sol! {
    #[allow(non_camel_case_types)]
    contract QuoteBoard {
        struct Quote {
            address maker;
            address asset;
            uint8 backend;
            uint256 rateNum;
            uint256 rateDen;
            uint256 minAmt;
            uint256 maxAmt;
            uint256 bond;
            bytes32 adaptorHash;
            bytes32 mDigest;
            bytes envelope;
            uint64 ttl;
            bool live;
        }

        function postTxHash(
            bytes32 swapId,
            bytes32 txHash,
            bytes tauPub,
            bytes evmSig
        );

        function get(uint256 id) view returns (Quote quote_);
        function takerDestination(bytes32 swapId) view returns (bytes destination);
        function takeQuote(
            uint256 id,
            uint256 amount,
            uint256 tip,
            uint64 expiry,
            bytes destination
        );
    }
}

/// Arguments for posting a Monero transaction hash on-chain.
pub struct PostTxHashArgs<'a> {
    pub swap_id: [u8; 32],
    pub monero_tx_hash: [u8; 32],
    pub tau_pub: &'a [u8],
}

/// Client wrapper for QuoteBoard interactions.
pub struct QuoteBoardClient<T: EvmTransport + EvmMessageSigner + EvmViewTransport> {
    board: alloy_primitives::Address,
    transport: T,
}

impl<T: EvmTransport + EvmMessageSigner + EvmViewTransport> QuoteBoardClient<T> {
    pub fn new(board: alloy_primitives::Address, transport: T) -> Self {
        Self { board, transport }
    }

    pub fn address(&self) -> alloy_primitives::Address {
        self.board
    }

    pub fn post_tx_hash(&self, args: PostTxHashArgs<'_>) -> Result<TxHash> {
        if args.monero_tx_hash == [0u8; 32] {
            return Err(ErrorCode::TxHashMissing);
        }
        if args.tau_pub.len() != 33 {
            return Err(ErrorCode::TauPubInvalid);
        }

        let digest = tx_hash_message(args.swap_id, args.monero_tx_hash, args.tau_pub);
        let signature = self.transport.sign_hash(digest)?;

        let calldata = QuoteBoard::postTxHashCall {
            swapId: FixedBytes::<32>::from_slice(&args.swap_id),
            txHash: FixedBytes::<32>::from_slice(&args.monero_tx_hash),
            tauPub: Bytes::from(args.tau_pub.to_vec()),
            evmSig: signature,
        }
        .abi_encode();
        let call =
            EvmCall::new(self.board, Bytes::from(calldata), U256::ZERO).with_gas_limit(150_000);
        self.transport.send(call).map(Into::into)
    }

    /// Fetches a quote by id, returning its adaptor commitment and envelope (if any).
    pub fn quote(&self, id: U256) -> Result<QuoteSnapshot> {
        let calldata = QuoteBoard::getCall { id }.abi_encode();
        let call =
            EvmCall::new(self.board, Bytes::from(calldata), U256::ZERO).with_gas_limit(200_000);
        let raw = self.transport.call_view(call)?;
        let quote_return = QuoteBoard::getCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        QuoteSnapshot::try_from((id, quote_return.quote_))
    }

    /// Returns the taker-provided destination payload for a given swap (empty if unset).
    pub fn taker_destination(&self, swap_id: [u8; 32]) -> Result<Vec<u8>> {
        let calldata = QuoteBoard::takerDestinationCall {
            swapId: FixedBytes::<32>::from_slice(&swap_id),
        }
        .abi_encode();
        let call =
            EvmCall::new(self.board, Bytes::from(calldata), U256::ZERO).with_gas_limit(150_000);
        let raw = self.transport.call_view(call)?;
        let decoded = QuoteBoard::takerDestinationCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded.destination.to_vec())
    }

    /// Calls `takeQuote` with the provided parameters.
    pub fn take_quote(&self, args: TakeQuoteArgs<'_>) -> Result<TxHash> {
        let calldata = QuoteBoard::takeQuoteCall {
            id: args.quote_id,
            amount: args.amount,
            tip: args.tip,
            expiry: args.expiry,
            destination: Bytes::from(args.destination.to_vec()),
        }
        .abi_encode();
        let call = EvmCall::new(self.board, Bytes::from(calldata), args.value)
            .with_gas_limit(args.gas_limit.unwrap_or(700_000));
        self.transport.send(call).map(Into::into)
    }
}

/// Arguments for invoking QuoteBoard.takeQuote.
pub struct TakeQuoteArgs<'a> {
    pub quote_id: U256,
    pub amount: U256,
    pub tip: U256,
    pub expiry: u64,
    pub destination: &'a [u8],
    pub value: U256,
    pub gas_limit: Option<u64>,
}

/// Minimal view of a quote commitment needed for adaptor handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteCommitment {
    pub adaptor_hash: [u8; 32],
    pub m_digest: [u8; 32],
    pub envelope: Bytes,
}

/// Snapshot of an on-chain QuoteBoard entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteSnapshot {
    pub id: U256,
    pub maker: Address,
    pub asset: Address,
    pub backend: crate::adaptor::Backend,
    pub rate_num: U256,
    pub rate_den: U256,
    pub min_amt: U256,
    pub max_amt: U256,
    pub bond: U256,
    pub ttl: u64,
    pub commitment: QuoteCommitment,
    pub live: bool,
}

impl QuoteSnapshot {
    pub fn commitment(&self) -> QuoteCommitment {
        self.commitment.clone()
    }
}

impl TryFrom<(U256, QuoteBoard::Quote)> for QuoteSnapshot {
    type Error = ErrorCode;

    fn try_from(value: (U256, QuoteBoard::Quote)) -> Result<Self> {
        let (id, quote) = value;
        Ok(Self {
            id,
            maker: quote.maker,
            asset: quote.asset,
            backend: crate::escrow::backend_from_byte(quote.backend)?,
            rate_num: quote.rateNum,
            rate_den: quote.rateDen,
            min_amt: quote.minAmt,
            max_amt: quote.maxAmt,
            bond: quote.bond,
            ttl: quote.ttl,
            commitment: QuoteCommitment {
                adaptor_hash: quote.adaptorHash.into(),
                m_digest: quote.mDigest.into(),
                envelope: quote.envelope,
            },
            live: quote.live,
        })
    }
}
