//! Deterministic helpers for interacting with the EVM escrow contracts.

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};

use crate::{
    adaptor::Backend,
    contracts::TxHash,
    error::{ErrorCode, Result},
    settlement::SettlementCtx,
    transport::{EvmCall, EvmTransport},
    tx_hash::QuoteCommitment,
};

sol! {
    #[allow(non_camel_case_types)]
    contract Escrow {
        function lockETH(
            bytes32 swapId,
            address taker,
            bytes32 adaptorHash,
            address maker,
            uint256 amount,
            uint256 tip,
            uint64 expiry,
            uint8 backend,
            bytes32 settleDigest
        ) payable returns (bytes32);

        function lockERC20(
            bytes32 swapId,
            address taker,
            address token,
            uint256 amount,
            uint256 tip,
            bytes32 adaptorHash,
            address maker,
            uint64 expiry,
            uint8 backend,
            bytes32 settleDigest,
            bytes permit
        ) payable returns (bytes32);

        function settle(bytes32 swapId, bytes32 adaptorSecret);
        function refund(bytes32 swapId);
    }
}

/// Client bound to an escrow contract with a provided EVM transport.
#[derive(Clone)]
pub struct EscrowClient<T: EvmTransport> {
    escrow: Address,
    transport: T,
}

impl<T: EvmTransport> EscrowClient<T> {
    pub fn new(escrow: Address, transport: T) -> Self {
        Self { escrow, transport }
    }

    pub fn address(&self) -> Address {
        self.escrow
    }

    pub fn lock_eth(&self, args: LockEthArgs) -> Result<TxHash> {
        if args.expiry == 0 || args.amount.is_zero() {
            return Err(ErrorCode::PolicyDeadlineOrder);
        }
        let calldata = Escrow::lockETHCall {
            swapId: FixedBytes::<32>::from_slice(&args.swap_id),
            taker: args.taker,
            adaptorHash: FixedBytes::<32>::from_slice(&args.quote_commitment.adaptor_hash),
            maker: args.maker,
            amount: args.amount,
            tip: args.tip,
            expiry: args.expiry,
            backend: backend_to_byte(args.backend),
            settleDigest: FixedBytes::<32>::from_slice(&args.settle_digest),
        }
        .abi_encode();
        let value = args.amount + args.tip;
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), value)
            .with_gas_limit(args.gas_limit.unwrap_or(500_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn lock_erc20(&self, args: LockErc20Args) -> Result<TxHash> {
        if args.expiry == 0 || args.amount.is_zero() {
            return Err(ErrorCode::PolicyDeadlineOrder);
        }
        let calldata = Escrow::lockERC20Call {
            swapId: FixedBytes::<32>::from_slice(&args.swap_id),
            taker: args.taker,
            token: args.token,
            amount: args.amount,
            tip: args.tip,
            adaptorHash: FixedBytes::<32>::from_slice(&args.quote_commitment.adaptor_hash),
            maker: args.maker,
            expiry: args.expiry,
            backend: backend_to_byte(args.backend),
            settleDigest: FixedBytes::<32>::from_slice(&args.settle_digest),
            permit: args.permit.clone(),
        }
        .abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), args.tip)
            .with_gas_limit(args.gas_limit.unwrap_or(700_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn settle(&self, args: SettleArgs) -> Result<TxHash> {
        if args.adaptor_secret == [0u8; 32] {
            return Err(ErrorCode::SettlementDigestMismatch);
        }
        let calldata = Escrow::settleCall {
            swapId: FixedBytes::<32>::from_slice(&args.swap_id),
            adaptorSecret: FixedBytes::<32>::from_slice(&args.adaptor_secret),
        }
        .abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), U256::ZERO)
            .with_gas_limit(args.gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn refund(&self, args: RefundArgs) -> Result<TxHash> {
        let calldata = Escrow::refundCall {
            swapId: FixedBytes::<32>::from_slice(&args.swap_id),
        }
        .abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), U256::ZERO)
            .with_gas_limit(args.gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }
}

/// Arguments for `lockETH`.
#[derive(Clone, Debug)]
pub struct LockEthArgs {
    pub swap_id: [u8; 32],
    pub taker: Address,
    pub maker: Address,
    pub amount: U256,
    pub tip: U256,
    pub expiry: u64,
    pub backend: Backend,
    pub settle_digest: [u8; 32],
    pub quote_commitment: QuoteCommitment,
    pub gas_limit: Option<u64>,
}

/// Arguments for `lockERC20`.
#[derive(Clone, Debug)]
pub struct LockErc20Args {
    pub swap_id: [u8; 32],
    pub taker: Address,
    pub token: Address,
    pub amount: U256,
    pub tip: U256,
    pub maker: Address,
    pub expiry: u64,
    pub backend: Backend,
    pub settle_digest: [u8; 32],
    pub quote_commitment: QuoteCommitment,
    pub permit: Bytes,
    pub gas_limit: Option<u64>,
}

/// Arguments for `settle`.
#[derive(Clone, Debug)]
pub struct SettleArgs {
    pub swap_id: [u8; 32],
    pub adaptor_secret: [u8; 32],
    pub gas_limit: Option<u64>,
}

/// Arguments for `refund`.
#[derive(Clone, Debug)]
pub struct RefundArgs {
    pub swap_id: [u8; 32],
    pub gas_limit: Option<u64>,
}

pub(crate) fn backend_from_byte(byte: u8) -> Result<Backend> {
    match byte {
        0x01 => Ok(Backend::Clsag),
        _ => Err(ErrorCode::BridgeBackendUnsupported),
    }
}

pub(crate) fn backend_to_byte(backend: Backend) -> u8 {
    match backend {
        Backend::Clsag => 0x01,
    }
}

/// Raw log representation emitted by the escrow.
#[derive(Clone, Debug)]
pub struct EscrowLog {
    /// Numeric identifier of the event kind (0 = locked, 1 = settled, 2 = refunded).
    pub kind: u8,
    pub swap_id: [u8; 32],
    pub amount: U256,
    /// Numeric backend identifier (0x01 = CLSAG).
    pub backend: u8,
}

impl EscrowLog {
    pub fn locked(swap_id: [u8; 32], amount: U256, backend: Backend) -> Self {
        Self::new(EscrowEventKind::SwapLocked, swap_id, amount, backend)
    }

    pub fn new(kind: EscrowEventKind, swap_id: [u8; 32], amount: U256, backend: Backend) -> Self {
        Self {
            kind: kind.into(),
            swap_id,
            amount,
            backend: backend_to_byte(backend),
        }
    }
}

/// High level escrow events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EscrowEvent {
    SwapLocked {
        swap_id: [u8; 32],
        amount: U256,
        backend: Backend,
    },
    SwapSettled {
        swap_id: [u8; 32],
        backend: Backend,
    },
    SwapRefunded {
        swap_id: [u8; 32],
        backend: Backend,
    },
}

/// Enumeration of log kinds produced on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EscrowEventKind {
    SwapLocked,
    SwapSettled,
    SwapRefunded,
}

impl EscrowEventKind {
    fn try_from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(EscrowEventKind::SwapLocked),
            1 => Ok(EscrowEventKind::SwapSettled),
            2 => Ok(EscrowEventKind::SwapRefunded),
            _ => Err(ErrorCode::BridgeInvalidLog),
        }
    }

    fn domain(self) -> &'static str {
        match self {
            EscrowEventKind::SwapLocked => "event-lock",
            EscrowEventKind::SwapSettled => "event-settle",
            EscrowEventKind::SwapRefunded => "event-refund",
        }
    }
}

impl From<EscrowEventKind> for u8 {
    fn from(kind: EscrowEventKind) -> Self {
        kind as u8
    }
}

/// Event decoding output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventResult {
    pub digest: [u8; 32],
    pub event: EscrowEvent,
}

/// Decodes raw logs into structured events bound to the settlement context.
pub fn decode_events(ctx: &SettlementCtx, logs: &[EscrowLog]) -> Result<Vec<EventResult>> {
    logs.iter()
        .map(|log| {
            let kind = EscrowEventKind::try_from_byte(log.kind)?;
            let backend = backend_from_byte(log.backend)?;
            let digest = ctx.binding(log.swap_id, kind.domain());
            let event = match kind {
                EscrowEventKind::SwapLocked => EscrowEvent::SwapLocked {
                    swap_id: log.swap_id,
                    amount: log.amount,
                    backend,
                },
                EscrowEventKind::SwapSettled => EscrowEvent::SwapSettled {
                    swap_id: log.swap_id,
                    backend,
                },
                EscrowEventKind::SwapRefunded => EscrowEvent::SwapRefunded {
                    swap_id: log.swap_id,
                    backend,
                },
            };
            Ok(EventResult { digest, event })
        })
        .collect()
}
