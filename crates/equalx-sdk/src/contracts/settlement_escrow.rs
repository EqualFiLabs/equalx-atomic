use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};

use crate::{
    contracts::TxHash,
    error::{ErrorCode, Result},
    transport::{EvmCall, EvmTransport, EvmViewTransport},
};

sol! {
    #[allow(non_camel_case_types)]
    contract SettlementEscrow {
        enum ReservationStatus {
            None,
            Active,
            Settled,
            Refunded
        }

        struct Reservation {
            bytes32 reservationId;
            bytes32 deskId;
            bytes32 positionKey;
            uint256 positionId;
            address desk;
            address taker;
            uint256 poolIdA;
            uint256 poolIdB;
            address tokenA;
            address tokenB;
            bool baseIsA;
            address asset;
            uint256 amount;
            bytes32 settlementDigest;
            bytes32 hashlock;
            uint256 counter;
            uint64 expiry;
            uint64 createdAt;
            uint16 feeBps;
            uint8 feePayer;
            ReservationStatus status;
        }

        event ReservationCreated(
            bytes32 reservationId,
            address taker,
            address desk,
            uint256 amount,
            uint256 counter
        );

        event ReservationSettled(bytes32 reservationId, bytes32 tau);
        event ReservationRefunded(bytes32 reservationId, bytes32 evidence);
        event HashlockSet(bytes32 reservationId, bytes32 hashlock);

        function setHashlock(bytes32 reservationId, bytes32 hashlock);
        function settle(bytes32 reservationId, bytes32 tau);
        function refund(bytes32 reservationId, bytes32 noSpendEvidence);
        function getReservation(bytes32 reservationId) view returns (Reservation);
        function refundSafetyWindow() view returns (uint64);
        function committee(address member) view returns (bool);
        function governor() view returns (address);
        function mailbox() view returns (address);
        function atomicDesk() view returns (address);
        function setCommittee(address member, bool allowed);
        function configureMailbox(address mailbox_);
        function configureAtomicDesk(address atomicDesk_);
        function transferGovernor(address newGovernor);
        function setRefundSafetyWindow(uint64 newWindow);
    }
}

pub use SettlementEscrow::ReservationStatus;

#[derive(Clone)]
pub struct SettlementReservation {
    pub reservation_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub position_key: FixedBytes<32>,
    pub position_id: U256,
    pub desk: Address,
    pub taker: Address,
    pub pool_id_a: U256,
    pub pool_id_b: U256,
    pub token_a: Address,
    pub token_b: Address,
    pub base_is_a: bool,
    pub asset: Address,
    pub amount: U256,
    pub settlement_digest: FixedBytes<32>,
    pub hashlock: FixedBytes<32>,
    pub counter: U256,
    pub expiry: u64,
    pub created_at: u64,
    pub fee_bps: u16,
    pub fee_payer: u8,
    pub status: ReservationStatus,
}

impl From<SettlementEscrow::Reservation> for SettlementReservation {
    fn from(value: SettlementEscrow::Reservation) -> Self {
        Self {
            reservation_id: value.reservationId,
            desk_id: value.deskId,
            position_key: value.positionKey,
            position_id: value.positionId,
            desk: value.desk,
            taker: value.taker,
            pool_id_a: value.poolIdA,
            pool_id_b: value.poolIdB,
            token_a: value.tokenA,
            token_b: value.tokenB,
            base_is_a: value.baseIsA,
            asset: value.asset,
            amount: value.amount,
            settlement_digest: value.settlementDigest,
            hashlock: value.hashlock,
            counter: value.counter,
            expiry: value.expiry,
            created_at: value.createdAt,
            fee_bps: value.feeBps,
            fee_payer: value.feePayer,
            status: value.status,
        }
    }
}

#[derive(Clone)]
pub struct SettlementEscrowClient<T: EvmTransport + EvmViewTransport> {
    escrow: Address,
    transport: T,
}

impl<T: EvmTransport + EvmViewTransport> SettlementEscrowClient<T> {
    pub fn new(escrow: Address, transport: T) -> Self {
        Self { escrow, transport }
    }

    pub fn address(&self) -> Address {
        self.escrow
    }

    pub fn set_hashlock(
        &self,
        reservation_id: FixedBytes<32>,
        hashlock: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        if hashlock == [0u8; 32] {
            return Err(ErrorCode::SettlementDigestMismatch);
        }
        let calldata = SettlementEscrow::setHashlockCall {
            reservationId: reservation_id,
            hashlock: FixedBytes::<32>::from_slice(&hashlock),
        }
        .abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn settle(
        &self,
        reservation_id: FixedBytes<32>,
        tau: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        if tau == [0u8; 32] {
            return Err(ErrorCode::SettlementDigestMismatch);
        }
        let calldata = SettlementEscrow::settleCall {
            reservationId: reservation_id,
            tau: FixedBytes::<32>::from_slice(&tau),
        }
        .abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn refund(
        &self,
        reservation_id: FixedBytes<32>,
        evidence: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        if evidence == [0u8; 32] {
            return Err(ErrorCode::SettlementDigestMismatch);
        }
        let calldata = SettlementEscrow::refundCall {
            reservationId: reservation_id,
            noSpendEvidence: FixedBytes::<32>::from(evidence),
        }
        .abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn get_reservation(&self, reservation_id: FixedBytes<32>) -> Result<SettlementReservation> {
        let calldata = SettlementEscrow::getReservationCall {
            reservationId: reservation_id,
        }
        .abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = SettlementEscrow::getReservationCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0.into())
    }

    pub fn refund_safety_window(&self) -> Result<u64> {
        let calldata = SettlementEscrow::refundSafetyWindowCall {}.abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = SettlementEscrow::refundSafetyWindowCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn governor(&self) -> Result<Address> {
        let calldata = SettlementEscrow::governorCall {}.abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = SettlementEscrow::governorCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn mailbox(&self) -> Result<Address> {
        let calldata = SettlementEscrow::mailboxCall {}.abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = SettlementEscrow::mailboxCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn atomic_desk(&self) -> Result<Address> {
        let calldata = SettlementEscrow::atomicDeskCall {}.abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = SettlementEscrow::atomicDeskCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn committee_member(&self, member: Address) -> Result<bool> {
        let calldata = SettlementEscrow::committeeCall { member }.abi_encode();
        let call = EvmCall::new(self.escrow, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = SettlementEscrow::committeeCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }
}
