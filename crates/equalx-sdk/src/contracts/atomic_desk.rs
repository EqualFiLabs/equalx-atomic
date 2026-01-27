use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};

use crate::{
    contracts::TxHash,
    error::{ErrorCode, Result},
    transport::{EvmCall, EvmTransport, EvmViewTransport},
};

sol! {
    #[allow(non_camel_case_types)]
    contract AtomicDesk {
        enum ReservationStatus {
            None,
            Active,
            Settled,
            Refunded
        }

        #[derive(Debug)]
        enum FeePayer {
            Maker,
            Taker
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
            FeePayer feePayer;
            uint8 status;
        }

        struct Tranche {
            bytes32 trancheId;
            bytes32 deskId;
            bytes32 positionKey;
            uint256 positionId;
            address maker;
            address asset;
            uint256 priceNumerator;
            uint256 priceDenominator;
            uint256 totalLiquidity;
            uint256 remainingLiquidity;
            uint256 minFill;
            uint16 feeBps;
            FeePayer feePayer;
            uint64 expiry;
            uint64 createdAt;
            bool active;
        }

        struct TakerTranche {
            bytes32 trancheId;
            bytes32 deskId;
            bytes32 positionKey;
            uint256 positionId;
            address taker;
            address asset;
            uint256 priceNumerator;
            uint256 priceDenominator;
            uint256 totalLiquidity;
            uint256 remainingLiquidity;
            uint256 minFill;
            uint16 feeBps;
            FeePayer feePayer;
            uint64 expiry;
            uint64 createdAt;
            bool active;
        }

        function registerDesk(uint256 positionId, uint256 poolIdA, uint256 poolIdB, bool baseIsA)
            returns (bytes32 deskId);
        function setDeskStatus(bytes32 deskId, bool active);
        function openTranche(
            bytes32 deskId,
            uint256 totalLiquidity,
            uint256 minFill,
            uint256 priceNumerator,
            uint256 priceDenominator,
            uint16 feeBps,
            FeePayer feePayer,
            uint64 expiry
        ) returns (bytes32 trancheId);
        function setTrancheStatus(bytes32 trancheId, bool active);
        function getTranche(bytes32 trancheId) view returns (Tranche);
        function getReservationTranche(bytes32 reservationId) view returns (bytes32 trancheId);
        function openTakerTranche(
            bytes32 deskId,
            uint256 totalLiquidity,
            uint256 minFill,
            uint256 priceNumerator,
            uint256 priceDenominator,
            uint16 feeBps,
            FeePayer feePayer,
            uint64 expiry
        ) payable returns (bytes32 trancheId);
        function setTakerTrancheStatus(bytes32 trancheId, bool active);
        function getTakerTranche(bytes32 trancheId) view returns (TakerTranche);
        function reserveFromTakerTranche(
            bytes32 trancheId,
            uint256 amount,
            bytes32 settlementDigest,
            uint64 expiry
        ) payable returns (bytes32 reservationId);
        function reserveFromTranche(
            bytes32 trancheId,
            uint256 amount,
            bytes32 settlementDigest,
            uint64 expiry
        ) payable returns (bytes32 reservationId);
        function setTakerTranchePostingFee(uint256 feeWei);
        function reserveAtomicSwap(
            bytes32 deskId,
            address taker,
            address asset,
            uint256 amount,
            bytes32 settlementDigest,
            uint64 expiry
        ) payable returns (bytes32 reservationId);
        function setHashlock(bytes32 reservationId, bytes32 hashlock);
        function getReservation(bytes32 reservationId) view returns (Reservation);
    }
}

#[derive(Clone, Debug)]
pub struct AtomicReservation {
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
    pub fee_payer: AtomicDesk::FeePayer,
    pub status: u8,
}

impl From<AtomicDesk::Reservation> for AtomicReservation {
    fn from(value: AtomicDesk::Reservation) -> Self {
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

#[derive(Clone, Debug)]
pub struct AtomicTranche {
    pub tranche_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub position_key: FixedBytes<32>,
    pub position_id: U256,
    pub maker: Address,
    pub asset: Address,
    pub price_numerator: U256,
    pub price_denominator: U256,
    pub total_liquidity: U256,
    pub remaining_liquidity: U256,
    pub min_fill: U256,
    pub fee_bps: u16,
    pub fee_payer: AtomicDesk::FeePayer,
    pub expiry: u64,
    pub created_at: u64,
    pub active: bool,
}

impl From<AtomicDesk::Tranche> for AtomicTranche {
    fn from(value: AtomicDesk::Tranche) -> Self {
        Self {
            tranche_id: value.trancheId,
            desk_id: value.deskId,
            position_key: value.positionKey,
            position_id: value.positionId,
            maker: value.maker,
            asset: value.asset,
            price_numerator: value.priceNumerator,
            price_denominator: value.priceDenominator,
            total_liquidity: value.totalLiquidity,
            remaining_liquidity: value.remainingLiquidity,
            min_fill: value.minFill,
            fee_bps: value.feeBps,
            fee_payer: value.feePayer,
            expiry: value.expiry,
            created_at: value.createdAt,
            active: value.active,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AtomicTakerTranche {
    pub tranche_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub position_key: FixedBytes<32>,
    pub position_id: U256,
    pub taker: Address,
    pub asset: Address,
    pub price_numerator: U256,
    pub price_denominator: U256,
    pub total_liquidity: U256,
    pub remaining_liquidity: U256,
    pub min_fill: U256,
    pub fee_bps: u16,
    pub fee_payer: AtomicDesk::FeePayer,
    pub expiry: u64,
    pub created_at: u64,
    pub active: bool,
}

impl From<AtomicDesk::TakerTranche> for AtomicTakerTranche {
    fn from(value: AtomicDesk::TakerTranche) -> Self {
        Self {
            tranche_id: value.trancheId,
            desk_id: value.deskId,
            position_key: value.positionKey,
            position_id: value.positionId,
            taker: value.taker,
            asset: value.asset,
            price_numerator: value.priceNumerator,
            price_denominator: value.priceDenominator,
            total_liquidity: value.totalLiquidity,
            remaining_liquidity: value.remainingLiquidity,
            min_fill: value.minFill,
            fee_bps: value.feeBps,
            fee_payer: value.feePayer,
            expiry: value.expiry,
            created_at: value.createdAt,
            active: value.active,
        }
    }
}

#[derive(Clone)]
pub struct AtomicDeskClient<T: EvmTransport + EvmViewTransport> {
    desk: Address,
    transport: T,
}

impl<T: EvmTransport + EvmViewTransport> AtomicDeskClient<T> {
    pub fn new(desk: Address, transport: T) -> Self {
        Self { desk, transport }
    }

    pub fn address(&self) -> Address {
        self.desk
    }

    pub fn reserve(
        &self,
        desk_id: FixedBytes<32>,
        taker: Address,
        asset: Address,
        amount: U256,
        settlement_digest: FixedBytes<32>,
        expiry: u64,
        value: U256,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::reserveAtomicSwapCall {
            deskId: desk_id,
            taker,
            asset,
            amount,
            settlementDigest: settlement_digest,
            expiry,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), value)
            .with_gas_limit(gas_limit.unwrap_or(500_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn open_tranche(
        &self,
        desk_id: FixedBytes<32>,
        total_liquidity: U256,
        min_fill: U256,
        price_numerator: U256,
        price_denominator: U256,
        fee_bps: u16,
        fee_payer: AtomicDesk::FeePayer,
        expiry: u64,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::openTrancheCall {
            deskId: desk_id,
            totalLiquidity: total_liquidity,
            minFill: min_fill,
            priceNumerator: price_numerator,
            priceDenominator: price_denominator,
            feeBps: fee_bps,
            feePayer: fee_payer,
            expiry,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(500_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn set_tranche_status(
        &self,
        tranche_id: FixedBytes<32>,
        active: bool,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::setTrancheStatusCall {
            trancheId: tranche_id,
            active,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn reserve_from_tranche(
        &self,
        tranche_id: FixedBytes<32>,
        amount: U256,
        settlement_digest: FixedBytes<32>,
        expiry: u64,
        value: U256,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::reserveFromTrancheCall {
            trancheId: tranche_id,
            amount,
            settlementDigest: settlement_digest,
            expiry,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), value)
            .with_gas_limit(gas_limit.unwrap_or(500_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn open_taker_tranche(
        &self,
        desk_id: FixedBytes<32>,
        total_liquidity: U256,
        min_fill: U256,
        price_numerator: U256,
        price_denominator: U256,
        fee_bps: u16,
        fee_payer: AtomicDesk::FeePayer,
        expiry: u64,
        value: U256,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::openTakerTrancheCall {
            deskId: desk_id,
            totalLiquidity: total_liquidity,
            minFill: min_fill,
            priceNumerator: price_numerator,
            priceDenominator: price_denominator,
            feeBps: fee_bps,
            feePayer: fee_payer,
            expiry,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), value)
            .with_gas_limit(gas_limit.unwrap_or(500_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn set_taker_tranche_status(
        &self,
        tranche_id: FixedBytes<32>,
        active: bool,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::setTakerTrancheStatusCall {
            trancheId: tranche_id,
            active,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn reserve_from_taker_tranche(
        &self,
        tranche_id: FixedBytes<32>,
        amount: U256,
        settlement_digest: FixedBytes<32>,
        expiry: u64,
        value: U256,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::reserveFromTakerTrancheCall {
            trancheId: tranche_id,
            amount,
            settlementDigest: settlement_digest,
            expiry,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), value)
            .with_gas_limit(gas_limit.unwrap_or(500_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn set_taker_tranche_posting_fee(
        &self,
        fee_wei: U256,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::setTakerTranchePostingFeeCall { feeWei: fee_wei }.abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn get_tranche(&self, tranche_id: FixedBytes<32>) -> Result<AtomicTranche> {
        let calldata = AtomicDesk::getTrancheCall { trancheId: tranche_id }.abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AtomicDesk::getTrancheCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0.into())
    }

    pub fn get_taker_tranche(&self, tranche_id: FixedBytes<32>) -> Result<AtomicTakerTranche> {
        let calldata = AtomicDesk::getTakerTrancheCall { trancheId: tranche_id }.abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AtomicDesk::getTakerTrancheCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0.into())
    }

    pub fn get_reservation_tranche(&self, reservation_id: FixedBytes<32>) -> Result<FixedBytes<32>> {
        let calldata = AtomicDesk::getReservationTrancheCall {
            reservationId: reservation_id,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AtomicDesk::getReservationTrancheCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded.trancheId)
    }

    pub fn set_hashlock(
        &self,
        reservation_id: FixedBytes<32>,
        hashlock: FixedBytes<32>,
        gas_limit: Option<u64>,
    ) -> Result<TxHash> {
        let calldata = AtomicDesk::setHashlockCall {
            reservationId: reservation_id,
            hashlock,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(200_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn get_reservation(&self, reservation_id: FixedBytes<32>) -> Result<AtomicReservation> {
        let calldata = AtomicDesk::getReservationCall {
            reservationId: reservation_id,
        }
        .abi_encode();
        let call = EvmCall::new(self.desk, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AtomicDesk::getReservationCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0.into())
    }
}
