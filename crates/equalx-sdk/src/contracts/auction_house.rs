use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};

use crate::{
    error::{ErrorCode, Result},
    transport::{EvmCall, EvmViewTransport},
};

sol! {
    #[allow(non_camel_case_types)]
    contract AuctionHouse {
        struct StoredCurve {
            bytes32 commitment;
            uint128 remainingVolume;
            uint64 endTime;
            uint32 generation;
            bool active;
        }

        struct CurveData {
            bytes32 deskId;
            address maker;
            bool baseIsA;
            uint64 endTime;
            uint256 bucketId;
        }

        struct CurveFillView {
            bytes32 deskId;
            address maker;
            address tokenA;
            address tokenB;
            bool baseIsA;
            uint128 startPrice;
            uint128 endPrice;
            uint64 startTime;
            uint64 duration;
            uint16 feeRateBps;
            uint128 remainingVolume;
        }

        function loadCurve(uint256 curveId) view returns (StoredCurve curve, CurveData data);
        function loadCurveForFill(uint256 curveId) view returns (CurveFillView viewData);
        function auctionCounter() view returns (uint256);
        function nextCurveId() view returns (uint256);
        function vault() view returns (address);
    }
}

/// Snapshot of a stored curve plus immutable desk metadata.
#[derive(Clone)]
pub struct CurveView {
    pub stored: AuctionHouse::StoredCurve,
    pub desk_id: FixedBytes<32>,
    pub maker: Address,
    pub base_is_a: bool,
    pub end_time: u64,
    pub bucket_id: U256,
}

/// View returned by `loadCurveForFill`.
#[derive(Clone, Debug)]
pub struct CurveFill {
    pub desk_id: FixedBytes<32>,
    pub maker: Address,
    pub token_a: Address,
    pub token_b: Address,
    pub base_is_a: bool,
    pub start_price: U256,
    pub end_price: U256,
    pub start_time: u64,
    pub duration: u64,
    pub fee_rate_bps: u16,
    pub remaining_volume: U256,
}

impl From<AuctionHouse::CurveFillView> for CurveFill {
    fn from(value: AuctionHouse::CurveFillView) -> Self {
        Self {
            desk_id: value.deskId,
            maker: value.maker,
            token_a: value.tokenA,
            token_b: value.tokenB,
            base_is_a: value.baseIsA,
            start_price: U256::from(value.startPrice),
            end_price: U256::from(value.endPrice),
            start_time: value.startTime,
            duration: value.duration,
            fee_rate_bps: value.feeRateBps,
            remaining_volume: U256::from(value.remainingVolume),
        }
    }
}

#[derive(Clone)]
pub struct AuctionHouseClient<T: EvmViewTransport> {
    house: Address,
    transport: T,
}

impl<T: EvmViewTransport> AuctionHouseClient<T> {
    pub fn new(house: Address, transport: T) -> Self {
        Self { house, transport }
    }

    pub fn address(&self) -> Address {
        self.house
    }

    /// View curve storage and desk metadata.
    pub fn load_curve(&self, id: U256) -> Result<CurveView> {
        let calldata = AuctionHouse::loadCurveCall { curveId: id }.abi_encode();
        let call = EvmCall::new(self.house, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AuctionHouse::loadCurveCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        let (stored, data) = (decoded.curve, decoded.data);
        Ok(CurveView {
            stored,
            desk_id: data.deskId,
            maker: data.maker,
            base_is_a: data.baseIsA,
            end_time: data.endTime,
            bucket_id: data.bucketId,
        })
    }

    /// View fill-ready curve data.
    pub fn load_curve_for_fill(&self, id: U256) -> Result<CurveFill> {
        let calldata = AuctionHouse::loadCurveForFillCall { curveId: id }.abi_encode();
        let call = EvmCall::new(self.house, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AuctionHouse::loadCurveForFillCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded.viewData.into())
    }

    /// Legacy getter maintained by the contract (aliases nextCurveId).
    pub fn auction_counter(&self) -> Result<U256> {
        let calldata = AuctionHouse::auctionCounterCall {}.abi_encode();
        let call = EvmCall::new(self.house, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AuctionHouse::auctionCounterCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    /// Current nextCurveId value.
    pub fn next_curve_id(&self) -> Result<U256> {
        let calldata = AuctionHouse::nextCurveIdCall {}.abi_encode();
        let call = EvmCall::new(self.house, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AuctionHouse::nextCurveIdCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn vault(&self) -> Result<Address> {
        let calldata = AuctionHouse::vaultCall {}.abi_encode();
        let call = EvmCall::new(self.house, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = AuctionHouse::vaultCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }
}
