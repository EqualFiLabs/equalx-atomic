use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};

use crate::{
    error::{ErrorCode, Result},
    transport::{EvmCall, EvmViewTransport},
};

sol! {
    #[allow(non_camel_case_types)]
    contract DeskVault {
        struct Balances {
            uint256 freeA;
            uint256 reservedA;
            uint256 freeB;
            uint256 reservedB;
        }

        struct MakerFees {
            uint256 feeA;
            uint256 feeB;
        }

        function getBalances(address maker, address tokenX, address tokenY) view returns (Balances);
        function getDeskBalances(bytes32 deskId) view returns (Balances, MakerFees);
        function getMakerFees(address maker, address tokenX, address tokenY) view returns (uint256 feeA, uint256 feeB);
        function canonicalPair(address tokenX, address tokenY) pure returns (address tokenA, address tokenB);
        function computeDeskId(address maker, address tokenX, address tokenY) pure returns (bytes32);
        function atomicDeskEnabled(bytes32 deskId) view returns (bool);
        function withdrawalLocks(bytes32 deskId) view returns (uint64);
        function settlementEscrow() view returns (address);
        function router() view returns (address);
        function auctionHouse() view returns (address);
    }
}

/// Helper that mirrors the onchain Balances struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeskBalances {
    pub free_a: U256,
    pub reserved_a: U256,
    pub free_b: U256,
    pub reserved_b: U256,
}

/// Helper that mirrors the onchain MakerFees struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeskMakerFees {
    pub fee_a: U256,
    pub fee_b: U256,
}

impl From<DeskVault::Balances> for DeskBalances {
    fn from(value: DeskVault::Balances) -> Self {
        Self {
            free_a: value.freeA,
            reserved_a: value.reservedA,
            free_b: value.freeB,
            reserved_b: value.reservedB,
        }
    }
}

impl From<DeskVault::MakerFees> for DeskMakerFees {
    fn from(value: DeskVault::MakerFees) -> Self {
        Self {
            fee_a: value.feeA,
            fee_b: value.feeB,
        }
    }
}

/// View-only client for DeskVault getters.
#[derive(Clone)]
pub struct DeskVaultClient<T: EvmViewTransport> {
    vault: Address,
    transport: T,
}

impl<T: EvmViewTransport> DeskVaultClient<T> {
    pub fn new(vault: Address, transport: T) -> Self {
        Self { vault, transport }
    }

    pub fn address(&self) -> Address {
        self.vault
    }

    /// Deterministically computes the desk id offchain using canonical ordering.
    pub fn compute_desk_id(maker: Address, token_x: Address, token_y: Address) -> FixedBytes<32> {
        let (token_a, token_b) = canonical_pair(token_x, token_y);
        let mut encoded = [0u8; 20 * 3];
        encoded[..20].copy_from_slice(maker.as_slice());
        encoded[20..40].copy_from_slice(token_a.as_slice());
        encoded[40..60].copy_from_slice(token_b.as_slice());
        FixedBytes::from(keccak256(encoded))
    }

    /// Canonicalize a pair using the contract's pure function.
    pub fn canonical_pair(&self, token_x: Address, token_y: Address) -> Result<(Address, Address)> {
        let calldata = DeskVault::canonicalPairCall { tokenX: token_x, tokenY: token_y }
            .abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::canonicalPairCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok((decoded.tokenA, decoded.tokenB))
    }

    pub fn compute_desk_id_remote(
        &self,
        maker: Address,
        token_x: Address,
        token_y: Address,
    ) -> Result<FixedBytes<32>> {
        let calldata = DeskVault::computeDeskIdCall {
            maker,
            tokenX: token_x,
            tokenY: token_y,
        }
        .abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::computeDeskIdCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn get_balances(
        &self,
        maker: Address,
        token_x: Address,
        token_y: Address,
    ) -> Result<DeskBalances> {
        let calldata =
            DeskVault::getBalancesCall { maker, tokenX: token_x, tokenY: token_y }.abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::getBalancesCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0.into())
    }

    pub fn get_desk_balances(&self, desk_id: FixedBytes<32>) -> Result<(DeskBalances, DeskMakerFees)> {
        let calldata = DeskVault::getDeskBalancesCall { deskId: desk_id }.abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::getDeskBalancesCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok((decoded._0.into(), decoded._1.into()))
    }

    pub fn get_maker_fees(
        &self,
        maker: Address,
        token_x: Address,
        token_y: Address,
    ) -> Result<(U256, U256)> {
        let calldata = DeskVault::getMakerFeesCall {
            maker,
            tokenX: token_x,
            tokenY: token_y,
        }
        .abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::getMakerFeesCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok((decoded.feeA, decoded.feeB))
    }

    pub fn atomic_desk_enabled(&self, desk_id: FixedBytes<32>) -> Result<bool> {
        let calldata = DeskVault::atomicDeskEnabledCall { deskId: desk_id }.abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::atomicDeskEnabledCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn withdrawal_lock(&self, desk_id: FixedBytes<32>) -> Result<u64> {
        let calldata = DeskVault::withdrawalLocksCall { deskId: desk_id }.abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::withdrawalLocksCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn settlement_escrow(&self) -> Result<Address> {
        let calldata = DeskVault::settlementEscrowCall {}.abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::settlementEscrowCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn router(&self) -> Result<Address> {
        let calldata = DeskVault::routerCall {}.abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::routerCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }

    pub fn auction_house(&self) -> Result<Address> {
        let calldata = DeskVault::auctionHouseCall {}.abi_encode();
        let call = EvmCall::new(self.vault, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = DeskVault::auctionHouseCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded._0)
    }
}

fn canonical_pair(token_x: Address, token_y: Address) -> (Address, Address) {
    if token_x == token_y || token_x == Address::ZERO || token_y == Address::ZERO {
        return (token_x, token_y);
    }
    if token_x < token_y {
        (token_x, token_y)
    } else {
        (token_y, token_x)
    }
}
