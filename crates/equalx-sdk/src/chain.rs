//! Chain-agnostic traits for swap-facing contract interactions.

use alloy_primitives::{Address, FixedBytes, U256};

use crate::{
    contracts::{MailboxClient, SettlementEscrowClient, SettlementReservation, TxHash},
    error::Result,
    key_registry::KeyRegistryClient,
    transport::{EvmTransport, EvmViewTransport},
};

/// Shared reservation status across chain adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationStatus {
    None,
    Active,
    Settled,
    Refunded,
}

/// Minimal reservation view used by the swap flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationView<Id, Addr, Amount> {
    pub reservation_id: Id,
    pub desk: Addr,
    pub taker: Addr,
    pub asset: Addr,
    pub amount: Amount,
    pub settlement_digest: [u8; 32],
    pub hashlock: [u8; 32],
    pub expiry: u64,
    pub created_at: u64,
    pub status: ReservationStatus,
}

/// Mailbox publish arguments for chain adapters.
#[derive(Clone, Debug)]
pub struct ChainEnvelopeArgs<'a, Id> {
    pub reservation_id: Id,
    pub envelope: &'a [u8],
    pub gas_limit: Option<u64>,
}

/// Chain-agnostic interface to the encrypted pubkey registry.
pub trait KeyRegistryApi {
    type Address;
    type TxHash;

    fn register_enc_pub(&self, pubkey: &[u8; 33], gas_limit: Option<u64>) -> Result<Self::TxHash>;
    fn get_enc_pub(&self, owner: Self::Address) -> Result<Vec<u8>>;
    fn is_registered(&self, owner: Self::Address) -> Result<bool>;
}

/// Chain-agnostic interface to the encrypted mailbox.
pub trait MailboxApi {
    type Address;
    type ReservationId;
    type TxHash;

    fn register_pubkey(&self, pubkey: &[u8; 33], gas_limit: Option<u64>) -> Result<Self::TxHash>;
    fn publish_context(&self, args: ChainEnvelopeArgs<'_, Self::ReservationId>) -> Result<Self::TxHash>;
    fn publish_presig(&self, args: ChainEnvelopeArgs<'_, Self::ReservationId>) -> Result<Self::TxHash>;
    fn publish_final_sig(&self, args: ChainEnvelopeArgs<'_, Self::ReservationId>) -> Result<Self::TxHash>;
    fn fetch(&self, reservation_id: Self::ReservationId) -> Result<Vec<Vec<u8>>>;
    fn desk_pubkey(&self, desk: Self::Address) -> Result<Vec<u8>>;
}

/// Chain-agnostic interface to the settlement escrow.
pub trait SettlementEscrowApi {
    type Address;
    type ReservationId;
    type Amount;
    type TxHash;

    fn set_hashlock(
        &self,
        reservation_id: Self::ReservationId,
        hashlock: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<Self::TxHash>;
    fn settle(
        &self,
        reservation_id: Self::ReservationId,
        tau: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<Self::TxHash>;
    fn refund(
        &self,
        reservation_id: Self::ReservationId,
        evidence: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<Self::TxHash>;
    fn get_reservation(
        &self,
        reservation_id: Self::ReservationId,
    ) -> Result<ReservationView<Self::ReservationId, Self::Address, Self::Amount>>;
}

impl From<crate::contracts::settlement_escrow::ReservationStatus> for ReservationStatus {
    fn from(value: crate::contracts::settlement_escrow::ReservationStatus) -> Self {
        match value {
            crate::contracts::settlement_escrow::ReservationStatus::None => Self::None,
            crate::contracts::settlement_escrow::ReservationStatus::Active => Self::Active,
            crate::contracts::settlement_escrow::ReservationStatus::Settled => Self::Settled,
            crate::contracts::settlement_escrow::ReservationStatus::Refunded => Self::Refunded,
            crate::contracts::settlement_escrow::ReservationStatus::__Invalid => Self::None,
        }
    }
}

impl From<SettlementReservation>
    for ReservationView<FixedBytes<32>, Address, U256>
{
    fn from(value: SettlementReservation) -> Self {
        Self {
            reservation_id: value.reservation_id,
            desk: value.desk,
            taker: value.taker,
            asset: value.asset,
            amount: value.amount,
            settlement_digest: value.settlement_digest.into(),
            hashlock: value.hashlock.into(),
            expiry: value.expiry,
            created_at: value.created_at,
            status: value.status.into(),
        }
    }
}

impl<T> KeyRegistryApi for KeyRegistryClient<T>
where
    T: EvmTransport + EvmViewTransport,
{
    type Address = Address;
    type TxHash = TxHash;

    fn register_enc_pub(&self, pubkey: &[u8; 33], gas_limit: Option<u64>) -> Result<Self::TxHash> {
        KeyRegistryClient::register_enc_pub(self, pubkey, gas_limit)
    }

    fn get_enc_pub(&self, owner: Self::Address) -> Result<Vec<u8>> {
        KeyRegistryClient::get_enc_pub(self, owner)
    }

    fn is_registered(&self, owner: Self::Address) -> Result<bool> {
        KeyRegistryClient::is_registered(self, owner)
    }
}

impl<T> MailboxApi for MailboxClient<T>
where
    T: EvmTransport + EvmViewTransport,
{
    type Address = Address;
    type ReservationId = FixedBytes<32>;
    type TxHash = TxHash;

    fn register_pubkey(&self, pubkey: &[u8; 33], gas_limit: Option<u64>) -> Result<Self::TxHash> {
        MailboxClient::register_pubkey(self, pubkey, gas_limit)
    }

    fn publish_context(
        &self,
        args: ChainEnvelopeArgs<'_, Self::ReservationId>,
    ) -> Result<Self::TxHash> {
        MailboxClient::publish_context(
            self,
            crate::contracts::PublishEnvelopeArgs {
                reservation_id: args.reservation_id,
                envelope: args.envelope,
                gas_limit: args.gas_limit,
            },
        )
    }

    fn publish_presig(
        &self,
        args: ChainEnvelopeArgs<'_, Self::ReservationId>,
    ) -> Result<Self::TxHash> {
        MailboxClient::publish_presig(
            self,
            crate::contracts::PublishEnvelopeArgs {
                reservation_id: args.reservation_id,
                envelope: args.envelope,
                gas_limit: args.gas_limit,
            },
        )
    }

    fn publish_final_sig(
        &self,
        args: ChainEnvelopeArgs<'_, Self::ReservationId>,
    ) -> Result<Self::TxHash> {
        MailboxClient::publish_final_sig(
            self,
            crate::contracts::PublishEnvelopeArgs {
                reservation_id: args.reservation_id,
                envelope: args.envelope,
                gas_limit: args.gas_limit,
            },
        )
    }

    fn fetch(&self, reservation_id: Self::ReservationId) -> Result<Vec<Vec<u8>>> {
        MailboxClient::fetch(self, reservation_id)
    }

    fn desk_pubkey(&self, desk: Self::Address) -> Result<Vec<u8>> {
        MailboxClient::desk_pubkey(self, desk)
    }
}

impl<T> SettlementEscrowApi for SettlementEscrowClient<T>
where
    T: EvmTransport + EvmViewTransport,
{
    type Address = Address;
    type ReservationId = FixedBytes<32>;
    type Amount = U256;
    type TxHash = TxHash;

    fn set_hashlock(
        &self,
        reservation_id: Self::ReservationId,
        hashlock: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<Self::TxHash> {
        SettlementEscrowClient::set_hashlock(self, reservation_id, hashlock, gas_limit)
    }

    fn settle(
        &self,
        reservation_id: Self::ReservationId,
        tau: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<Self::TxHash> {
        SettlementEscrowClient::settle(self, reservation_id, tau, gas_limit)
    }

    fn refund(
        &self,
        reservation_id: Self::ReservationId,
        evidence: [u8; 32],
        gas_limit: Option<u64>,
    ) -> Result<Self::TxHash> {
        SettlementEscrowClient::refund(self, reservation_id, evidence, gas_limit)
    }

    fn get_reservation(
        &self,
        reservation_id: Self::ReservationId,
    ) -> Result<ReservationView<Self::ReservationId, Self::Address, Self::Amount>> {
        SettlementEscrowClient::get_reservation(self, reservation_id).map(Into::into)
    }
}
