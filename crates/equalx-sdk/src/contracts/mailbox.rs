use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_sol_types::{sol, SolCall};

use crate::{
    contracts::TxHash,
    error::{ErrorCode, Result},
    transport::{EvmCall, EvmTransport, EvmViewTransport},
};

sol! {
    #[allow(non_camel_case_types)]
    contract Mailbox {
        event DeskKeyRegistered(address desk, bytes pubkey);
        event ContextPublished(bytes32 reservationId, address taker, bytes envelope);
        event PreSigPublished(bytes32 reservationId, address desk, bytes envelope);
        event FinalSigPublished(bytes32 reservationId, address poster, bytes envelope);
        event ReservationAuthorized(bytes32 reservationId);
        event ReservationRevoked(bytes32 reservationId);

        function registerPubkey(bytes pubkey);
        function publishContext(bytes32 reservationId, bytes envelope);
        function publishPreSig(bytes32 reservationId, bytes envelope);
        function publishFinalSig(bytes32 reservationId, bytes envelope);
        function fetch(bytes32 reservationId) view returns (bytes[] envelopes);
        function deskEncryptionPubkey(address desk) view returns (bytes pubkey);
    }
}

#[derive(Clone, Debug)]
pub struct PublishEnvelopeArgs<'a> {
    pub reservation_id: FixedBytes<32>,
    pub envelope: &'a [u8],
    pub gas_limit: Option<u64>,
}

#[derive(Clone)]
pub struct MailboxClient<T: EvmTransport + EvmViewTransport> {
    mailbox: Address,
    transport: T,
}

impl<T: EvmTransport + EvmViewTransport> MailboxClient<T> {
    pub fn new(mailbox: Address, transport: T) -> Self {
        Self { mailbox, transport }
    }

    pub fn address(&self) -> Address {
        self.mailbox
    }

    pub fn register_pubkey(&self, pubkey: &[u8; 33], gas_limit: Option<u64>) -> Result<TxHash> {
        let calldata = Mailbox::registerPubkeyCall {
            pubkey: Bytes::from(pubkey.to_vec()),
        }
        .abi_encode();
        let call = EvmCall::new(self.mailbox, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(120_000));
        self.transport.send(call).map(Into::into)
    }

    pub fn publish_context(&self, args: PublishEnvelopeArgs<'_>) -> Result<TxHash> {
        self.publish_envelope(
            Mailbox::publishContextCall {
                reservationId: args.reservation_id,
                envelope: Bytes::from(args.envelope.to_vec()),
            },
            args.gas_limit.or(Some(300_000)),
        )
    }

    pub fn publish_presig(&self, args: PublishEnvelopeArgs<'_>) -> Result<TxHash> {
        self.publish_envelope(
            Mailbox::publishPreSigCall {
                reservationId: args.reservation_id,
                envelope: Bytes::from(args.envelope.to_vec()),
            },
            args.gas_limit.or(Some(400_000)),
        )
    }

    pub fn publish_final_sig(&self, args: PublishEnvelopeArgs<'_>) -> Result<TxHash> {
        self.publish_envelope(
            Mailbox::publishFinalSigCall {
                reservationId: args.reservation_id,
                envelope: Bytes::from(args.envelope.to_vec()),
            },
            args.gas_limit.or(Some(350_000)),
        )
    }

    pub fn fetch(&self, reservation_id: FixedBytes<32>) -> Result<Vec<Vec<u8>>> {
        let calldata = Mailbox::fetchCall {
            reservationId: reservation_id,
        }
        .abi_encode();
        let call = EvmCall::new(self.mailbox, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = Mailbox::fetchCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded
            .envelopes
            .into_iter()
            .map(|bytes| bytes.to_vec())
            .collect())
    }

    pub fn desk_pubkey(&self, desk: Address) -> Result<Vec<u8>> {
        let calldata = Mailbox::deskEncryptionPubkeyCall { desk }.abi_encode();
        let call = EvmCall::new(self.mailbox, Bytes::from(calldata), Default::default());
        let raw = self.transport.call_view(call)?;
        let decoded = Mailbox::deskEncryptionPubkeyCall::abi_decode_returns(&raw, true)
            .map_err(|_| ErrorCode::BridgeTransportEvm)?;
        Ok(decoded.pubkey.to_vec())
    }

    fn publish_envelope<C>(&self, call: C, gas_limit: Option<u64>) -> Result<TxHash>
    where
        C: SolCall,
    {
        let calldata = call.abi_encode();
        let evm_call = EvmCall::new(self.mailbox, Bytes::from(calldata), Default::default())
            .with_gas_limit(gas_limit.unwrap_or(300_000));
        self.transport.send(evm_call).map(Into::into)
    }
}
