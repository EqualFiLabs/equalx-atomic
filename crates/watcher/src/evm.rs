// SPDX-License-Identifier: Apache-2.0

//! Helpers for decoding AtomicDesk / SettlementEscrow events so dashboards and
//! automation layers can surface reservation metadata and state transitions.
//!
//! The module includes a polling interface over a host-provided RPC trait and
//! decodes raw logs into chronological lifecycle events.

use alloy_primitives::{b256, Address, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolType};
use anyhow::{anyhow, ensure, Result};
const RESERVATION_CREATED_TOPIC: B256 =
    b256!("bb284251eb13344d6670b853b97e3a219b42869b9c0aca301d23c80f805ec1d1");
const HASHLOCK_SET_TOPIC: B256 =
    b256!("b02f4cb7dd5a3cf6dddc6715fb1f561181a29e6f835adfed54e7370965a01972");
const ATOMIC_RESERVATION_TOPIC: B256 =
    b256!("1ddda36df969a97d0bc292e012733b07078d790ed011aef7fc50118ed19cb1f0");
const RESERVATION_SETTLED_TOPIC: B256 =
    b256!("6be47e61e7f7fd77b4e8201b3ace162fa32be35d1741c6e8d5a37b9463ff6ec8");
const RESERVATION_REFUNDED_TOPIC: B256 =
    b256!("ab528a5b2d7a20115e2f343695e1f2426261c227e7df5fc3ced5365e86a5e3a7");
const TRANCHE_OPENED_TOPIC: B256 =
    b256!("9868774a230125c8dec0be0294563355a987a3c915027e72aceeb2eacc71e556");
const TAKER_TRANCHE_OPENED_TOPIC: B256 =
    b256!("5ef608c488294ad87817c00aaa3f80f4f50416b62b8a5f603b1e3db3404f793f");
const TRANCHE_RESERVED_TOPIC: B256 =
    b256!("f1d082a8c1d907940678bec35245f9c9be7379f8b7306cbbb22671c0bca446fa");
const TAKER_TRANCHE_RESERVED_TOPIC: B256 =
    b256!("b6e30a044e2238b5f350746e7b8a93a129a815a16d2b0edffa4e4acd3e88bc58");

/// Raw EVM log returned by an RPC provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
}

/// Polling request describing the block range and contracts to monitor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmPollRequest {
    pub from_block: u64,
    pub to_block: u64,
    pub contract_addresses: Vec<Address>,
}

/// Decoded lifecycle event variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedLifecycleEvent {
    ReservationCreated(ReservationCreatedRecord),
    HashlockSet(HashlockSetRecord),
    AtomicReservationCreated(AtomicReservationRecord),
    TrancheOpened(TrancheOpenedRecord),
    TakerTrancheOpened(TakerTrancheOpenedRecord),
    TrancheReserved(TrancheReservedRecord),
    TakerTrancheReserved(TakerTrancheReservedRecord),
    ReservationSettled {
        reservation_id: FixedBytes<32>,
        tau: [u8; 32],
    },
    ReservationRefunded {
        reservation_id: FixedBytes<32>,
        evidence: [u8; 32],
    },
}

/// Chronologically sorted decoded event record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedEvmEvent {
    pub address: Address,
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
    pub event: DecodedLifecycleEvent,
}

/// Abstraction over an EVM RPC provider capable of returning logs.
pub trait EvmWatcherRpc {
    fn get_logs(
        &self,
        from_block: u64,
        to_block: u64,
        contract_addresses: &[Address],
    ) -> Result<Vec<EvmLog>>;
}

sol! {
    struct ReservationCreatedData {
        uint256 amount;
        uint256 counter;
    }

    struct HashlockSetData {
        bytes32 hashlock;
    }

    struct AtomicReservationData {
        address asset;
        uint256 amount;
        bytes32 settlementDigest;
        uint64 expiry;
        uint64 createdAt;
    }

    struct ReservationSettledData {
        bytes32 tau;
    }

    struct ReservationRefundedData {
        bytes32 evidence;
    }

    struct TrancheOpenedData {
        address asset;
        uint256 priceNumerator;
        uint256 priceDenominator;
        uint256 totalLiquidity;
        uint256 minFill;
        uint16 feeBps;
        uint8 feePayer;
        uint64 expiry;
    }

    struct TakerTrancheOpenedData {
        address asset;
        uint256 priceNumerator;
        uint256 priceDenominator;
        uint256 totalLiquidity;
        uint256 minFill;
        uint16 feeBps;
        uint8 feePayer;
        uint64 expiry;
        uint256 postingFee;
    }

    struct TrancheReservedData {
        uint256 amount;
        uint256 remainingLiquidity;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationCreatedRecord {
    pub reservation_id: FixedBytes<32>,
    pub taker: Address,
    pub desk: Address,
    pub amount: U256,
    pub counter: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashlockSetRecord {
    pub reservation_id: FixedBytes<32>,
    pub hashlock: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicReservationRecord {
    pub reservation_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub taker: Address,
    pub asset: Address,
    pub amount: U256,
    pub settlement_digest: [u8; 32],
    pub expiry: u64,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrancheOpenedRecord {
    pub tranche_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub maker: Address,
    pub asset: Address,
    pub price_numerator: U256,
    pub price_denominator: U256,
    pub total_liquidity: U256,
    pub min_fill: U256,
    pub fee_bps: u16,
    pub fee_payer: u8,
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakerTrancheOpenedRecord {
    pub tranche_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub taker: Address,
    pub asset: Address,
    pub price_numerator: U256,
    pub price_denominator: U256,
    pub total_liquidity: U256,
    pub min_fill: U256,
    pub fee_bps: u16,
    pub fee_payer: u8,
    pub expiry: u64,
    pub posting_fee: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrancheReservedRecord {
    pub tranche_id: FixedBytes<32>,
    pub reservation_id: FixedBytes<32>,
    pub taker: Address,
    pub amount: U256,
    pub remaining_liquidity: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakerTrancheReservedRecord {
    pub tranche_id: FixedBytes<32>,
    pub reservation_id: FixedBytes<32>,
    pub maker: Address,
    pub amount: U256,
    pub remaining_liquidity: U256,
}

// Legacy QuoteBoard decoding has been removed; watcher focuses on Router / SettlementEscrow events.

/// Decode a `ReservationCreated` event emitted by SettlementEscrow.
pub fn decode_reservation_created(
    topics: &[B256],
    data: &[u8],
) -> Result<ReservationCreatedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == RESERVATION_CREATED_TOPIC,
        "not a ReservationCreated log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let taker = topic_to_address(topics[2]);
    let desk = topic_to_address(topics[3]);
    let parsed = ReservationCreatedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode ReservationCreated: {err}"))?;
    Ok(ReservationCreatedRecord {
        reservation_id,
        taker,
        desk,
        amount: parsed.amount,
        counter: parsed.counter,
    })
}

/// Decode a `HashlockSet` event emitted by SettlementEscrow.
pub fn decode_hashlock_set(topics: &[B256], data: &[u8]) -> Result<HashlockSetRecord> {
    ensure!(
        topics.len() >= 2 && topics[0] == HASHLOCK_SET_TOPIC,
        "not a HashlockSet log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let parsed = HashlockSetData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode HashlockSet: {err}"))?;
    Ok(HashlockSetRecord {
        reservation_id,
        hashlock: parsed.hashlock.into(),
    })
}

/// Decode the AtomicDesk `ReservationCreated` event.
pub fn decode_atomic_reservation_created(
    topics: &[B256],
    data: &[u8],
) -> Result<AtomicReservationRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == ATOMIC_RESERVATION_TOPIC,
        "not an AtomicDesk ReservationCreated log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let desk_bytes: [u8; 32] = topics[2].into();
    let desk_id = FixedBytes::<32>::from(desk_bytes);
    let taker = topic_to_address(topics[3]);
    let parsed = AtomicReservationData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode AtomicDesk ReservationCreated: {err}"))?;
    Ok(AtomicReservationRecord {
        reservation_id,
        desk_id,
        taker,
        asset: parsed.asset,
        amount: parsed.amount,
        settlement_digest: parsed.settlementDigest.into(),
        expiry: parsed.expiry,
        created_at: parsed.createdAt,
    })
}

/// Decode the AtomicDesk `TrancheOpened` event.
pub fn decode_tranche_opened(topics: &[B256], data: &[u8]) -> Result<TrancheOpenedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TRANCHE_OPENED_TOPIC,
        "not an AtomicDesk TrancheOpened log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let desk_bytes: [u8; 32] = topics[2].into();
    let desk_id = FixedBytes::<32>::from(desk_bytes);
    let maker = topic_to_address(topics[3]);
    let parsed = TrancheOpenedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TrancheOpened: {err}"))?;
    Ok(TrancheOpenedRecord {
        tranche_id,
        desk_id,
        maker,
        asset: parsed.asset,
        price_numerator: parsed.priceNumerator,
        price_denominator: parsed.priceDenominator,
        total_liquidity: parsed.totalLiquidity,
        min_fill: parsed.minFill,
        fee_bps: parsed.feeBps,
        fee_payer: parsed.feePayer,
        expiry: parsed.expiry,
    })
}

/// Decode the AtomicDesk `TakerTrancheOpened` event.
pub fn decode_taker_tranche_opened(
    topics: &[B256],
    data: &[u8],
) -> Result<TakerTrancheOpenedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TAKER_TRANCHE_OPENED_TOPIC,
        "not an AtomicDesk TakerTrancheOpened log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let desk_bytes: [u8; 32] = topics[2].into();
    let desk_id = FixedBytes::<32>::from(desk_bytes);
    let taker = topic_to_address(topics[3]);
    let parsed = TakerTrancheOpenedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TakerTrancheOpened: {err}"))?;
    Ok(TakerTrancheOpenedRecord {
        tranche_id,
        desk_id,
        taker,
        asset: parsed.asset,
        price_numerator: parsed.priceNumerator,
        price_denominator: parsed.priceDenominator,
        total_liquidity: parsed.totalLiquidity,
        min_fill: parsed.minFill,
        fee_bps: parsed.feeBps,
        fee_payer: parsed.feePayer,
        expiry: parsed.expiry,
        posting_fee: parsed.postingFee,
    })
}

/// Decode the AtomicDesk `TrancheReserved` event.
pub fn decode_tranche_reserved(topics: &[B256], data: &[u8]) -> Result<TrancheReservedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TRANCHE_RESERVED_TOPIC,
        "not an AtomicDesk TrancheReserved log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let reservation_id = topic_to_bytes32(topics[2]);
    let taker = topic_to_address(topics[3]);
    let parsed = TrancheReservedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TrancheReserved: {err}"))?;
    Ok(TrancheReservedRecord {
        tranche_id,
        reservation_id,
        taker,
        amount: parsed.amount,
        remaining_liquidity: parsed.remainingLiquidity,
    })
}

/// Decode the AtomicDesk `TakerTrancheReserved` event.
pub fn decode_taker_tranche_reserved(
    topics: &[B256],
    data: &[u8],
) -> Result<TakerTrancheReservedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TAKER_TRANCHE_RESERVED_TOPIC,
        "not an AtomicDesk TakerTrancheReserved log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let reservation_id = topic_to_bytes32(topics[2]);
    let maker = topic_to_address(topics[3]);
    let parsed = TrancheReservedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TakerTrancheReserved: {err}"))?;
    Ok(TakerTrancheReservedRecord {
        tranche_id,
        reservation_id,
        maker,
        amount: parsed.amount,
        remaining_liquidity: parsed.remainingLiquidity,
    })
}

/// Decode a lifecycle event based on topic[0].
pub fn decode_lifecycle_event(topics: &[B256], data: &[u8]) -> Result<DecodedLifecycleEvent> {
    let topic0 = topics
        .first()
        .copied()
        .ok_or_else(|| anyhow!("event topics cannot be empty"))?;
    match topic0 {
        RESERVATION_CREATED_TOPIC => {
            decode_reservation_created(topics, data).map(DecodedLifecycleEvent::ReservationCreated)
        }
        HASHLOCK_SET_TOPIC => {
            decode_hashlock_set(topics, data).map(DecodedLifecycleEvent::HashlockSet)
        }
        ATOMIC_RESERVATION_TOPIC => decode_atomic_reservation_created(topics, data)
            .map(DecodedLifecycleEvent::AtomicReservationCreated),
        TRANCHE_OPENED_TOPIC => {
            decode_tranche_opened(topics, data).map(DecodedLifecycleEvent::TrancheOpened)
        }
        TAKER_TRANCHE_OPENED_TOPIC => {
            decode_taker_tranche_opened(topics, data).map(DecodedLifecycleEvent::TakerTrancheOpened)
        }
        TRANCHE_RESERVED_TOPIC => {
            decode_tranche_reserved(topics, data).map(DecodedLifecycleEvent::TrancheReserved)
        }
        TAKER_TRANCHE_RESERVED_TOPIC => decode_taker_tranche_reserved(topics, data)
            .map(DecodedLifecycleEvent::TakerTrancheReserved),
        RESERVATION_SETTLED_TOPIC => {
            let (reservation_id, tau) = decode_reservation_settled(topics, data)?;
            Ok(DecodedLifecycleEvent::ReservationSettled {
                reservation_id,
                tau,
            })
        }
        RESERVATION_REFUNDED_TOPIC => {
            let (reservation_id, evidence) = decode_reservation_refunded(topics, data)?;
            Ok(DecodedLifecycleEvent::ReservationRefunded {
                reservation_id,
                evidence,
            })
        }
        _ => Err(anyhow!("unknown event topic: {topic0:#x}")),
    }
}

/// Poll logs from a provider and return decoded lifecycle events in chronological order.
pub fn poll_lifecycle_events<R: EvmWatcherRpc>(
    rpc: &R,
    request: &EvmPollRequest,
) -> Result<Vec<DecodedEvmEvent>> {
    ensure!(
        request.from_block <= request.to_block,
        "invalid block range: from_block > to_block"
    );
    ensure!(
        !request.contract_addresses.is_empty(),
        "contract address set cannot be empty"
    );

    let mut logs = rpc.get_logs(
        request.from_block,
        request.to_block,
        &request.contract_addresses,
    )?;
    logs.retain(|log| request.contract_addresses.contains(&log.address));
    logs.sort_by_key(|log| (log.block_number, log.transaction_index, log.log_index));

    logs.into_iter()
        .map(|log| {
            let event = decode_lifecycle_event(&log.topics, &log.data)?;
            Ok(DecodedEvmEvent {
                address: log.address,
                block_number: log.block_number,
                transaction_index: log.transaction_index,
                log_index: log.log_index,
                event,
            })
        })
        .collect()
}

fn topic_to_bytes32(topic: B256) -> FixedBytes<32> {
    let bytes: [u8; 32] = topic.into();
    FixedBytes::<32>::from(bytes)
}

fn topic_to_address(topic: B256) -> Address {
    let bytes: [u8; 32] = topic.into();
    Address::from_slice(&bytes[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, B256};
    use alloy_sol_types::SolValue;
    use proptest::prelude::*;
    use std::sync::{Arc, Mutex};

    fn encode_address_topic(addr: Address) -> B256 {
        let mut buf = [0u8; 32];
        buf[12..].copy_from_slice(addr.as_slice());
        B256::from(buf)
    }

    #[derive(Clone, Debug)]
    enum GeneratedEvmEvent {
        ReservationCreated {
            reservation_id: [u8; 32],
            taker: Address,
            desk: Address,
            amount: U256,
            counter: U256,
        },
        HashlockSet {
            reservation_id: [u8; 32],
            hashlock: [u8; 32],
        },
        AtomicReservationCreated {
            reservation_id: [u8; 32],
            desk_id: [u8; 32],
            taker: Address,
            asset: Address,
            amount: U256,
            settlement_digest: [u8; 32],
            expiry: u64,
            created_at: u64,
        },
        TrancheOpened {
            tranche_id: [u8; 32],
            desk_id: [u8; 32],
            maker: Address,
            asset: Address,
            price_numerator: U256,
            price_denominator: U256,
            total_liquidity: U256,
            min_fill: U256,
            fee_bps: u16,
            fee_payer: u8,
            expiry: u64,
        },
        TakerTrancheOpened {
            tranche_id: [u8; 32],
            desk_id: [u8; 32],
            taker: Address,
            asset: Address,
            price_numerator: U256,
            price_denominator: U256,
            total_liquidity: U256,
            min_fill: U256,
            fee_bps: u16,
            fee_payer: u8,
            expiry: u64,
            posting_fee: U256,
        },
        TrancheReserved {
            tranche_id: [u8; 32],
            reservation_id: [u8; 32],
            taker: Address,
            amount: U256,
            remaining_liquidity: U256,
        },
        TakerTrancheReserved {
            tranche_id: [u8; 32],
            reservation_id: [u8; 32],
            maker: Address,
            amount: U256,
            remaining_liquidity: U256,
        },
        ReservationSettled {
            reservation_id: [u8; 32],
            tau: [u8; 32],
        },
        ReservationRefunded {
            reservation_id: [u8; 32],
            evidence: [u8; 32],
        },
    }

    impl GeneratedEvmEvent {
        fn encode(&self) -> (Vec<B256>, Vec<u8>) {
            match self {
                Self::ReservationCreated {
                    reservation_id,
                    taker,
                    desk,
                    amount,
                    counter,
                } => {
                    let topics = vec![
                        RESERVATION_CREATED_TOPIC,
                        B256::from(*reservation_id),
                        encode_address_topic(*taker),
                        encode_address_topic(*desk),
                    ];
                    let data = SolValue::abi_encode(&ReservationCreatedData {
                        amount: *amount,
                        counter: *counter,
                    });
                    (topics, data)
                }
                Self::HashlockSet {
                    reservation_id,
                    hashlock,
                } => {
                    let topics = vec![HASHLOCK_SET_TOPIC, B256::from(*reservation_id)];
                    let data = SolValue::abi_encode(&HashlockSetData {
                        hashlock: FixedBytes::<32>::from(*hashlock),
                    });
                    (topics, data)
                }
                Self::AtomicReservationCreated {
                    reservation_id,
                    desk_id,
                    taker,
                    asset,
                    amount,
                    settlement_digest,
                    expiry,
                    created_at,
                } => {
                    let topics = vec![
                        ATOMIC_RESERVATION_TOPIC,
                        B256::from(*reservation_id),
                        B256::from(*desk_id),
                        encode_address_topic(*taker),
                    ];
                    let data = SolValue::abi_encode(&AtomicReservationData {
                        asset: *asset,
                        amount: *amount,
                        settlementDigest: FixedBytes::<32>::from(*settlement_digest),
                        expiry: *expiry,
                        createdAt: *created_at,
                    });
                    (topics, data)
                }
                Self::TrancheOpened {
                    tranche_id,
                    desk_id,
                    maker,
                    asset,
                    price_numerator,
                    price_denominator,
                    total_liquidity,
                    min_fill,
                    fee_bps,
                    fee_payer,
                    expiry,
                } => {
                    let topics = vec![
                        TRANCHE_OPENED_TOPIC,
                        B256::from(*tranche_id),
                        B256::from(*desk_id),
                        encode_address_topic(*maker),
                    ];
                    let data = SolValue::abi_encode(&TrancheOpenedData {
                        asset: *asset,
                        priceNumerator: *price_numerator,
                        priceDenominator: *price_denominator,
                        totalLiquidity: *total_liquidity,
                        minFill: *min_fill,
                        feeBps: *fee_bps,
                        feePayer: *fee_payer,
                        expiry: *expiry,
                    });
                    (topics, data)
                }
                Self::TakerTrancheOpened {
                    tranche_id,
                    desk_id,
                    taker,
                    asset,
                    price_numerator,
                    price_denominator,
                    total_liquidity,
                    min_fill,
                    fee_bps,
                    fee_payer,
                    expiry,
                    posting_fee,
                } => {
                    let topics = vec![
                        TAKER_TRANCHE_OPENED_TOPIC,
                        B256::from(*tranche_id),
                        B256::from(*desk_id),
                        encode_address_topic(*taker),
                    ];
                    let data = SolValue::abi_encode(&TakerTrancheOpenedData {
                        asset: *asset,
                        priceNumerator: *price_numerator,
                        priceDenominator: *price_denominator,
                        totalLiquidity: *total_liquidity,
                        minFill: *min_fill,
                        feeBps: *fee_bps,
                        feePayer: *fee_payer,
                        expiry: *expiry,
                        postingFee: *posting_fee,
                    });
                    (topics, data)
                }
                Self::TrancheReserved {
                    tranche_id,
                    reservation_id,
                    taker,
                    amount,
                    remaining_liquidity,
                } => {
                    let topics = vec![
                        TRANCHE_RESERVED_TOPIC,
                        B256::from(*tranche_id),
                        B256::from(*reservation_id),
                        encode_address_topic(*taker),
                    ];
                    let data = SolValue::abi_encode(&TrancheReservedData {
                        amount: *amount,
                        remainingLiquidity: *remaining_liquidity,
                    });
                    (topics, data)
                }
                Self::TakerTrancheReserved {
                    tranche_id,
                    reservation_id,
                    maker,
                    amount,
                    remaining_liquidity,
                } => {
                    let topics = vec![
                        TAKER_TRANCHE_RESERVED_TOPIC,
                        B256::from(*tranche_id),
                        B256::from(*reservation_id),
                        encode_address_topic(*maker),
                    ];
                    let data = SolValue::abi_encode(&TrancheReservedData {
                        amount: *amount,
                        remainingLiquidity: *remaining_liquidity,
                    });
                    (topics, data)
                }
                Self::ReservationSettled {
                    reservation_id,
                    tau,
                } => {
                    let topics = vec![RESERVATION_SETTLED_TOPIC, B256::from(*reservation_id)];
                    let data = SolValue::abi_encode(&ReservationSettledData {
                        tau: FixedBytes::<32>::from(*tau),
                    });
                    (topics, data)
                }
                Self::ReservationRefunded {
                    reservation_id,
                    evidence,
                } => {
                    let topics = vec![RESERVATION_REFUNDED_TOPIC, B256::from(*reservation_id)];
                    let data = SolValue::abi_encode(&ReservationRefundedData {
                        evidence: FixedBytes::<32>::from(*evidence),
                    });
                    (topics, data)
                }
            }
        }

        fn decode_into_unit(&self, topics: &[B256], data: &[u8]) -> Result<()> {
            match self {
                Self::ReservationCreated { .. } => {
                    decode_reservation_created(topics, data).map(|_| ())
                }
                Self::HashlockSet { .. } => decode_hashlock_set(topics, data).map(|_| ()),
                Self::AtomicReservationCreated { .. } => {
                    decode_atomic_reservation_created(topics, data).map(|_| ())
                }
                Self::TrancheOpened { .. } => decode_tranche_opened(topics, data).map(|_| ()),
                Self::TakerTrancheOpened { .. } => {
                    decode_taker_tranche_opened(topics, data).map(|_| ())
                }
                Self::TrancheReserved { .. } => decode_tranche_reserved(topics, data).map(|_| ()),
                Self::TakerTrancheReserved { .. } => {
                    decode_taker_tranche_reserved(topics, data).map(|_| ())
                }
                Self::ReservationSettled { .. } => {
                    decode_reservation_settled(topics, data).map(|_| ())
                }
                Self::ReservationRefunded { .. } => {
                    decode_reservation_refunded(topics, data).map(|_| ())
                }
            }
        }

        fn assert_decodes(&self) {
            let (topics, data) = self.encode();
            match self {
                Self::ReservationCreated {
                    reservation_id,
                    taker,
                    desk,
                    amount,
                    counter,
                } => {
                    let record =
                        decode_reservation_created(&topics, &data).expect("decode reservation");
                    assert_eq!(
                        record.reservation_id,
                        FixedBytes::<32>::from(*reservation_id)
                    );
                    assert_eq!(record.taker, *taker);
                    assert_eq!(record.desk, *desk);
                    assert_eq!(record.amount, *amount);
                    assert_eq!(record.counter, *counter);
                }
                Self::HashlockSet {
                    reservation_id,
                    hashlock,
                } => {
                    let record = decode_hashlock_set(&topics, &data).expect("decode hashlock");
                    assert_eq!(
                        record.reservation_id,
                        FixedBytes::<32>::from(*reservation_id)
                    );
                    assert_eq!(record.hashlock, *hashlock);
                }
                Self::AtomicReservationCreated {
                    reservation_id,
                    desk_id,
                    taker,
                    asset,
                    amount,
                    settlement_digest,
                    expiry,
                    created_at,
                } => {
                    let record = decode_atomic_reservation_created(&topics, &data)
                        .expect("decode atomic reservation");
                    assert_eq!(
                        record.reservation_id,
                        FixedBytes::<32>::from(*reservation_id)
                    );
                    assert_eq!(record.desk_id, FixedBytes::<32>::from(*desk_id));
                    assert_eq!(record.taker, *taker);
                    assert_eq!(record.asset, *asset);
                    assert_eq!(record.amount, *amount);
                    assert_eq!(record.settlement_digest, *settlement_digest);
                    assert_eq!(record.expiry, *expiry);
                    assert_eq!(record.created_at, *created_at);
                }
                Self::TrancheOpened {
                    tranche_id,
                    desk_id,
                    maker,
                    asset,
                    price_numerator,
                    price_denominator,
                    total_liquidity,
                    min_fill,
                    fee_bps,
                    fee_payer,
                    expiry,
                } => {
                    let record = decode_tranche_opened(&topics, &data).expect("decode tranche");
                    assert_eq!(record.tranche_id, FixedBytes::<32>::from(*tranche_id));
                    assert_eq!(record.desk_id, FixedBytes::<32>::from(*desk_id));
                    assert_eq!(record.maker, *maker);
                    assert_eq!(record.asset, *asset);
                    assert_eq!(record.price_numerator, *price_numerator);
                    assert_eq!(record.price_denominator, *price_denominator);
                    assert_eq!(record.total_liquidity, *total_liquidity);
                    assert_eq!(record.min_fill, *min_fill);
                    assert_eq!(record.fee_bps, *fee_bps);
                    assert_eq!(record.fee_payer, *fee_payer);
                    assert_eq!(record.expiry, *expiry);
                }
                Self::TakerTrancheOpened {
                    tranche_id,
                    desk_id,
                    taker,
                    asset,
                    price_numerator,
                    price_denominator,
                    total_liquidity,
                    min_fill,
                    fee_bps,
                    fee_payer,
                    expiry,
                    posting_fee,
                } => {
                    let record =
                        decode_taker_tranche_opened(&topics, &data).expect("decode tranche");
                    assert_eq!(record.tranche_id, FixedBytes::<32>::from(*tranche_id));
                    assert_eq!(record.desk_id, FixedBytes::<32>::from(*desk_id));
                    assert_eq!(record.taker, *taker);
                    assert_eq!(record.asset, *asset);
                    assert_eq!(record.price_numerator, *price_numerator);
                    assert_eq!(record.price_denominator, *price_denominator);
                    assert_eq!(record.total_liquidity, *total_liquidity);
                    assert_eq!(record.min_fill, *min_fill);
                    assert_eq!(record.fee_bps, *fee_bps);
                    assert_eq!(record.fee_payer, *fee_payer);
                    assert_eq!(record.expiry, *expiry);
                    assert_eq!(record.posting_fee, *posting_fee);
                }
                Self::TrancheReserved {
                    tranche_id,
                    reservation_id,
                    taker,
                    amount,
                    remaining_liquidity,
                } => {
                    let record =
                        decode_tranche_reserved(&topics, &data).expect("decode tranche reserve");
                    assert_eq!(record.tranche_id, FixedBytes::<32>::from(*tranche_id));
                    assert_eq!(
                        record.reservation_id,
                        FixedBytes::<32>::from(*reservation_id)
                    );
                    assert_eq!(record.taker, *taker);
                    assert_eq!(record.amount, *amount);
                    assert_eq!(record.remaining_liquidity, *remaining_liquidity);
                }
                Self::TakerTrancheReserved {
                    tranche_id,
                    reservation_id,
                    maker,
                    amount,
                    remaining_liquidity,
                } => {
                    let record = decode_taker_tranche_reserved(&topics, &data)
                        .expect("decode taker tranche reserve");
                    assert_eq!(record.tranche_id, FixedBytes::<32>::from(*tranche_id));
                    assert_eq!(
                        record.reservation_id,
                        FixedBytes::<32>::from(*reservation_id)
                    );
                    assert_eq!(record.maker, *maker);
                    assert_eq!(record.amount, *amount);
                    assert_eq!(record.remaining_liquidity, *remaining_liquidity);
                }
                Self::ReservationSettled {
                    reservation_id,
                    tau,
                } => {
                    let (decoded_id, decoded_tau) =
                        decode_reservation_settled(&topics, &data).expect("decode settled");
                    assert_eq!(decoded_id, FixedBytes::<32>::from(*reservation_id));
                    assert_eq!(decoded_tau, *tau);
                }
                Self::ReservationRefunded {
                    reservation_id,
                    evidence,
                } => {
                    let (decoded_id, decoded_evidence) =
                        decode_reservation_refunded(&topics, &data).expect("decode refunded");
                    assert_eq!(decoded_id, FixedBytes::<32>::from(*reservation_id));
                    assert_eq!(decoded_evidence, *evidence);
                }
            }
        }
    }

    #[derive(Clone, Default)]
    struct MockPollRpc {
        logs: Vec<EvmLog>,
        request_capture: Arc<Mutex<Option<(u64, u64, Vec<Address>)>>>,
    }

    impl MockPollRpc {
        fn with_logs(logs: Vec<EvmLog>) -> Self {
            Self {
                logs,
                request_capture: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl EvmWatcherRpc for MockPollRpc {
        fn get_logs(
            &self,
            from_block: u64,
            to_block: u64,
            contract_addresses: &[Address],
        ) -> Result<Vec<EvmLog>> {
            *self.request_capture.lock().expect("capture lock") =
                Some((from_block, to_block, contract_addresses.to_vec()));
            Ok(self.logs.clone())
        }
    }

    fn log_for(
        address: Address,
        event: GeneratedEvmEvent,
        block_number: u64,
        transaction_index: u64,
        log_index: u64,
    ) -> EvmLog {
        let (topics, data) = event.encode();
        EvmLog {
            address,
            topics,
            data,
            block_number,
            transaction_index,
            log_index,
        }
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(|bytes| Address::from_slice(&bytes))
    }

    fn arb_u256() -> impl Strategy<Value = U256> {
        any::<u128>().prop_map(U256::from)
    }

    fn arb_lifecycle_event() -> impl Strategy<Value = GeneratedEvmEvent> {
        prop_oneof![
            (
                any::<[u8; 32]>(),
                arb_address(),
                arb_address(),
                arb_u256(),
                arb_u256(),
            )
                .prop_map(|(reservation_id, taker, desk, amount, counter)| {
                    GeneratedEvmEvent::ReservationCreated {
                        reservation_id,
                        taker,
                        desk,
                        amount,
                        counter,
                    }
                }),
            (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, hashlock)| {
                GeneratedEvmEvent::HashlockSet {
                    reservation_id,
                    hashlock,
                }
            }),
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                arb_address(),
                arb_address(),
                arb_u256(),
                any::<[u8; 32]>(),
                any::<u64>(),
                any::<u64>(),
            )
                .prop_map(
                    |(
                        reservation_id,
                        desk_id,
                        taker,
                        asset,
                        amount,
                        settlement_digest,
                        expiry,
                        created_at,
                    )| GeneratedEvmEvent::AtomicReservationCreated {
                        reservation_id,
                        desk_id,
                        taker,
                        asset,
                        amount,
                        settlement_digest,
                        expiry,
                        created_at,
                    }
                ),
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                arb_address(),
                arb_address(),
                arb_u256(),
                arb_u256(),
                arb_u256(),
                arb_u256(),
                any::<u16>(),
                any::<u8>(),
                any::<u64>(),
            )
                .prop_map(
                    |(
                        tranche_id,
                        desk_id,
                        maker,
                        asset,
                        price_numerator,
                        price_denominator,
                        total_liquidity,
                        min_fill,
                        fee_bps,
                        fee_payer,
                        expiry,
                    )| GeneratedEvmEvent::TrancheOpened {
                        tranche_id,
                        desk_id,
                        maker,
                        asset,
                        price_numerator,
                        price_denominator,
                        total_liquidity,
                        min_fill,
                        fee_bps,
                        fee_payer,
                        expiry,
                    }
                ),
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                arb_address(),
                arb_address(),
                arb_u256(),
                arb_u256(),
                arb_u256(),
                arb_u256(),
                any::<u16>(),
                any::<u8>(),
                any::<u64>(),
                arb_u256(),
            )
                .prop_map(
                    |(
                        tranche_id,
                        desk_id,
                        taker,
                        asset,
                        price_numerator,
                        price_denominator,
                        total_liquidity,
                        min_fill,
                        fee_bps,
                        fee_payer,
                        expiry,
                        posting_fee,
                    )| GeneratedEvmEvent::TakerTrancheOpened {
                        tranche_id,
                        desk_id,
                        taker,
                        asset,
                        price_numerator,
                        price_denominator,
                        total_liquidity,
                        min_fill,
                        fee_bps,
                        fee_payer,
                        expiry,
                        posting_fee,
                    }
                ),
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                arb_address(),
                arb_u256(),
                arb_u256(),
            )
                .prop_map(
                    |(tranche_id, reservation_id, taker, amount, remaining_liquidity)| {
                        GeneratedEvmEvent::TrancheReserved {
                            tranche_id,
                            reservation_id,
                            taker,
                            amount,
                            remaining_liquidity,
                        }
                    }
                ),
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                arb_address(),
                arb_u256(),
                arb_u256(),
            )
                .prop_map(
                    |(tranche_id, reservation_id, maker, amount, remaining_liquidity)| {
                        GeneratedEvmEvent::TakerTrancheReserved {
                            tranche_id,
                            reservation_id,
                            maker,
                            amount,
                            remaining_liquidity,
                        }
                    }
                ),
            (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, tau)| {
                GeneratedEvmEvent::ReservationSettled {
                    reservation_id,
                    tau,
                }
            }),
            (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(reservation_id, evidence)| {
                GeneratedEvmEvent::ReservationRefunded {
                    reservation_id,
                    evidence,
                }
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 96,
            .. ProptestConfig::default()
        })]

        /// Property 19: EVM event decoding correctness.
        #[test]
        fn property19_evm_event_decoding_correctness(event in arb_lifecycle_event()) {
            event.assert_decodes();
        }

        /// Property 20: EVM event decoder rejects invalid inputs.
        #[test]
        fn property20_evm_event_decoder_rejects_invalid_inputs(
            event in arb_lifecycle_event(),
            unknown_topic in any::<[u8; 32]>(),
        ) {
            let (topics, data) = event.encode();

            let mut wrong_topic = topics.clone();
            wrong_topic[0] = B256::from(unknown_topic);
            prop_assume!(wrong_topic[0] != topics[0]);
            let err = event
                .decode_into_unit(&wrong_topic, &data)
                .expect_err("unknown topic must fail");
            prop_assert!(err.to_string().contains("not a"));

            let short_topics = &topics[..topics.len() - 1];
            let err = event
                .decode_into_unit(short_topics, &data)
                .expect_err("insufficient topics must fail");
            prop_assert!(err.to_string().contains("not a"));

            prop_assume!(!data.is_empty());
            let truncated = &data[..data.len() - 1];
            let err = event
                .decode_into_unit(&topics, truncated)
                .expect_err("truncated data must fail");
            prop_assert!(err.to_string().contains("decode"));
        }
    }

    #[test]
    fn decode_reservation_created_event() {
        let reservation_bytes = [0x07u8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let taker = address!("0x7777777777777777777777777777777777777777");
        let desk = address!("0x8888888888888888888888888888888888888888");
        let amount = U256::from(5_000u64);
        let counter = U256::from(321u64);
        let topics = vec![
            RESERVATION_CREATED_TOPIC,
            B256::from(reservation_bytes),
            encode_address_topic(taker),
            encode_address_topic(desk),
        ];
        let data = SolValue::abi_encode(&ReservationCreatedData { amount, counter });

        let record = decode_reservation_created(&topics, &data).expect("decode reservation");
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.desk, desk);
        assert_eq!(record.amount, amount);
        assert_eq!(record.counter, counter);
    }

    #[test]
    fn decode_hashlock_set_event() {
        let reservation_bytes = [0x09u8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let hashlock = [0xABu8; 32];
        let topics = vec![HASHLOCK_SET_TOPIC, B256::from(reservation_bytes)];
        let data = SolValue::abi_encode(&HashlockSetData {
            hashlock: FixedBytes::<32>::from(hashlock),
        });

        let record = decode_hashlock_set(&topics, &data).expect("decode hashlock");
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.hashlock, hashlock);
    }

    #[test]
    fn decode_atomic_reservation_created_event() {
        let reservation_bytes = [0x23u8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let desk_bytes = [0x11u8; 32];
        let desk_id = FixedBytes::<32>::from(desk_bytes);
        let taker = address!("0x9999999999999999999999999999999999999999");
        let asset = address!("0x1111111111111111111111111111111111111111");
        let amount = U256::from(456u64);
        let digest = [0x22u8; 32];
        let expiry = 1_650_000_000u64;
        let created_at = 1_650_000_500u64;
        let topics = vec![
            ATOMIC_RESERVATION_TOPIC,
            B256::from(reservation_bytes),
            B256::from(desk_bytes),
            encode_address_topic(taker),
        ];
        let data = SolValue::abi_encode(&AtomicReservationData {
            asset,
            amount,
            settlementDigest: FixedBytes::<32>::from(digest),
            expiry,
            createdAt: created_at,
        });

        let record =
            decode_atomic_reservation_created(&topics, &data).expect("decode atomic reservation");
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.desk_id, desk_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.asset, asset);
        assert_eq!(record.amount, amount);
        assert_eq!(record.settlement_digest, digest);
        assert_eq!(record.expiry, expiry);
        assert_eq!(record.created_at, created_at);
    }

    #[test]
    fn decode_tranche_opened_event() {
        let tranche_bytes = [0x44u8; 32];
        let tranche_id = FixedBytes::<32>::from(tranche_bytes);
        let desk_bytes = [0x55u8; 32];
        let desk_id = FixedBytes::<32>::from(desk_bytes);
        let maker = address!("0x1111111111111111111111111111111111111111");
        let asset = address!("0x2222222222222222222222222222222222222222");
        let topics = vec![
            TRANCHE_OPENED_TOPIC,
            B256::from(tranche_bytes),
            B256::from(desk_bytes),
            encode_address_topic(maker),
        ];
        let data = SolValue::abi_encode(&TrancheOpenedData {
            asset,
            priceNumerator: U256::from(5_000u64),
            priceDenominator: U256::from(10_000u64),
            totalLiquidity: U256::from(8_000u64),
            minFill: U256::from(1_000u64),
            feeBps: 125,
            feePayer: 1,
            expiry: 1_700_000_000u64,
        });

        let record = decode_tranche_opened(&topics, &data).expect("decode tranche opened");
        assert_eq!(record.tranche_id, tranche_id);
        assert_eq!(record.desk_id, desk_id);
        assert_eq!(record.maker, maker);
        assert_eq!(record.asset, asset);
        assert_eq!(record.price_numerator, U256::from(5_000u64));
        assert_eq!(record.price_denominator, U256::from(10_000u64));
        assert_eq!(record.total_liquidity, U256::from(8_000u64));
        assert_eq!(record.min_fill, U256::from(1_000u64));
        assert_eq!(record.fee_bps, 125);
        assert_eq!(record.fee_payer, 1);
        assert_eq!(record.expiry, 1_700_000_000u64);
    }

    #[test]
    fn decode_taker_tranche_opened_event() {
        let tranche_bytes = [0x66u8; 32];
        let tranche_id = FixedBytes::<32>::from(tranche_bytes);
        let desk_bytes = [0x77u8; 32];
        let desk_id = FixedBytes::<32>::from(desk_bytes);
        let taker = address!("0x3333333333333333333333333333333333333333");
        let asset = address!("0x4444444444444444444444444444444444444444");
        let topics = vec![
            TAKER_TRANCHE_OPENED_TOPIC,
            B256::from(tranche_bytes),
            B256::from(desk_bytes),
            encode_address_topic(taker),
        ];
        let data = SolValue::abi_encode(&TakerTrancheOpenedData {
            asset,
            priceNumerator: U256::from(2_000u64),
            priceDenominator: U256::from(3_000u64),
            totalLiquidity: U256::from(9_000u64),
            minFill: U256::from(500u64),
            feeBps: 250,
            feePayer: 0,
            expiry: 1_800_000_000u64,
            postingFee: U256::from(12_345u64),
        });

        let record =
            decode_taker_tranche_opened(&topics, &data).expect("decode taker tranche opened");
        assert_eq!(record.tranche_id, tranche_id);
        assert_eq!(record.desk_id, desk_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.asset, asset);
        assert_eq!(record.price_numerator, U256::from(2_000u64));
        assert_eq!(record.price_denominator, U256::from(3_000u64));
        assert_eq!(record.total_liquidity, U256::from(9_000u64));
        assert_eq!(record.min_fill, U256::from(500u64));
        assert_eq!(record.fee_bps, 250);
        assert_eq!(record.fee_payer, 0);
        assert_eq!(record.expiry, 1_800_000_000u64);
        assert_eq!(record.posting_fee, U256::from(12_345u64));
    }

    #[test]
    fn decode_tranche_reserved_event() {
        let tranche_bytes = [0x88u8; 32];
        let reservation_bytes = [0x99u8; 32];
        let tranche_id = FixedBytes::<32>::from(tranche_bytes);
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let taker = address!("0x5555555555555555555555555555555555555555");
        let topics = vec![
            TRANCHE_RESERVED_TOPIC,
            B256::from(tranche_bytes),
            B256::from(reservation_bytes),
            encode_address_topic(taker),
        ];
        let data = SolValue::abi_encode(&TrancheReservedData {
            amount: U256::from(777u64),
            remainingLiquidity: U256::from(888u64),
        });

        let record = decode_tranche_reserved(&topics, &data).expect("decode tranche reserved");
        assert_eq!(record.tranche_id, tranche_id);
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.amount, U256::from(777u64));
        assert_eq!(record.remaining_liquidity, U256::from(888u64));
    }

    #[test]
    fn decode_reservation_settled_and_refunded_events() {
        let reservation_bytes = [0xAAu8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let tau = [0x55u8; 32];
        let settled_topics = vec![RESERVATION_SETTLED_TOPIC, B256::from(reservation_bytes)];
        let settled_data = SolValue::abi_encode(&ReservationSettledData {
            tau: FixedBytes::<32>::from(tau),
        });
        let (decoded_id, decoded_tau) =
            decode_reservation_settled(&settled_topics, &settled_data).expect("decode settled");
        assert_eq!(decoded_id, reservation_id);
        assert_eq!(decoded_tau, tau);
        assert!(decode_reservation_settled(&settled_topics[..1], &settled_data).is_err());

        let refunded_topics = vec![RESERVATION_REFUNDED_TOPIC, B256::from(reservation_bytes)];
        let evidence = [0x99u8; 32];
        let refunded_data = SolValue::abi_encode(&ReservationRefundedData {
            evidence: FixedBytes::<32>::from(evidence),
        });
        let (decoded_id, decoded_evidence) =
            decode_reservation_refunded(&refunded_topics, &refunded_data).expect("decode refunded");
        assert_eq!(decoded_id, reservation_id);
        assert_eq!(decoded_evidence, evidence);
        assert!(decode_reservation_refunded(&refunded_topics[..1], &refunded_data).is_err());
    }

    #[test]
    fn poll_interface_decodes_and_sorts_chronologically() {
        let tracked = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let untracked = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let logs = vec![
            log_for(
                tracked,
                GeneratedEvmEvent::ReservationRefunded {
                    reservation_id: [0x44; 32],
                    evidence: [0x55; 32],
                },
                12,
                0,
                1,
            ),
            log_for(
                untracked,
                GeneratedEvmEvent::HashlockSet {
                    reservation_id: [0x01; 32],
                    hashlock: [0x02; 32],
                },
                9,
                0,
                0,
            ),
            log_for(
                tracked,
                GeneratedEvmEvent::HashlockSet {
                    reservation_id: [0x10; 32],
                    hashlock: [0x11; 32],
                },
                10,
                0,
                2,
            ),
            log_for(
                tracked,
                GeneratedEvmEvent::ReservationCreated {
                    reservation_id: [0x20; 32],
                    taker: address!("0x7777777777777777777777777777777777777777"),
                    desk: address!("0x8888888888888888888888888888888888888888"),
                    amount: U256::from(100u64),
                    counter: U256::from(5u64),
                },
                10,
                0,
                1,
            ),
        ];
        let rpc = MockPollRpc::with_logs(logs);
        let request = EvmPollRequest {
            from_block: 9,
            to_block: 12,
            contract_addresses: vec![tracked],
        };

        let decoded = poll_lifecycle_events(&rpc, &request).expect("poll lifecycle events");
        assert_eq!(decoded.len(), 3);
        assert_eq!(
            decoded
                .iter()
                .map(|event| (event.block_number, event.transaction_index, event.log_index))
                .collect::<Vec<_>>(),
            vec![(10, 0, 1), (10, 0, 2), (12, 0, 1)]
        );
        assert!(matches!(
            decoded[0].event,
            DecodedLifecycleEvent::ReservationCreated(_)
        ));
        assert!(matches!(
            decoded[1].event,
            DecodedLifecycleEvent::HashlockSet(_)
        ));
        assert!(matches!(
            decoded[2].event,
            DecodedLifecycleEvent::ReservationRefunded { .. }
        ));

        let captured = rpc.request_capture.lock().expect("capture lock");
        let (from, to, addresses) = captured.clone().expect("captured request");
        assert_eq!(from, 9);
        assert_eq!(to, 12);
        assert_eq!(addresses, vec![tracked]);
    }

    #[test]
    fn poll_interface_rejects_unknown_topics_for_tracked_contracts() {
        let tracked = address!("0x9999999999999999999999999999999999999999");
        let rpc = MockPollRpc::with_logs(vec![EvmLog {
            address: tracked,
            topics: vec![B256::from([0xFE; 32])],
            data: vec![],
            block_number: 1,
            transaction_index: 0,
            log_index: 0,
        }]);
        let request = EvmPollRequest {
            from_block: 1,
            to_block: 2,
            contract_addresses: vec![tracked],
        };

        let err = poll_lifecycle_events(&rpc, &request).expect_err("unknown topic must fail");
        assert!(err.to_string().contains("unknown event topic"));
    }

    #[test]
    fn poll_interface_validates_request_shape() {
        let tracked = address!("0x1212121212121212121212121212121212121212");
        let rpc = MockPollRpc::default();

        let bad_range = EvmPollRequest {
            from_block: 10,
            to_block: 9,
            contract_addresses: vec![tracked],
        };
        assert!(poll_lifecycle_events(&rpc, &bad_range).is_err());

        let empty_contracts = EvmPollRequest {
            from_block: 0,
            to_block: 1,
            contract_addresses: vec![],
        };
        assert!(poll_lifecycle_events(&rpc, &empty_contracts).is_err());
    }
}

/// Decode a `ReservationSettled` event emitted by SettlementEscrow.
pub fn decode_reservation_settled(
    topics: &[B256],
    data: &[u8],
) -> Result<(FixedBytes<32>, [u8; 32])> {
    ensure!(
        topics.len() >= 2 && topics[0] == RESERVATION_SETTLED_TOPIC,
        "not a ReservationSettled log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let parsed = ReservationSettledData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode ReservationSettled: {err}"))?;
    Ok((reservation_id, parsed.tau.into()))
}

/// Decode a `ReservationRefunded` event emitted by SettlementEscrow.
pub fn decode_reservation_refunded(
    topics: &[B256],
    data: &[u8],
) -> Result<(FixedBytes<32>, [u8; 32])> {
    ensure!(
        topics.len() >= 2 && topics[0] == RESERVATION_REFUNDED_TOPIC,
        "not a ReservationRefunded log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let parsed = ReservationRefundedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode ReservationRefunded: {err}"))?;
    Ok((reservation_id, parsed.evidence.into()))
}
