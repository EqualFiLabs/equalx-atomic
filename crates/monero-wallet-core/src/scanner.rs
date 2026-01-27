use crate::{
    config::{SubAddr, WalletConfig},
    model::OwnedOutput,
    storage::{ScanCursor, WalletStore},
};
use anyhow::{anyhow, Context, Result};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    Scalar,
};
use monero_oxide::{
    block::Block,
    generators::biased_hash_to_point,
    io::{read_byte, read_point, read_vec, CompressedPoint, VarInt},
    primitives::{keccak256, keccak256_to_scalar, Commitment},
    ringct::EncryptedAmount,
    transaction::{Input, Transaction},
};
use monero_rpc::{GetBlockParams, GetTransactionsRequest, MoneroRpc};
use std::{collections::HashMap, ops::Deref};
use zeroize::{Zeroize, Zeroizing};

pub struct ScanParams {
    pub start_height: Option<u64>,
    pub end_height_inclusive: Option<u64>,
}

pub struct Scanner<S: WalletStore> {
    pub cfg: WalletConfig,
    pub store: S,
    pub rpc: MoneroRpc,
}

impl<S: WalletStore> Scanner<S> {
    pub fn new(cfg: WalletConfig, store: S, rpc: MoneroRpc) -> Self {
        Self { cfg, store, rpc }
    }

    pub fn scan(&self, params: &ScanParams) -> Result<()> {
        let mut cursor = self
            .store
            .get_cursor()
            .unwrap_or(ScanCursor { next_height: 0 });
        let start = params.start_height.unwrap_or(cursor.next_height);
        let daemon_height = self.rpc.get_height()?;
        let top_height = daemon_height.saturating_sub(1);
        if start > top_height {
            return Ok(()); // nothing new to scan yet
        }
        let end = params
            .end_height_inclusive
            .unwrap_or(top_height)
            .min(top_height)
            .max(start);

        for height in start..=end {
            let blk = self.rpc.get_block(&GetBlockParams {
                height: Some(height),
                ..Default::default()
            })?;
            let block_bytes = hex::decode(&blk.blob).context("decode block blob")?;
            let block =
                Block::read(&mut &block_bytes[..]).map_err(|_| anyhow!("block parse failed"))?;

            self.process_transaction(block.miner_transaction(), height, None)?;

            if !blk.tx_hashes.is_empty() {
                let txs = self.rpc.get_transactions(&GetTransactionsRequest {
                    txs_hashes: blk.tx_hashes.clone(),
                    ..Default::default()
                })?;

                if !txs.missed_tx.is_empty() {
                    return Err(anyhow!("missing tx blobs for hashes: {:?}", txs.missed_tx));
                }

                if txs.txs_as_hex.len() != txs.txs.len() {
                    return Err(anyhow!("missing tx metadata for blobs"));
                }

                for (tx_hex, meta) in txs.txs_as_hex.iter().zip(txs.txs.iter()) {
                    let tx_bytes = hex::decode(tx_hex).context("decode tx blob")?;
                    let tx = Transaction::read(&mut &tx_bytes[..])
                        .map_err(|_| anyhow!("tx parse failed"))?;
                    self.process_transaction(&tx, height, Some(&meta.output_indices))?;
                }
            }

            cursor.next_height = height + 1;
            self.store.put_cursor(cursor)?;
        }
        Ok(())
    }

    fn process_transaction(
        &self,
        tx: &Transaction,
        height: u64,
        output_indices: Option<&[u64]>,
    ) -> Result<()> {
        let txid = tx.hash();
        let prefix = tx.prefix();
        let tx_unlock_value = timelock_to_u64(&prefix.additional_timelock);

        let mut indices: Option<Vec<u64>> = output_indices.map(|idxs| idxs.to_vec());
        if indices.is_none() {
            let tx_hash_hex = hex::encode(txid);
            match self.rpc.get_tx_global_output_indices(&tx_hash_hex) {
                Ok(fetched) => {
                    indices = Some(fetched);
                }
                Err(err) => {
                    return Err(anyhow!(
                        "failed to fetch global indices for tx {tx_hash_hex}: {err}"
                    ));
                }
            }
        }

        for (vout_idx, _) in prefix.outputs.iter().enumerate() {
            let global_index = indices
                .as_ref()
                .and_then(|idxs| idxs.get(vout_idx).copied());
            let owned = try_match_owned(
                &self.cfg,
                tx,
                vout_idx as u32,
                global_index,
                tx_unlock_value,
            )?;

            if let Some(mut rec) = owned {
                rec.txid = txid;
                rec.block_height = height;
                self.store.put_owned_output(&rec)?;
            }
        }
        Ok(())
    }

    pub fn list_owned(&self) -> Result<Vec<OwnedOutput>> {
        self.store.list_owned_outputs()
    }
}

fn try_match_owned(
    cfg: &WalletConfig,
    tx: &Transaction,
    out_index_in_tx: u32,
    global_index: Option<u64>,
    tx_unlock_time: u64,
) -> Result<Option<OwnedOutput>> {
    let output_idx = out_index_in_tx as usize;
    let prefix = tx.prefix();
    let output = match prefix.outputs.get(output_idx) {
        Some(out) => out,
        None => return Ok(None),
    };

    let spend_pub = CompressedEdwardsY(cfg.spend_pub)
        .decompress()
        .ok_or_else(|| anyhow!("invalid spend_pub key in wallet config"))?;
    let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(cfg.view_key));

    let subaddr_map = build_subaddress_map(&cfg.subaddrs, &spend_pub, view_scalar.deref());

    let extra_keys = match parse_extra_keys(prefix.extra.as_slice())? {
        Some(keys) => keys,
        None => return Ok(None),
    };

    let output_point = match output.key.decompress() {
        Some(point) => point,
        None => return Ok(None),
    };

    let mut candidates: Vec<EdwardsPoint> = extra_keys.primary;
    if let Some(additional) = extra_keys.additional {
        if let Some(extra_key) = additional.get(output_idx) {
            candidates.push(*extra_key);
        }
    }

    for key in candidates {
        let ecdh_point = view_scalar.deref() * key;
        let derivations =
            SharedKeyDerivations::output_derivations(None, Zeroizing::new(ecdh_point), output_idx);

        if let Some(view_tag) = output.view_tag {
            if view_tag != derivations.view_tag {
                continue;
            }
        }

        let shared_scalar = derivations.shared_key;
        let spend_candidate = output_point - (&shared_scalar * ED25519_BASEPOINT_TABLE);
        let entry = match subaddr_map.get(&spend_candidate.compress().to_bytes()) {
            Some(entry) => entry,
            None => continue,
        };

        let mut key_offset = shared_scalar;
        let (subaddr_account, subaddr_index) = match entry {
            SubaddressEntry::Primary => (0, 0),
            SubaddressEntry::Subaddress {
                account,
                index,
                derivation,
            } => {
                key_offset += derivation;
                (*account, *index)
            }
        };

        let commitment = if let Some(amount) = output.amount {
            let mut commitment = Commitment::zero();
            commitment.amount = amount;
            commitment
        } else {
            let Transaction::V2 {
                proofs: Some(proofs),
                ..
            } = tx
            else {
                return Err(anyhow!("transaction missing RingCT proofs"));
            };
            let Some(enc_amount) = proofs.base.encrypted_amounts.get(output_idx) else {
                continue;
            };

            let commitment = derivations.decrypt(enc_amount);
            let calculated = CompressedPoint::from(commitment.calculate().compress());
            if proofs.base.commitments.get(output_idx) != Some(&calculated) {
                continue;
            }
            commitment
        };

        let key_image = cfg.spend_key.map(|sk| {
            let spend_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(sk));
            let priv_key = spend_scalar.deref() + key_offset;
            let ki_point = priv_key * biased_hash_to_point(output.key.to_bytes());
            ki_point.compress().to_bytes()
        });

        return Ok(Some(OwnedOutput {
            txid: [0u8; 32],
            out_index_in_tx,
            amount: commitment.amount,
            global_index: global_index.unwrap_or_default(),
            mask: commitment.mask.to_bytes(),
            one_time_pubkey: output.key.to_bytes(),
            subaddr_account,
            subaddr_index,
            unlock_time: tx_unlock_time,
            block_height: 0,
            key_image,
        }));
    }

    Ok(None)
}

fn timelock_to_u64(lock: &monero_oxide::transaction::Timelock) -> u64 {
    match lock {
        monero_oxide::transaction::Timelock::None => 0,
        monero_oxide::transaction::Timelock::Block(h) => (*h) as u64,
        monero_oxide::transaction::Timelock::Time(ts) => *ts,
    }
}

#[derive(Debug)]
enum SubaddressEntry {
    Primary,
    Subaddress {
        account: u32,
        index: u32,
        derivation: Scalar,
    },
}

fn build_subaddress_map(
    configured: &[SubAddr],
    spend_pub: &EdwardsPoint,
    view_scalar: &Scalar,
) -> HashMap<[u8; 32], SubaddressEntry> {
    let mut map = HashMap::new();
    map.insert(spend_pub.compress().to_bytes(), SubaddressEntry::Primary);

    for sub in configured {
        let derivation = subaddress_derivation(view_scalar, sub.account, sub.index);
        let spend_point = spend_pub + (&derivation * ED25519_BASEPOINT_TABLE);
        let entry = if sub.account == 0 && sub.index == 0 {
            SubaddressEntry::Primary
        } else {
            SubaddressEntry::Subaddress {
                account: sub.account,
                index: sub.index,
                derivation,
            }
        };
        map.insert(spend_point.compress().to_bytes(), entry);
    }

    map
}

fn subaddress_derivation(view_scalar: &Scalar, account: u32, index: u32) -> Scalar {
    let mut data = Zeroizing::new(Vec::new());
    data.extend_from_slice(b"SubAddr\0");
    data.extend_from_slice(&view_scalar.to_bytes());
    data.extend_from_slice(&account.to_le_bytes());
    data.extend_from_slice(&index.to_le_bytes());
    keccak256_to_scalar(data.as_slice())
}

#[derive(Debug)]
struct ExtraKeys {
    primary: Vec<EdwardsPoint>,
    additional: Option<Vec<EdwardsPoint>>,
}

fn parse_extra_keys(extra: &[u8]) -> Result<Option<ExtraKeys>> {
    let mut reader = extra;
    let mut keys = Vec::new();
    let mut additional: Option<Vec<EdwardsPoint>> = None;

    while !reader.is_empty() {
        let tag = match read_byte(&mut reader) {
            Ok(tag) => tag,
            Err(_) => break,
        };
        match tag {
            0 => {
                let mut count = 1usize;
                while let Some((&next, rest)) = reader.split_first() {
                    if next != 0 {
                        break;
                    }
                    if count > 255 {
                        return Err(anyhow!("extra padding exceeded limit"));
                    }
                    reader = rest;
                    count += 1;
                }
            }
            1 => {
                let point = read_point(&mut reader)
                    .map_err(|e| anyhow!("failed to read tx public key: {:?}", e))?;
                keys.push(point);
            }
            2 => {
                let len: usize = VarInt::read(&mut reader)
                    .map_err(|e| anyhow!("failed to read extra nonce length: {:?}", e))?;
                if reader.len() < len {
                    return Err(anyhow!("extra nonce truncated"));
                }
                reader = &reader[len..];
            }
            3 => {
                let _height: u64 = VarInt::read(&mut reader)
                    .map_err(|e| anyhow!("failed to read extra nonce height: {:?}", e))?;
                if reader.len() < 32 {
                    return Err(anyhow!("extra nonce digest truncated"));
                }
                reader = &reader[32..];
            }
            4 => {
                let vec = read_vec(read_point, None, &mut reader)
                    .map_err(|e| anyhow!("failed to read additional tx keys: {:?}", e))?;
                if additional.is_none() {
                    additional = Some(vec);
                }
            }
            0xDE => {
                let data = read_vec(read_byte, None, &mut reader)
                    .map_err(|e| anyhow!("failed to read tx data: {:?}", e))?;
                if data.is_empty() {
                    continue;
                }
            }
            _ => break,
        }
    }

    if keys.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ExtraKeys {
            primary: keys,
            additional,
        }))
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct SharedKeyDerivations {
    view_tag: u8,
    shared_key: Scalar,
}

impl SharedKeyDerivations {
    #[allow(dead_code)]
    fn uniqueness(inputs: &[Input]) -> [u8; 32] {
        let mut u = b"uniqueness".to_vec();
        for input in inputs {
            match input {
                Input::Gen(height) => {
                    VarInt::write(height, &mut u)
                        .expect("writing to Vec should not fail for VarInt");
                }
                Input::ToKey { key_image, .. } => u.extend(key_image.to_bytes()),
            }
        }
        keccak256(u)
    }

    pub fn output_derivations(
        uniqueness: Option<[u8; 32]>,
        ecdh: Zeroizing<EdwardsPoint>,
        o: usize,
    ) -> Zeroizing<SharedKeyDerivations> {
        let mut output_derivation = Zeroizing::new(
            Zeroizing::new(Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes()).to_vec(),
        );

        {
            let output_derivation_vec: &mut Vec<u8> = output_derivation.as_mut();
            VarInt::write(&o, output_derivation_vec)
                .expect("writing to Vec should not fail for VarInt");
        }

        let view_tag = keccak256([b"view_tag".as_slice(), &output_derivation].concat())[0];

        let output_derivation = if let Some(uniqueness) = uniqueness {
            Zeroizing::new([uniqueness.as_slice(), &output_derivation].concat())
        } else {
            output_derivation
        };

        Zeroizing::new(SharedKeyDerivations {
            view_tag,
            shared_key: keccak256_to_scalar(&output_derivation),
        })
    }

    pub fn view_tag(&self) -> u8 {
        self.view_tag
    }

    pub fn shared_key(&self) -> &Scalar {
        &self.shared_key
    }

    pub fn commitment_mask(&self) -> Scalar {
        let mut mask = b"commitment_mask".to_vec();
        mask.extend(self.shared_key.as_bytes());
        let res = keccak256_to_scalar(&mask);
        mask.zeroize();
        res
    }

    pub fn compact_amount_encryption(&self, amount: u64) -> [u8; 8] {
        let mut amount_mask = Zeroizing::new(b"amount".to_vec());
        amount_mask.extend(self.shared_key.to_bytes());
        let mut amount_mask = keccak256(&amount_mask);

        let mut amount_mask_8 = [0; 8];
        amount_mask_8.copy_from_slice(&amount_mask[..8]);
        amount_mask.zeroize();

        (amount ^ u64::from_le_bytes(amount_mask_8)).to_le_bytes()
    }

    fn decrypt(&self, enc_amount: &EncryptedAmount) -> Commitment {
        match enc_amount {
            EncryptedAmount::Original { mask, amount } => {
                let mask_shared_scalar = keccak256_to_scalar(self.shared_key.as_bytes());
                let amount_shared_scalar = keccak256_to_scalar(mask_shared_scalar.as_bytes());

                let mask = Scalar::from_bytes_mod_order(*mask) - mask_shared_scalar;
                let amount_scalar = Scalar::from_bytes_mod_order(*amount) - amount_shared_scalar;

                let amount = u64::from_le_bytes(
                    amount_scalar.to_bytes()[..8]
                        .try_into()
                        .expect("amount scalar should be at least 8 bytes"),
                );

                Commitment::new(mask, amount)
            }
            EncryptedAmount::Compact { amount } => Commitment::new(
                self.commitment_mask(),
                u64::from_le_bytes(self.compact_amount_encryption(u64::from_le_bytes(*amount))),
            ),
        }
    }
}
