//! CLSAG pre-signature envelope encryption helpers.
//!
//! Implements the `secpp256k1` ECDH + HKDF-SHA256 + ChaCha20-Poly1305 AEAD
//! binding described in `CLSAG-ADAPTOR-SPEC.md`. The API exposes the
//! encrypted envelope alongside the derived key, nonce, and AAD for auditing.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use thiserror::Error;
use zeroize::Zeroize;

const SALT: &[u8] = b"EqualX v1 presig";
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Structured envelope returned to on-chain mailbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    #[serde(with = "serde_pubkey")]
    pub maker_eph_public: [u8; 33],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

impl Envelope {
    /// Serialize the envelope into the wire format: `version || pub || ct || tag`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + self.maker_eph_public.len() + self.ciphertext.len() + TAG_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.maker_eph_public);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parse an envelope from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < 1 + 33 + TAG_LEN {
            return Err(EnvelopeError::InvalidEnvelope);
        }
        let version = bytes[0];
        let mut maker_eph_public = [0u8; 33];
        maker_eph_public.copy_from_slice(&bytes[1..1 + 33]);
        let ct_len = bytes.len() - 1 - 33 - TAG_LEN;
        if ct_len == 0 {
            return Err(EnvelopeError::InvalidEnvelope);
        }
        let ciphertext = bytes[1 + 33..1 + 33 + ct_len].to_vec();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[bytes.len() - TAG_LEN..]);
        Ok(Self {
            version,
            maker_eph_public,
            ciphertext,
            tag,
        })
    }
}

/// Derived key/nonce/AAD used for the ChaCha20-Poly1305 envelope.
#[derive(Clone, Debug, Zeroize)]
pub struct EnvelopeParts {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: Vec<u8>,
}

impl EnvelopeParts {
    pub fn key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad
    }
}

impl Drop for EnvelopeParts {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Static metadata required to derive the AEAD transcript bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeContext {
    pub chain_id: u64,
    pub escrow_address: [u8; 20],
    pub swap_id: [u8; 32],
    pub settle_digest: [u8; 32],
    pub m_digest: [u8; 32],
    pub maker_address: [u8; 20],
    pub taker_address: [u8; 20],
    pub version: u8,
}

/// Parameters used to encrypt a pre-signature.
#[derive(Clone, Debug)]
pub struct EncryptRequest<'a> {
    pub taker_pubkey: &'a [u8; 33],
    pub maker_eph_secret: Option<[u8; 32]>,
    pub presig: &'a [u8],
    pub context: EnvelopeContext,
}

/// Result of `encrypt_presig` containing the envelope and derived parts.
#[derive(Clone, Debug)]
pub struct EncryptionOutput {
    pub envelope: Envelope,
    pub parts: EnvelopeParts,
}

/// Parameters used to decrypt a pre-signature.
#[derive(Clone, Debug)]
pub struct DecryptRequest<'a> {
    pub taker_secret: &'a [u8; 32],
    pub envelope: &'a Envelope,
    pub context: EnvelopeContext,
}

/// Result of `decrypt_presig` containing the plaintext and derived parts.
#[derive(Clone, Debug)]
pub struct DecryptionOutput {
    pub plaintext: Vec<u8>,
    pub parts: EnvelopeParts,
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("invalid secp256k1 public key")]
    InvalidPublicKey,
    #[error("invalid secp256k1 secret key")]
    InvalidSecretKey,
    #[error("ecdh failed")]
    Ecdh,
    #[error("hkdf expand error")]
    HkdfExpand,
    #[error("invalid envelope encoding")]
    InvalidEnvelope,
    #[error("aead failure")]
    Aead,
}

/// Encrypt a pre-signature payload according to the CLSAG adaptor spec.
pub fn encrypt_presig(req: &EncryptRequest<'_>) -> Result<EncryptionOutput, EnvelopeError> {
    let taker_pub = PublicKey::from_sec1_bytes(req.taker_pubkey)
        .map_err(|_| EnvelopeError::InvalidPublicKey)?;

    let mut rng = OsRng;
    let maker_secret = match req.maker_eph_secret {
        Some(bytes) => {
            SecretKey::from_slice(&bytes).map_err(|_| EnvelopeError::InvalidSecretKey)?
        }
        None => SecretKey::random(&mut rng),
    };
    let maker_scalar = maker_secret.to_nonzero_scalar();
    let maker_pub = PublicKey::from_secret_scalar(&maker_scalar);

    let shared = diffie_hellman(&maker_scalar, taker_pub.as_affine());
    let shared_bytes = shared.raw_secret_bytes().to_vec();
    let parts = derive_parts(&shared_bytes, &req.context)?;

    let mut key = Key::default();
    key.clone_from_slice(parts.key());
    let mut nonce = Nonce::default();
    nonce.clone_from_slice(parts.nonce());

    let cipher = ChaCha20Poly1305::new(&key);
    let payload = Payload {
        msg: req.presig,
        aad: parts.aad(),
    };
    let mut ct = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| EnvelopeError::Aead)?;
    let tag_start = ct.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ct[tag_start..]);
    ct.truncate(tag_start);

    let mut maker_eph_public = [0u8; 33];
    maker_eph_public.copy_from_slice(maker_pub.to_encoded_point(true).as_bytes());

    Ok(EncryptionOutput {
        envelope: Envelope {
            version: req.context.version,
            maker_eph_public,
            ciphertext: ct,
            tag,
        },
        parts,
    })
}

/// Decrypt an envelope, returning the plaintext and derived parts.
pub fn decrypt_presig(req: &DecryptRequest<'_>) -> Result<DecryptionOutput, EnvelopeError> {
    let maker_pub = PublicKey::from_sec1_bytes(&req.envelope.maker_eph_public)
        .map_err(|_| EnvelopeError::InvalidPublicKey)?;
    let taker_secret =
        SecretKey::from_slice(req.taker_secret).map_err(|_| EnvelopeError::InvalidSecretKey)?;
    let taker_scalar = taker_secret.to_nonzero_scalar();

    let shared = diffie_hellman(&taker_scalar, maker_pub.as_affine());
    let shared_bytes = shared.raw_secret_bytes().to_vec();
    let parts = derive_parts(&shared_bytes, &req.context)?;

    let mut key = Key::default();
    key.clone_from_slice(parts.key());
    let mut nonce = Nonce::default();
    nonce.clone_from_slice(parts.nonce());

    let cipher = ChaCha20Poly1305::new(&key);

    let mut combined = Vec::with_capacity(req.envelope.ciphertext.len() + TAG_LEN);
    combined.extend_from_slice(&req.envelope.ciphertext);
    combined.extend_from_slice(&req.envelope.tag);

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &combined,
                aad: parts.aad(),
            },
        )
        .map_err(|_| EnvelopeError::Aead)?;

    Ok(DecryptionOutput { plaintext, parts })
}

fn derive_parts(shared: &[u8], ctx: &EnvelopeContext) -> Result<EnvelopeParts, EnvelopeError> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), shared);
    let mut okm = [0u8; KEY_LEN + NONCE_LEN];
    let mut info = Vec::with_capacity(ctx.swap_id.len() + ctx.settle_digest.len());
    info.extend_from_slice(&ctx.swap_id);
    info.extend_from_slice(&ctx.settle_digest);
    hk.expand(&info, &mut okm)
        .map_err(|_| EnvelopeError::HkdfExpand)?;

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&okm[..KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&okm[KEY_LEN..]);
    okm.zeroize();

    let aad = compute_aad(ctx);

    Ok(EnvelopeParts { key, nonce, aad })
}

fn compute_aad(ctx: &EnvelopeContext) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(ctx.chain_id.to_be_bytes());
    hasher.update(ctx.escrow_address);
    hasher.update(ctx.swap_id);
    hasher.update(ctx.settle_digest);
    hasher.update(ctx.m_digest);
    hasher.update(ctx.maker_address);
    hasher.update(ctx.taker_address);
    hasher.update([ctx.version]);
    hasher.finalize().to_vec()
}

mod serde_pubkey {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 33 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"33-byte secp256k1 point",
            ));
        }
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip() {
        let taker_secret = [0x11u8; 32];
        let taker_sk = SecretKey::from_slice(&taker_secret).expect("taker secret");
        let taker_pub = PublicKey::from_secret_scalar(&taker_sk.to_nonzero_scalar());
        let mut taker_pub_bytes = [0u8; 33];
        taker_pub_bytes.copy_from_slice(taker_pub.to_encoded_point(true).as_bytes());

        let mut swap_id = [0u8; 32];
        swap_id[..4].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        let mut settle_digest = [0u8; 32];
        settle_digest[..4].copy_from_slice(&0xabcdef01u32.to_be_bytes());
        let mut m_digest = [0u8; 32];
        m_digest[..4].copy_from_slice(&0x01020304u32.to_be_bytes());

        let ctx = EnvelopeContext {
            chain_id: 11155111,
            escrow_address: [0u8; 20],
            swap_id,
            settle_digest,
            m_digest,
            maker_address: [1u8; 20],
            taker_address: [2u8; 20],
            version: 1,
        };

        let presig = b"example-presig";
        let maker_eph = [0x42u8; 32];

        let enc = encrypt_presig(&EncryptRequest {
            taker_pubkey: &taker_pub_bytes,
            maker_eph_secret: Some(maker_eph),
            presig,
            context: ctx,
        })
        .expect("encrypt");

        let envelope_bytes = enc.envelope.to_bytes();
        let enc_again = encrypt_presig(&EncryptRequest {
            taker_pubkey: &taker_pub_bytes,
            maker_eph_secret: Some(maker_eph),
            presig,
            context: ctx,
        })
        .expect("encrypt again");
        assert_eq!(
            envelope_bytes,
            enc_again.envelope.to_bytes(),
            "envelope encoding must be deterministic for fixed inputs"
        );

        let dec = decrypt_presig(&DecryptRequest {
            taker_secret: &taker_secret,
            envelope: &enc.envelope,
            context: ctx,
        })
        .expect("decrypt");
        assert_eq!(dec.plaintext, presig);
    }

    #[test]
    fn tamper_tag_should_fail() {
        let taker_secret = [0x33u8; 32];
        let taker_sk = SecretKey::from_slice(&taker_secret).unwrap();
        let taker_pub = PublicKey::from_secret_scalar(&taker_sk.to_nonzero_scalar());
        let mut taker_pub_bytes = [0u8; 33];
        taker_pub_bytes.copy_from_slice(taker_pub.to_encoded_point(true).as_bytes());

        let ctx = EnvelopeContext {
            chain_id: 1,
            escrow_address: [3u8; 20],
            swap_id: [4u8; 32],
            settle_digest: [5u8; 32],
            m_digest: [6u8; 32],
            maker_address: [7u8; 20],
            taker_address: [8u8; 20],
            version: 1,
        };

        let enc = encrypt_presig(&EncryptRequest {
            taker_pubkey: &taker_pub_bytes,
            maker_eph_secret: Some([0x77; 32]),
            presig: b"payload",
            context: ctx,
        })
        .unwrap();

        let mut corrupted = enc.envelope.clone();
        corrupted.tag[0] ^= 0xAA;

        let result = decrypt_presig(&DecryptRequest {
            taker_secret: &taker_secret,
            envelope: &corrupted,
            context: ctx,
        });
        assert!(matches!(result, Err(EnvelopeError::Aead)));
    }

    #[test]
    fn aad_matches_mailbox_spec_layout() {
        let ctx = EnvelopeContext {
            chain_id: 42,
            escrow_address: [0xAA; 20],
            swap_id: [0xBB; 32],
            settle_digest: [0xCC; 32],
            m_digest: [0xDD; 32],
            maker_address: [0xEE; 20],
            taker_address: [0xFF; 20],
            version: 3,
        };

        let aad = super::compute_aad(&ctx);

        let mut hasher = Keccak256::new();
        hasher.update(ctx.chain_id.to_be_bytes());
        hasher.update(ctx.escrow_address);
        hasher.update(ctx.swap_id);
        hasher.update(ctx.settle_digest);
        hasher.update(ctx.m_digest);
        hasher.update(ctx.maker_address);
        hasher.update(ctx.taker_address);
        hasher.update([ctx.version]);
        let expected = hasher.finalize().to_vec();

        assert_eq!(aad, expected);
    }
}
