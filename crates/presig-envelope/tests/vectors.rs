use k256::elliptic_curve::sec1::ToEncodedPoint;
use presig_envelope::*;
use rand_core::{CryptoRng, Error, RngCore};

#[derive(Clone)]
struct FixedRng {
    seed: [u8; 32],
    offset: usize,
}

impl FixedRng {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed, offset: 0 }
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.seed[self.offset % self.seed.len()];
            self.offset = self.offset.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

fn ctx() -> EnvelopeContext {
    EnvelopeContext {
        chain_id: 11155111,
        escrow_address: [0x11; 20],
        swap_id: [0x22; 32],
        settle_digest: [0x33; 32],
        m_digest: [0x44; 32],
        maker_address: [0x55; 20],
        taker_address: [0x66; 20],
        version: 1,
    }
}

#[test]
fn encrypt_matches_vector() {
    let taker_secret = [0xA1; 32];
    let taker_sk = k256::SecretKey::from_slice(&taker_secret).unwrap();
    let taker_pub = k256::PublicKey::from_secret_scalar(&taker_sk.to_nonzero_scalar());
    let mut pub_bytes = [0u8; 33];
    pub_bytes.copy_from_slice(taker_pub.to_encoded_point(true).as_bytes());

    let request = EncryptRequest {
        taker_pubkey: &pub_bytes,
        presig: b"vector-presig",
        context: ctx(),
    };

    let mut rng = FixedRng::new([0x90; 32]);
    let out = encrypt_presig_with_rng(&request, &mut rng).unwrap();
    assert_eq!(
        hex::encode(out.envelope.to_bytes()),
        "010262cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79e891ca7afcc3a69a72a195dd1e2d53313d15528bcf915ef831a2b379f0"
    );

    let decryption = decrypt_presig(&DecryptRequest {
        taker_secret: &taker_secret,
        envelope: &out.envelope,
        context: ctx(),
    })
    .unwrap();
    assert_eq!(decryption.plaintext, b"vector-presig");
}

#[test]
fn envelope_encoding_roundtrip() {
    let taker_secret = [0xB2; 32];
    let taker_sk = k256::SecretKey::from_slice(&taker_secret).unwrap();
    let taker_pub = k256::PublicKey::from_secret_scalar(&taker_sk.to_nonzero_scalar());
    let mut pub_bytes = [0u8; 33];
    pub_bytes.copy_from_slice(taker_pub.to_encoded_point(true).as_bytes());

    let out = encrypt_presig(&EncryptRequest {
        taker_pubkey: &pub_bytes,
        presig: b"encode",
        context: ctx(),
    })
    .unwrap();

    let bytes = out.envelope.to_bytes();
    let parsed = Envelope::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, out.envelope);
}
