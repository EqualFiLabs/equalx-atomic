use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha3::Sha3_256;

pub fn derive_tau(hashlock: &[u8; 32], swap_id: &[u8; 32], stmt: &[u8], j: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(stmt), hashlock);
    let mut t = [0u8; 32];
    let mut info = Vec::with_capacity(9 + swap_id.len() + 4);
    info.extend_from_slice(b"clsag/tau");
    info.extend_from_slice(swap_id);
    info.extend_from_slice(&j.to_le_bytes());
    hk.expand(&info, &mut t).expect("hkdf expand tau");
    let s = Scalar::from_bytes_mod_order(t);
    (if s == Scalar::ZERO { Scalar::ONE } else { s }).to_bytes()
}
