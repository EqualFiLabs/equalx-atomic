use sha3::{Digest, Sha3_256};

pub fn compute_designated_index(
    ring_hash: &[u8; 32],
    key_image: &[u8; 32],
    message_hash: &[u8; 32],
    swap_id: &[u8; 32],
    settlement_hash: &[u8; 32],
    ring_size: usize,
) -> usize {
    assert!(ring_size > 0, "ring must contain at least one member");

    let mut h = Sha3_256::new();
    h.update(ring_hash);
    h.update(key_image);
    h.update(message_hash);
    h.update(swap_id);
    h.update(settlement_hash);

    let digest = h.finalize();
    let mut index_bytes = [0u8; 4];
    index_bytes.copy_from_slice(&digest[..4]);

    (u32::from_le_bytes(index_bytes) as usize) % ring_size
}
