#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct EswpEscrowLog {
  unsigned char kind;
  unsigned char backend;
  uint8_t swap_id[32];
  uint8_t amount_be[32];
};

struct EswpEscrowEvent {
  uint8_t digest[32];
  uint8_t swap_id[32];
  uint8_t amount_be[32];
  unsigned char backend;
  unsigned char kind;
};

extern "C" {

unsigned int eswp_wire_version();

unsigned char eswp_backend_clsag_id();

/// # Safety
/// `out_spend32` and `out_view32` must be valid, caller-owned pointers to 32-byte buffers.
int eswp_generate_monero_keypair(unsigned char *out_spend32, unsigned char *out_view32);

/// # Safety
/// All pointer arguments must reference caller-owned memory. `out_address_len` must be writable
/// and `out_address_capacity` specifies the bytes available at `out_address_ptr`. The derived
/// address is copied as ASCII bytes without a trailing NUL terminator.
int eswp_monero_derive_subaddress(const unsigned char *view_ptr,
                                  const unsigned char *spend_ptr,
                                  unsigned int index,
                                  unsigned char *out_address_ptr,
                                  unsigned int out_address_capacity,
                                  unsigned int *out_address_len,
                                  unsigned char *out_derived_spend32);

/// # Safety
/// Input pointers must reference 32-byte buffers and `out_key_image32` must be writable.
int eswp_monero_compute_key_image(const unsigned char *tx_pub_ptr,
                                  const unsigned char *spend_ptr,
                                  unsigned char *out_key_image32);

/// # Safety
/// `out_priv32` and `out_addr20` must be writable buffers owned by the caller.
int eswp_generate_evm_keypair(unsigned char *out_priv32, unsigned char *out_addr20);

/// # Safety
/// `priv_ptr` and `msg_ptr` must reference 32-byte inputs and `out_sig65` must have room for 65 bytes.
int eswp_sign_evm_message(const unsigned char *priv_ptr,
                          const unsigned char *msg_ptr,
                          unsigned char *out_sig65);

/// # Safety
/// `msg_ptr`, `ring_ptr`, `swap_id_ptr`, and `ctx_ptr` must reference readable buffers of
/// the stated lengths. `out_bytes` must point to a buffer large enough to receive the
/// pre-signature bytes, and `out_len` must be writable.
int eswp_clsag_make_pre_sig(const unsigned char *msg_ptr,
                            unsigned int msg_len,
                            const unsigned char *ring_ptr,
                            unsigned int ring_len,
                            unsigned int i_star,
                            const unsigned char *swap_id_ptr,
                            const unsigned char *ctx_ptr,
                            unsigned int ctx_len,
                            unsigned char *out_bytes,
                            unsigned int *out_len);

/// # Safety
/// All pointer arguments must be non-null, with `pre_ptr` and `secret_ptr`
/// referencing readable buffers of the stated lengths, and `out_ptr`/`out_len`
/// writable for the produced signature bytes and length.
int eswp_clsag_complete(const unsigned char *pre_ptr,
                        unsigned int pre_len,
                        const unsigned char *secret_ptr,
                        unsigned int secret_len,
                        unsigned char *out_ptr,
                        unsigned int *out_len);

/// # Safety
/// `out_ok` must be a valid, writable pointer.
int eswp_clsag_verify(const unsigned char *pre_ptr,
                      unsigned int pre_len,
                      const unsigned char *final_ptr,
                      unsigned int final_len,
                      bool *out_ok);

/// # Safety
/// `pre_ptr` must reference `pre_len` readable bytes and `out_scalar32` must
/// point to a writable buffer large enough to receive 32 bytes.
int eswp_clsag_extract_t(const unsigned char *pre_ptr,
                         unsigned int pre_len,
                         const unsigned char *final_ptr,
                         unsigned int final_len,
                         unsigned char *out_scalar32);

/// # Safety
/// The caller owns all buffers. `out_tx_ptr` must have space for `out_tx_capacity` bytes and
/// `out_tx_len` / `out_lock_time` must be writable.
int eswp_prepare_refund(const unsigned char *ctx_ptr,
                        unsigned int ctx_len,
                        const unsigned char *swap_id_ptr,
                        uint64_t xmr_lock_height,
                        uint64_t eth_expiry,
                        uint64_t delta,
                        const unsigned char *template_ptr,
                        unsigned int template_len,
                        unsigned char *out_tx_ptr,
                        unsigned int out_tx_capacity,
                        unsigned int *out_tx_len,
                        uint64_t *out_lock_time);

/// # Safety
/// Caller provides all buffers. `out_data_ptr` must have capacity `out_data_capacity`.
int eswp_escrow_lock_eth_call(const unsigned char *escrow_ptr,
                              const unsigned char *swap_id_ptr,
                              const unsigned char *taker_ptr,
                              const unsigned char *adaptor_hash_ptr,
                              const unsigned char *maker_ptr,
                              const unsigned char *amount_be_ptr,
                              const unsigned char *tip_be_ptr,
                              uint64_t expiry,
                              unsigned char backend_id,
                              const unsigned char *settle_digest_ptr,
                              uint64_t gas_limit,
                              unsigned char *out_data_ptr,
                              unsigned int out_data_capacity,
                              unsigned int *out_data_len,
                              unsigned char *out_value_ptr,
                              uint64_t *out_gas_limit);

/// # Safety
/// Caller owns all buffers; `swap_id_ptr` must reference 32 readable bytes.
int eswp_escrow_refund_call(const unsigned char *escrow_ptr,
                            const unsigned char *swap_id_ptr,
                            uint64_t gas_limit,
                            unsigned char *out_data_ptr,
                            unsigned int out_data_capacity,
                            unsigned int *out_data_len,
                            unsigned char *out_value_ptr,
                            uint64_t *out_gas_limit);

/// # Safety
/// Caller provides `logs_ptr` (optional when `logs_len` is zero) and an output slice with enough
/// capacity to hold all decoded events.
int eswp_decode_escrow_events(const unsigned char *ctx_ptr,
                              unsigned int ctx_len,
                              const EswpEscrowLog *logs_ptr,
                              unsigned int logs_len,
                              EswpEscrowEvent *out_events_ptr,
                              unsigned int out_events_capacity,
                              unsigned int *out_events_written);

/// # Safety
/// Caller provides the QuoteBoard address, inputs, and output buffers used to receive the
/// calldata/value pair required for posting the tx hash on-chain.
int eswp_post_tx_hash_call(const unsigned char *board_ptr,
                           const unsigned char *swap_id_ptr,
                           const unsigned char *monero_tx_hash_ptr,
                           const unsigned char *tau_pub_ptr,
                           unsigned int tau_pub_len,
                           const unsigned char *evm_privkey_ptr,
                           uint64_t gas_limit,
                           unsigned char *out_data_ptr,
                           unsigned int out_data_capacity,
                           unsigned int *out_data_len,
                           unsigned char *out_value_ptr,
                           uint64_t *out_gas_limit);

/// # Safety
/// Caller must allocate output buffers. Inputs must reference readable buffers of the stated sizes.
int eswp_escrow_settle_call(const unsigned char *escrow_ptr,
                            const unsigned char *swap_id_ptr,
                            const unsigned char *adaptor_secret_ptr,
                            uint64_t gas_limit,
                            unsigned char *out_data_ptr,
                            unsigned int out_data_capacity,
                            unsigned int *out_data_len,
                            unsigned char *out_value_ptr,
                            uint64_t *out_gas_limit);

/// # Safety
/// Caller provides buffers for outputs. `permit_ptr` may be null when `permit_len` is zero.
int eswp_escrow_lock_erc20_call(const unsigned char *escrow_ptr,
                                const unsigned char *swap_id_ptr,
                                const unsigned char *taker_ptr,
                                const unsigned char *token_ptr,
                                const unsigned char *amount_be_ptr,
                                const unsigned char *tip_be_ptr,
                                const unsigned char *adaptor_hash_ptr,
                                const unsigned char *maker_ptr,
                                uint64_t expiry,
                                unsigned char backend_id,
                                const unsigned char *settle_digest_ptr,
                                const unsigned char *permit_ptr,
                                unsigned int permit_len,
                                uint64_t gas_limit,
                                unsigned char *out_data_ptr,
                                unsigned int out_data_capacity,
                                unsigned int *out_data_len,
                                unsigned char *out_value_ptr,
                                uint64_t *out_gas_limit);

}  // extern "C"
