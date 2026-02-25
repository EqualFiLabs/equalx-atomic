#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

constexpr static const unsigned int ESWP_CMD_MAKER_CREATE_RESERVATION = 1;

constexpr static const unsigned int ESWP_CMD_MAKER_SET_HASHLOCK = 2;

constexpr static const unsigned int ESWP_CMD_MAKER_HANDLE_CONTEXT = 3;

constexpr static const unsigned int ESWP_CMD_MAKER_PUBLISH_PRESIG = 4;

constexpr static const unsigned int ESWP_CMD_MAKER_HANDLE_FINAL_SIG = 5;

constexpr static const unsigned int ESWP_CMD_MAKER_SETTLE = 6;

constexpr static const unsigned int ESWP_CMD_TAKER_ACCEPT_RESERVATION = 11;

constexpr static const unsigned int ESWP_CMD_TAKER_PUBLISH_CONTEXT = 12;

constexpr static const unsigned int ESWP_CMD_TAKER_HANDLE_PRESIG = 13;

constexpr static const unsigned int ESWP_CMD_TAKER_COMPLETE_AND_BROADCAST = 14;

constexpr static const unsigned int ESWP_CMD_TAKER_PUBLISH_FINAL_SIG = 15;

struct FfiOrchestratorHandle;

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

struct CapabilityDescriptor {
  uint16_t version_major;
  uint16_t version_minor;
  uint16_t version_patch;
  uint32_t backends;
  uint32_t api_groups;
  uint32_t wire_version;
};

struct EswpAtomicReservationCreatedEvent {
  uint8_t reservation_id[32];
  uint8_t desk_id[32];
  uint8_t taker[20];
  uint8_t asset[20];
  uint8_t amount_be[32];
  uint8_t settlement_digest[32];
  uint64_t expiry;
  uint64_t created_at;
};

struct EswpReservationCreatedEvent {
  uint8_t reservation_id[32];
  uint8_t taker[20];
  uint8_t desk[20];
  uint8_t amount_be[32];
  uint8_t counter_be[32];
};

struct EswpHashlockSetEvent {
  uint8_t reservation_id[32];
  uint8_t hashlock[32];
};

struct EswpTrancheOpenedEvent {
  uint8_t tranche_id[32];
  uint8_t desk_id[32];
  uint8_t maker[20];
  uint8_t asset[20];
  uint8_t price_numerator_be[32];
  uint8_t price_denominator_be[32];
  uint8_t total_liquidity_be[32];
  uint8_t min_fill_be[32];
  uint16_t fee_bps;
  uint8_t fee_payer;
  uint64_t expiry;
};

struct EswpTakerTrancheOpenedEvent {
  uint8_t tranche_id[32];
  uint8_t desk_id[32];
  uint8_t taker[20];
  uint8_t asset[20];
  uint8_t price_numerator_be[32];
  uint8_t price_denominator_be[32];
  uint8_t total_liquidity_be[32];
  uint8_t min_fill_be[32];
  uint16_t fee_bps;
  uint8_t fee_payer;
  uint64_t expiry;
  uint8_t posting_fee_be[32];
};

struct EswpTrancheReservedEvent {
  uint8_t tranche_id[32];
  uint8_t reservation_id[32];
  uint8_t actor[20];
  uint8_t amount_be[32];
  uint8_t remaining_liquidity_be[32];
};

struct EswpSettleEvent {
  uint8_t reservation_id[32];
  uint8_t value[32];
};

struct CKeyCallbacks {
  int (*evm_address)(void *user_data, unsigned char *out_addr20);
  int (*sign_evm_message)(void *user_data,
                          const unsigned char *digest32,
                          unsigned char *out_sig_ptr,
                          unsigned int out_sig_capacity,
                          unsigned int *out_sig_len);
  int (*monero_spend_public_key)(void *user_data, unsigned char *out_key32);
  int (*monero_view_public_key)(void *user_data, unsigned char *out_key32);
  int (*monero_derive_subaddress)(void *user_data,
                                  uint32_t major,
                                  uint32_t minor,
                                  unsigned char *out_addr_ptr,
                                  unsigned int out_addr_capacity,
                                  unsigned int *out_addr_len);
  int (*monero_compute_key_image)(void *user_data,
                                  const unsigned char *output_pubkey32,
                                  uint64_t output_index,
                                  unsigned char *out_key_image32);
  void *user_data;
};

struct CEvmCallbacks {
  int (*send_raw_tx)(void *user_data,
                     const unsigned char *tx_ptr,
                     unsigned int tx_len,
                     unsigned char *out_hash32);
  int (*estimate_gas)(void *user_data,
                      const unsigned char *call_data_ptr,
                      unsigned int call_data_len,
                      uint64_t *out_gas);
  int (*replace_tx)(void *user_data,
                    const unsigned char *original_hash32,
                    uint64_t new_gas,
                    unsigned char *out_hash32);
  int (*get_receipt)(void *user_data,
                     const unsigned char *tx_hash32,
                     unsigned char *out_receipt_ptr,
                     unsigned int out_receipt_capacity,
                     unsigned int *out_receipt_len);
  int (*get_logs)(void *user_data,
                  const unsigned char *filter_ptr,
                  unsigned int filter_len,
                  unsigned char *out_logs_ptr,
                  unsigned int out_logs_capacity,
                  unsigned int *out_logs_len);
  int (*chain_id)(void *user_data, uint64_t *out_chain_id);
  int (*block_number)(void *user_data, uint64_t *out_block);
  int (*gas_price)(void *user_data, unsigned char *out_gas_price_be16);
  void *user_data;
};

struct CMoneroCallbacks {
  int (*broadcast_tx)(void *user_data,
                      const unsigned char *tx_ptr,
                      unsigned int tx_len,
                      unsigned char *out_hash32);
  int (*is_key_image_spent)(void *user_data,
                            const unsigned char *key_images_ptr,
                            unsigned int key_images_count,
                            unsigned char *out_states_ptr,
                            unsigned int out_states_capacity,
                            unsigned int *out_states_len);
  int (*get_tx_confirmations)(void *user_data,
                              const unsigned char *tx_hash32,
                              unsigned char *out_has_value,
                              uint64_t *out_confirmations);
  int (*node_health)(void *user_data,
                     unsigned char *out_health_ptr,
                     unsigned int out_health_capacity,
                     unsigned int *out_health_len);
  void *user_data;
};

struct CPersistenceCallbacks {
  int (*save_checkpoint)(void *user_data,
                         const unsigned char *reservation_id32,
                         const unsigned char *state_ptr,
                         unsigned int state_len);
  int (*load_checkpoint)(void *user_data,
                         const unsigned char *reservation_id32,
                         unsigned char *out_ptr,
                         unsigned int out_capacity,
                         unsigned int *out_len);
  int (*list_active_swaps)(void *user_data,
                           unsigned char *out_ids_ptr,
                           unsigned int out_ids_capacity,
                           unsigned int *out_ids_len);
  int (*delete_swap)(void *user_data, const unsigned char *reservation_id32);
  void *user_data;
};

struct CTimeNetworkCallbacks {
  int (*current_block_number)(void *user_data, uint64_t *out_block);
  int (*current_timestamp)(void *user_data, uint64_t *out_ts);
  int (*is_evm_reachable)(void *user_data, unsigned char *out_value);
  int (*is_monero_reachable)(void *user_data, unsigned char *out_value);
  void *user_data;
};

struct CUxCallbacks {
  int (*on_event)(void *user_data, const unsigned char *event_ptr, unsigned int event_len);
  void *user_data;
};

struct EswpOrchestratorConfig {
  uint8_t checkpoint_version;
  uint64_t maker_timeout_secs;
  uint64_t taker_timeout_secs;
};

struct EswpDeadlineEvent {
  uint8_t reservation_id[32];
  uint64_t deadline;
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
/// the stated lengths. `out_len` is an in/out pointer: initialize `*out_len` with the
/// available capacity at `out_bytes`; on success it is replaced with the encoded length.
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
/// referencing readable buffers of the stated lengths. `out_len` is in/out:
/// initialize `*out_len` with the `out_ptr` capacity; on success it is replaced
/// with the produced signature length.
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
                            const unsigned char *min_received_be_ptr,
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

/// # Safety
/// [out] `out_descriptor` must be a valid writable pointer to a caller-allocated
/// `CapabilityDescriptor` structure.
int eswp_capability_query(CapabilityDescriptor *out_descriptor);

/// # Safety
/// [in] `owner_ptr` points to a 20-byte owner address.
/// [in] `pubkey_ptr` points to `pubkey_len` bytes and must be 33 bytes.
int eswp_register_enc_pub(const unsigned char *owner_ptr,
                          const unsigned char *pubkey_ptr,
                          unsigned int pubkey_len);

/// # Safety
/// [in] `owner_ptr` points to a 20-byte owner address.
/// [out][owned] on success, `out_pubkey_ptr` receives a library-owned buffer and `out_pubkey_len`
/// receives its size; free with `eswp_free_buffer`.
int eswp_get_enc_pub(const unsigned char *owner_ptr,
                     unsigned char **out_pubkey_ptr,
                     unsigned int *out_pubkey_len);

/// # Safety
/// [in] `owner_ptr` points to a 20-byte owner address.
/// [out] `out_registered` must be writable.
int eswp_is_registered(const unsigned char *owner_ptr, unsigned char *out_registered);

/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `envelope_ptr` points to `envelope_len` bytes.
int eswp_publish_context(const unsigned char *reservation_id_ptr,
                         const unsigned char *envelope_ptr,
                         unsigned int envelope_len);

/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `envelope_ptr` points to `envelope_len` bytes.
int eswp_publish_presig(const unsigned char *reservation_id_ptr,
                        const unsigned char *envelope_ptr,
                        unsigned int envelope_len);

/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `envelope_ptr` points to `envelope_len` bytes.
int eswp_publish_final_sig(const unsigned char *reservation_id_ptr,
                           const unsigned char *envelope_ptr,
                           unsigned int envelope_len);

/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [out][owned] `out_messages_ptr` receives a library-owned encoded message blob and
/// `out_messages_len` its size; free via `eswp_free_buffer`.
int eswp_fetch_messages(const unsigned char *reservation_id_ptr,
                        unsigned char **out_messages_ptr,
                        unsigned int *out_messages_len);

/// # Safety
/// [in] `desk_id_ptr` points to 32 bytes.
int eswp_register_desk(const unsigned char *desk_id_ptr);

/// # Safety
/// [in] all pointer inputs must point to fixed-size buffers:
/// reservation (32), desk_id (32), taker (20), asset (20), amount (32), settlement_digest (32).
int eswp_reserve_atomic_swap(const unsigned char *reservation_id_ptr,
                             const unsigned char *desk_id_ptr,
                             const unsigned char *taker_ptr,
                             const unsigned char *asset_ptr,
                             const unsigned char *amount_be_ptr,
                             const unsigned char *settlement_digest_ptr,
                             uint64_t expiry,
                             uint64_t created_at);

/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [out] `out_reservation` must be writable.
int eswp_get_reservation(const unsigned char *reservation_id_ptr,
                         EswpAtomicReservationCreatedEvent *out_reservation);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes (nullable when `data_len == 0`).
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_reservation_created(const unsigned char *topics_ptr,
                                    unsigned int topics_len,
                                    const unsigned char *data_ptr,
                                    unsigned int data_len,
                                    EswpReservationCreatedEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_hashlock_set(const unsigned char *topics_ptr,
                             unsigned int topics_len,
                             const unsigned char *data_ptr,
                             unsigned int data_len,
                             EswpHashlockSetEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_atomic_reservation_created(const unsigned char *topics_ptr,
                                           unsigned int topics_len,
                                           const unsigned char *data_ptr,
                                           unsigned int data_len,
                                           EswpAtomicReservationCreatedEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_tranche_opened(const unsigned char *topics_ptr,
                               unsigned int topics_len,
                               const unsigned char *data_ptr,
                               unsigned int data_len,
                               EswpTrancheOpenedEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_taker_tranche_opened(const unsigned char *topics_ptr,
                                     unsigned int topics_len,
                                     const unsigned char *data_ptr,
                                     unsigned int data_len,
                                     EswpTakerTrancheOpenedEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_tranche_reserved(const unsigned char *topics_ptr,
                                 unsigned int topics_len,
                                 const unsigned char *data_ptr,
                                 unsigned int data_len,
                                 EswpTrancheReservedEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_taker_tranche_reserved(const unsigned char *topics_ptr,
                                       unsigned int topics_len,
                                       const unsigned char *data_ptr,
                                       unsigned int data_len,
                                       EswpTrancheReservedEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_settled(const unsigned char *topics_ptr,
                        unsigned int topics_len,
                        const unsigned char *data_ptr,
                        unsigned int data_len,
                        EswpSettleEvent *out_event);

/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
int eswp_decode_refunded(const unsigned char *topics_ptr,
                         unsigned int topics_len,
                         const unsigned char *data_ptr,
                         unsigned int data_len,
                         EswpSettleEvent *out_event);

/// # Safety
/// [in] all callback pointers are borrowed for orchestrator lifetime.
/// [out] `out_handle` receives an owned orchestrator handle; release via `eswp_orchestrator_free`.
int eswp_orchestrator_new(const CKeyCallbacks *key_callbacks,
                          const CEvmCallbacks *evm_callbacks,
                          const CMoneroCallbacks *monero_callbacks,
                          const CPersistenceCallbacks *persistence_callbacks,
                          const CTimeNetworkCallbacks *time_callbacks,
                          const CUxCallbacks *ux_callbacks,
                          const EswpOrchestratorConfig *config,
                          FfiOrchestratorHandle **out_handle);

/// # Safety
/// [in] `handle` must be a pointer returned by `eswp_orchestrator_new` and freed once.
void eswp_orchestrator_free(FfiOrchestratorHandle *handle);

/// # Safety
/// [in] `handle` must be valid.
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [out][owned] `out_state_ptr` receives a library-owned UTF-8 state string; free via `eswp_free_buffer`.
int eswp_orchestrator_resume(FfiOrchestratorHandle *handle,
                             const unsigned char *reservation_id_ptr,
                             unsigned char **out_state_ptr,
                             unsigned int *out_state_len);

/// # Safety
/// [in] `handle` must be valid.
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `payload_ptr` is optional when `payload_len == 0`.
/// [out] `out_result32` may be null when caller ignores command return value.
int eswp_orchestrator_step(FfiOrchestratorHandle *handle,
                           const unsigned char *reservation_id_ptr,
                           unsigned int command_id,
                           const unsigned char *payload_ptr,
                           unsigned int payload_len,
                           unsigned char *out_result32);

/// # Safety
/// [in] `handle` must be valid.
/// [out] `out_events_ptr` is caller-allocated for `out_events_capacity` entries.
/// [out] `out_events_len` receives the number of written entries.
int eswp_orchestrator_check_deadlines(FfiOrchestratorHandle *handle,
                                      EswpDeadlineEvent *out_events_ptr,
                                      unsigned int out_events_capacity,
                                      unsigned int *out_events_len);

/// # Safety
/// [in][owned] `ptr` must be a library-owned buffer returned by this ABI.
/// Passing unknown pointers is ignored.
void eswp_free_buffer(unsigned char *ptr, unsigned int _len);

/// # Safety
/// [in][owned] `ptr` must be a library-owned string returned by this ABI.
/// Passing unknown pointers is ignored.
void eswp_free_string(char *ptr);

/// # Safety
/// [in] `error_code` is a numeric error code from this ABI.
/// [out][owned] `out_message` receives a library-owned string; free via `eswp_free_string`.
int eswp_error_message(int error_code, char **out_message);

}  // extern "C"
