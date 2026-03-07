#ifndef LOCALNET_ENCRYPTION_H
#define LOCALNET_ENCRYPTION_H

#include <stdint.h>
#include <stddef.h>

/* ========================================================================== */
/* Configuration Constants                                                     */
/* ========================================================================== */

#define MAX_SESSIONS                  32
#define X25519_KEY_SIZE               32
#define X25519_SHARED_SECRET_SIZE     32
#define AES128_KEY_SIZE               16
#define AES128_IV_SIZE                16
#define HMAC_SHA256_SIZE              32
#define HMAC_SHA256_TRUNCATED_SIZE    12    /* 96 bits */
#define NONCE_SIZE                    7
#define OOB_COMMITMENT_SIZE           4     /* 4 bytes = 8 hex digits */
#define MASTER_KEY_SIZE               32
#define AUTH_KEY_SIZE                  32
#define ENCRYPTION_KEY_SIZE           16
#define STATIC_OOB_TOKEN_MAX_SIZE     64
#define FRAME_COUNTER_MAX             0xFFFFFFFF
#define SESSION_MAX_LIFETIME_SECONDS  86400  /* 24 hours */
#define OOB_TIMEOUT_SECONDS           60
#define MAC_FAILURE_THRESHOLD         3
#define ENCRYPTION_TAG                "ENCRYPTION"

/* ========================================================================== */
/* Session States                                                              */
/* ========================================================================== */

enum session_state {
    SESSION_STATE_EMPTY = 0,
    SESSION_STATE_PENDING,         /* ECDH handshake in progress */
    SESSION_STATE_OOB_PENDING,     /* ECDH complete, OOB verification awaiting */
    SESSION_STATE_OOB_VERIFIED     /* Fully authenticated, data frames permitted */
};

/* ========================================================================== */
/* OOB Verification Methods                                                    */
/* ========================================================================== */

enum oob_method {
    OOB_METHOD_NONE = 0,
    OOB_METHOD_QR_CODE     = 0x01,
    OOB_METHOD_NFC_TAP     = 0x02,
    OOB_METHOD_OUTPUT_OOB  = 0x03,
    OOB_METHOD_INPUT_OOB   = 0x04,
    OOB_METHOD_STATIC_OOB  = 0x05
};

/* ========================================================================== */
/* Error Codes for encrypted frame processing                                  */
/* ========================================================================== */

enum encryption_error {
    ENC_SUCCESS = 0,
    ENC_ERROR_NO_SESSION = -1,
    ENC_ERROR_SESSION_UNVERIFIED = -2,
    ENC_ERROR_COUNTER_MISMATCH = -3,
    ENC_ERROR_MAC_FAILURE = -4,
    ENC_ERROR_DECRYPT_FAILURE = -5,
    ENC_ERROR_ENCRYPT_FAILURE = -6,
    ENC_ERROR_INVALID_PARAMS = -7,
    ENC_ERROR_SESSION_EXPIRED = -8,
    ENC_ERROR_KEY_ROTATION_NEEDED = -9,
    ENC_ERROR_OOB_MISMATCH = -10,
    ENC_ERROR_OOB_TIMEOUT = -11,
    ENC_ERROR_INTERNAL = -12
};

/* ========================================================================== */
/* Key Exchange Message Types                                                  */
/* ========================================================================== */

enum key_exchange_type {
    KEX_TYPE_REQUEST  = 0x00,
    KEX_TYPE_RESPONSE = 0x01
};

/* ========================================================================== */
/* Security Block (matches protocol.h struct security layout)                  */
/* ========================================================================== */

struct security_block {
    uint8_t key_id;
    uint32_t frame_counter;
    uint8_t nonce[NONCE_SIZE];
    uint8_t mac[HMAC_SHA256_TRUNCATED_SIZE];
};

/* ========================================================================== */
/* Encryption Session                                                          */
/* ========================================================================== */

struct encryption_session {
    uint32_t peer_id;                          /* Remote node device ID */
    enum session_state state;

    uint8_t key_id;                            /* Session key identifier */

    /* Ephemeral X25519 key pair (local) */
    uint8_t local_public_key[X25519_KEY_SIZE];
    uint8_t local_private_key[X25519_KEY_SIZE];

    /* Remote public key */
    uint8_t remote_public_key[X25519_KEY_SIZE];

    /* Derived keys */
    uint8_t master_key[MASTER_KEY_SIZE];
    uint8_t encryption_key[ENCRYPTION_KEY_SIZE];
    uint8_t auth_key[AUTH_KEY_SIZE];

    /* Frame counters */
    uint32_t send_frame_counter;               /* Outgoing frame counter */
    uint32_t recv_frame_counter;               /* Expected incoming frame counter */

    /* OOB verification */
    uint8_t oob_commitment[OOB_COMMITMENT_SIZE];
    enum oob_method negotiated_oob_method;
    uint8_t supported_oob_methods;             /* Bitmask of supported methods */

    /* Session metadata */
    uint32_t created_at;                       /* Timestamp */
    uint32_t last_activity;                    /* Last frame sent/received */
    uint8_t mac_failure_count;                 /* Consecutive MAC failures */

    /* Who initiated the key exchange */
    uint8_t we_initiated;
};

/* ========================================================================== */
/* OOB Callback                                                                */
/* ========================================================================== */

/**
 * OOB display callback - called when the local node needs to present
 * the short_code to the operator for out-of-band verification.
 *
 * @param peer_id       Remote node ID
 * @param short_code    4-byte OOB commitment (display as 8 hex digits)
 * @param oob_method    Negotiated OOB method
 *
 * The user must implement this callback to handle OOB presentation
 * (e.g., display on screen, blink LED, generate QR code, etc.)
 */
typedef void (*oob_display_callback_t)(uint32_t peer_id,
                                        const uint8_t short_code[OOB_COMMITMENT_SIZE],
                                        enum oob_method oob_method);

/* ========================================================================== */
/* Session Manager                                                             */
/* ========================================================================== */

struct session_manager {
    struct encryption_session sessions[MAX_SESSIONS];
    size_t session_count;

    uint32_t local_device_id;

    /* Next key_id to assign */
    uint8_t next_key_id;

    /* OOB callback for user implementation */
    oob_display_callback_t oob_display_cb;

    /* Static OOB token (optional) */
    uint8_t static_oob_token[STATIC_OOB_TOKEN_MAX_SIZE];
    size_t static_oob_token_len;
    uint8_t has_static_oob_token;
};

/* ========================================================================== */
/* Extended Key Exchange Message                                               */
/* ========================================================================== */

/**
 * Extended key exchange message for ECDH handshake.
 * Carries the ephemeral public key, OOB method preferences,
 * and whether this is a request or response.
 */
struct key_exchange_ext_message {
    uint8_t public_key[X25519_KEY_SIZE];       /* 32 bytes */
    uint32_t device_id;                         /* 4 bytes */
    uint32_t timestamp;                         /* 4 bytes */
    uint8_t kex_type;                           /* 1 byte: request or response */
    uint8_t supported_oob_methods;              /* 1 byte: bitmask */
    uint8_t preferred_oob_method;               /* 1 byte */
};
/* Total serialized: 43 bytes */

#define KEY_EXCHANGE_EXT_SIZE 43

/* ========================================================================== */
/* Session Manager Functions                                                   */
/* ========================================================================== */

/**
 * Initialize the session manager.
 * Must call crypto_init() before this function.
 */
int session_manager_init(struct session_manager *mgr, uint32_t local_device_id);

/** Clean up session manager and securely wipe all key material */
void session_manager_cleanup(struct session_manager *mgr);

/** Set the OOB display callback */
void session_manager_set_oob_callback(struct session_manager *mgr,
                                       oob_display_callback_t callback);

/** Set a static OOB token for Static OOB method */
int session_manager_set_static_oob_token(struct session_manager *mgr,
                                          const uint8_t *token, size_t token_len);

/* ========================================================================== */
/* Key Exchange Functions                                                      */
/* ========================================================================== */

/**
 * Initiate a key exchange with a peer node.
 * Generates ephemeral X25519 keypair, creates a PENDING session,
 * and fills kex_out with the message to send.
 */
int initiate_key_exchange(struct session_manager *mgr, uint32_t peer_id,
                          struct key_exchange_ext_message *kex_out);

/**
 * Handle an incoming key exchange message.
 * If it's a request: generates our response and computes shared secret.
 * If it's a response: completes the handshake.
 *
 * @param need_response  Output: 1 if response_out should be sent, 0 otherwise
 * @return 0 on success, negative on error
 */
int handle_key_exchange(struct session_manager *mgr, uint32_t peer_id,
                        const struct key_exchange_ext_message *kex_msg,
                        struct key_exchange_ext_message *response_out,
                        int *need_response);

/* ========================================================================== */
/* OOB Verification Functions                                                  */
/* ========================================================================== */

/**
 * Verify OOB code for a session with a peer.
 * On match: session becomes OOB_VERIFIED.
 * On mismatch: session is torn down, keys purged.
 */
int verify_oob_code(struct session_manager *mgr, uint32_t peer_id,
                    const uint8_t user_code[OOB_COMMITMENT_SIZE]);

/**
 * Get the OOB short code for a session (for display purposes).
 * @return 0 on success, -1 if no OOB_PENDING session exists
 */
int get_oob_code(struct session_manager *mgr, uint32_t peer_id,
                 uint8_t code_out[OOB_COMMITMENT_SIZE]);

/* ========================================================================== */
/* Frame Encryption / Decryption                                               */
/* ========================================================================== */

/**
 * Encrypt application data for transmission to a peer.
 * Only works on OOB_VERIFIED sessions.
 *
 * @param ciphertext_out     Output: encrypted data (caller must free)
 * @param ciphertext_len_out Output: length of ciphertext
 * @param security_out       Output: security block to attach to frame
 * @return 0 on success, negative error code on failure
 */
int encrypt_frame(struct session_manager *mgr,
                  uint32_t destination_id,
                  const uint8_t *header_data, size_t header_len,
                  const uint8_t *network_data, size_t network_len,
                  const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t **ciphertext_out, size_t *ciphertext_len_out,
                  struct security_block *security_out);

/**
 * Decrypt an incoming encrypted frame.
 * Only processes frames from OOB_VERIFIED sessions.
 *
 * @param plaintext_out      Output: decrypted data (caller must free)
 * @param plaintext_len_out  Output: length of plaintext
 * @return 0 on success, negative error code on failure
 */
int decrypt_frame(struct session_manager *mgr,
                  uint32_t source_id,
                  const uint8_t *header_data, size_t header_len,
                  const uint8_t *network_data, size_t network_len,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const struct security_block *security,
                  uint8_t **plaintext_out, size_t *plaintext_len_out);

/* ========================================================================== */
/* Session Query Functions                                                     */
/* ========================================================================== */

struct encryption_session *session_find_by_peer(struct session_manager *mgr,
                                                 uint32_t peer_id);

struct encryption_session *session_find_by_key_id(struct session_manager *mgr,
                                                   uint8_t key_id);

void session_destroy(struct session_manager *mgr, uint32_t peer_id);

int session_needs_rotation(const struct encryption_session *session,
                           uint32_t current_time);

size_t session_check_oob_timeouts(struct session_manager *mgr,
                                   uint32_t current_time);

size_t session_check_lifetimes(struct session_manager *mgr,
                                uint32_t current_time);

size_t session_get_count(const struct session_manager *mgr);

const char *session_state_to_string(enum session_state state);

const char *oob_method_to_string(enum oob_method method);

/* ========================================================================== */
/* Serialization for Extended Key Exchange Message                             */
/* ========================================================================== */

size_t serialize_key_exchange_ext(const struct key_exchange_ext_message *kex,
                                  uint8_t *buffer, size_t buffer_size);

int parse_key_exchange_ext(const uint8_t *buffer, size_t buffer_size,
                           struct key_exchange_ext_message *kex);

/* ========================================================================== */
/* Low-Level Crypto Primitives (exposed for testing)                           */
/* ========================================================================== */

/** Initialize crypto library (call once at startup) */
int crypto_init(void);

/** Generate an ephemeral X25519 key pair */
int ecdh_generate_keypair(uint8_t public_key[X25519_KEY_SIZE],
                          uint8_t private_key[X25519_KEY_SIZE]);

/** Compute X25519 shared secret */
int ecdh_compute_shared_secret(uint8_t shared_secret[X25519_SHARED_SECRET_SIZE],
                               const uint8_t private_key[X25519_KEY_SIZE],
                               const uint8_t remote_public_key[X25519_KEY_SIZE]);

/** HKDF-SHA256 derive key material */
int hkdf_sha256(const uint8_t *input_key_material, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *output_key_material, size_t okm_len);

/** AES-128-CTR encrypt/decrypt (same operation for CTR mode) */
int aes128_ctr_crypt(const uint8_t key[AES128_KEY_SIZE],
                     const uint8_t iv[AES128_IV_SIZE],
                     const uint8_t *input, size_t input_len,
                     uint8_t *output);

/** HMAC-SHA256 full output */
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t output[HMAC_SHA256_SIZE]);

/** HMAC-SHA256 truncated to 96 bits (12 bytes) */
int hmac_sha256_truncated(const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len,
                          uint8_t output[HMAC_SHA256_TRUNCATED_SIZE]);

/** Generate cryptographically secure random bytes */
void crypto_random_bytes(uint8_t *buffer, size_t len);

/** Securely wipe memory */
void crypto_secure_wipe(void *buffer, size_t len);

#endif /* LOCALNET_ENCRYPTION_H */

