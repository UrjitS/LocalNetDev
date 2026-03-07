#include "encryption.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sodium.h>
#include <openssl/evp.h>

/* ========================================================================== */
/* Low-Level Crypto Primitives                                                 */
/* ========================================================================== */

int crypto_init(void) {
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}

int ecdh_generate_keypair(uint8_t public_key[X25519_KEY_SIZE],
                          uint8_t private_key[X25519_KEY_SIZE]) {
    if (!public_key || !private_key) return -1;
    /* Generate random private key */
    randombytes_buf(private_key, X25519_KEY_SIZE);
    /* Derive public key from private key */
    if (crypto_scalarmult_base(public_key, private_key) != 0) {
        sodium_memzero(private_key, X25519_KEY_SIZE);
        return -1;
    }
    return 0;
}

int ecdh_compute_shared_secret(uint8_t shared_secret[X25519_SHARED_SECRET_SIZE],
                               const uint8_t private_key[X25519_KEY_SIZE],
                               const uint8_t remote_public_key[X25519_KEY_SIZE]) {
    if (!shared_secret || !private_key || !remote_public_key) return -1;
    if (crypto_scalarmult(shared_secret, private_key, remote_public_key) != 0) {
        sodium_memzero(shared_secret, X25519_SHARED_SECRET_SIZE);
        return -1;
    }
    return 0;
}

int hkdf_sha256(const uint8_t *input_key_material, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *output_key_material, size_t okm_len) {
    if (!input_key_material || !output_key_material || okm_len == 0) return -1;

    /* HKDF-Extract: PRK = HMAC-SHA256(salt="", IKM) */
    uint8_t prk[HMAC_SHA256_SIZE];
    const uint8_t salt[HMAC_SHA256_SIZE] = {0}; /* empty salt */

    crypto_auth_hmacsha256_state extract_state;
    crypto_auth_hmacsha256_init(&extract_state, salt, HMAC_SHA256_SIZE);
    crypto_auth_hmacsha256_update(&extract_state, input_key_material, ikm_len);
    crypto_auth_hmacsha256_final(&extract_state, prk);

    /* HKDF-Expand: OKM = T(1) || T(2) || ... */
    uint8_t t[HMAC_SHA256_SIZE] = {0};
    size_t t_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;

    while (offset < okm_len) {
        crypto_auth_hmacsha256_state expand_state;
        crypto_auth_hmacsha256_init(&expand_state, prk, HMAC_SHA256_SIZE);
        if (t_len > 0) {
            crypto_auth_hmacsha256_update(&expand_state, t, t_len);
        }
        if (info && info_len > 0) {
            crypto_auth_hmacsha256_update(&expand_state, info, info_len);
        }
        crypto_auth_hmacsha256_update(&expand_state, &counter, 1);
        crypto_auth_hmacsha256_final(&expand_state, t);
        t_len = HMAC_SHA256_SIZE;

        const size_t to_copy = (okm_len - offset < HMAC_SHA256_SIZE) ?
                               (okm_len - offset) : HMAC_SHA256_SIZE;
        memcpy(output_key_material + offset, t, to_copy);
        offset += to_copy;
        counter++;
    }

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(t, sizeof(t));
    return 0;
}

int aes128_ctr_crypt(const uint8_t key[AES128_KEY_SIZE],
                     const uint8_t iv[AES128_IV_SIZE],
                     const uint8_t *input, size_t input_len,
                     uint8_t *output) {
    if (!key || !iv || !input || !output || input_len == 0) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int out_len = 0;
    int final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, output, &out_len, input, (int)input_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, output + out_len, &final_len) != 1)
        goto cleanup;

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t output[HMAC_SHA256_SIZE]) {
    if (!key || !data || !output) return -1;

    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, data, data_len);
    crypto_auth_hmacsha256_final(&state, output);
    return 0;
}

int hmac_sha256_truncated(const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len,
                          uint8_t output[HMAC_SHA256_TRUNCATED_SIZE]) {
    uint8_t full[HMAC_SHA256_SIZE];
    if (hmac_sha256(key, key_len, data, data_len, full) != 0) return -1;
    memcpy(output, full, HMAC_SHA256_TRUNCATED_SIZE);
    sodium_memzero(full, sizeof(full));
    return 0;
}

void crypto_random_bytes(uint8_t *buffer, size_t len) {
    if (buffer && len > 0) {
        randombytes_buf(buffer, len);
    }
}

void crypto_secure_wipe(void *buffer, size_t len) {
    if (buffer && len > 0) {
        sodium_memzero(buffer, len);
    }
}

/* ========================================================================== */
/* Internal Helper Functions                                                   */
/* ========================================================================== */

/**
 * Derive session keys from shared secret.
 * master_key = HKDF(shared_secret [|| static_oob_token], "master", 32)
 * EK = HKDF(master_key, "encryption" || src_id || dst_id, 16)
 * AK = HKDF(master_key, "auth" || src_id || dst_id, 16)
 */
static int derive_session_keys(struct encryption_session *session,
                               const uint8_t shared_secret[X25519_SHARED_SECRET_SIZE],
                               uint32_t src_id, uint32_t dst_id,
                               const uint8_t *static_oob_token,
                               size_t static_oob_token_len) {
    /* Build IKM for master key: shared_secret [|| static_oob_token] */
    uint8_t ikm[X25519_SHARED_SECRET_SIZE + STATIC_OOB_TOKEN_MAX_SIZE];
    size_t ikm_len = X25519_SHARED_SECRET_SIZE;
    memcpy(ikm, shared_secret, X25519_SHARED_SECRET_SIZE);

    if (static_oob_token && static_oob_token_len > 0) {
        memcpy(ikm + X25519_SHARED_SECRET_SIZE, static_oob_token, static_oob_token_len);
        ikm_len += static_oob_token_len;
    }

    /* master_key = HKDF(ikm, "master", 32) */
    const char *master_info = "master";
    if (hkdf_sha256(ikm, ikm_len, (const uint8_t *)master_info, strlen(master_info),
                    session->master_key, MASTER_KEY_SIZE) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        return -1;
    }
    sodium_memzero(ikm, sizeof(ikm));

    /* Build info for EK: "encryption" || src_id || dst_id */
    const char *enc_prefix = "encryption";
    const size_t enc_prefix_len = strlen(enc_prefix);
    uint8_t ek_info[64];
    size_t ek_info_len = 0;
    memcpy(ek_info, enc_prefix, enc_prefix_len);
    ek_info_len += enc_prefix_len;
    ek_info[ek_info_len++] = (src_id >> 24) & 0xFF;
    ek_info[ek_info_len++] = (src_id >> 16) & 0xFF;
    ek_info[ek_info_len++] = (src_id >> 8) & 0xFF;
    ek_info[ek_info_len++] = src_id & 0xFF;
    ek_info[ek_info_len++] = (dst_id >> 24) & 0xFF;
    ek_info[ek_info_len++] = (dst_id >> 16) & 0xFF;
    ek_info[ek_info_len++] = (dst_id >> 8) & 0xFF;
    ek_info[ek_info_len++] = dst_id & 0xFF;

    if (hkdf_sha256(session->master_key, MASTER_KEY_SIZE,
                    ek_info, ek_info_len,
                    session->encryption_key, ENCRYPTION_KEY_SIZE) != 0) {
        return -1;
    }

    /* Build info for AK: "auth" || src_id || dst_id */
    const char *auth_prefix = "auth";
    const size_t auth_prefix_len = strlen(auth_prefix);
    uint8_t ak_info[64];
    size_t ak_info_len = 0;
    memcpy(ak_info, auth_prefix, auth_prefix_len);
    ak_info_len += auth_prefix_len;
    ak_info[ak_info_len++] = (src_id >> 24) & 0xFF;
    ak_info[ak_info_len++] = (src_id >> 16) & 0xFF;
    ak_info[ak_info_len++] = (src_id >> 8) & 0xFF;
    ak_info[ak_info_len++] = src_id & 0xFF;
    ak_info[ak_info_len++] = (dst_id >> 24) & 0xFF;
    ak_info[ak_info_len++] = (dst_id >> 16) & 0xFF;
    ak_info[ak_info_len++] = (dst_id >> 8) & 0xFF;
    ak_info[ak_info_len++] = dst_id & 0xFF;

    if (hkdf_sha256(session->master_key, MASTER_KEY_SIZE,
                    ak_info, ak_info_len,
                    session->auth_key, AUTH_KEY_SIZE) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Compute OOB commitment:
 * oob_commitment = HMAC-SHA256(AK, A_public || B_public || src_id || dst_id)
 * Truncated to first 4 bytes.
 */
static int compute_oob_commitment(struct encryption_session *session,
                                  const uint8_t a_public[X25519_KEY_SIZE],
                                  const uint8_t b_public[X25519_KEY_SIZE],
                                  uint32_t src_id, uint32_t dst_id) {
    /* Build data: A_public || B_public || src_id || dst_id */
    uint8_t data[X25519_KEY_SIZE * 2 + 8];
    size_t offset = 0;

    memcpy(data + offset, a_public, X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;
    memcpy(data + offset, b_public, X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;
    data[offset++] = (src_id >> 24) & 0xFF;
    data[offset++] = (src_id >> 16) & 0xFF;
    data[offset++] = (src_id >> 8) & 0xFF;
    data[offset++] = src_id & 0xFF;
    data[offset++] = (dst_id >> 24) & 0xFF;
    data[offset++] = (dst_id >> 16) & 0xFF;
    data[offset++] = (dst_id >> 8) & 0xFF;
    data[offset++] = dst_id & 0xFF;

    uint8_t full_hmac[HMAC_SHA256_SIZE];
    if (hmac_sha256(session->auth_key, AUTH_KEY_SIZE,
                    data, offset, full_hmac) != 0) {
        return -1;
    }

    /* Truncate to first 4 bytes */
    memcpy(session->oob_commitment, full_hmac, OOB_COMMITMENT_SIZE);
    sodium_memzero(full_hmac, sizeof(full_hmac));
    return 0;
}

/**
 * Negotiate OOB method between local and remote supported methods.
 * Returns the highest-priority method both sides support.
 */
static enum oob_method negotiate_oob_method(uint8_t local_supported,
                                             uint8_t remote_supported) {
    /* Priority order: QR > NFC > Output > Input > Static */
    const enum oob_method priority[] = {
        OOB_METHOD_QR_CODE,
        OOB_METHOD_NFC_TAP,
        OOB_METHOD_OUTPUT_OOB,
        OOB_METHOD_INPUT_OOB,
        OOB_METHOD_STATIC_OOB
    };

    for (size_t i = 0; i < sizeof(priority) / sizeof(priority[0]); i++) {
        const uint8_t mask = (uint8_t)(1 << priority[i]);
        if ((local_supported & mask) && (remote_supported & mask)) {
            return priority[i];
        }
    }

    return OOB_METHOD_NONE;
}

/**
 * Complete the ECDH handshake: compute shared secret, derive keys,
 * compute OOB commitment, transition to OOB_PENDING.
 */
static int complete_handshake(struct session_manager *mgr,
                              struct encryption_session *session,
                              uint32_t src_id, uint32_t dst_id) {
    uint8_t shared_secret[X25519_SHARED_SECRET_SIZE];

    /* Compute shared secret: X25519(local_private, remote_public) */
    if (ecdh_compute_shared_secret(shared_secret,
                                    session->local_private_key,
                                    session->remote_public_key) != 0) {
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    /* Derive EK and AK */
    const uint8_t *static_token = mgr->has_static_oob_token ? mgr->static_oob_token : NULL;
    const size_t token_len = mgr->has_static_oob_token ? mgr->static_oob_token_len : 0;

    if (derive_session_keys(session, shared_secret, src_id, dst_id,
                            static_token, token_len) != 0) {
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }
    sodium_memzero(shared_secret, sizeof(shared_secret));

    /* Determine which public key is "A" and which is "B" based on who initiated */
    const uint8_t *a_public, *b_public;
    if (session->we_initiated) {
        a_public = session->local_public_key;
        b_public = session->remote_public_key;
    } else {
        a_public = session->remote_public_key;
        b_public = session->local_public_key;
    }

    /* Compute OOB commitment */
    if (compute_oob_commitment(session, a_public, b_public,
                                src_id, dst_id) != 0) {
        return -1;
    }

    /* Transition to OOB_PENDING */
    session->state = SESSION_STATE_OOB_PENDING;

    /* Invoke OOB callback if set */
    if (mgr->oob_display_cb) {
        mgr->oob_display_cb(session->peer_id, session->oob_commitment,
                            session->negotiated_oob_method);
    }

    return 0;
}

/* ========================================================================== */
/* Session Manager Functions                                                   */
/* ========================================================================== */

int session_manager_init(struct session_manager *mgr, uint32_t local_device_id) {
    if (!mgr) return -1;

    memset(mgr, 0, sizeof(*mgr));
    mgr->local_device_id = local_device_id;
    mgr->next_key_id = 1;
    mgr->session_count = 0;
    mgr->oob_display_cb = NULL;
    mgr->has_static_oob_token = 0;
    mgr->static_oob_token_len = 0;

    return 0;
}

void session_manager_cleanup(struct session_manager *mgr) {
    if (!mgr) return;

    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state != SESSION_STATE_EMPTY) {
            crypto_secure_wipe(&mgr->sessions[i], sizeof(struct encryption_session));
        }
    }
    crypto_secure_wipe(mgr->static_oob_token, sizeof(mgr->static_oob_token));
    mgr->session_count = 0;
}

void session_manager_set_oob_callback(struct session_manager *mgr,
                                       oob_display_callback_t callback) {
    if (mgr) {
        mgr->oob_display_cb = callback;
    }
}

int session_manager_set_static_oob_token(struct session_manager *mgr,
                                          const uint8_t *token, size_t token_len) {
    if (!mgr || !token || token_len == 0 || token_len > STATIC_OOB_TOKEN_MAX_SIZE) {
        return -1;
    }

    memcpy(mgr->static_oob_token, token, token_len);
    mgr->static_oob_token_len = token_len;
    mgr->has_static_oob_token = 1;
    return 0;
}

/* ========================================================================== */
/* Session Query Functions                                                     */
/* ========================================================================== */

struct encryption_session *session_find_by_peer(struct session_manager *mgr,
                                                 uint32_t peer_id) {
    if (!mgr) return NULL;
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state != SESSION_STATE_EMPTY &&
            mgr->sessions[i].peer_id == peer_id) {
            return &mgr->sessions[i];
        }
    }
    return NULL;
}

struct encryption_session *session_find_by_key_id(struct session_manager *mgr,
                                                   uint8_t key_id) {
    if (!mgr) return NULL;
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state != SESSION_STATE_EMPTY &&
            mgr->sessions[i].key_id == key_id) {
            return &mgr->sessions[i];
        }
    }
    return NULL;
}

void session_destroy(struct session_manager *mgr, uint32_t peer_id) {
    if (!mgr) return;
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state != SESSION_STATE_EMPTY &&
            mgr->sessions[i].peer_id == peer_id) {
            crypto_secure_wipe(&mgr->sessions[i], sizeof(struct encryption_session));
            mgr->sessions[i].state = SESSION_STATE_EMPTY;
            if (mgr->session_count > 0) mgr->session_count--;
            return;
        }
    }
}

int session_needs_rotation(const struct encryption_session *session,
                           uint32_t current_time) {
    if (!session || session->state != SESSION_STATE_OOB_VERIFIED) return 0;

    /* Check frame counter exhaustion */
    if (session->send_frame_counter >= FRAME_COUNTER_MAX) return 1;

    /* Check session lifetime */
    if (current_time - session->created_at >= SESSION_MAX_LIFETIME_SECONDS) return 1;

    /* Check MAC failure threshold */
    if (session->mac_failure_count >= MAC_FAILURE_THRESHOLD) return 1;

    return 0;
}

size_t session_check_oob_timeouts(struct session_manager *mgr,
                                   uint32_t current_time) {
    if (!mgr) return 0;
    size_t count = 0;

    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state == SESSION_STATE_OOB_PENDING) {
            if (current_time - mgr->sessions[i].created_at >= OOB_TIMEOUT_SECONDS) {
                session_destroy(mgr, mgr->sessions[i].peer_id);
                count++;
            }
        }
    }
    return count;
}

size_t session_check_lifetimes(struct session_manager *mgr,
                                uint32_t current_time) {
    if (!mgr) return 0;
    size_t count = 0;

    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state == SESSION_STATE_OOB_VERIFIED) {
            if (session_needs_rotation(&mgr->sessions[i], current_time)) {
                count++;
            }
        }
    }
    return count;
}

size_t session_get_count(const struct session_manager *mgr) {
    if (!mgr) return 0;
    size_t count = 0;
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state != SESSION_STATE_EMPTY) {
            count++;
        }
    }
    return count;
}

const char *session_state_to_string(enum session_state state) {
    switch (state) {
        case SESSION_STATE_EMPTY:        return "EMPTY";
        case SESSION_STATE_PENDING:      return "PENDING";
        case SESSION_STATE_OOB_PENDING:  return "OOB_PENDING";
        case SESSION_STATE_OOB_VERIFIED: return "OOB_VERIFIED";
        default:                         return "UNKNOWN";
    }
}

const char *oob_method_to_string(enum oob_method method) {
    switch (method) {
        case OOB_METHOD_NONE:       return "NONE";
        case OOB_METHOD_QR_CODE:    return "QR_CODE";
        case OOB_METHOD_NFC_TAP:    return "NFC_TAP";
        case OOB_METHOD_OUTPUT_OOB: return "OUTPUT_OOB";
        case OOB_METHOD_INPUT_OOB:  return "INPUT_OOB";
        case OOB_METHOD_STATIC_OOB: return "STATIC_OOB";
        default:                    return "UNKNOWN";
    }
}

/* ========================================================================== */
/* Key Exchange Functions                                                      */
/* ========================================================================== */

static struct encryption_session *session_allocate(struct session_manager *mgr) {
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (mgr->sessions[i].state == SESSION_STATE_EMPTY) {
            mgr->session_count++;
            return &mgr->sessions[i];
        }
    }
    return NULL;
}

int initiate_key_exchange(struct session_manager *mgr, uint32_t peer_id,
                          struct key_exchange_ext_message *kex_out) {
    if (!mgr || !kex_out || peer_id == 0) return -1;

    /* Check if session already exists */
    struct encryption_session *existing = session_find_by_peer(mgr, peer_id);
    if (existing) {
        /* Tear down old session for re-exchange */
        session_destroy(mgr, peer_id);
    }

    /* Allocate new session */
    struct encryption_session *session = session_allocate(mgr);
    if (!session) return -1;

    memset(session, 0, sizeof(*session));
    session->peer_id = peer_id;
    session->state = SESSION_STATE_PENDING;
    session->key_id = mgr->next_key_id++;
    session->we_initiated = 1;
    session->created_at = (uint32_t)time(NULL);
    session->last_activity = session->created_at;

    /* Default supported OOB methods: all methods */
    session->supported_oob_methods = (1 << OOB_METHOD_QR_CODE) |
                                     (1 << OOB_METHOD_NFC_TAP) |
                                     (1 << OOB_METHOD_OUTPUT_OOB) |
                                     (1 << OOB_METHOD_INPUT_OOB) |
                                     (1 << OOB_METHOD_STATIC_OOB);

    /* Generate ephemeral X25519 key pair */
    if (ecdh_generate_keypair(session->local_public_key,
                              session->local_private_key) != 0) {
        session->state = SESSION_STATE_EMPTY;
        mgr->session_count--;
        return -1;
    }

    /* Build key exchange request message */
    memcpy(kex_out->public_key, session->local_public_key, X25519_KEY_SIZE);
    kex_out->device_id = mgr->local_device_id;
    kex_out->timestamp = session->created_at;
    kex_out->kex_type = KEX_TYPE_REQUEST;
    kex_out->supported_oob_methods = session->supported_oob_methods;
    kex_out->preferred_oob_method = OOB_METHOD_OUTPUT_OOB; /* Default preference */

    return 0;
}

int handle_key_exchange(struct session_manager *mgr, uint32_t peer_id,
                        const struct key_exchange_ext_message *kex_msg,
                        struct key_exchange_ext_message *response_out,
                        int *need_response) {
    if (!mgr || !kex_msg || !need_response) return -1;

    *need_response = 0;

    if (kex_msg->kex_type == KEX_TYPE_REQUEST) {
        /* We received a key exchange request */

        /* Remove any existing session for this peer */
        struct encryption_session *existing = session_find_by_peer(mgr, peer_id);
        if (existing) {
            session_destroy(mgr, peer_id);
        }

        /* Allocate new session */
        struct encryption_session *session = session_allocate(mgr);
        if (!session) return -1;

        memset(session, 0, sizeof(*session));
        session->peer_id = peer_id;
        session->state = SESSION_STATE_PENDING;
        session->key_id = mgr->next_key_id++;
        session->we_initiated = 0;
        session->created_at = (uint32_t)time(NULL);
        session->last_activity = session->created_at;

        /* Store remote public key */
        memcpy(session->remote_public_key, kex_msg->public_key, X25519_KEY_SIZE);

        /* Generate our ephemeral key pair */
        if (ecdh_generate_keypair(session->local_public_key,
                                  session->local_private_key) != 0) {
            session->state = SESSION_STATE_EMPTY;
            mgr->session_count--;
            return -1;
        }

        /* Negotiate OOB method */
        session->supported_oob_methods = (1 << OOB_METHOD_QR_CODE) |
                                         (1 << OOB_METHOD_NFC_TAP) |
                                         (1 << OOB_METHOD_OUTPUT_OOB) |
                                         (1 << OOB_METHOD_INPUT_OOB) |
                                         (1 << OOB_METHOD_STATIC_OOB);

        session->negotiated_oob_method = negotiate_oob_method(
            session->supported_oob_methods, kex_msg->supported_oob_methods);

        /* Complete handshake: compute shared secret, derive keys, compute OOB */
        /* Initiator (A) is the remote node, Responder (B) is us */
        uint32_t src_id = peer_id;
        uint32_t dst_id = mgr->local_device_id;

        if (complete_handshake(mgr, session, src_id, dst_id) != 0) {
            session_destroy(mgr, peer_id);
            return -1;
        }

        /* Build response message */
        if (response_out) {
            memcpy(response_out->public_key, session->local_public_key, X25519_KEY_SIZE);
            response_out->device_id = mgr->local_device_id;
            response_out->timestamp = session->created_at;
            response_out->kex_type = KEX_TYPE_RESPONSE;
            response_out->supported_oob_methods = session->supported_oob_methods;
            response_out->preferred_oob_method = (uint8_t)session->negotiated_oob_method;
            *need_response = 1;
        }

    } else if (kex_msg->kex_type == KEX_TYPE_RESPONSE) {
        /* We received a key exchange response to our request */
        struct encryption_session *session = session_find_by_peer(mgr, peer_id);
        if (!session || session->state != SESSION_STATE_PENDING) {
            return -1; /* No pending session */
        }

        /* Store remote public key */
        memcpy(session->remote_public_key, kex_msg->public_key, X25519_KEY_SIZE);

        /* Negotiate OOB method */
        session->negotiated_oob_method = negotiate_oob_method(
            session->supported_oob_methods, kex_msg->supported_oob_methods);

        /* Complete handshake: we are the initiator (A) */
        uint32_t src_id = mgr->local_device_id;
        uint32_t dst_id = peer_id;

        if (complete_handshake(mgr, session, src_id, dst_id) != 0) {
            session_destroy(mgr, peer_id);
            return -1;
        }
    } else {
        return -1; /* Unknown key exchange type */
    }

    return 0;
}

/* ========================================================================== */
/* OOB Verification Functions                                                  */
/* ========================================================================== */

int verify_oob_code(struct session_manager *mgr, uint32_t peer_id,
                    const uint8_t user_code[OOB_COMMITMENT_SIZE]) {
    if (!mgr || !user_code) return ENC_ERROR_INVALID_PARAMS;

    struct encryption_session *session = session_find_by_peer(mgr, peer_id);
    if (!session) return ENC_ERROR_NO_SESSION;

    if (session->state != SESSION_STATE_OOB_PENDING) {
        return ENC_ERROR_SESSION_UNVERIFIED;
    }

    /* Compare codes using constant-time comparison */
    if (sodium_memcmp(session->oob_commitment, user_code, OOB_COMMITMENT_SIZE) != 0) {
        /* Mismatch: tear down session */
        session_destroy(mgr, peer_id);
        return ENC_ERROR_OOB_MISMATCH;
    }

    /* Match: session is verified */
    session->state = SESSION_STATE_OOB_VERIFIED;
    session->send_frame_counter = 0;
    session->recv_frame_counter = 0;
    session->last_activity = (uint32_t)time(NULL);

    return ENC_SUCCESS;
}

int get_oob_code(struct session_manager *mgr, uint32_t peer_id,
                 uint8_t code_out[OOB_COMMITMENT_SIZE]) {
    if (!mgr || !code_out) return -1;

    struct encryption_session *session = session_find_by_peer(mgr, peer_id);
    if (!session || session->state != SESSION_STATE_OOB_PENDING) {
        return -1;
    }

    memcpy(code_out, session->oob_commitment, OOB_COMMITMENT_SIZE);
    return 0;
}

/* ========================================================================== */
/* Frame Encryption                                                            */
/* ========================================================================== */

/**
 * Build IV: nonce (7 bytes) || frame_counter (4 bytes) || padding (5 bytes zeros)
 */
static void build_iv(const uint8_t nonce[NONCE_SIZE], uint32_t frame_counter,
                     uint8_t iv[AES128_IV_SIZE]) {
    memcpy(iv, nonce, NONCE_SIZE);
    iv[7]  = (frame_counter >> 24) & 0xFF;
    iv[8]  = (frame_counter >> 16) & 0xFF;
    iv[9]  = (frame_counter >> 8) & 0xFF;
    iv[10] = frame_counter & 0xFF;
    memset(iv + 11, 0, 5); /* padding */
}

/**
 * Compute MAC: HMAC-SHA256(AK, header || network || encrypted_payload || frame_counter)[0:12]
 */
static int compute_mac(const uint8_t *auth_key,
                       const uint8_t *header_data, size_t header_len,
                       const uint8_t *network_data, size_t network_len,
                       const uint8_t *encrypted_payload, size_t encrypted_len,
                       uint32_t frame_counter,
                       uint8_t mac_out[HMAC_SHA256_TRUNCATED_SIZE]) {
    /* Build mac_input: header || network || encrypted_payload || frame_counter */
    const size_t total_len = header_len + network_len + encrypted_len + 4;
    uint8_t *mac_input = malloc(total_len);
    if (!mac_input) return -1;

    size_t offset = 0;
    memcpy(mac_input + offset, header_data, header_len);
    offset += header_len;
    memcpy(mac_input + offset, network_data, network_len);
    offset += network_len;
    memcpy(mac_input + offset, encrypted_payload, encrypted_len);
    offset += encrypted_len;
    mac_input[offset++] = (frame_counter >> 24) & 0xFF;
    mac_input[offset++] = (frame_counter >> 16) & 0xFF;
    mac_input[offset++] = (frame_counter >> 8) & 0xFF;
    mac_input[offset++] = frame_counter & 0xFF;

    const int ret = hmac_sha256_truncated(auth_key, AUTH_KEY_SIZE,
                                          mac_input, total_len,
                                          mac_out);
    free(mac_input);
    return ret;
}

int encrypt_frame(struct session_manager *mgr,
                  uint32_t destination_id,
                  const uint8_t *header_data, size_t header_len,
                  const uint8_t *network_data, size_t network_len,
                  const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t **ciphertext_out, size_t *ciphertext_len_out,
                  struct security_block *security_out) {
    if (!mgr || !header_data || !network_data || !plaintext || !ciphertext_out ||
        !ciphertext_len_out || !security_out) {
        return ENC_ERROR_INVALID_PARAMS;
    }

    /* Find session */
    struct encryption_session *session = session_find_by_peer(mgr, destination_id);
    if (!session) return ENC_ERROR_NO_SESSION;

    /* Check session state */
    if (session->state != SESSION_STATE_OOB_VERIFIED) {
        return ENC_ERROR_SESSION_UNVERIFIED;
    }

    /* Check if key rotation is needed */
    if (session->send_frame_counter >= FRAME_COUNTER_MAX) {
        return ENC_ERROR_KEY_ROTATION_NEEDED;
    }

    /* Generate nonce */
    uint8_t nonce[NONCE_SIZE];
    crypto_random_bytes(nonce, NONCE_SIZE);

    /* Build IV */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(nonce, session->send_frame_counter, iv);

    /* Allocate ciphertext buffer */
    uint8_t *ciphertext = malloc(plaintext_len);
    if (!ciphertext) return ENC_ERROR_INTERNAL;

    /* Encrypt */
    if (aes128_ctr_crypt(session->encryption_key, iv,
                         plaintext, plaintext_len, ciphertext) != 0) {
        free(ciphertext);
        return ENC_ERROR_ENCRYPT_FAILURE;
    }

    /* Compute MAC */
    uint8_t mac[HMAC_SHA256_TRUNCATED_SIZE];
    if (compute_mac(session->auth_key,
                    header_data, header_len,
                    network_data, network_len,
                    ciphertext, plaintext_len,
                    session->send_frame_counter,
                    mac) != 0) {
        free(ciphertext);
        return ENC_ERROR_INTERNAL;
    }

    /* Fill security block */
    security_out->key_id = session->key_id;
    security_out->frame_counter = session->send_frame_counter;
    memcpy(security_out->nonce, nonce, NONCE_SIZE);
    memcpy(security_out->mac, mac, HMAC_SHA256_TRUNCATED_SIZE);

    /* Output ciphertext */
    *ciphertext_out = ciphertext;
    *ciphertext_len_out = plaintext_len;

    /* Advance counter */
    session->send_frame_counter++;
    session->last_activity = (uint32_t)time(NULL);

    return ENC_SUCCESS;
}

/* ========================================================================== */
/* Frame Decryption                                                            */
/* ========================================================================== */

int decrypt_frame(struct session_manager *mgr,
                  uint32_t source_id,
                  const uint8_t *header_data, size_t header_len,
                  const uint8_t *network_data, size_t network_len,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const struct security_block *security,
                  uint8_t **plaintext_out, size_t *plaintext_len_out) {
    if (!mgr || !header_data || !network_data || !ciphertext || !security ||
        !plaintext_out || !plaintext_len_out) {
        return ENC_ERROR_INVALID_PARAMS;
    }

    /* Session lookup */
    struct encryption_session *session = session_find_by_peer(mgr, source_id);
    if (!session) return ENC_ERROR_NO_SESSION;

    /* OOB verification gate */
    if (session->state != SESSION_STATE_OOB_VERIFIED) {
        return ENC_ERROR_SESSION_UNVERIFIED;
    }

    /* Replay protection */
    if (security->frame_counter != session->recv_frame_counter) {
        return ENC_ERROR_COUNTER_MISMATCH;
    }

    /* Verify MAC */
    uint8_t expected_mac[HMAC_SHA256_TRUNCATED_SIZE];
    if (compute_mac(session->auth_key,
                    header_data, header_len,
                    network_data, network_len,
                    ciphertext, ciphertext_len,
                    security->frame_counter,
                    expected_mac) != 0) {
        return ENC_ERROR_INTERNAL;
    }

    if (sodium_memcmp(expected_mac, security->mac, HMAC_SHA256_TRUNCATED_SIZE) != 0) {
        session->mac_failure_count++;
        return ENC_ERROR_MAC_FAILURE;
    }

    /* Reset MAC failure count on success */
    session->mac_failure_count = 0;

    /* Build IV for decryption */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(security->nonce, security->frame_counter, iv);

    /* Allocate plaintext buffer */
    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) return ENC_ERROR_INTERNAL;

    /* Decrypt */
    if (aes128_ctr_crypt(session->encryption_key, iv,
                         ciphertext, ciphertext_len, plaintext) != 0) {
        free(plaintext);
        return ENC_ERROR_DECRYPT_FAILURE;
    }

    /* Output */
    *plaintext_out = plaintext;
    *plaintext_len_out = ciphertext_len;

    /* Advance expected counter */
    session->recv_frame_counter++;
    session->last_activity = (uint32_t)time(NULL);

    return ENC_SUCCESS;
}

/* ========================================================================== */
/* Extended Key Exchange Message Serialization                                 */
/* ========================================================================== */

size_t serialize_key_exchange_ext(const struct key_exchange_ext_message *kex,
                                  uint8_t *buffer, size_t buffer_size) {
    if (!kex || !buffer || buffer_size < KEY_EXCHANGE_EXT_SIZE) return 0;

    size_t offset = 0;

    /* public_key: 32 bytes */
    memcpy(buffer + offset, kex->public_key, X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;

    /* device_id: 4 bytes big-endian */
    buffer[offset++] = (kex->device_id >> 24) & 0xFF;
    buffer[offset++] = (kex->device_id >> 16) & 0xFF;
    buffer[offset++] = (kex->device_id >> 8) & 0xFF;
    buffer[offset++] = kex->device_id & 0xFF;

    /* timestamp: 4 bytes big-endian */
    buffer[offset++] = (kex->timestamp >> 24) & 0xFF;
    buffer[offset++] = (kex->timestamp >> 16) & 0xFF;
    buffer[offset++] = (kex->timestamp >> 8) & 0xFF;
    buffer[offset++] = kex->timestamp & 0xFF;

    /* kex_type: 1 byte */
    buffer[offset++] = kex->kex_type;

    /* supported_oob_methods: 1 byte */
    buffer[offset++] = kex->supported_oob_methods;

    /* preferred_oob_method: 1 byte */
    buffer[offset++] = kex->preferred_oob_method;

    return offset;
}

int parse_key_exchange_ext(const uint8_t *buffer, size_t buffer_size,
                           struct key_exchange_ext_message *kex) {
    if (!buffer || !kex || buffer_size < KEY_EXCHANGE_EXT_SIZE) return -1;

    size_t offset = 0;

    /* public_key: 32 bytes */
    memcpy(kex->public_key, buffer + offset, X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;

    /* device_id: 4 bytes big-endian */
    kex->device_id = ((uint32_t)buffer[offset] << 24) |
                     ((uint32_t)buffer[offset + 1] << 16) |
                     ((uint32_t)buffer[offset + 2] << 8) |
                     buffer[offset + 3];
    offset += 4;

    /* timestamp: 4 bytes big-endian */
    kex->timestamp = ((uint32_t)buffer[offset] << 24) |
                     ((uint32_t)buffer[offset + 1] << 16) |
                     ((uint32_t)buffer[offset + 2] << 8) |
                     buffer[offset + 3];
    offset += 4;

    /* kex_type: 1 byte */
    kex->kex_type = buffer[offset++];

    /* supported_oob_methods: 1 byte */
    kex->supported_oob_methods = buffer[offset++];

    /* preferred_oob_method: 1 byte */
    kex->preferred_oob_method = buffer[offset++];

    return 0;
}
