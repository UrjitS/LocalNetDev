/**
 * test_encryption.c - Unit tests for E2E encryption module
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "encryption.h"

#define TEST_PASS() printf("  PASS\n")
#define TEST_FAIL(msg) do { printf("  FAIL: %s\n", msg); failures++; } while(0)

static int failures = 0;

// ==========================================================================
// Test: crypto_init                                                           
// ==========================================================================
static void test_crypto_init(void) {
    printf("[TEST] crypto_init...");
    assert(crypto_init() == 0);
    TEST_PASS();
}

// ==========================================================================
// Test: X25519 key generation                                                 
// ==========================================================================
static void test_ecdh_generate_keypair(void) {
    printf("[TEST] ecdh_generate_keypair...");

    uint8_t pub[X25519_KEY_SIZE], priv[X25519_KEY_SIZE];
    assert(ecdh_generate_keypair(pub, priv) == 0);

    // Keys should not be all zeros 
    uint8_t zeros[X25519_KEY_SIZE] = {0};
    assert(memcmp(pub, zeros, X25519_KEY_SIZE) != 0);
    assert(memcmp(priv, zeros, X25519_KEY_SIZE) != 0);

    // Two keypairs should be different 
    uint8_t pub2[X25519_KEY_SIZE], priv2[X25519_KEY_SIZE];
    assert(ecdh_generate_keypair(pub2, priv2) == 0);
    assert(memcmp(pub, pub2, X25519_KEY_SIZE) != 0);

    TEST_PASS();
}

// ==========================================================================
// Test: X25519 shared secret agreement                                        
// ==========================================================================
static void test_ecdh_shared_secret(void) {
    printf("[TEST] ecdh_compute_shared_secret...");

    uint8_t pub_a[X25519_KEY_SIZE], priv_a[X25519_KEY_SIZE];
    uint8_t pub_b[X25519_KEY_SIZE], priv_b[X25519_KEY_SIZE];
    uint8_t secret_a[X25519_SHARED_SECRET_SIZE], secret_b[X25519_SHARED_SECRET_SIZE];

    assert(ecdh_generate_keypair(pub_a, priv_a) == 0);
    assert(ecdh_generate_keypair(pub_b, priv_b) == 0);

    // Both sides compute the same shared secret 
    assert(ecdh_compute_shared_secret(secret_a, priv_a, pub_b) == 0);
    assert(ecdh_compute_shared_secret(secret_b, priv_b, pub_a) == 0);

    assert(memcmp(secret_a, secret_b, X25519_SHARED_SECRET_SIZE) == 0);

    // Shared secret should not be all zeros 
    uint8_t zeros[X25519_SHARED_SECRET_SIZE] = {0};
    assert(memcmp(secret_a, zeros, X25519_SHARED_SECRET_SIZE) != 0);

    TEST_PASS();
}

// ==========================================================================
// Test: HKDF-SHA256                                                           
// ==========================================================================
static void test_hkdf_sha256(void) {
    printf("[TEST] hkdf_sha256...");

    uint8_t ikm[32];
    memset(ikm, 0x0b, 32);

    uint8_t okm1[32], okm2[32];
    const char *info1 = "test1";
    const char *info2 = "test2";

    assert(hkdf_sha256(ikm, 32, (const uint8_t *)info1, strlen(info1), okm1, 32) == 0);
    assert(hkdf_sha256(ikm, 32, (const uint8_t *)info2, strlen(info2), okm2, 32) == 0);

    // Different info should produce different output 
    assert(memcmp(okm1, okm2, 32) != 0);

    // Same input should produce same output 
    uint8_t okm3[32];
    assert(hkdf_sha256(ikm, 32, (const uint8_t *)info1, strlen(info1), okm3, 32) == 0);
    assert(memcmp(okm1, okm3, 32) == 0);

    // Different output lengths 
    uint8_t okm_short[16];
    assert(hkdf_sha256(ikm, 32, (const uint8_t *)info1, strlen(info1), okm_short, 16) == 0);
    assert(memcmp(okm1, okm_short, 16) == 0); /* First 16 bytes should match */

    TEST_PASS();
}

// ==========================================================================
// Test: AES-128-CTR encrypt/decrypt                                           
// ==========================================================================
static void test_aes128_ctr(void) {
    printf("[TEST] aes128_ctr_crypt...");

    uint8_t key[AES128_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t iv[AES128_IV_SIZE] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    const char *plaintext = "Hello, World! This is a test of AES-128-CTR encryption.";
    const size_t len = strlen(plaintext);

    uint8_t ciphertext[256], decrypted[256];

    // Encrypt 
    assert(aes128_ctr_crypt(key, iv, (const uint8_t *)plaintext, len, ciphertext) == 0);

    // Ciphertext should differ from plaintext 
    assert(memcmp(plaintext, ciphertext, len) != 0);

    // Decrypt (CTR mode: encrypt again = decrypt) 
    assert(aes128_ctr_crypt(key, iv, ciphertext, len, decrypted) == 0);

    // Should recover original plaintext 
    assert(memcmp(plaintext, decrypted, len) == 0);

    TEST_PASS();
}

// ==========================================================================
// Test: HMAC-SHA256                                                           
// ==========================================================================
static void test_hmac_sha256(void) {
    printf("[TEST] hmac_sha256...");

    uint8_t key[16] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const char *data = "test data for HMAC";

    uint8_t mac1[HMAC_SHA256_SIZE], mac2[HMAC_SHA256_SIZE];

    assert(hmac_sha256(key, 16, (const uint8_t *)data, strlen(data), mac1) == 0);
    assert(hmac_sha256(key, 16, (const uint8_t *)data, strlen(data), mac2) == 0);

    // Same input -> same output 
    assert(memcmp(mac1, mac2, HMAC_SHA256_SIZE) == 0);

    // Different data -> different output 
    const char *data2 = "different data";
    assert(hmac_sha256(key, 16, (const uint8_t *)data2, strlen(data2), mac2) == 0);
    assert(memcmp(mac1, mac2, HMAC_SHA256_SIZE) != 0);

    TEST_PASS();
}

// ==========================================================================
// Test: HMAC-SHA256 truncated                                                 
// ==========================================================================
static void test_hmac_sha256_truncated(void) {
    printf("[TEST] hmac_sha256_truncated...");

    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const char *data = "test data";

    uint8_t full[HMAC_SHA256_SIZE], trunc[HMAC_SHA256_TRUNCATED_SIZE];

    assert(hmac_sha256(key, 16, (const uint8_t *)data, strlen(data), full) == 0);
    assert(hmac_sha256_truncated(key, 16, (const uint8_t *)data, strlen(data), trunc) == 0);

    // Truncated should be first 12 bytes of full 
    assert(memcmp(full, trunc, HMAC_SHA256_TRUNCATED_SIZE) == 0);

    TEST_PASS();
}

// ==========================================================================
// Test: Session Manager init/cleanup                                          
// ==========================================================================
static void test_session_manager_init(void) {
    printf("[TEST] session_manager_init...");

    struct session_manager mgr;
    assert(session_manager_init(&mgr, 0x12345678) == 0);
    assert(mgr.local_device_id == 0x12345678);
    assert(mgr.session_count == 0);
    assert(session_get_count(&mgr) == 0);

    session_manager_cleanup(&mgr);

    TEST_PASS();
}

// ==========================================================================
// Test: Key exchange handshake between two nodes                              
// ==========================================================================
static void test_key_exchange_handshake(void) {
    printf("[TEST] key_exchange_handshake...");

    const uint32_t node_a_id = 0xAAAA0001;
    const uint32_t node_b_id = 0xBBBB0002;

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, node_a_id) == 0);
    assert(session_manager_init(&mgr_b, node_b_id) == 0);

    // Step 1: Node A initiates key exchange 
    struct key_exchange_ext_message kex_request;
    assert(initiate_key_exchange(&mgr_a, node_b_id, &kex_request) == 0);

    // Verify session A is PENDING 
    struct encryption_session *sess_a = session_find_by_peer(&mgr_a, node_b_id);
    assert(sess_a != NULL);
    assert(sess_a->state == SESSION_STATE_PENDING);

    // Step 2: Node B receives request and generates response 
    struct key_exchange_ext_message kex_response;
    int need_response = 0;
    assert(handle_key_exchange(&mgr_b, node_a_id, &kex_request,
                               &kex_response, &need_response) == 0);
    assert(need_response == 1);

    // Node B should be in OOB_PENDING state 
    struct encryption_session *sess_b = session_find_by_peer(&mgr_b, node_a_id);
    assert(sess_b != NULL);
    assert(sess_b->state == SESSION_STATE_OOB_PENDING);

    // Step 3: Node A receives response 
    int need_response_2 = 0;
    assert(handle_key_exchange(&mgr_a, node_b_id, &kex_response,
                               NULL, &need_response_2) == 0);
    assert(need_response_2 == 0);

    // Node A should be in OOB_PENDING state 
    sess_a = session_find_by_peer(&mgr_a, node_b_id);
    assert(sess_a != NULL);
    assert(sess_a->state == SESSION_STATE_OOB_PENDING);

    // Step 4: Verify both nodes computed the same OOB commitment 
    uint8_t code_a[OOB_COMMITMENT_SIZE], code_b[OOB_COMMITMENT_SIZE];
    assert(get_oob_code(&mgr_a, node_b_id, code_a) == 0);
    assert(get_oob_code(&mgr_b, node_a_id, code_b) == 0);
    assert(memcmp(code_a, code_b, OOB_COMMITMENT_SIZE) == 0);

    printf("OOB code: %02X%02X%02X%02X ", code_a[0], code_a[1], code_a[2], code_a[3]);

    // Step 5: Verify OOB on both sides 
    assert(verify_oob_code(&mgr_a, node_b_id, code_a) == ENC_SUCCESS);
    assert(verify_oob_code(&mgr_b, node_a_id, code_b) == ENC_SUCCESS);

    // Both should be OOB_VERIFIED 
    sess_a = session_find_by_peer(&mgr_a, node_b_id);
    sess_b = session_find_by_peer(&mgr_b, node_a_id);
    assert(sess_a->state == SESSION_STATE_OOB_VERIFIED);
    assert(sess_b->state == SESSION_STATE_OOB_VERIFIED);

    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Test: OOB mismatch tears down session                                       
// ==========================================================================
static void test_oob_mismatch(void) {
    printf("[TEST] oob_mismatch...");

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, 0x1111) == 0);
    assert(session_manager_init(&mgr_b, 0x2222) == 0);

    struct key_exchange_ext_message kex_req, kex_resp;
    assert(initiate_key_exchange(&mgr_a, 0x2222, &kex_req) == 0);

    int need_resp = 0;
    assert(handle_key_exchange(&mgr_b, 0x1111, &kex_req, &kex_resp, &need_resp) == 0);
    assert(handle_key_exchange(&mgr_a, 0x2222, &kex_resp, NULL, &need_resp) == 0);

    // Provide wrong OOB code 
    uint8_t wrong_code[OOB_COMMITMENT_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF};
    int result = verify_oob_code(&mgr_a, 0x2222, wrong_code);
    assert(result == ENC_ERROR_OOB_MISMATCH);

    // Session should be destroyed 
    assert(session_find_by_peer(&mgr_a, 0x2222) == NULL);

    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Test: Frame encrypt and decrypt roundtrip                                   
// ==========================================================================
static void test_frame_encrypt_decrypt(void) {
    printf("[TEST] frame_encrypt_decrypt...");

    const uint32_t node_a_id = 0xAAAA1111;
    const uint32_t node_b_id = 0xBBBB2222;

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, node_a_id) == 0);
    assert(session_manager_init(&mgr_b, node_b_id) == 0);

    // Complete key exchange 
    struct key_exchange_ext_message kex_req, kex_resp;
    assert(initiate_key_exchange(&mgr_a, node_b_id, &kex_req) == 0);
    int need_resp = 0;
    assert(handle_key_exchange(&mgr_b, node_a_id, &kex_req, &kex_resp, &need_resp) == 0);
    assert(handle_key_exchange(&mgr_a, node_b_id, &kex_resp, NULL, &need_resp) == 0);

    // Verify OOB 
    uint8_t code[OOB_COMMITMENT_SIZE];
    assert(get_oob_code(&mgr_a, node_b_id, code) == 0);
    assert(verify_oob_code(&mgr_a, node_b_id, code) == ENC_SUCCESS);
    assert(verify_oob_code(&mgr_b, node_a_id, code) == ENC_SUCCESS);

    // Prepare test data 
    const char *message = "Hello secure world!";
    const size_t msg_len = strlen(message);

    uint8_t header_data[8] = {0x10, 0x00, 0x01, 0x0F, 0x00, 0x13, 0x00, 0x01};
    uint8_t network_data[8];
    network_data[0] = (node_a_id >> 24) & 0xFF;
    network_data[1] = (node_a_id >> 16) & 0xFF;
    network_data[2] = (node_a_id >> 8) & 0xFF;
    network_data[3] = node_a_id & 0xFF;
    network_data[4] = (node_b_id >> 24) & 0xFF;
    network_data[5] = (node_b_id >> 16) & 0xFF;
    network_data[6] = (node_b_id >> 8) & 0xFF;
    network_data[7] = node_b_id & 0xFF;

    // Encrypt on Node A 
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    struct security_block sec;

    int enc_result = encrypt_frame(&mgr_a, node_b_id,
                                    header_data, 8,
                                    network_data, 8,
                                    (const uint8_t *)message, msg_len,
                                    &ciphertext, &ciphertext_len, &sec);
    assert(enc_result == ENC_SUCCESS);
    assert(ciphertext != NULL);
    assert(ciphertext_len == msg_len);

    // Ciphertext should differ from plaintext 
    assert(memcmp(ciphertext, message, msg_len) != 0);

    // Decrypt on Node B 
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;

    int dec_result = decrypt_frame(&mgr_b, node_a_id,
                                    header_data, 8,
                                    network_data, 8,
                                    ciphertext, ciphertext_len,
                                    &sec,
                                    &decrypted, &decrypted_len);
    assert(dec_result == ENC_SUCCESS);
    assert(decrypted != NULL);
    assert(decrypted_len == msg_len);
    assert(memcmp(decrypted, message, msg_len) == 0);

    free(ciphertext);
    free(decrypted);

    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Test: Replay protection                                                     
// ==========================================================================
static void test_replay_protection(void) {
    printf("[TEST] replay_protection...");

    const uint32_t node_a_id = 0xAAAA3333;
    const uint32_t node_b_id = 0xBBBB4444;

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, node_a_id) == 0);
    assert(session_manager_init(&mgr_b, node_b_id) == 0);

    // Complete key exchange and verify OOB 
    struct key_exchange_ext_message kex_req, kex_resp;
    assert(initiate_key_exchange(&mgr_a, node_b_id, &kex_req) == 0);
    int need_resp = 0;
    assert(handle_key_exchange(&mgr_b, node_a_id, &kex_req, &kex_resp, &need_resp) == 0);
    assert(handle_key_exchange(&mgr_a, node_b_id, &kex_resp, NULL, &need_resp) == 0);
    uint8_t code[OOB_COMMITMENT_SIZE];
    assert(get_oob_code(&mgr_a, node_b_id, code) == 0);
    assert(verify_oob_code(&mgr_a, node_b_id, code) == ENC_SUCCESS);
    assert(verify_oob_code(&mgr_b, node_a_id, code) == ENC_SUCCESS);

    uint8_t header_data[8] = {0};
    uint8_t network_data[8] = {0};
    const char *msg = "Test replay";

    // Encrypt a frame 
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    struct security_block sec;
    assert(encrypt_frame(&mgr_a, node_b_id, header_data, 8, network_data, 8,
                         (const uint8_t *)msg, strlen(msg), &ct, &ct_len, &sec) == ENC_SUCCESS);

    // First decrypt should succeed 
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    assert(decrypt_frame(&mgr_b, node_a_id, header_data, 8, network_data, 8,
                         ct, ct_len, &sec, &pt, &pt_len) == ENC_SUCCESS);
    free(pt);

    // Replaying same frame should fail (counter mismatch) 
    pt = NULL;
    int result = decrypt_frame(&mgr_b, node_a_id, header_data, 8, network_data, 8,
                                ct, ct_len, &sec, &pt, &pt_len);
    assert(result == ENC_ERROR_COUNTER_MISMATCH);
    assert(pt == NULL);

    free(ct);
    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Test: MAC tamper detection                                                  
// ==========================================================================
static void test_mac_tamper_detection(void) {
    printf("[TEST] mac_tamper_detection...");

    const uint32_t node_a_id = 0xAAAA5555;
    const uint32_t node_b_id = 0xBBBB6666;

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, node_a_id) == 0);
    assert(session_manager_init(&mgr_b, node_b_id) == 0);

    struct key_exchange_ext_message kex_req, kex_resp;
    assert(initiate_key_exchange(&mgr_a, node_b_id, &kex_req) == 0);
    int need_resp = 0;
    assert(handle_key_exchange(&mgr_b, node_a_id, &kex_req, &kex_resp, &need_resp) == 0);
    assert(handle_key_exchange(&mgr_a, node_b_id, &kex_resp, NULL, &need_resp) == 0);
    uint8_t code[OOB_COMMITMENT_SIZE];
    assert(get_oob_code(&mgr_a, node_b_id, code) == 0);
    assert(verify_oob_code(&mgr_a, node_b_id, code) == ENC_SUCCESS);
    assert(verify_oob_code(&mgr_b, node_a_id, code) == ENC_SUCCESS);

    uint8_t header_data[8] = {0};
    uint8_t network_data[8] = {0};

    uint8_t *ct = NULL;
    size_t ct_len = 0;
    struct security_block sec;
    assert(encrypt_frame(&mgr_a, node_b_id, header_data, 8, network_data, 8,
                         (const uint8_t *)"test", 4, &ct, &ct_len, &sec) == ENC_SUCCESS);

    // Tamper with MAC 
    sec.mac[0] ^= 0xFF;

    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int result = decrypt_frame(&mgr_b, node_a_id, header_data, 8, network_data, 8,
                                ct, ct_len, &sec, &pt, &pt_len);
    assert(result == ENC_ERROR_MAC_FAILURE);

    free(ct);
    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Test: Session needs rotation                                                
// ==========================================================================
static void test_session_rotation(void) {
    printf("[TEST] session_needs_rotation...");

    struct encryption_session session = {0};
    session.state = SESSION_STATE_OOB_VERIFIED;
    session.created_at = 1000;
    session.send_frame_counter = 0;
    session.mac_failure_count = 0;

    // Fresh session: no rotation needed 
    assert(session_needs_rotation(&session, 1001) == 0);

    // Counter exhaustion 
    session.send_frame_counter = FRAME_COUNTER_MAX;
    assert(session_needs_rotation(&session, 1001) == 1);
    session.send_frame_counter = 0;

    // Lifetime expired 
    assert(session_needs_rotation(&session, 1000 + SESSION_MAX_LIFETIME_SECONDS + 1) == 1);

    // MAC failure threshold 
    session.mac_failure_count = MAC_FAILURE_THRESHOLD;
    assert(session_needs_rotation(&session, 1001) == 1);

    TEST_PASS();
}

// ==========================================================================
// Test: Static OOB token                                                      
// ==========================================================================
static void test_static_oob(void) {
    printf("[TEST] static_oob_token...");

    const uint32_t node_a_id = 0xAAAA7777;
    const uint32_t node_b_id = 0xBBBB8888;

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, node_a_id) == 0);
    assert(session_manager_init(&mgr_b, node_b_id) == 0);

    // Set same static OOB token on both sides 
    const uint8_t token[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    assert(session_manager_set_static_oob_token(&mgr_a, token, sizeof(token)) == 0);
    assert(session_manager_set_static_oob_token(&mgr_b, token, sizeof(token)) == 0);

    // Complete handshake 
    struct key_exchange_ext_message kex_req, kex_resp;
    assert(initiate_key_exchange(&mgr_a, node_b_id, &kex_req) == 0);
    int need_resp = 0;
    assert(handle_key_exchange(&mgr_b, node_a_id, &kex_req, &kex_resp, &need_resp) == 0);
    assert(handle_key_exchange(&mgr_a, node_b_id, &kex_resp, NULL, &need_resp) == 0);

    // OOB codes should still match (static token folded into HKDF) 
    uint8_t code_a[OOB_COMMITMENT_SIZE], code_b[OOB_COMMITMENT_SIZE];
    assert(get_oob_code(&mgr_a, node_b_id, code_a) == 0);
    assert(get_oob_code(&mgr_b, node_a_id, code_b) == 0);
    assert(memcmp(code_a, code_b, OOB_COMMITMENT_SIZE) == 0);

    // Verify and test E2E 
    assert(verify_oob_code(&mgr_a, node_b_id, code_a) == ENC_SUCCESS);
    assert(verify_oob_code(&mgr_b, node_a_id, code_b) == ENC_SUCCESS);

    uint8_t header_data[8] = {0};
    uint8_t network_data[8] = {0};
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    struct security_block sec;
    assert(encrypt_frame(&mgr_a, node_b_id, header_data, 8, network_data, 8,
                         (const uint8_t *)"secret", 6, &ct, &ct_len, &sec) == ENC_SUCCESS);

    uint8_t *pt = NULL;
    size_t pt_len = 0;
    assert(decrypt_frame(&mgr_b, node_a_id, header_data, 8, network_data, 8,
                         ct, ct_len, &sec, &pt, &pt_len) == ENC_SUCCESS);
    assert(memcmp(pt, "secret", 6) == 0);

    free(ct);
    free(pt);
    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Test: Static OOB mismatch between nodes                                     
// ==========================================================================
static void test_static_oob_mismatch(void) {
    printf("[TEST] static_oob_mismatch...");

    const uint32_t node_a_id = 0xCCCC1111;
    const uint32_t node_b_id = 0xDDDD2222;

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, node_a_id) == 0);
    assert(session_manager_init(&mgr_b, node_b_id) == 0);

    // Different static OOB tokens 
    const uint8_t token_a[] = {0xAA, 0xAA, 0xAA, 0xAA};
    const uint8_t token_b[] = {0xBB, 0xBB, 0xBB, 0xBB};
    assert(session_manager_set_static_oob_token(&mgr_a, token_a, sizeof(token_a)) == 0);
    assert(session_manager_set_static_oob_token(&mgr_b, token_b, sizeof(token_b)) == 0);

    struct key_exchange_ext_message kex_req, kex_resp;
    assert(initiate_key_exchange(&mgr_a, node_b_id, &kex_req) == 0);
    int need_resp = 0;
    assert(handle_key_exchange(&mgr_b, node_a_id, &kex_req, &kex_resp, &need_resp) == 0);
    assert(handle_key_exchange(&mgr_a, node_b_id, &kex_resp, NULL, &need_resp) == 0);

    // OOB codes should NOT match (different static tokens) 
    uint8_t code_a[OOB_COMMITMENT_SIZE], code_b[OOB_COMMITMENT_SIZE];
    assert(get_oob_code(&mgr_a, node_b_id, code_a) == 0);
    assert(get_oob_code(&mgr_b, node_a_id, code_b) == 0);
    assert(memcmp(code_a, code_b, OOB_COMMITMENT_SIZE) != 0);

    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Test: Key exchange ext serialization                                        
// ==========================================================================
static void test_kex_serialization(void) {
    printf("[TEST] kex_ext_serialization...");

    struct key_exchange_ext_message kex = {0};
    memset(kex.public_key, 0xAB, X25519_KEY_SIZE);
    kex.device_id = 0xDEADBEEF;
    kex.timestamp = 0x12345678;
    kex.kex_type = KEX_TYPE_REQUEST;
    kex.supported_oob_methods = 0x1F;
    kex.preferred_oob_method = OOB_METHOD_OUTPUT_OOB;

    uint8_t buffer[64];
    size_t written = serialize_key_exchange_ext(&kex, buffer, sizeof(buffer));
    assert(written == KEY_EXCHANGE_EXT_SIZE);

    struct key_exchange_ext_message parsed = {0};
    assert(parse_key_exchange_ext(buffer, written, &parsed) == 0);

    assert(memcmp(parsed.public_key, kex.public_key, X25519_KEY_SIZE) == 0);
    assert(parsed.device_id == kex.device_id);
    assert(parsed.timestamp == kex.timestamp);
    assert(parsed.kex_type == kex.kex_type);
    assert(parsed.supported_oob_methods == kex.supported_oob_methods);
    assert(parsed.preferred_oob_method == kex.preferred_oob_method);

    TEST_PASS();
}

// ==========================================================================
// Test: Unverified session blocks data                                        
// ==========================================================================
static void test_unverified_session_blocks_data(void) {
    printf("[TEST] unverified_session_blocks_data...");

    struct session_manager mgr;
    assert(session_manager_init(&mgr, 0x1111) == 0);

    // Create a session but don't complete OOB 
    struct key_exchange_ext_message kex_req;
    assert(initiate_key_exchange(&mgr, 0x2222, &kex_req) == 0);

    // Try to encrypt - should fail (session is PENDING, not OOB_VERIFIED) 
    uint8_t hdr[8] = {0}, net[8] = {0};
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    struct security_block sec;

    int result = encrypt_frame(&mgr, 0x2222, hdr, 8, net, 8,
                                (const uint8_t *)"test", 4, &ct, &ct_len, &sec);
    assert(result == ENC_ERROR_SESSION_UNVERIFIED);

    session_manager_cleanup(&mgr);
    TEST_PASS();
}

// ==========================================================================
// Test: Multiple sequential frames                                            
// ==========================================================================
static void test_multiple_frames(void) {
    printf("[TEST] multiple_frames...");

    const uint32_t node_a = 0xAAAA9999;
    const uint32_t node_b = 0xBBBB0000;

    struct session_manager mgr_a, mgr_b;
    assert(session_manager_init(&mgr_a, node_a) == 0);
    assert(session_manager_init(&mgr_b, node_b) == 0);

    // Full handshake + OOB 
    struct key_exchange_ext_message kex_req, kex_resp;
    assert(initiate_key_exchange(&mgr_a, node_b, &kex_req) == 0);
    int nr = 0;
    assert(handle_key_exchange(&mgr_b, node_a, &kex_req, &kex_resp, &nr) == 0);
    assert(handle_key_exchange(&mgr_a, node_b, &kex_resp, NULL, &nr) == 0);
    uint8_t code[OOB_COMMITMENT_SIZE];
    assert(get_oob_code(&mgr_a, node_b, code) == 0);
    assert(verify_oob_code(&mgr_a, node_b, code) == ENC_SUCCESS);
    assert(verify_oob_code(&mgr_b, node_a, code) == ENC_SUCCESS);

    uint8_t hdr[8] = {0}, net[8] = {0};

    // Send multiple frames 
    for (int i = 0; i < 10; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Message #%d", i);

        uint8_t *ct = NULL;
        size_t ct_len = 0;
        struct security_block sec;
        assert(encrypt_frame(&mgr_a, node_b, hdr, 8, net, 8,
                             (const uint8_t *)msg, strlen(msg), &ct, &ct_len, &sec) == ENC_SUCCESS);

        assert(sec.frame_counter == (uint32_t)i);

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        assert(decrypt_frame(&mgr_b, node_a, hdr, 8, net, 8,
                             ct, ct_len, &sec, &pt, &pt_len) == ENC_SUCCESS);
        assert(memcmp(pt, msg, strlen(msg)) == 0);

        free(ct);
        free(pt);
    }

    // Verify counters advanced 
    struct encryption_session *sa = session_find_by_peer(&mgr_a, node_b);
    struct encryption_session *sb = session_find_by_peer(&mgr_b, node_a);
    assert(sa->send_frame_counter == 10);
    assert(sb->recv_frame_counter == 10);

    session_manager_cleanup(&mgr_a);
    session_manager_cleanup(&mgr_b);

    TEST_PASS();
}

// ==========================================================================
// Main                                                                        
// ==========================================================================
int main(void) {
    printf("==============================================\n");
    printf("LocalNet E2E Encryption Tests\n");
    printf("==============================================\n\n");

    test_crypto_init();
    test_ecdh_generate_keypair();
    test_ecdh_shared_secret();
    test_hkdf_sha256();
    test_aes128_ctr();
    test_hmac_sha256();
    test_hmac_sha256_truncated();
    test_session_manager_init();
    test_key_exchange_handshake();
    test_oob_mismatch();
    test_frame_encrypt_decrypt();
    test_replay_protection();
    test_mac_tamper_detection();
    test_session_rotation();
    test_static_oob();
    test_static_oob_mismatch();
    test_kex_serialization();
    test_unverified_session_blocks_data();
    test_multiple_frames();

    printf("\n==============================================\n");
    if (failures == 0) {
        printf("All tests PASSED!\n");
    } else {
        printf("%d test(s) FAILED!\n", failures);
    }
    printf("==============================================\n");

    return failures;
}

