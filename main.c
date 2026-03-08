#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "bluetooth/bluetooth.h"
#include "protocol/protocol.h"
#include "routing/routing.h"
#include "utils/utils.h"
#include "encryption/encryption.h"
#include "logger.h"

#define TAG "LOCALNET"

static ble_node_manager_t * g_ble_manager = NULL;
static volatile gboolean g_running = TRUE;
static uint32_t g_device_id = 0;
static struct session_manager g_session_mgr;

typedef void (*menu_command_handler)(void);

typedef struct {
    const char * key;
    const char * description;
    menu_command_handler handler;
} menu_command_t;

// Command handlers
static void cmd_show_connections(void);
static void cmd_show_node_info(void);
static void cmd_show_routes(void);
static void cmd_discover_route(void);
static void cmd_send_message(void);
static void cmd_show_pending_packets(void);
static void cmd_initiate_key_exchange(void);
static void cmd_show_sessions(void);
static void cmd_verify_oob(void);
static void cmd_set_static_oob(void);
static void cmd_show_help(void);
static void cmd_quit(void);

static const menu_command_t g_menu_commands[] = {
    { "1", "Show connection table",       cmd_show_connections },
    { "2", "Show Node info",              cmd_show_node_info },
    { "3", "Show routing table",          cmd_show_routes },
    { "4", "Discover route to node",      cmd_discover_route },
    { "5", "Send message to node",        cmd_send_message },
    { "6", "Show pending packets",        cmd_show_pending_packets },
    { "7", "Initiate key exchange",       cmd_initiate_key_exchange },
    { "8", "Show encryption sessions",    cmd_show_sessions },
    { "9", "Verify OOB code",            cmd_verify_oob },
    { "0", "Set static OOB token",       cmd_set_static_oob },
    { "h", "Show help",                   cmd_show_help },
    { "q", "Quit",                        cmd_quit },
    { NULL, NULL, NULL }
};

static void cmd_show_connections(void) {
    if (g_ble_manager) {
        ble_print_connection_table(g_ble_manager);
    } else {
        fprintf(stderr, "Error: BLE Manager not initialized\n");
    }
}

static void cmd_show_node_info(void) {
    if (!g_ble_manager) {
        fprintf(stderr, "Error: BLE Manager not initialized\n");
        return;
    }

    printf("\n");
    printf("--------------------------------------------------------------------\n");
    printf("NODE INFORMATION\n");
    printf("\n");
    printf("\t Device ID: 0x%08X \n", g_device_id);
    printf("\t Connected Nodes: %-49u \n", ble_get_connected_count(g_ble_manager));
    printf("--------------------------------------------------------------------\n");
    printf("\n");
}

static void cmd_show_routes(void) {
    if (!g_ble_manager) {
        fprintf(stderr, "Error: BLE Manager not initialized\n");
        return;
    }

    struct mesh_node * node = ble_get_mesh_node(g_ble_manager);
    if (!node || !node->routing_table) {
        fprintf(stderr, "Error: Routing table not available\n");
        return;
    }

    printf("\n");
    printf("--------------------------------------------------------------------\n");
    printf("ROUTING TABLE\n");
    printf("--------------------------------------------------------------------\n");
    printf("\t %-12s %-12s %-6s %-8s %-8s\n", "Destination", "Next Hop", "Hops", "Cost", "Valid");
    printf("--------------------------------------------------------------------\n");

    const struct routing_table * rt = node->routing_table;
    size_t valid_count = 0;

    for (size_t i = 0; i < rt->count; i++) {
        const struct routing_entry * entry = &rt->entries[i];
        if (entry->destination_id == 0) continue;

        const char * valid_str = entry->is_valid ? "Yes" : "No";
        printf("\t 0x%08X   0x%08X   %-6u %-8.2f %-8s\n",
               entry->destination_id,
               entry->next_hop,
               entry->hop_count,
               entry->route_cost,
               valid_str);

        if (entry->is_valid) valid_count++;
    }

    if (rt->count == 0) {
        printf("\t (no routes exist)\n");
    }

    printf("--------------------------------------------------------------------\n");
    printf("\t Total: %zu routes (%zu valid)\n", rt->count, valid_count);
    printf("--------------------------------------------------------------------\n");
    printf("\n");
}

static void cmd_discover_route(void) {
    if (!g_ble_manager) {
        fprintf(stderr, "Error: BLE Manager not initialized\n");
        return;
    }

    printf("Enter destination node ID (e.g., 0x12345678): ");
    fflush(stdout);

    char input[32];
    if (read_stdin_line(input, sizeof(input)) != 0) {
        fprintf(stderr, "Error reading input\n");
        return;
    }

    uint32_t dest_id;
    if (parse_node_id(input, &dest_id) != 0) {
        fprintf(stderr, "Invalid node ID format. Use hex format like 0x12345678\n");
        return;
    }

    if (validate_destination_id(dest_id, g_device_id) != 0) {
        fprintf(stderr, "Invalid destination (cannot be 0 or self)\n");
        return;
    }

    printf("Initiating route discovery for 0x%08X\n", dest_id);
    const uint32_t request_id = ble_initiate_route_discovery(g_ble_manager, dest_id);

    if (request_id > 0) {
        printf("Route discovery initiated (request ID: 0x%08X)\n", request_id);
    } else {
        printf("Route discovery failed or route already exists.\n");
    }
}

static void cmd_send_message(void) {
    if (!g_ble_manager) {
        fprintf(stderr, "Error: BLE Manager not initialized\n");
        return;
    }

    printf("Enter destination node ID (e.g., 0x12345678): ");
    fflush(stdout);

    char input[256];
    if (read_stdin_line(input, sizeof(input)) != 0) {
        fprintf(stderr, "Error reading input\n");
        return;
    }

    uint32_t dest_id;
    if (parse_node_id(input, &dest_id) != 0) {
        fprintf(stderr, "Invalid node ID format. Use hex format like 0x12345678\n");
        return;
    }

    if (validate_destination_id(dest_id, g_device_id) != 0) {
        fprintf(stderr, "Invalid destination (cannot be 0 or self)\n");
        return;
    }

    printf("Enter message: ");
    fflush(stdout);

    char message[200];
    if (read_stdin_line(message, sizeof(message)) != 0) {
        fprintf(stderr, "Error reading message\n");
        return;
    }

    if (strlen(message) == 0) {
        fprintf(stderr, "Message cannot be empty\n");
        return;
    }

    printf("Sending message to 0x%08X: \"%s\"\n", dest_id, message);

    const uint16_t seq = ble_send_message(g_ble_manager, dest_id, (const uint8_t *)message, strlen(message));

    if (seq > 0) {
        printf("Message queued for transmission (sequence: %u)\n", seq);
    } else {
        printf("Failed to queue message.\n");
    }
}

static void cmd_show_pending_packets(void) {
    if (!g_ble_manager) {
        fprintf(stderr, "Error: BLE Manager not initialized\n");
        return;
    }

    struct mesh_node * node = ble_get_mesh_node(g_ble_manager);
    if (!node || !node->packet_queue) {
        fprintf(stderr, "Error: Packet queue not available\n");
        return;
    }

    printf("\n");
    printf("--------------------------------------------------------------------\n");
    printf("PENDING PACKETS\n");
    printf("--------------------------------------------------------------------\n");
    printf("\t %-6s %-12s %-15s %-8s %-10s\n", "Seq", "Destination", "State", "Retries", "Interval");
    printf("--------------------------------------------------------------------\n");

    const struct pending_packet_queue * queue = node->packet_queue;
    size_t pending_count = 0;

    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        const struct pending_packet * pkt = &queue->packets[i];
        if (pkt->state == PACKET_STATE_EMPTY) continue;

        const char * state_str;
        switch (pkt->state) {
            case PACKET_STATE_AWAITING_ROUTE: state_str = "AWAITING_ROUTE"; break;
            case PACKET_STATE_AWAITING_ACK: state_str = "AWAITING_ACK"; break;
            case PACKET_STATE_DELIVERED: state_str = "DELIVERED"; break;
            case PACKET_STATE_FAILED: state_str = "FAILED"; break;
            default: state_str = "UNKNOWN"; break;
        }

        printf("\t %-6u 0x%08X   %-15s %-8u %-10u ms\n",
               pkt->sequence_number,
               pkt->destination_id,
               state_str,
               pkt->retry_count,
               pkt->retry_interval_ms);

        if (pkt->state == PACKET_STATE_AWAITING_ROUTE ||
            pkt->state == PACKET_STATE_AWAITING_ACK) {
            pending_count++;
        }
    }

    if (queue->count == 0) {
        printf("\t (no pending packets)\n");
    }

    printf("--------------------------------------------------------------------\n");
    printf("\t Total: %zu pending, Next seq: %u\n", pending_count, queue->next_sequence_number);
    printf("--------------------------------------------------------------------\n");
    printf("\n");
}

/* ========================================================================== */
/* OOB Display Callback                                                        */
/* ========================================================================== */

/**
 * Default OOB display callback.
 * Displays the OOB short code on the terminal.
 * Users should replace this with their own implementation
 * (e.g., QR code display, LED blink pattern, NFC write).
 */
static void on_oob_display(uint32_t peer_id,
                           const uint8_t short_code[OOB_COMMITMENT_SIZE],
                           enum oob_method method) {
    printf("\n");
    printf("************************************************************\n");
    printf("  OOB VERIFICATION REQUIRED\n");
    printf("************************************************************\n");
    printf("  Peer Node:  0x%08X\n", peer_id);
    printf("  OOB Method: %s\n", oob_method_to_string(method));
    printf("  Short Code: %02X%02X%02X%02X\n",
           short_code[0], short_code[1], short_code[2], short_code[3]);
    printf("\n");
    printf("  Verify this code matches on the peer device.\n");
    printf("  Then use menu option [9] to confirm.\n");
    printf("************************************************************\n");
    printf("\n");
}

/* ========================================================================== */
/* Encryption Menu Commands                                                    */
/* ========================================================================== */

static void cmd_initiate_key_exchange(void) {
    if (!g_ble_manager) {
        fprintf(stderr, "Error: BLE Manager not initialized\n");
        return;
    }

    printf("Enter peer node ID (e.g., 0x12345678): ");
    fflush(stdout);

    char input[32];
    if (read_stdin_line(input, sizeof(input)) != 0) {
        fprintf(stderr, "Error reading input\n");
        return;
    }

    uint32_t peer_id;
    if (parse_node_id(input, &peer_id) != 0) {
        fprintf(stderr, "Invalid node ID format. Use hex format like 0x12345678\n");
        return;
    }

    if (validate_destination_id(peer_id, g_device_id) != 0) {
        fprintf(stderr, "Invalid destination (cannot be 0 or self)\n");
        return;
    }

    printf("Initiating key exchange with 0x%08X...\n", peer_id);

    if (ble_initiate_key_exchange(g_ble_manager, peer_id) == 0) {
        printf("Key exchange request sent to 0x%08X\n", peer_id);
    } else {
        printf("Failed to initiate key exchange.\n");
    }
}

static void cmd_show_sessions(void) {
    printf("\n");
    printf("--------------------------------------------------------------------\n");
    printf("ENCRYPTION SESSIONS\n");
    printf("--------------------------------------------------------------------\n");
    printf("\t %-12s %-14s %-12s %-8s %-8s\n",
           "Peer", "State", "OOB Method", "TX Cnt", "RX Cnt");
    printf("--------------------------------------------------------------------\n");

    size_t count = 0;
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        const struct encryption_session * session = &g_session_mgr.sessions[i];
        if (session->state == SESSION_STATE_EMPTY) continue;

        printf("\t 0x%08X   %-14s %-12s %-8u %-8u\n",
               session->peer_id,
               session_state_to_string(session->state),
               oob_method_to_string(session->negotiated_oob_method),
               session->send_frame_counter,
               session->recv_frame_counter);
        count++;
    }

    if (count == 0) {
        printf("\t (no active sessions)\n");
    }

    printf("--------------------------------------------------------------------\n");
    printf("\t Total: %zu session(s)\n", count);
    printf("--------------------------------------------------------------------\n");
    printf("\n");
}

static void cmd_verify_oob(void) {
    printf("Enter peer node ID (e.g., 0x12345678): ");
    fflush(stdout);

    char input[32];
    if (read_stdin_line(input, sizeof(input)) != 0) {
        fprintf(stderr, "Error reading input\n");
        return;
    }

    uint32_t peer_id;
    if (parse_node_id(input, &peer_id) != 0) {
        fprintf(stderr, "Invalid node ID format. Use hex format like 0x12345678\n");
        return;
    }

    // Show the local OOB code for reference
    uint8_t local_code[OOB_COMMITMENT_SIZE];
    if (get_oob_code(&g_session_mgr, peer_id, local_code) == 0) {
        printf("Local OOB code: %02X%02X%02X%02X\n",
               local_code[0], local_code[1], local_code[2], local_code[3]);
    } else {
        fprintf(stderr, "No OOB_PENDING session found for 0x%08X\n", peer_id);
        return;
    }

    printf("Enter OOB code from peer (8 hex digits, e.g., A1B2C3D4): ");
    fflush(stdout);

    char code_input[32];
    if (read_stdin_line(code_input, sizeof(code_input)) != 0) {
        fprintf(stderr, "Error reading input\n");
        return;
    }

    // Parse hex code
    if (strlen(code_input) != 8) {
        fprintf(stderr, "OOB code must be exactly 8 hex digits\n");
        return;
    }

    uint8_t user_code[OOB_COMMITMENT_SIZE];
    for (int i = 0; i < OOB_COMMITMENT_SIZE; i++) {
        char byte_str[3] = { code_input[i * 2], code_input[i * 2 + 1], '\0' };
        char *end_ptr;
        const unsigned long val = strtoul(byte_str, &end_ptr, 16);
        if (*end_ptr != '\0') {
            fprintf(stderr, "Invalid hex character in OOB code\n");
            return;
        }
        user_code[i] = (uint8_t)val;
    }

    const int result = verify_oob_code(&g_session_mgr, peer_id, user_code);
    switch (result) {
        case ENC_SUCCESS:
            printf("OOB verification successful! Session with 0x%08X is now VERIFIED.\n", peer_id);
            break;
        case ENC_ERROR_OOB_MISMATCH:
            printf("OOB verification FAILED! Codes do not match.\n");
            printf("Session has been torn down. Please re-initiate key exchange.\n");
            break;
        case ENC_ERROR_NO_SESSION:
            printf("No session found for 0x%08X\n", peer_id);
            break;
        default:
            printf("OOB verification error: %d\n", result);
            break;
    }
}

static void cmd_set_static_oob(void) {
    printf("Enter static OOB token (hex string, e.g., DEADBEEF01020304): ");
    fflush(stdout);

    char input[256];
    if (read_stdin_line(input, sizeof(input)) != 0) {
        fprintf(stderr, "Error reading input\n");
        return;
    }

    const size_t hex_len = strlen(input);
    if (hex_len == 0 || hex_len % 2 != 0 || hex_len > STATIC_OOB_TOKEN_MAX_SIZE * 2) {
        fprintf(stderr, "Invalid token: must be even-length hex string (max %d bytes)\n",
                STATIC_OOB_TOKEN_MAX_SIZE);
        return;
    }

    const size_t token_len = hex_len / 2;
    uint8_t token[STATIC_OOB_TOKEN_MAX_SIZE];

    for (size_t i = 0; i < token_len; i++) {
        char byte_str[3] = { input[i * 2], input[i * 2 + 1], '\0' };
        char *end_ptr;
        const unsigned long val = strtoul(byte_str, &end_ptr, 16);
        if (*end_ptr != '\0') {
            fprintf(stderr, "Invalid hex character at position %zu\n", i * 2);
            return;
        }
        token[i] = (uint8_t)val;
    }

    if (session_manager_set_static_oob_token(&g_session_mgr, token, token_len) == 0) {
        printf("Static OOB token set (%zu bytes)\n", token_len);
    } else {
        fprintf(stderr, "Failed to set static OOB token\n");
    }
}

static void cmd_show_help(void) {
    printf("\n");
    printf("--------------------------------------------------------------------\n");
    printf("LOCALNET COMMANDS\n");
    printf("--------------------------------------------------------------------\n");

    for (int i = 0; g_menu_commands[i].key != NULL; i++) {
        printf("\t [%s] %-60s\n", g_menu_commands[i].key, g_menu_commands[i].description);
    }

    printf("--------------------------------------------------------------------\n");
    printf("\n");
}

static void cmd_quit(void) {
    printf("Quitting...\n");
    g_running = FALSE;
    if (g_ble_manager) {
        ble_quit_loop(g_ble_manager);
    }
}

// Process Command input
static void process_command(const char * input) {
    while (*input && isspace(*input)) input++;

    if (*input == '\0') return;

    for (int i = 0; g_menu_commands[i].key != NULL; i++) {
        if (g_ascii_strcasecmp(input, g_menu_commands[i].key) == 0) {
            g_menu_commands[i].handler();
            return;
        }
    }

    printf("Unknown command: '%s'. Press 'h' for help.\n", input);
}

static gboolean stdin_callback(GIOChannel * source, const GIOCondition condition, gpointer data) {
    if (condition & G_IO_IN) {
        gchar * line = NULL;
        gsize length;
        GError * error = NULL;

        if (g_io_channel_read_line(source, &line, &length, NULL, &error) == G_IO_STATUS_NORMAL) {
            if (line) {
                line[strcspn(line, "\n\r")] = '\0';
                process_command(line);
                g_free(line);
            }
        }

        if (error) {
            g_error_free(error);
        }
    }

    return TRUE;
}

void usage(const char * program_name) {
    printf("--------------------------------------------------------------------\n");
    printf("LocalNet Mesh Node\n");
    printf("--------------------------------------------------------------------\n");
    printf("Usage: %s [options]\n\n", program_name);
    printf("Options:\n");
    printf("\t -t, --type <type>   Node type: 0=EDGE, 1=FULL (default), 2=GATEWAY\n");
    printf("\t -v, --verbose       Enable verbose logging\n");
    printf("\t -h, --help          Show help message\n\n");
}

static void signal_handler(const int sig_no) {
    if (sig_no == SIGINT || sig_no == SIGTERM) {
        log_info(TAG, "Received signal %d, shutting down...", sig_no);
        if (g_ble_manager) {
            ble_quit_loop(g_ble_manager);
        }
    }
}

static void on_node_discovered(const uint32_t node_id, const int16_t rssi) {
    log_info(TAG, "Discovered Node: 0x%08X (RSSI: %d dBm)", node_id, rssi);
}

static void on_node_connected(const uint32_t node_id) {
    log_info(TAG, "Connected to Node: 0x%08X", node_id);

    if (g_ble_manager) {
        const guint connected = ble_get_connected_count(g_ble_manager);
        log_info(TAG, "Total connected Nodes: %d", connected);
    }
}

static void on_node_disconnected(const uint32_t node_id) {
    log_info(TAG, "Disconnected from Node: 0x%08X", node_id);

    if (g_ble_manager) {
        const struct mesh_node * node = ble_get_mesh_node(g_ble_manager);
        if (node) {
            // Invalidate all routes that use this node
            if (node->routing_table) {
                const size_t invalidated = invalidate_routes_via_node(node->routing_table, node_id);
                if (invalidated > 0) {
                    log_info(TAG, "Invalidated %zu routes via disconnected node 0x%08X", invalidated, node_id);
                }
            }

            // Remove from connection table
            if (node->connection_table) {
                remove_connection(node->connection_table, node_id);
            }
        }

        const guint connected = ble_get_connected_count(g_ble_manager);
        log_info(TAG, "Remaining connected Nodes: %d", connected);
    }
}

static void on_data_received(const uint32_t sender_id, const uint8_t * data, const size_t len) {
    log_info(TAG, "Received %zu bytes from Node 0x%08X", len, sender_id);

    struct header hdr;
    if (parse_header(data, len, &hdr) == 0) {
        switch (hdr.message_type) {
            case MSG_DISCOVERY:
                log_info(TAG, "Received discovery message");
                break;
            case MSG_HEARTBEAT:
                log_info(TAG, "Received heartbeat from 0x%08X", sender_id);
                break;
            case MSG_DATA: {
                struct network net;
                if (len >= 16 && parse_network(data + 8, len - 8, &net) == 0) {
                    const size_t payload_offset = 16;
                    const size_t payload_len = hdr.payload_length;
                    const size_t expected_unencrypted = payload_offset + payload_len;
                    const size_t expected_encrypted = expected_unencrypted + 24; // 24 = security block size

                    if (payload_offset + payload_len > len) {
                        log_error(TAG, "Invalid payload length in data message");
                        break;
                    }

                    const uint8_t * raw_payload = data + payload_offset;

                    // Check if frame has a security block appended (encrypted)
                    if (len >= expected_encrypted) {
                        // Parse the security block
                        struct security sec;
                        if (parse_security(data + expected_unencrypted, len - expected_unencrypted, &sec) != 0) {
                            log_error(TAG, "Failed to parse security block");
                            break;
                        }

                        // Build the security_block for the encryption module
                        struct security_block sec_block = {
                            .key_id = sec.key_id,
                            .frame_counter = sec.frame_counter,
                        };
                        memcpy(sec_block.nonce, sec.nonce, 7);
                        memcpy(sec_block.mac, sec.mac, 12);

                        // Serialize header and network for MAC verification
                        uint8_t header_bytes[8];
                        uint8_t network_bytes[8];
                        memcpy(header_bytes, data, 8);
                        memcpy(network_bytes, data + 8, 8);

                        // Decrypt the payload
                        uint8_t * plaintext = NULL;
                        size_t plaintext_len = 0;
                        int dec_result = decrypt_frame(&g_session_mgr, net.source_id,
                                                       header_bytes, sizeof(header_bytes),
                                                       network_bytes, sizeof(network_bytes),
                                                       raw_payload, payload_len,
                                                       &sec_block,
                                                       &plaintext, &plaintext_len);

                        if (dec_result != ENC_SUCCESS) {
                            log_error(TAG, "Failed to decrypt message from 0x%08X (error: %d)",
                                      net.source_id, dec_result);
                            break;
                        }

                        // Display decrypted message
                        printf("\n\xF0\x9F\x94\x92 ENCRYPTED MESSAGE FROM 0x%08X\n", net.source_id);
                        printf("\tSequence: %u\n", hdr.sequence_number);
                        printf("\tTTL: %u\n", hdr.time_to_live);
                        printf("\tLength: %zu bytes (encrypted)\n", plaintext_len);
                        printf("\tFrame Counter: %u\n", sec_block.frame_counter);

                        // Print as string if printable, otherwise hex dump
                        int is_printable = 1;
                        for (size_t i = 0; i < plaintext_len; i++) {
                            if (plaintext[i] < 32 && plaintext[i] != '\n' && plaintext[i] != '\r' && plaintext[i] != '\t') {
                                if (plaintext[i] != 0 || i < plaintext_len - 1) {
                                    is_printable = 0;
                                    break;
                                }
                            }
                        }

                        if (is_printable) {
                            printf("\tMessage: %.*s\n", (int)plaintext_len, plaintext);
                        } else {
                            printf("\tData (hex): ");
                            for (size_t i = 0; i < plaintext_len; i++) {
                                printf("%02X ", plaintext[i]);
                                if ((i + 1) % 16 == 0 && i + 1 < plaintext_len) printf("\n\t            ");
                            }
                            printf("\n");
                        }

                        printf("\n");
                        free(plaintext);
                    } else {
                        // Unencrypted message (no security block)
                        printf("\nMESSAGE FROM 0x%08X\n", net.source_id);
                        printf("\tSequence: %u\n", hdr.sequence_number);
                        printf("\tTTL: %u\n", hdr.time_to_live);
                        printf("\tLength: %zu bytes\n", payload_len);

                        // Print as string if printable, otherwise hex dump
                        int is_printable = 1;
                        for (size_t i = 0; i < payload_len; i++) {
                            if (raw_payload[i] < 32 && raw_payload[i] != '\n' && raw_payload[i] != '\r' && raw_payload[i] != '\t') {
                                if (raw_payload[i] != 0 || i < payload_len - 1) {
                                    is_printable = 0;
                                    break;
                                }
                            }
                        }

                        if (is_printable) {
                            printf("\tMessage: %.*s\n", (int)payload_len, raw_payload);
                        } else {
                            printf("\tData (hex): ");
                            for (size_t i = 0; i < payload_len; i++) {
                                printf("%02X ", raw_payload[i]);
                                if ((i + 1) % 16 == 0 && i + 1 < payload_len) printf("\n\t            ");
                            }
                            printf("\n");
                        }

                        printf("\n");
                    }
                }
                log_info(TAG, "Received data message from 0x%08X", sender_id);
                break;
            }
            case MSG_KEY_EXCHANGE: {
                log_info(TAG, "Received key exchange message from 0x%08X", sender_id);

                if (hdr.payload_length < KEY_EXCHANGE_EXT_SIZE || len < 16 + KEY_EXCHANGE_EXT_SIZE) {
                    log_error(TAG, "Key exchange message too short");
                    break;
                }

                struct key_exchange_ext_message kex_msg;
                if (parse_key_exchange_ext(data + 16, hdr.payload_length, &kex_msg) != 0) {
                    log_error(TAG, "Failed to parse key exchange message");
                    break;
                }

                struct key_exchange_ext_message response;
                int need_response = 0;

                if (handle_key_exchange(&g_session_mgr, sender_id,
                                        &kex_msg, &response, &need_response) != 0) {
                    log_error(TAG, "Failed to handle key exchange from 0x%08X", sender_id);
                    break;
                }

                if (need_response && g_ble_manager) {
                    // Serialize and send response
                    uint8_t resp_payload[KEY_EXCHANGE_EXT_SIZE];
                    const size_t resp_len = serialize_key_exchange_ext(&response, resp_payload,
                                                                      sizeof(resp_payload));
                    if (resp_len > 0) {
                        struct header resp_hdr = {
                            .protocol_version = 1,
                            .message_type = MSG_KEY_EXCHANGE,
                            .fragmentation_flag = 0,
                            .fragmentation_number = 0,
                            .total_fragments = 1,
                            .time_to_live = 15,
                            .payload_length = (uint16_t)resp_len,
                            .sequence_number = 0
                        };

                        struct network resp_net = {
                            .source_id = g_device_id,
                            .destination_id = sender_id
                        };

                        struct packet resp_pkt = {
                            .header = &resp_hdr,
                            .network = &resp_net,
                            .payload = resp_payload,
                            .security = NULL
                        };

                        uint8_t resp_buffer[256];
                        const size_t total = serialize_packet(&resp_pkt, resp_buffer,
                                                             sizeof(resp_buffer));
                        if (total > 0) {
                            ble_send_data(g_ble_manager, sender_id, resp_buffer, total);
                            log_info(TAG, "Key exchange response sent to 0x%08X", sender_id);
                        }
                    }
                }

                log_info(TAG, "Key exchange with 0x%08X: session in %s state",
                         sender_id,
                         session_state_to_string(
                             session_find_by_peer(&g_session_mgr, sender_id)
                                 ? session_find_by_peer(&g_session_mgr, sender_id)->state
                                 : SESSION_STATE_EMPTY));
                break;
            }
            default:
                log_info(TAG, "Received unknown message type: %d", hdr.message_type);
                break;
        }
    }
}

// NOLINTNEXTLINE
static int get_adapter_address(char * address, size_t len) {
    GDBusConnection * dbus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (!dbus) return -1;

    Adapter * adapter = binc_adapter_get_default(dbus);
    if (!adapter) {
        g_object_unref(dbus);
        return -1;
    }

    const char * addr = binc_adapter_get_address(adapter);
    if (addr) {
        strncpy(address, addr, len - 1);
        address[len - 1] = '\0';
    }

    binc_adapter_free(adapter);

    g_object_unref(dbus);

    return addr ? 0 : -1;
}


int main(const int argc, char * argv[]) {
    enum NODE_TYPE node_type = FULL_NODE;
    int verbose = 0;

    static struct option long_options[] = {
        {"type",    required_argument, 0, 't'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "t:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 't': {
                const long type_val = strtol(optarg, NULL, 10);
                if (type_val >= 0 && type_val <= 2) {
                    node_type = (enum NODE_TYPE)type_val;
                } else {
                    fprintf(stderr, "Invalid node type: %s (must be 0, 1, or 2)\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'v':
                verbose = 1;
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    // Enable logging
    log_enabled(TRUE);
    log_set_level(verbose ? LOG_DEBUG : LOG_INFO);

    log_debug(TAG, "LocalNet starting");

    // Initialize crypto library
    if (crypto_init() != 0) {
        log_error(TAG, "Failed to initialize crypto library");
        return EXIT_FAILURE;
    }

    // Get adapter MAC address
    char mac_address[18] = {0};
    if (get_adapter_address(mac_address, sizeof(mac_address)) != 0) {
        log_error(TAG, "Failed to get Bluetooth adapter address");
        return EXIT_FAILURE;
    }

    // Convert MAC to device ID
    g_device_id = mac_to_device_id(mac_address);
    if (g_device_id == 0) {
        log_error(TAG, "Failed to parse MAC address: %s", mac_address);
        return EXIT_FAILURE;
    }

    log_info(TAG, "Starting LocalNet Node:");
    log_info(TAG, "\t Adapter: %s", mac_address);
    log_info(TAG, "\t Device ID: 0x%08X", g_device_id);
    log_info(TAG, "\t Node Type: %s", node_type_to_string(node_type));
    log_info(TAG, "\t Max Connections: %d", get_max_connections(node_type));

    // Setup signal handlers
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        log_error(TAG, "Cannot set SIGINT handler");
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        log_error(TAG, "Cannot set SIGTERM handler");
    }
    struct mesh_node * mesh_node = create_mesh_node(g_device_id, node_type);

    // Initialize BLE node manager with callbacks
    g_ble_manager = ble_init(mesh_node, g_device_id,
                              on_node_discovered,
                              on_node_connected,
                              on_node_disconnected,
                              on_data_received);
    if (!g_ble_manager) {
        log_error(TAG, "Failed to initialize BLE node manager");
        return EXIT_FAILURE;
    }

    // Initialize encryption session manager
    if (session_manager_init(&g_session_mgr, g_device_id) != 0) {
        log_error(TAG, "Failed to initialize encryption session manager");
        ble_cleanup(g_ble_manager);
        return EXIT_FAILURE;
    }
    session_manager_set_oob_callback(&g_session_mgr, on_oob_display);
    ble_set_session_manager(g_ble_manager, &g_session_mgr);
    log_info(TAG, "Encryption session manager initialized");

    // Start the BLE node
    if (!ble_start(g_ble_manager)) {
        log_error(TAG, "Failed to start BLE node manager");
        ble_cleanup(g_ble_manager);
        return EXIT_FAILURE;
    }

    log_info(TAG, "Node is running");
    log_info(TAG, "Advertising as: LocalNet-%08X", g_device_id);
    log_info(TAG, "Initiating Scanning");

    // Set up stdin input handling for menu commands
    GIOChannel * stdin_channel = g_io_channel_unix_new(STDIN_FILENO);
    g_io_channel_set_encoding(stdin_channel, NULL, NULL);
    g_io_channel_set_buffered(stdin_channel, TRUE);
    const guint stdin_watch_id = g_io_add_watch(stdin_channel, G_IO_IN, stdin_callback, NULL);

    // Run the main loop
    ble_run_loop(g_ble_manager);

    // Cleanup stdin channel
    g_source_remove(stdin_watch_id);
    g_io_channel_unref(stdin_channel);

    // Cleanup
    log_info(TAG, "Shutting down");
    session_manager_cleanup(&g_session_mgr);
    ble_cleanup(g_ble_manager);
    g_ble_manager = NULL;

    log_info(TAG, "LocalNet Node stopped");
    return EXIT_SUCCESS;
}
