#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include "bluetooth.h"
#include "protocol.h"
#include "logger.h"
#include "utils.h"
#include "routing.h"

/* Global BLE manager for signal handler */
static ble_node_manager_t *g_ble_manager = NULL;

void usage(const char *program_name) {
    printf("LocalNet Mesh Node\n");
    printf("==================\n\n");
    printf("Usage: %s [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -t, --type <type>   Node type: 0=EDGE, 1=FULL (default), 2=GATEWAY\n");
    printf("  -v, --verbose       Enable verbose logging\n");
    printf("  -h, --help          Show this help message\n\n");
    printf("Example:\n");
    printf("  %s                  # Start as a FULL node (default)\n", program_name);
    printf("  %s -t 2             # Start as a GATEWAY node\n", program_name);
    printf("  %s -t 0 -v          # Start as EDGE node with verbose logging\n\n", program_name);
}

/* Signal handler for graceful shutdown */
static void signal_handler(const int sig_no) {
    if (sig_no == SIGINT || sig_no == SIGTERM) {
        log_info(TAG, "Received signal %d, shutting down...", sig_no);
        if (g_ble_manager) {
            ble_quit_main_loop(g_ble_manager);
        }
    }
}

/* Callback: Node discovered */
static void on_node_discovered(uint32_t node_id, int8_t rssi) {
    log_info(TAG, "Discovered node: 0x%08X (RSSI: %d dBm)", node_id, rssi);
}

/* Callback: Node connected */
static void on_node_connected(uint32_t node_id) {
    log_info(TAG, "Connected to node: 0x%08X", node_id);

    if (g_ble_manager) {
        int connected = ble_get_connected_count(g_ble_manager);
        log_info(TAG, "Total connected nodes: %d", connected);
    }
}

/* Callback: Node disconnected */
static void on_node_disconnected(uint32_t node_id) {
    log_info(TAG, "Disconnected from node: 0x%08X", node_id);

    if (g_ble_manager) {
        int connected = ble_get_connected_count(g_ble_manager);
        log_info(TAG, "Remaining connected nodes: %d", connected);
    }
}

/* Callback: Data received */
static void on_data_received(uint32_t sender_id, const uint8_t *data, size_t len) {
    log_debug(TAG, "Received %zu bytes from node 0x%08X", len, sender_id);

    /* Parse the header to determine message type */
    if (len >= sizeof(struct header)) {
        struct header hdr;
        if (parse_header(data, len, &hdr) == 0) {
            switch (hdr.message_type) {
                case MSG_DISCOVERY:
                    log_debug(TAG, "Received discovery message");
                    break;
                case MSG_HEARTBEAT:
                    log_debug(TAG, "Received heartbeat from 0x%08X", sender_id);
                    break;
                case MSG_DATA:
                    log_debug(TAG, "Received data message");
                    break;
                case MSG_ROUTE_REQUEST:
                    log_debug(TAG, "Received route request");
                    break;
                case MSG_ROUTE_REPLY:
                    log_debug(TAG, "Received route reply");
                    break;
                default:
                    log_debug(TAG, "Received unknown message type: %d", hdr.message_type);
                    break;
            }
        }
    }
}

const char *node_type_to_string(enum NODE_TYPE type) {
    switch (type) {
        case EDGE_NODE: return "EDGE";
        case FULL_NODE: return "FULL";
        case GATEWAY_NODE: return "GATEWAY";
        default: return "UNKNOWN";
    }
}

/* Convert MAC address to 32-bit device ID (uses last 4 bytes) */
static uint32_t mac_to_device_id(const char *mac) {
    unsigned int bytes[6];
    if (sscanf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) != 6) {
        return 0;
    }
    /* Use last 4 bytes of MAC for unique 32-bit ID */
    return (bytes[2] << 24) | (bytes[3] << 16) | (bytes[4] << 8) | bytes[5];
}

int main(int argc, char *argv[]) {
    enum NODE_TYPE node_type = FULL_NODE;  /* Default to FULL */
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
                long type_val = strtol(optarg, NULL, 10);
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

    /* Enable logging */
    log_enabled(TRUE);
    log_set_level(verbose ? LOG_DEBUG : LOG_INFO);

    log_debug(TAG, "LocalNet starting...");

    /* Get adapter MAC address */
    char mac_address[18] = {0};
    if (ble_get_adapter_address(mac_address, sizeof(mac_address)) != 0) {
        log_error(TAG, "Failed to get Bluetooth adapter address");
        return EXIT_FAILURE;
    }

    /* Convert MAC to device ID */
    uint32_t device_id = mac_to_device_id(mac_address);
    if (device_id == 0) {
        log_error(TAG, "Failed to parse MAC address: %s", mac_address);
        return EXIT_FAILURE;
    }

    log_info(TAG, "Starting LocalNet node:");
    log_info(TAG, "  Adapter: %s", mac_address);
    log_info(TAG, "  Device ID: 0x%08X", device_id);
    log_info(TAG, "  Node Type: %s", node_type_to_string(node_type));
    log_info(TAG, "  Max Connections: %d", get_max_connections(node_type));

    /* Setup signal handlers */
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        log_error(TAG, "Cannot set SIGINT handler");
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        log_error(TAG, "Cannot set SIGTERM handler");
    }

    /* Initialize BLE node manager */
    g_ble_manager = ble_init(device_id, node_type);
    if (!g_ble_manager) {
        log_error(TAG, "Failed to initialize BLE node manager");
        return EXIT_FAILURE;
    }

    /* Set up callbacks */
    ble_set_discovered_callback(g_ble_manager, on_node_discovered);
    ble_set_connected_callback(g_ble_manager, on_node_connected);
    ble_set_disconnected_callback(g_ble_manager, on_node_disconnected);
    ble_set_data_callback(g_ble_manager, on_data_received);

    /* Start the BLE node */
    if (ble_start(g_ble_manager) != 0) {
        log_error(TAG, "Failed to start BLE node manager");
        ble_cleanup(g_ble_manager);
        return EXIT_FAILURE;
    }

    log_info(TAG, "Node is running. Press Ctrl+C to exit.");
    log_info(TAG, "Advertising as: LocalNet-%08X", device_id);
    log_info(TAG, "Scanning for other LocalNet nodes...");

    /* Run the main loop (blocks until quit) */
    ble_run_main_loop(g_ble_manager);

    /* Cleanup */
    log_info(TAG, "Shutting down...");
    ble_cleanup(g_ble_manager);
    g_ble_manager = NULL;

    log_info(TAG, "LocalNet node stopped");
    return EXIT_SUCCESS;
}
