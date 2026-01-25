#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "bluetooth.h"
#include "protocol.h"
#include "logger.h"
#include "utils.h"
#include "routing.h"

/* Global BLE manager for signal handler */
static ble_node_manager_t *g_ble_manager = NULL;
static volatile gboolean g_running = TRUE;

/* ============================================================================
 * MENU COMMAND SYSTEM
 * ============================================================================ */

/* Command handler function type */
typedef void (*menu_command_handler)(void);

/* Menu command structure */
typedef struct {
    const char *key;           /* Key to press (e.g., "1", "c", "q") */
    const char *description;   /* Description shown in menu */
    menu_command_handler handler;
} menu_command_t;

/* Forward declarations for command handlers */
static void cmd_show_connections(void);
static void cmd_show_discovered(void);
static void cmd_show_node_info(void);
static void cmd_show_routing_table(void);
static void cmd_toggle_discovery(void);
static void cmd_toggle_advertising(void);
static void cmd_show_help(void);
static void cmd_quit(void);

/* Define menu commands - easily extendable by adding new entries */
static const menu_command_t g_menu_commands[] = {
    { "1", "Show connection table",     cmd_show_connections },
    { "2", "Show discovered devices",   cmd_show_discovered },
    { "3", "Show node info",            cmd_show_node_info },
    { "4", "Show routing table",        cmd_show_routing_table },
    { "d", "Toggle discovery",          cmd_toggle_discovery },
    { "a", "Toggle advertising",        cmd_toggle_advertising },
    { "h", "Show help",                 cmd_show_help },
    { "q", "Quit",                      cmd_quit },
    { NULL, NULL, NULL }  /* Sentinel */
};

/* Command handlers implementation */
static void cmd_show_connections(void) {
    if (g_ble_manager) {
        ble_print_connection_table(g_ble_manager);
    } else {
        printf("Error: BLE manager not initialized\n");
    }
}

static void cmd_show_discovered(void) {
    if (!g_ble_manager) {
        printf("Error: BLE manager not initialized\n");
        return;
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                    DISCOVERED DEVICES                            ║\n");
    printf("╠────────────────┬────────────┬────────────┬────────────────────────╣\n");
    printf("║ Device ID      │ Connected  │ RSSI       │ Last Seen              ║\n");
    printf("╠────────────────┼────────────┼────────────┼────────────────────────╣\n");

    /* Access discovered devices directly - we need to expose this or use accessor */
    /* For now, just indicate how many we know about */
    printf("║ Total discovered devices: (use verbose mode to see scan results) ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void cmd_show_node_info(void) {
    if (!g_ble_manager) {
        printf("Error: BLE manager not initialized\n");
        return;
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                      NODE INFORMATION                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");

    char mac_address[18] = {0};
    if (ble_get_adapter_address(mac_address, sizeof(mac_address)) == 0) {
        printf("║ Adapter MAC:    %-50s ║\n", mac_address);
    }

    printf("║ Connected nodes: %-49d ║\n", ble_get_connected_count(g_ble_manager));
    printf("║ Advertising:     %-49s ║\n", ble_is_advertising(g_ble_manager) ? "YES" : "NO");
    printf("║ Discovering:     %-49s ║\n", ble_is_discovering(g_ble_manager) ? "YES" : "NO");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void cmd_show_routing_table(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                     ROUTING TABLE                                ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║ (Routing table display - to be implemented)                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void cmd_toggle_discovery(void) {
    if (!g_ble_manager) {
        printf("Error: BLE manager not initialized\n");
        return;
    }

    if (ble_is_discovering(g_ble_manager)) {
        ble_stop_discovery(g_ble_manager);
        printf("Discovery STOPPED\n");
    } else {
        ble_start_discovery(g_ble_manager);
        printf("Discovery STARTED\n");
    }
}

static void cmd_toggle_advertising(void) {
    if (!g_ble_manager) {
        printf("Error: BLE manager not initialized\n");
        return;
    }

    if (ble_is_advertising(g_ble_manager)) {
        ble_stop_advertising(g_ble_manager);
        printf("Advertising STOPPED\n");
    } else {
        ble_start_advertising(g_ble_manager);
        printf("Advertising STARTED\n");
    }
}

static void cmd_show_help(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                    LOCALNET COMMANDS                             ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");

    for (int i = 0; g_menu_commands[i].key != NULL; i++) {
        printf("║  [%s] %-60s ║\n", g_menu_commands[i].key, g_menu_commands[i].description);
    }

    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void cmd_quit(void) {
    printf("Quitting...\n");
    g_running = FALSE;
    if (g_ble_manager) {
        ble_quit_main_loop(g_ble_manager);
    }
}

/* Process a single command input */
static void process_command(const char *input) {
    /* Trim whitespace */
    while (*input && isspace(*input)) input++;

    if (*input == '\0') return;  /* Empty input */

    /* Find matching command */
    for (int i = 0; g_menu_commands[i].key != NULL; i++) {
        if (g_ascii_strcasecmp(input, g_menu_commands[i].key) == 0) {
            g_menu_commands[i].handler();
            return;
        }
    }

    printf("Unknown command: '%s'. Press 'h' for help.\n", input);
}

/* Callback for stdin input in GLib main loop */
static gboolean stdin_callback(GIOChannel *source, GIOCondition condition, gpointer data) {
    if (condition & G_IO_IN) {
        gchar *line = NULL;
        gsize length;
        GError *error = NULL;

        if (g_io_channel_read_line(source, &line, &length, NULL, &error) == G_IO_STATUS_NORMAL) {
            if (line) {
                /* Remove newline */
                line[strcspn(line, "\n\r")] = '\0';
                process_command(line);
                g_free(line);
            }
        }

        if (error) {
            g_error_free(error);
        }
    }

    return TRUE;  /* Continue watching */
}

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
static void on_node_discovered(const uint32_t node_id, const int8_t rssi) {
    log_info(TAG, "Discovered node: 0x%08X (RSSI: %d dBm)", node_id, rssi);
}

/* Callback: Node connected */
static void on_node_connected(const uint32_t node_id) {
    log_info(TAG, "Connected to node: 0x%08X", node_id);

    if (g_ble_manager) {
        int connected = ble_get_connected_count(g_ble_manager);
        log_info(TAG, "Total connected nodes: %d", connected);
    }
}

/* Callback: Node disconnected */
static void on_node_disconnected(const uint32_t node_id) {
    log_info(TAG, "Disconnected from node: 0x%08X", node_id);

    if (g_ble_manager) {
        const int connected = ble_get_connected_count(g_ble_manager);
        log_info(TAG, "Remaining connected nodes: %d", connected);
    }
}

/* Callback: Data received */
static void on_data_received(const uint32_t sender_id, const uint8_t *data, const size_t len) {
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

int main(const int argc, char *argv[]) {
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
    log_info(TAG, "Press 'h' for help menu.");

    /* Set up stdin input handling for menu commands */
    GIOChannel *stdin_channel = g_io_channel_unix_new(STDIN_FILENO);
    g_io_channel_set_encoding(stdin_channel, NULL, NULL);
    g_io_channel_set_buffered(stdin_channel, TRUE);
    guint stdin_watch_id = g_io_add_watch(stdin_channel, G_IO_IN, stdin_callback, NULL);

    /* Run the main loop (blocks until quit) */
    ble_run_main_loop(g_ble_manager);

    /* Cleanup stdin channel */
    g_source_remove(stdin_watch_id);
    g_io_channel_unref(stdin_channel);

    /* Cleanup */
    log_info(TAG, "Shutting down...");
    ble_cleanup(g_ble_manager);
    g_ble_manager = NULL;

    log_info(TAG, "LocalNet node stopped");
    return EXIT_SUCCESS;
}
