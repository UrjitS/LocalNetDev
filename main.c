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
#include "logger.h"

#define TAG "LOCALNET"

// Global BLE manager for signal handler
static ble_node_manager_t * g_ble_manager = NULL;
static volatile gboolean g_running = TRUE;
static uint32_t g_device_id = 0;

// Command handler function type
typedef void (*menu_command_handler)(void);

typedef struct {
    const char *key;
    const char *description;
    menu_command_handler handler;
} menu_command_t;

// Command handlers
static void cmd_show_connections(void);
static void cmd_show_node_info(void);
static void cmd_show_help(void);
static void cmd_quit(void);

// Menu
static const menu_command_t g_menu_commands[] = {
    { "1", "Show connection table",     cmd_show_connections },
    { "2", "Show Node info",            cmd_show_node_info },
    { "h", "Show help",                 cmd_show_help },
    { "q", "Quit",                      cmd_quit },
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
    printf("Quitting\n");
    g_running = FALSE;
    if (g_ble_manager) {
        ble_quit_loop(g_ble_manager);
    }
}

// Process Command input
static void process_command(const char *input) {
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

static gboolean stdin_callback(GIOChannel *source, const GIOCondition condition, gpointer data) {
    if (condition & G_IO_IN) {
        gchar *line = NULL;
        gsize length;
        GError *error = NULL;

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

void usage(const char *program_name) {
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
        log_info(TAG, "Received signal %d, shutting down", sig_no);
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
        const guint connected = ble_get_connected_count(g_ble_manager);
        log_info(TAG, "Remaining connected Nodes: %d", connected);
    }
}

static void on_data_received(const uint32_t sender_id, const uint8_t *data, const size_t len) {
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
            case MSG_DATA:
                log_info(TAG, "Received data message");
                break;
            default:
                log_info(TAG, "Received unknown message type: %d", hdr.message_type);
                break;
        }
    }
}

const char *node_type_to_string(const enum NODE_TYPE type) {
    switch (type) {
        case EDGE_NODE: return "EDGE";
        case FULL_NODE: return "FULL";
        case GATEWAY_NODE: return "GATEWAY";
        default: return "UNKNOWN";
    }
}

// NOLINTNEXTLINE
static int get_adapter_address(char *address, size_t len) {
    GDBusConnection *dbus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (!dbus) return -1;

    Adapter *adapter = binc_adapter_get_default(dbus);
    if (!adapter) {
        g_object_unref(dbus);
        return -1;
    }

    const char *addr = binc_adapter_get_address(adapter);
    if (addr) {
        strncpy(address, addr, len - 1);
        address[len - 1] = '\0';
    }

    binc_adapter_free(adapter);

    g_object_unref(dbus);

    return addr ? 0 : -1;
}

// Convert MAC address to 32-bit device ID (uses last 4 bytes)
static uint32_t mac_to_device_id(const char *mac) {
    unsigned long bytes[6];
    char *end = NULL;

    for (int i = 0; i < 6; i++) {
        if (!isxdigit((unsigned char)mac[0]) ||
            !isxdigit((unsigned char)mac[1])) {
            return 0;
            }

        bytes[i] = strtoul(mac, &end, 16);
        if (end != mac + 2 || bytes[i] > 0xFF) {
            return 0;
        }

        mac = end;

        if (i < 5) {
            if (*mac != ':') {
                return 0;
            }
            mac++;
        }
    }

    // Use last 4 bytes of MAC for unique 32-bit ID
    return ((uint32_t)bytes[2] << 24) |
           ((uint32_t)bytes[3] << 16) |
           ((uint32_t)bytes[4] << 8)  |
           ((uint32_t)bytes[5]);
}


int main(const int argc, char *argv[]) {
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

    // Initialize BLE node manager with callbacks
    g_ble_manager = ble_init(NULL, g_device_id,
                              on_node_discovered,
                              on_node_connected,
                              on_node_disconnected,
                              on_data_received);
    if (!g_ble_manager) {
        log_error(TAG, "Failed to initialize BLE node manager");
        return EXIT_FAILURE;
    }

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
    GIOChannel *stdin_channel = g_io_channel_unix_new(STDIN_FILENO);
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
    ble_cleanup(g_ble_manager);
    g_ble_manager = NULL;

    log_info(TAG, "LocalNet Node stopped");
    return EXIT_SUCCESS;
}
