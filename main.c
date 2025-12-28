/**
 * LocalNet - Bluetooth Mesh Networking Library Example
 *
 * This example demonstrates how developers can use the LocalNet mesh networking
 * library to build decentralized communication applications over Bluetooth.
 *
 * Features demonstrated:
 * - Network initialization and configuration
 * - Message sending (unicast and broadcast)
 * - Route discovery
 * - Event callbacks for network events
 * - Network status monitoring
 *
 * Usage: ./LocalNet [node_type] [command] [args...]
 *   node_type: edge, full, gateway
 *   commands:
 *     scan     - Scan for nearby devices
 *     listen   - Listen for messages
 *     send <id> <message> - Send message to device
 *     broadcast <message> - Broadcast message to all neighbors
 *     status   - Print network status
 *     demo     - Run interactive demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include "mesh/mesh_network.h"

/* Global network instance for signal handler */
static struct mesh_network *g_network = NULL;
static volatile bool g_running = true;

/* ============== Callback Functions ============== */

/**
 * Called when a message is received from another node
 */
void on_message_received(struct mesh_network *network, uint32_t source_id,
                         const uint8_t *data, size_t len, void *user_data) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║            MESSAGE RECEIVED                      ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ From: 0x%08X                                 ║\n", source_id);
    printf("║ Size: %zu bytes                                   ║\n", len);
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Content: ");

    // Print as string if printable, otherwise hex
    bool printable = true;
    for (size_t i = 0; i < len && printable; i++) {
        if (data[i] < 32 || data[i] > 126) printable = false;
    }

    if (printable) {
        printf("%.*s", (int)len, data);
    } else {
        for (size_t i = 0; i < len && i < 20; i++) {
            printf("%02X ", data[i]);
        }
        if (len > 20) printf("...");
    }
    printf("\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
}

/**
 * Called when a new node joins the network (direct connection)
 */
void on_node_joined(struct mesh_network *network, uint32_t device_id, void *user_data) {
    printf("\n[+] Node 0x%08X joined the network\n", device_id);
}

/**
 * Called when a node leaves the network (disconnects)
 */
void on_node_left(struct mesh_network *network, uint32_t device_id, void *user_data) {
    printf("\n[-] Node 0x%08X left the network\n", device_id);
}

/**
 * Called when a route to a destination is discovered
 */
void on_route_discovered(struct mesh_network *network, uint32_t destination_id,
                         uint8_t hop_count, void *user_data) {
    printf("\n[R] Route discovered to 0x%08X (%d hops)\n", destination_id, hop_count);
}

/**
 * Called when route discovery fails
 */
void on_route_failed(struct mesh_network *network, uint32_t destination_id, void *user_data) {
    printf("\n[!] Route discovery failed for 0x%08X\n", destination_id);
}

/**
 * Delivery status callback for async message sending
 */
void on_message_delivery(uint32_t destination_id, enum mesh_delivery_status status, void *user_data) {
    const char *status_str;
    switch (status) {
        case MESH_DELIVERY_SUCCESS:   status_str = "SUCCESS"; break;
        case MESH_DELIVERY_FAILED:    status_str = "FAILED"; break;
        case MESH_DELIVERY_NO_ROUTE:  status_str = "NO ROUTE"; break;
        case MESH_DELIVERY_TIMEOUT:   status_str = "TIMEOUT"; break;
        case MESH_DELIVERY_TTL_EXPIRED: status_str = "TTL EXPIRED"; break;
        default:                      status_str = "PENDING"; break;
    }
    printf("[D] Message to 0x%08X: %s\n", destination_id, status_str);
}

/* ============== Signal Handler ============== */

void signal_handler(int sig) {
    printf("\n\nReceived signal %d, shutting down...\n", sig);
    g_running = false;
}

/* ============== Command Handlers ============== */

void print_help(const char *program_name) {
    printf("\n");
    printf("LocalNet - Bluetooth Mesh Networking Library\n");
    printf("=============================================\n\n");
    printf("Usage: %s [node_type] [command] [args...]\n\n", program_name);
    printf("Node Types:\n");
    printf("  edge     - Edge node (limited routing, low power)\n");
    printf("  full     - Full node (full routing capabilities)\n");
    printf("  gateway  - Gateway node (bridges to external networks)\n\n");
    printf("Commands:\n");
    printf("  scan                     - Scan for nearby Bluetooth devices\n");
    printf("  listen                   - Listen for incoming messages\n");
    printf("  send <hex_id> <message>  - Send message to specific device\n");
    printf("  broadcast <message>      - Broadcast to all neighbors\n");
    printf("  status                   - Print network status\n");
    printf("  routes                   - Print routing table\n");
    printf("  connections              - Print connection table\n");
    printf("  discover <hex_id>        - Discover route to device\n");
    printf("  demo                     - Run interactive demo\n\n");
    printf("Examples:\n");
    printf("  %s full listen\n", program_name);
    printf("  %s edge send 0x12345678 \"Hello World\"\n", program_name);
    printf("  %s gateway demo\n\n", program_name);
}

int parse_node_type(const char *type_str, enum NODE_TYPE *node_type) {
    if (strcmp(type_str, "edge") == 0) {
        *node_type = EDGE_NODE;
        return 0;
    } else if (strcmp(type_str, "full") == 0) {
        *node_type = FULL_NODE;
        return 0;
    } else if (strcmp(type_str, "gateway") == 0) {
        *node_type = GATEWAY_NODE;
        return 0;
    }
    return -1;
}

void print_status(struct mesh_network *network) {
    char buffer[1024];
    mesh_get_stats_string(network, buffer, sizeof(buffer));
    printf("\n%s\n", buffer);

    printf("Neighbors:\n");
    uint32_t neighbors[32];
    int count = mesh_get_neighbors(network, neighbors, 32);
    if (count == 0) {
        printf("  (no neighbors connected)\n");
    } else {
        for (int i = 0; i < count; i++) {
            int8_t rssi;
            float quality;
            mesh_get_neighbor_quality(network, neighbors[i], &rssi, &quality);
            printf("  0x%08X (RSSI: %d, Quality: %.1f%%)\n",
                   neighbors[i], rssi, quality * 100);
        }
    }
    printf("\n");
}

void run_scan(struct mesh_network *network) {
    printf("Scanning for Bluetooth devices...\n");
    int found = mesh_scan_for_devices(network);
    if (found < 0) {
        printf("Scan failed\n");
    } else {
        printf("Found %d device(s)\n", found);
    }
}

void run_listen(struct mesh_network *network) {
    printf("\nListening for messages... (Press Ctrl+C to stop)\n\n");

    // Display local device info
    printf("Local Device ID: 0x%08X\n\n", mesh_get_local_id(network));

    while (g_running) {
        sleep(1);

        // Periodic status update
        static int counter = 0;
        if (++counter % 30 == 0) {
            printf("--- Status: %d connections, %d routes ---\n",
                   mesh_get_connection_count(network),
                   mesh_get_route_count(network));
        }
    }
}

void run_send(struct mesh_network *network, const char *dest_str, const char *message) {
    uint32_t dest_id = strtoul(dest_str, NULL, 16);
    if (dest_id == 0) {
        printf("Invalid destination ID: %s\n", dest_str);
        return;
    }

    printf("Sending message to 0x%08X: \"%s\"\n", dest_id, message);

    int result = mesh_send_message_async(network, dest_id,
                                         (const uint8_t *)message, strlen(message),
                                         on_message_delivery, NULL);

    if (result == 0) {
        printf("Message queued for delivery\n");
    } else {
        printf("Failed to queue message\n");
    }

    // Wait a bit for delivery status
    sleep(3);
}

void run_broadcast(struct mesh_network *network, const char *message) {
    printf("Broadcasting message: \"%s\"\n", message);

    int sent = mesh_broadcast_message(network, (const uint8_t *)message, strlen(message));
    printf("Message sent to %d neighbor(s)\n", sent);
}

void run_discover(struct mesh_network *network, const char *dest_str) {
    uint32_t dest_id = strtoul(dest_str, NULL, 16);
    if (dest_id == 0) {
        printf("Invalid destination ID: %s\n", dest_str);
        return;
    }

    printf("Initiating route discovery to 0x%08X...\n", dest_id);

    int request_id = mesh_discover_route(network, dest_id);
    if (request_id > 0) {
        printf("Route request initiated (ID: %d)\n", request_id);

        // Wait for discovery
        for (int i = 0; i < 10; i++) {
            sleep(1);
            if (mesh_has_route(network, dest_id)) {
                uint32_t next_hop;
                uint8_t hop_count;
                mesh_get_route_info(network, dest_id, &next_hop, &hop_count);
                printf("Route found! Next hop: 0x%08X, Hops: %d\n", next_hop, hop_count);
                return;
            }
        }
        printf("Route discovery timed out\n");
    } else {
        printf("Failed to initiate route discovery\n");
    }
}

void run_demo(struct mesh_network *network) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║        LocalNet Interactive Demo                 ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Commands:                                        ║\n");
    printf("║   scan      - Scan for devices                   ║\n");
    printf("║   status    - Show network status                ║\n");
    printf("║   routes    - Show routing table                 ║\n");
    printf("║   conns     - Show connections                   ║\n");
    printf("║   send <id> - Send message                       ║\n");
    printf("║   bcast     - Broadcast message                  ║\n");
    printf("║   quit      - Exit demo                          ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    char input[256];
    char cmd[32];
    char arg1[128];
    char arg2[128];

    while (g_running) {
        printf("[0x%08X]> ", mesh_get_local_id(network));
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        // Parse command
        arg1[0] = arg2[0] = '\0';
        int parsed = sscanf(input, "%31s %127s %127[^\n]", cmd, arg1, arg2);
        if (parsed < 1) continue;

        if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            break;
        } else if (strcmp(cmd, "scan") == 0) {
            run_scan(network);
        } else if (strcmp(cmd, "status") == 0) {
            print_status(network);
        } else if (strcmp(cmd, "routes") == 0) {
            mesh_print_routing_table(network);
        } else if (strcmp(cmd, "conns") == 0) {
            mesh_print_connections(network);
        } else if (strcmp(cmd, "send") == 0 && parsed >= 2) {
            if (arg2[0] == '\0') {
                printf("Enter message: ");
                fgets(arg2, sizeof(arg2), stdin);
                arg2[strcspn(arg2, "\n")] = 0;
            }
            run_send(network, arg1, arg2);
        } else if (strcmp(cmd, "bcast") == 0) {
            if (arg1[0] == '\0') {
                printf("Enter message: ");
                fgets(arg1, sizeof(arg1), stdin);
                arg1[strcspn(arg1, "\n")] = 0;
            }
            run_broadcast(network, arg1);
        } else if (strcmp(cmd, "discover") == 0 && parsed >= 2) {
            run_discover(network, arg1);
        } else if (strcmp(cmd, "help") == 0) {
            printf("Available commands: scan, status, routes, conns, send, bcast, discover, quit\n");
        } else {
            printf("Unknown command: %s (type 'help' for commands)\n", cmd);
        }
    }
}

/* ============== Main ============== */

int main(int argc, char *argv[]) {
    // Print header
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║                 LocalNet v1.0                    ║\n");
    printf("║        Bluetooth Mesh Networking Library         ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    // Check arguments
    if (argc < 3) {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }

    // Parse node type
    enum NODE_TYPE node_type;
    if (parse_node_type(argv[1], &node_type) != 0) {
        printf("Error: Invalid node type '%s'\n", argv[1]);
        printf("Valid types: edge, full, gateway\n");
        return EXIT_FAILURE;
    }

    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize mesh network
    printf("Initializing mesh network as %s node...\n", argv[1]);
    struct mesh_network *network = mesh_network_init(node_type);
    if (!network) {
        printf("Error: Failed to initialize mesh network\n");
        printf("Make sure Bluetooth is enabled and you have proper permissions.\n");
        return EXIT_FAILURE;
    }

    g_network = network;

    // Set up callbacks
    mesh_set_message_callback(network, on_message_received, NULL);
    mesh_set_node_joined_callback(network, on_node_joined);
    mesh_set_node_left_callback(network, on_node_left);
    mesh_set_route_discovered_callback(network, on_route_discovered);
    mesh_set_route_failed_callback(network, on_route_failed);

    // Start the network
    printf("Starting mesh network...\n");
    if (mesh_network_start(network) != 0) {
        printf("Error: Failed to start mesh network\n");
        mesh_network_shutdown(network);
        return EXIT_FAILURE;
    }

    printf("Network started successfully!\n\n");

    // Execute command
    const char *command = argv[2];

    if (strcmp(command, "scan") == 0) {
        run_scan(network);
    } else if (strcmp(command, "listen") == 0) {
        run_listen(network);
    } else if (strcmp(command, "send") == 0) {
        if (argc < 5) {
            printf("Usage: %s %s send <dest_id> <message>\n", argv[0], argv[1]);
        } else {
            run_send(network, argv[3], argv[4]);
        }
    } else if (strcmp(command, "broadcast") == 0) {
        if (argc < 4) {
            printf("Usage: %s %s broadcast <message>\n", argv[0], argv[1]);
        } else {
            run_broadcast(network, argv[3]);
        }
    } else if (strcmp(command, "status") == 0) {
        print_status(network);
    } else if (strcmp(command, "routes") == 0) {
        mesh_print_routing_table(network);
    } else if (strcmp(command, "connections") == 0) {
        mesh_print_connections(network);
    } else if (strcmp(command, "discover") == 0) {
        if (argc < 4) {
            printf("Usage: %s %s discover <dest_id>\n", argv[0], argv[1]);
        } else {
            run_discover(network, argv[3]);
        }
    } else if (strcmp(command, "demo") == 0) {
        run_demo(network);
    } else {
        printf("Unknown command: %s\n", command);
        print_help(argv[0]);
    }

    // Cleanup
    printf("\nShutting down mesh network...\n");
    mesh_network_shutdown(network);

    printf("Goodbye!\n");

    return EXIT_SUCCESS;
}

