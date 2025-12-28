#include "mesh_network.h"
#include "../bluetooth/bluetooth_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

/* Protocol version */
#define MESH_PROTOCOL_VERSION 1

/* Helper to get current timestamp in milliseconds */
static uint32_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* Helper to get next sequence number */
static uint16_t get_next_sequence(struct mesh_network *network) {
    return ++network->sequence_counter;
}

/* Forward declarations for internal functions */
static void handle_data_message(struct mesh_network *network, uint32_t source_id,
                                 struct header *hdr, struct network *net,
                                 const uint8_t *payload, size_t payload_len);
static void handle_route_request_msg(struct mesh_network *network, uint32_t sender_id,
                                  const uint8_t *payload, size_t payload_len);
static void handle_route_reply_msg(struct mesh_network *network, uint32_t sender_id,
                                const uint8_t *payload, size_t payload_len);
static void handle_heartbeat_msg(struct mesh_network *network, uint32_t sender_id,
                              const uint8_t *payload, size_t payload_len);
static void handle_discovery_msg(struct mesh_network *network, uint32_t sender_id,
                              const uint8_t *payload, size_t payload_len);
static void handle_acknowledgement_msg(struct mesh_network *network, uint32_t sender_id,
                                    const uint8_t *payload, size_t payload_len);

static int send_route_request_packet(struct mesh_network *network, uint32_t destination_id,
                                     uint32_t request_id, uint32_t *reverse_path, uint8_t path_len);
static int send_route_reply_packet(struct mesh_network *network, uint32_t destination_id,
                                   uint32_t request_id, uint8_t route_cost,
                                   uint32_t *forward_path, uint8_t path_len);
static int send_data_packet(struct mesh_network *network, uint32_t destination_id,
                            uint32_t next_hop, const uint8_t *data, size_t len, uint8_t ttl);
static int send_heartbeat_packet(struct mesh_network *network, uint32_t neighbor_id);
static int send_discovery_packet(struct mesh_network *network);
static int send_acknowledgement_packet(struct mesh_network *network, uint32_t destination_id,
                                       uint16_t seq_num, uint8_t status_code);

static void handle_route_discovery_complete(struct mesh_network *network, uint32_t destination_id);
static void handle_route_discovery_failed(struct mesh_network *network, uint32_t destination_id);

/* Bluetooth transport callbacks */
static void on_bt_device_connected(struct bt_transport *transport,
                                   struct bt_device_info *device, void *user_data);
static void on_bt_device_disconnected(struct bt_transport *transport,
                                      struct bt_device_info *device, void *user_data);
static void on_bt_data_received(struct bt_transport *transport, struct bt_device_info *device,
                                const uint8_t *data, size_t len, void *user_data);

/* Worker thread function */
static void *mesh_worker_thread(void *arg);

/* ============== Core API Implementation ============== */

struct mesh_network *mesh_network_init(enum NODE_TYPE node_type) {
    struct mesh_network *network = calloc(1, sizeof(struct mesh_network));
    if (!network) {
        fprintf(stderr, "Failed to allocate mesh network\n");
        return NULL;
    }

    // Initialize Bluetooth transport
    network->transport = bt_transport_init();
    if (!network->transport) {
        fprintf(stderr, "Failed to initialize Bluetooth transport\n");
        free(network);
        return NULL;
    }

    // Create mesh node with Bluetooth device ID
    network->node = create_mesh_node(network->transport->local_device_id, node_type);
    if (!network->node) {
        fprintf(stderr, "Failed to create mesh node\n");
        bt_transport_shutdown(network->transport);
        free(network);
        return NULL;
    }

    // Initialize mutex
    if (pthread_mutex_init(&network->lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize mutex\n");
        free_mesh_node(network->node);
        bt_transport_shutdown(network->transport);
        free(network);
        return NULL;
    }

    // Set Bluetooth callbacks
    bt_set_callbacks(network->transport,
                     NULL,  // on_discovered
                     on_bt_device_connected,
                     on_bt_device_disconnected,
                     on_bt_data_received,
                     network);

    network->sequence_counter = 0;
    network->pending_request_count = 0;
    network->running = false;
    network->initialized = true;
    network->worker_running = false;

    printf("Mesh network initialized (Device ID: 0x%08X, Type: %s)\n",
           network->node->device_id,
           node_type == EDGE_NODE ? "Edge" :
           node_type == FULL_NODE ? "Full" : "Gateway");

    return network;
}

int mesh_network_start(struct mesh_network *network) {
    if (!network || !network->initialized) return -1;

    pthread_mutex_lock(&network->lock);

    if (network->running) {
        pthread_mutex_unlock(&network->lock);
        return 0;
    }

    // Set device discoverable
    if (bt_set_discoverable(network->transport, true) < 0) {
        fprintf(stderr, "Warning: Failed to set discoverable mode\n");
    }

    // Start Bluetooth listener
    if (bt_start_listener(network->transport) < 0) {
        fprintf(stderr, "Failed to start Bluetooth listener\n");
        pthread_mutex_unlock(&network->lock);
        return -1;
    }

    network->running = true;
    network->last_heartbeat_time = get_timestamp_ms();
    network->last_discovery_time = 0;  // Trigger immediate discovery
    network->last_maintenance_time = get_timestamp_ms();

    // Start worker thread
    network->worker_running = true;
    if (pthread_create(&network->worker_thread, NULL, mesh_worker_thread, network) != 0) {
        fprintf(stderr, "Failed to start worker thread\n");
        bt_stop_listener(network->transport);
        network->running = false;
        network->worker_running = false;
        pthread_mutex_unlock(&network->lock);
        return -1;
    }

    pthread_mutex_unlock(&network->lock);

    printf("Mesh network started\n");

    // Initial discovery scan
    mesh_scan_for_devices(network);

    return 0;
}

void mesh_network_stop(struct mesh_network *network) {
    if (!network) return;

    pthread_mutex_lock(&network->lock);

    network->running = false;
    network->worker_running = false;

    pthread_mutex_unlock(&network->lock);

    // Wait for worker thread
    pthread_join(network->worker_thread, NULL);

    // Stop Bluetooth
    bt_stop_listener(network->transport);
    bt_set_discoverable(network->transport, false);

    printf("Mesh network stopped\n");
}

void mesh_network_shutdown(struct mesh_network *network) {
    if (!network) return;

    if (network->running) {
        mesh_network_stop(network);
    }

    // Cleanup pending requests
    for (size_t i = 0; i < network->pending_request_count; i++) {
        if (network->pending_requests[i].pending_data) {
            free(network->pending_requests[i].pending_data);
        }
    }

    pthread_mutex_destroy(&network->lock);

    if (network->node) {
        free_mesh_node(network->node);
    }

    if (network->transport) {
        bt_transport_shutdown(network->transport);
    }

    free(network);

    printf("Mesh network shutdown complete\n");
}

uint32_t mesh_get_local_id(struct mesh_network *network) {
    if (!network || !network->node) return 0;
    return network->node->device_id;
}

/* ============== Messaging API Implementation ============== */

int mesh_send_message(struct mesh_network *network, uint32_t destination_id,
                      const uint8_t *data, size_t len) {
    return mesh_send_message_async(network, destination_id, data, len, NULL, NULL);
}

int mesh_send_message_async(struct mesh_network *network, uint32_t destination_id,
                            const uint8_t *data, size_t len,
                            void (*callback)(uint32_t, enum mesh_delivery_status, void*),
                            void *callback_data) {
    if (!network || !network->running || !data || len == 0) return -1;

    pthread_mutex_lock(&network->lock);

    // Check if destination is a direct neighbor
    struct connection_entry *neighbor = find_connection(network->node->connection_table, destination_id);
    if (neighbor && neighbor->state == STABLE) {
        // Direct send
        int result = send_data_packet(network, destination_id, destination_id, data, len, MESH_DEFAULT_TTL);
        pthread_mutex_unlock(&network->lock);

        if (callback) {
            callback(destination_id, result == 0 ? MESH_DELIVERY_SUCCESS : MESH_DELIVERY_FAILED, callback_data);
        }
        return result;
    }

    // Check routing table for a route
    struct routing_entry *route = find_best_route(network->node->routing_table, destination_id);
    if (route && route->is_valid) {
        int result = send_data_packet(network, destination_id, route->next_hop, data, len, MESH_DEFAULT_TTL);
        pthread_mutex_unlock(&network->lock);

        if (callback) {
            callback(destination_id, result == 0 ? MESH_DELIVERY_SUCCESS : MESH_DELIVERY_FAILED, callback_data);
        }
        return result;
    }

    // No route - initiate route discovery and queue message
    if (network->pending_request_count >= MESH_MAX_PENDING_MESSAGES) {
        pthread_mutex_unlock(&network->lock);
        if (callback) {
            callback(destination_id, MESH_DELIVERY_NO_ROUTE, callback_data);
        }
        return -1;
    }

    // Queue the message
    struct pending_route_request *pending = &network->pending_requests[network->pending_request_count];
    pending->destination_id = destination_id;
    pending->timestamp = get_timestamp_ms();
    pending->pending_data = malloc(len);
    if (!pending->pending_data) {
        pthread_mutex_unlock(&network->lock);
        if (callback) {
            callback(destination_id, MESH_DELIVERY_FAILED, callback_data);
        }
        return -1;
    }
    memcpy(pending->pending_data, data, len);
    pending->pending_data_len = len;
    pending->is_active = true;
    pending->callback = callback;
    pending->callback_data = callback_data;

    // Initiate route discovery
    uint32_t *reverse_path = NULL;
    uint8_t path_len = 0;
    int request_id = initiate_route_discovery(network->node, destination_id, &reverse_path, &path_len);

    if (request_id > 0) {
        pending->request_id = (uint32_t)request_id;
        network->pending_request_count++;

        // Send route request to all neighbors
        send_route_request_packet(network, destination_id, request_id, reverse_path, path_len);

        free(reverse_path);
    } else {
        free(pending->pending_data);
        pending->pending_data = NULL;
        pthread_mutex_unlock(&network->lock);
        if (callback) {
            callback(destination_id, MESH_DELIVERY_NO_ROUTE, callback_data);
        }
        return -1;
    }

    pthread_mutex_unlock(&network->lock);
    return 0;
}

int mesh_broadcast_message(struct mesh_network *network, const uint8_t *data, size_t len) {
    if (!network || !network->running || !data || len == 0) return -1;

    pthread_mutex_lock(&network->lock);

    int sent_count = 0;
    struct connection_table *conn_table = network->node->connection_table;

    for (size_t i = 0; i < conn_table->count; i++) {
        struct connection_entry *entry = &conn_table->entries[i];
        if (entry->state == STABLE) {
            int result = send_data_packet(network, entry->neighbor_id, entry->neighbor_id,
                                         data, len, MESH_DEFAULT_TTL);
            if (result == 0) {
                sent_count++;
            }
        }
    }

    pthread_mutex_unlock(&network->lock);
    return sent_count;
}

/* ============== Route Discovery API Implementation ============== */

int mesh_discover_route(struct mesh_network *network, uint32_t destination_id) {
    if (!network || !network->running) return -1;

    pthread_mutex_lock(&network->lock);

    uint32_t *reverse_path = NULL;
    uint8_t path_len = 0;
    int request_id = initiate_route_discovery(network->node, destination_id, &reverse_path, &path_len);

    if (request_id > 0) {
        send_route_request_packet(network, destination_id, request_id, reverse_path, path_len);
        free(reverse_path);
    }

    pthread_mutex_unlock(&network->lock);
    return request_id;
}

bool mesh_has_route(struct mesh_network *network, uint32_t destination_id) {
    if (!network || !network->node) return false;

    pthread_mutex_lock(&network->lock);

    // Check if it's a neighbor
    struct connection_entry *neighbor = find_connection(network->node->connection_table, destination_id);
    if (neighbor && neighbor->state == STABLE) {
        pthread_mutex_unlock(&network->lock);
        return true;
    }

    // Check routing table
    struct routing_entry *route = find_route(network->node->routing_table, destination_id);
    bool has_route = (route != NULL && route->is_valid);

    pthread_mutex_unlock(&network->lock);
    return has_route;
}

int mesh_get_route_info(struct mesh_network *network, uint32_t destination_id,
                        uint32_t *next_hop, uint8_t *hop_count) {
    if (!network || !next_hop || !hop_count) return -1;

    pthread_mutex_lock(&network->lock);

    // Check if it's a neighbor (direct route)
    struct connection_entry *neighbor = find_connection(network->node->connection_table, destination_id);
    if (neighbor && neighbor->state == STABLE) {
        *next_hop = destination_id;
        *hop_count = 1;
        pthread_mutex_unlock(&network->lock);
        return 0;
    }

    // Check routing table
    struct routing_entry *route = find_best_route(network->node->routing_table, destination_id);
    if (route && route->is_valid) {
        *next_hop = route->next_hop;
        *hop_count = route->hop_count;
        pthread_mutex_unlock(&network->lock);
        return 0;
    }

    pthread_mutex_unlock(&network->lock);
    return -1;
}

/* ============== Network Status API Implementation ============== */

int mesh_get_neighbors(struct mesh_network *network, uint32_t *neighbor_ids, size_t max_neighbors) {
    if (!network || !neighbor_ids || max_neighbors == 0) return 0;

    pthread_mutex_lock(&network->lock);

    int count = 0;
    struct connection_table *conn_table = network->node->connection_table;

    for (size_t i = 0; i < conn_table->count && (size_t)count < max_neighbors; i++) {
        if (conn_table->entries[i].state == STABLE) {
            neighbor_ids[count++] = conn_table->entries[i].neighbor_id;
        }
    }

    pthread_mutex_unlock(&network->lock);
    return count;
}

int mesh_get_neighbor_quality(struct mesh_network *network, uint32_t neighbor_id,
                              int8_t *rssi, float *link_quality) {
    if (!network || !rssi || !link_quality) return -1;

    pthread_mutex_lock(&network->lock);

    struct connection_entry *entry = find_connection(network->node->connection_table, neighbor_id);
    if (!entry) {
        pthread_mutex_unlock(&network->lock);
        return -1;
    }

    *rssi = entry->rssi;
    *link_quality = entry->link_quality;

    pthread_mutex_unlock(&network->lock);
    return 0;
}

int mesh_get_connection_count(struct mesh_network *network) {
    if (!network || !network->node) return 0;

    pthread_mutex_lock(&network->lock);

    int count = 0;
    struct connection_table *conn_table = network->node->connection_table;

    for (size_t i = 0; i < conn_table->count; i++) {
        if (conn_table->entries[i].state == STABLE) {
            count++;
        }
    }

    pthread_mutex_unlock(&network->lock);
    return count;
}

int mesh_get_route_count(struct mesh_network *network) {
    if (!network || !network->node) return 0;

    pthread_mutex_lock(&network->lock);

    int count = 0;
    struct routing_table *rt = network->node->routing_table;

    for (size_t i = 0; i < rt->count; i++) {
        if (rt->entries[i].is_valid) {
            count++;
        }
    }

    pthread_mutex_unlock(&network->lock);
    return count;
}

/* ============== Callback Registration Implementation ============== */

void mesh_set_message_callback(struct mesh_network *network,
                               void (*callback)(struct mesh_network*, uint32_t, const uint8_t*, size_t, void*),
                               void *user_data) {
    if (!network) return;
    network->on_message_received = callback;
    network->user_data = user_data;
}

void mesh_set_node_joined_callback(struct mesh_network *network,
                                   void (*callback)(struct mesh_network*, uint32_t, void*)) {
    if (!network) return;
    network->on_node_joined = callback;
}

void mesh_set_node_left_callback(struct mesh_network *network,
                                 void (*callback)(struct mesh_network*, uint32_t, void*)) {
    if (!network) return;
    network->on_node_left = callback;
}

void mesh_set_route_discovered_callback(struct mesh_network *network,
                                        void (*callback)(struct mesh_network*, uint32_t, uint8_t, void*)) {
    if (!network) return;
    network->on_route_discovered = callback;
}

void mesh_set_route_failed_callback(struct mesh_network *network,
                                    void (*callback)(struct mesh_network*, uint32_t, void*)) {
    if (!network) return;
    network->on_route_failed = callback;
}

/* ============== Maintenance Functions Implementation ============== */

int mesh_scan_for_devices(struct mesh_network *network) {
    if (!network || !network->running) return -1;

    struct bt_device_info devices[BT_MAX_DEVICES];
    const int num_found = bt_scan_devices(network->transport, devices, BT_MAX_DEVICES);

    if (num_found <= 0) return num_found;

    pthread_mutex_lock(&network->lock);

    // Try to connect to discovered devices
    for (int i = 0; i < num_found; i++) {
        // Skip if already connected
        if (bt_find_device(network->transport, devices[i].device_id)) {
            continue;
        }

        // Check if we have room for more connections
        if (!has_available_connections(network->node)) {
            break;
        }

        // Try to connect
        if (bt_connect(network->transport, &devices[i]) == 0) {
            printf("Connected to device 0x%08X\n", devices[i].device_id);
        }
    }

    pthread_mutex_unlock(&network->lock);

    return num_found;
}

int mesh_send_heartbeats(struct mesh_network *network) {
    if (!network || !network->running) return -1;

    pthread_mutex_lock(&network->lock);

    int sent_count = 0;
    struct connection_table *conn_table = network->node->connection_table;

    for (size_t i = 0; i < conn_table->count; i++) {
        struct connection_entry *entry = &conn_table->entries[i];
        if (entry->state == STABLE || entry->state == CONNECTING) {
            if (send_heartbeat_packet(network, entry->neighbor_id) == 0) {
                sent_count++;
            }
        }
    }

    pthread_mutex_unlock(&network->lock);
    return sent_count;
}

void mesh_perform_maintenance(struct mesh_network *network) {
    if (!network || !network->running) return;

    pthread_mutex_lock(&network->lock);

    uint32_t current_time = get_current_timestamp();

    // Check connection timeouts
    check_connection_timeouts(network->node->connection_table, current_time);

    // Check heartbeat timeouts
    check_heartbeat_timeouts(network->node, current_time);

    // Expire old routes
    maintain_routing_table(network->node->routing_table, current_time);

    // Cleanup old route requests
    cleanup_old_requests(network->node->request_cache, current_time, 60);  // 60 second timeout

    // Check pending message timeouts
    uint32_t current_time_ms = get_timestamp_ms();
    for (size_t i = 0; i < network->pending_request_count; i++) {
        struct pending_route_request *pending = &network->pending_requests[i];
        if (pending->is_active &&
            (current_time_ms - pending->timestamp) > MESH_ROUTE_REQUEST_TIMEOUT_MS) {
            // Timeout
            if (pending->callback) {
                pending->callback(pending->destination_id, MESH_DELIVERY_TIMEOUT, pending->callback_data);
            }
            if (pending->pending_data) {
                free(pending->pending_data);
                pending->pending_data = NULL;
            }
            pending->is_active = false;
        }
    }

    // Remove disconnected neighbors from routing paths
    struct connection_table *conn_table = network->node->connection_table;
    for (size_t i = 0; i < conn_table->count; i++) {
        struct connection_entry *entry = &conn_table->entries[i];
        if (entry->state == DISCONNECTED) {
            // Invalidate routes through this neighbor
            struct routing_table *rt = network->node->routing_table;
            for (size_t j = 0; j < rt->count; j++) {
                if (rt->entries[j].next_hop == entry->neighbor_id) {
                    rt->entries[j].is_valid = 0;
                }
            }
        }
    }

    pthread_mutex_unlock(&network->lock);
}

void mesh_process_incoming_data(struct mesh_network *network, uint32_t source_device_id,
                                const uint8_t *data, size_t len) {
    if (!network || !data || len < 16) return;  // Minimum: header (8) + network (8)

    pthread_mutex_lock(&network->lock);

    // Parse header
    struct header hdr;
    if (parse_header(data, len, &hdr) != 0) {
        printf("Failed to parse header\n");
        pthread_mutex_unlock(&network->lock);
        return;
    }

    // Parse network header
    struct network net;
    if (parse_network(data + 8, len - 8, &net) != 0) {
        printf("Failed to parse network header\n");
        pthread_mutex_unlock(&network->lock);
        return;
    }

    // Update link quality for sender
    update_link_quality(network->node->connection_table, source_device_id, 1);
    update_last_seen(network->node->connection_table, source_device_id, get_current_timestamp());
    reset_missed_heartbeats(network->node->connection_table, source_device_id);

    // Get payload
    const uint8_t *payload = data + 16;
    size_t payload_len = hdr.payload_length;

    if (16 + payload_len > len) {
        printf("Invalid payload length\n");
        pthread_mutex_unlock(&network->lock);
        return;
    }

    // Process based on message type
    switch (hdr.message_type) {
        case MSG_DATA:
            handle_data_message(network, source_device_id, &hdr, &net, payload, payload_len);
            break;
        case MSG_ROUTE_REQUEST:
            handle_route_request_msg(network, source_device_id, payload, payload_len);
            break;
        case MSG_ROUTE_REPLY:
            handle_route_reply_msg(network, source_device_id, payload, payload_len);
            break;
        case MSG_HEARTBEAT:
            handle_heartbeat_msg(network, source_device_id, payload, payload_len);
            break;
        case MSG_DISCOVERY:
            handle_discovery_msg(network, source_device_id, payload, payload_len);
            break;
        case MSG_ACKNOWLEDGEMENT:
            handle_acknowledgement_msg(network, source_device_id, payload, payload_len);
            break;
        default:
            printf("Unknown message type: %d\n", hdr.message_type);
            break;
    }

    pthread_mutex_unlock(&network->lock);
}

/* ============== Debug/Status Functions Implementation ============== */

void mesh_print_routing_table(struct mesh_network *network) {
    if (!network || !network->node) return;

    pthread_mutex_lock(&network->lock);

    struct routing_table *rt = network->node->routing_table;

    printf("\n=== Routing Table ===\n");
    printf("%-12s %-12s %-8s %-10s %-8s\n",
           "Destination", "Next Hop", "Hops", "Cost", "Valid");
    printf("--------------------------------------------------\n");

    for (size_t i = 0; i < rt->count; i++) {
        struct routing_entry *entry = &rt->entries[i];
        printf("0x%08X  0x%08X  %-8u %-10.2f %-8s\n",
               entry->destination_id, entry->next_hop, entry->hop_count,
               entry->route_cost, entry->is_valid ? "Yes" : "No");
    }

    printf("======================\n\n");

    pthread_mutex_unlock(&network->lock);
}

void mesh_print_connections(struct mesh_network *network) {
    if (!network || !network->node) return;

    pthread_mutex_lock(&network->lock);

    struct connection_table *ct = network->node->connection_table;

    printf("\n=== Connection Table ===\n");
    printf("%-12s %-6s %-12s %-12s %-12s\n",
           "Neighbor", "RSSI", "Quality", "Last Seen", "State");
    printf("--------------------------------------------------------\n");

    const char *state_names[] = {"DISCOVERING", "CONNECTING", "STABLE", "DISCONNECTED"};

    for (size_t i = 0; i < ct->count; i++) {
        struct connection_entry *entry = &ct->entries[i];
        printf("0x%08X  %-6d %-12.2f %-12u %s\n",
               entry->neighbor_id, entry->rssi, entry->link_quality,
               entry->last_seen, state_names[entry->state]);
    }

    printf("=========================\n\n");

    pthread_mutex_unlock(&network->lock);
}

int mesh_get_stats_string(struct mesh_network *network, char *buffer, size_t buffer_size) {
    if (!network || !buffer || buffer_size == 0) return 0;

    pthread_mutex_lock(&network->lock);

    int written = snprintf(buffer, buffer_size,
        "Mesh Network Statistics\n"
        "-----------------------\n"
        "Device ID: 0x%08X\n"
        "Node Type: %s\n"
        "Running: %s\n"
        "Connections: %d/%u\n"
        "Routes: %zu\n"
        "Pending Requests: %zu\n",
        network->node->device_id,
        network->node->node_type == EDGE_NODE ? "Edge" :
        network->node->node_type == FULL_NODE ? "Full" : "Gateway",
        network->running ? "Yes" : "No",
        mesh_get_connection_count(network),
        network->node->max_connections,
        network->node->routing_table->count,
        network->pending_request_count);

    pthread_mutex_unlock(&network->lock);
    return written;
}

/* ============== Internal Helper Functions ============== */

static void handle_data_message(struct mesh_network *network, uint32_t source_id,
                                 struct header *hdr, struct network *net,
                                 const uint8_t *payload, size_t payload_len) {
    // Check if message is for us
    if (net->destination_id == network->node->device_id) {
        // Message is for us - deliver to application
        if (network->on_message_received) {
            pthread_mutex_unlock(&network->lock);  // Unlock for callback
            network->on_message_received(network, net->source_id, payload, payload_len, network->user_data);
            pthread_mutex_lock(&network->lock);
        }

        // Send acknowledgement
        send_acknowledgement_packet(network, net->source_id, hdr->sequence_number, SUCCESS);
        return;
    }

    // Message needs forwarding
    uint8_t ttl = hdr->time_to_live;
    uint32_t next_hop;

    int result = forward_packet(network->node, net->destination_id, &ttl, &next_hop);

    if (result == -1) {
        // TTL expired
        printf("TTL expired for packet to 0x%08X\n", net->destination_id);
        send_acknowledgement_packet(network, net->source_id, hdr->sequence_number, TTL_EXPIRED);
        return;
    }

    if (result == -2) {
        // No route - initiate discovery
        printf("No route to 0x%08X, initiating discovery\n", net->destination_id);
        mesh_discover_route(network, net->destination_id);
        // TODO: Queue packet for later delivery
        return;
    }

    // Forward the packet
    send_data_packet(network, net->destination_id, next_hop, payload, payload_len, ttl);
}

static void handle_route_request_msg(struct mesh_network *network, uint32_t sender_id,
                                  const uint8_t *payload, size_t payload_len) {
    struct route_request req;
    if (parse_route_request(payload, payload_len, &req) != 0) {
        printf("Failed to parse route request\n");
        return;
    }

    printf("Received RREQ for 0x%08X from 0x%08X (hops: %d)\n",
           req.destination_id, sender_id, req.hop_count);

    // Process the route request using routing.h function
    int result = process_route_request(network->node, req.request_id, req.destination_id,
                                       req.hop_count, req.reverse_path, req.reverse_path_len,
                                       sender_id);

    if (result == 1) {
        // We are the destination - send route reply
        printf("We are the destination, sending route reply\n");

        // Build forward path from reverse path
        uint32_t *forward_path = malloc((req.reverse_path_len + 1) * sizeof(uint32_t));
        if (forward_path) {
            // Reverse the path and add ourselves
            for (uint8_t i = 0; i < req.reverse_path_len; i++) {
                forward_path[i] = req.reverse_path[req.reverse_path_len - 1 - i];
            }
            forward_path[req.reverse_path_len] = network->node->device_id;

            // Send reply back along the path
            uint32_t next_hop = req.reverse_path[req.reverse_path_len - 1];
            send_route_reply_packet(network, next_hop, req.request_id,
                                   req.hop_count + 1, forward_path, req.reverse_path_len + 1);

            free(forward_path);
        }
    } else if (result == 0) {
        // Forward the request
        printf("Forwarding route request\n");

        // Add ourselves to the reverse path
        uint32_t *new_path = malloc((req.reverse_path_len + 1) * sizeof(uint32_t));
        if (new_path) {
            memcpy(new_path, req.reverse_path, req.reverse_path_len * sizeof(uint32_t));
            new_path[req.reverse_path_len] = network->node->device_id;

            // Broadcast to all neighbors except sender
            send_route_request_packet(network, req.destination_id, req.request_id,
                                      new_path, req.reverse_path_len + 1);

            free(new_path);
        }
    }

    // Cleanup
    if (req.reverse_path) {
        free(req.reverse_path);
    }
}

static void handle_route_reply_msg(struct mesh_network *network, uint32_t sender_id,
                                const uint8_t *payload, size_t payload_len) {
    struct route_reply rep;
    if (parse_route_reply(payload, payload_len, &rep) != 0) {
        printf("Failed to parse route reply\n");
        return;
    }

    printf("Received RREP for request %u (cost: %d, path_len: %d)\n",
           rep.request_id, rep.route_cost, rep.forward_path_len);

    // Process the route reply using routing.h function
    int result = process_route_reply(network->node, rep.request_id, rep.route_cost,
                                     rep.forward_path, rep.forward_path_len);

    if (result == 0) {
        // Check if we are the originator
        uint32_t destination = rep.forward_path[rep.forward_path_len - 1];

        // Find our position in the path
        bool we_are_origin = (rep.forward_path_len > 0 && rep.forward_path[0] == network->node->device_id);

        if (we_are_origin) {
            // Route discovery complete - send pending messages
            printf("Route discovered to 0x%08X\n", destination);
            handle_route_discovery_complete(network, destination);

            if (network->on_route_discovered) {
                pthread_mutex_unlock(&network->lock);
                network->on_route_discovered(network, destination, rep.route_cost, network->user_data);
                pthread_mutex_lock(&network->lock);
            }
        } else {
            // Forward the reply to the previous node in the path
            int our_position = -1;
            for (uint8_t i = 0; i < rep.forward_path_len; i++) {
                if (rep.forward_path[i] == network->node->device_id) {
                    our_position = i;
                    break;
                }
            }

            if (our_position > 0) {
                uint32_t prev_hop = rep.forward_path[our_position - 1];
                send_route_reply_packet(network, prev_hop, rep.request_id,
                                       rep.route_cost, rep.forward_path, rep.forward_path_len);
            }
        }
    }

    // Cleanup
    if (rep.forward_path) {
        free(rep.forward_path);
    }
}

static void handle_heartbeat_msg(struct mesh_network *network, uint32_t sender_id,
                              const uint8_t *payload, size_t payload_len) {
    struct heartbeat hb;
    if (parse_heartbeat(payload, payload_len, &hb) != 0) {
        return;
    }

    // Update connection info
    struct connection_entry *entry = find_connection(network->node->connection_table, sender_id);
    if (entry) {
        reset_missed_heartbeats(network->node->connection_table, sender_id);
        update_last_seen(network->node->connection_table, sender_id, get_current_timestamp());

        if (entry->state == CONNECTING) {
            update_connection_state(network->node->connection_table, sender_id, STABLE);
            printf("Connection to 0x%08X now STABLE\n", sender_id);
        }
    }
}

static void handle_discovery_msg(struct mesh_network *network, uint32_t sender_id,
                              const uint8_t *payload, size_t payload_len) {
    struct discovery_message disc;
    if (parse_discovery(payload, payload_len, &disc) != 0) {
        return;
    }

    printf("Received discovery from 0x%08X (available: %d)\n",
           sender_id, disc.available_connections);

    // Check if we want to connect
    if (has_available_connections(network->node) && disc.available_connections > 0) {
        // Try to establish connection
        struct bt_device_info *device = bt_find_device(network->transport, sender_id);
        if (device && !device->is_connected) {
            if (bt_connect(network->transport, device) == 0) {
                add_connection(network->node->connection_table, sender_id, device->rssi);
                update_connection_state(network->node->connection_table, sender_id, CONNECTING);
            }
        }
    }
}

static void handle_acknowledgement_msg(struct mesh_network *network, uint32_t sender_id,
                                    const uint8_t *payload, size_t payload_len) {
    struct acknowledgement ack;
    if (parse_acknowledgement(payload, payload_len, &ack) != 0) {
        return;
    }

    // Update link quality based on acknowledgement
    if (ack.status_code == SUCCESS) {
        update_link_quality(network->node->connection_table, sender_id, 1);
    } else {
        update_link_quality(network->node->connection_table, sender_id, 0);
    }
}

static int send_route_request_packet(struct mesh_network *network, uint32_t destination_id,
                                     uint32_t request_id, uint32_t *reverse_path, uint8_t path_len) {
    // Serialize route request
    struct route_request req = {
        .request_id = request_id,
        .destination_id = destination_id,
        .hop_count = path_len - 1,
        .reverse_path_len = path_len,
        .reverse_path = reverse_path
    };

    uint8_t payload[256];
    size_t payload_len = serialize_route_request(&req, payload, sizeof(payload));
    if (payload_len == 0) return -1;

    // Create header
    struct header hdr = {
        .protocol_version = MESH_PROTOCOL_VERSION,
        .message_type = MSG_ROUTE_REQUEST,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = MESH_DEFAULT_TTL,
        .payload_length = payload_len,
        .sequence_number = get_next_sequence(network)
    };

    // Create network header
    struct network net = {
        .source_id = network->node->device_id,
        .destination_id = 0xFFFFFFFF  // Broadcast
    };

    // Serialize complete packet
    uint8_t packet[512];
    size_t offset = 0;

    offset += serialize_header(&hdr, packet, sizeof(packet));
    offset += serialize_network(&net, packet + offset, sizeof(packet) - offset);
    memcpy(packet + offset, payload, payload_len);
    offset += payload_len;

    // Broadcast to all neighbors
    return bt_broadcast(network->transport, packet, offset, NULL);
}

static int send_route_reply_packet(struct mesh_network *network, uint32_t destination_id,
                                   uint32_t request_id, uint8_t route_cost,
                                   uint32_t *forward_path, uint8_t path_len) {
    // Serialize route reply
    struct route_reply rep = {
        .request_id = request_id,
        .route_cost = route_cost,
        .forward_path_len = path_len,
        .forward_path = forward_path
    };

    uint8_t payload[256];
    size_t payload_len = serialize_route_reply(&rep, payload, sizeof(payload));
    if (payload_len == 0) return -1;

    // Create header
    struct header hdr = {
        .protocol_version = MESH_PROTOCOL_VERSION,
        .message_type = MSG_ROUTE_REPLY,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = MESH_DEFAULT_TTL,
        .payload_length = payload_len,
        .sequence_number = get_next_sequence(network)
    };

    // Create network header
    struct network net = {
        .source_id = network->node->device_id,
        .destination_id = destination_id
    };

    // Serialize complete packet
    uint8_t packet[512];
    size_t offset = 0;

    offset += serialize_header(&hdr, packet, sizeof(packet));
    offset += serialize_network(&net, packet + offset, sizeof(packet) - offset);
    memcpy(packet + offset, payload, payload_len);
    offset += payload_len;

    // Send to destination
    struct bt_device_info *device = bt_find_device(network->transport, destination_id);
    if (device && device->is_connected) {
        return bt_send(network->transport, device, packet, offset) > 0 ? 0 : -1;
    }

    return -1;
}

static int send_data_packet(struct mesh_network *network, uint32_t destination_id,
                            uint32_t next_hop, const uint8_t *data, size_t len, uint8_t ttl) {
    // Create header
    struct header hdr = {
        .protocol_version = MESH_PROTOCOL_VERSION,
        .message_type = MSG_DATA,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = ttl,
        .payload_length = len,
        .sequence_number = get_next_sequence(network)
    };

    // Create network header
    struct network net = {
        .source_id = network->node->device_id,
        .destination_id = destination_id
    };

    // Serialize complete packet
    uint8_t packet[MESH_MAX_MESSAGE_SIZE];
    size_t offset = 0;

    offset += serialize_header(&hdr, packet, sizeof(packet));
    offset += serialize_network(&net, packet + offset, sizeof(packet) - offset);

    if (offset + len > sizeof(packet)) {
        // TODO: Fragment the message
        return -1;
    }

    memcpy(packet + offset, data, len);
    offset += len;

    // Send to next hop
    struct bt_device_info *device = bt_find_device(network->transport, next_hop);
    if (device && device->is_connected) {
        return bt_send(network->transport, device, packet, offset) > 0 ? 0 : -1;
    }

    return -1;
}

static int send_heartbeat_packet(struct mesh_network *network, uint32_t neighbor_id) {
    // Create heartbeat
    struct heartbeat hb = {
        .device_status = 1,  // Active
        .active_connection_number = (uint8_t)(network->node->max_connections -
                                              network->node->connection_table->count),
        .timestamp = get_current_timestamp()
    };

    uint8_t payload[8];
    size_t payload_len = serialize_heartbeat(&hb, payload, sizeof(payload));
    if (payload_len == 0) return -1;

    // Create header
    struct header hdr = {
        .protocol_version = MESH_PROTOCOL_VERSION,
        .message_type = MSG_HEARTBEAT,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = 1,  // Heartbeats are direct only
        .payload_length = payload_len,
        .sequence_number = get_next_sequence(network)
    };

    // Create network header
    struct network net = {
        .source_id = network->node->device_id,
        .destination_id = neighbor_id
    };

    // Serialize complete packet
    uint8_t packet[64];
    size_t offset = 0;

    offset += serialize_header(&hdr, packet, sizeof(packet));
    offset += serialize_network(&net, packet + offset, sizeof(packet) - offset);
    memcpy(packet + offset, payload, payload_len);
    offset += payload_len;

    // Send to neighbor
    struct bt_device_info *device = bt_find_device(network->transport, neighbor_id);
    if (device && device->is_connected) {
        return bt_send(network->transport, device, packet, offset) > 0 ? 0 : -1;
    }

    return -1;
}

static int send_discovery_packet(struct mesh_network *network) {
    // Create discovery message
    struct discovery_message disc = {
        .available_connections = network->node->available_connections,
        .timestamp = get_current_timestamp()
    };

    uint8_t payload[8];
    size_t payload_len = serialize_discovery(&disc, payload, sizeof(payload));
    if (payload_len == 0) return -1;

    // Create header
    struct header hdr = {
        .protocol_version = MESH_PROTOCOL_VERSION,
        .message_type = MSG_DISCOVERY,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = 1,  // Discovery is direct only
        .payload_length = payload_len,
        .sequence_number = get_next_sequence(network)
    };

    // Create network header
    struct network net = {
        .source_id = network->node->device_id,
        .destination_id = 0xFFFFFFFF  // Broadcast
    };

    // Serialize complete packet
    uint8_t packet[64];
    size_t offset = 0;

    offset += serialize_header(&hdr, packet, sizeof(packet));
    offset += serialize_network(&net, packet + offset, sizeof(packet) - offset);
    memcpy(packet + offset, payload, payload_len);
    offset += payload_len;

    // Broadcast
    return bt_broadcast(network->transport, packet, offset, NULL);
}

static int send_acknowledgement_packet(struct mesh_network *network, uint32_t destination_id,
                                       uint16_t seq_num, uint8_t status_code) {
    // Create acknowledgement
    struct acknowledgement ack = {
        .sequence_number = seq_num,
        .status_code = status_code,
        .received_fragment_count = 1,
        .received_fragment_list = NULL
    };

    uint8_t payload[8];
    size_t payload_len = serialize_acknowledgement(&ack, payload, sizeof(payload));
    if (payload_len == 0) return -1;

    // Create header
    struct header hdr = {
        .protocol_version = MESH_PROTOCOL_VERSION,
        .message_type = MSG_ACKNOWLEDGEMENT,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = MESH_DEFAULT_TTL,
        .payload_length = payload_len,
        .sequence_number = get_next_sequence(network)
    };

    // Get next hop
    uint32_t next_hop = destination_id;
    struct routing_entry *route = find_best_route(network->node->routing_table, destination_id);
    if (route && route->is_valid) {
        next_hop = route->next_hop;
    }

    // Create network header
    struct network net = {
        .source_id = network->node->device_id,
        .destination_id = destination_id
    };

    // Serialize complete packet
    uint8_t packet[64];
    size_t offset = 0;

    offset += serialize_header(&hdr, packet, sizeof(packet));
    offset += serialize_network(&net, packet + offset, sizeof(packet) - offset);
    memcpy(packet + offset, payload, payload_len);
    offset += payload_len;

    // Send to next hop
    struct bt_device_info *device = bt_find_device(network->transport, next_hop);
    if (device && device->is_connected) {
        return bt_send(network->transport, device, packet, offset) > 0 ? 0 : -1;
    }

    return -1;
}

static void handle_route_discovery_complete(struct mesh_network *network, uint32_t destination_id) {
    // Send any pending messages for this destination
    for (size_t i = 0; i < network->pending_request_count; i++) {
        struct pending_route_request *pending = &network->pending_requests[i];

        if (pending->is_active && pending->destination_id == destination_id) {
            // Get the route
            struct routing_entry *route = find_best_route(network->node->routing_table, destination_id);
            if (route && route->is_valid && pending->pending_data) {
                // Send the pending message
                int result = send_data_packet(network, destination_id, route->next_hop,
                                             pending->pending_data, pending->pending_data_len,
                                             MESH_DEFAULT_TTL);

                if (pending->callback) {
                    pending->callback(destination_id,
                                     result == 0 ? MESH_DELIVERY_SUCCESS : MESH_DELIVERY_FAILED,
                                     pending->callback_data);
                }
            }

            // Cleanup
            if (pending->pending_data) {
                free(pending->pending_data);
                pending->pending_data = NULL;
            }
            pending->is_active = false;
        }
    }
}

static void handle_route_discovery_failed(struct mesh_network *network, uint32_t destination_id) {
    // Notify pending messages that route discovery failed
    for (size_t i = 0; i < network->pending_request_count; i++) {
        struct pending_route_request *pending = &network->pending_requests[i];

        if (pending->is_active && pending->destination_id == destination_id) {
            if (pending->callback) {
                pending->callback(destination_id, MESH_DELIVERY_NO_ROUTE, pending->callback_data);
            }

            // Cleanup
            if (pending->pending_data) {
                free(pending->pending_data);
                pending->pending_data = NULL;
            }
            pending->is_active = false;
        }
    }

    if (network->on_route_failed) {
        pthread_mutex_unlock(&network->lock);
        network->on_route_failed(network, destination_id, network->user_data);
        pthread_mutex_lock(&network->lock);
    }
}

/* ============== Bluetooth Callbacks ============== */

static void on_bt_device_connected(struct bt_transport *transport,
                                   struct bt_device_info *device, void *user_data) {
    struct mesh_network *network = (struct mesh_network *)user_data;
    if (!network) return;

    pthread_mutex_lock(&network->lock);

    // Add to connection table
    add_connection(network->node->connection_table, device->device_id, device->rssi);
    update_connection_state(network->node->connection_table, device->device_id, CONNECTING);

    // Update available connections
    network->node->available_connections = network->node->max_connections -
                                           network->node->connection_table->count;

    printf("Device 0x%08X connected, sending heartbeat\n", device->device_id);

    // Send initial heartbeat
    send_heartbeat_packet(network, device->device_id);

    pthread_mutex_unlock(&network->lock);

    // Notify callback
    if (network->on_node_joined) {
        network->on_node_joined(network, device->device_id, network->user_data);
    }
}

static void on_bt_device_disconnected(struct bt_transport *transport,
                                      struct bt_device_info *device, void *user_data) {
    struct mesh_network *network = (struct mesh_network *)user_data;
    if (!network) return;

    pthread_mutex_lock(&network->lock);

    // Update connection state
    update_connection_state(network->node->connection_table, device->device_id, DISCONNECTED);

    // Invalidate routes through this device
    struct routing_table *rt = network->node->routing_table;
    for (size_t i = 0; i < rt->count; i++) {
        if (rt->entries[i].next_hop == device->device_id) {
            rt->entries[i].is_valid = 0;
        }
    }

    // Update available connections
    network->node->available_connections = network->node->max_connections -
                                           mesh_get_connection_count(network);

    printf("Device 0x%08X disconnected\n", device->device_id);

    pthread_mutex_unlock(&network->lock);

    // Notify callback
    if (network->on_node_left) {
        network->on_node_left(network, device->device_id, network->user_data);
    }
}

static void on_bt_data_received(struct bt_transport *transport, struct bt_device_info *device,
                                const uint8_t *data, size_t len, void *user_data) {
    struct mesh_network *network = (struct mesh_network *)user_data;
    if (!network) return;

    mesh_process_incoming_data(network, device->device_id, data, len);
}

/* ============== Worker Thread ============== */

static void *mesh_worker_thread(void *arg) {
    struct mesh_network *network = (struct mesh_network *)arg;

    printf("Mesh worker thread started\n");

    while (network->worker_running) {
        uint32_t current_time = get_timestamp_ms();

        // Check if we need to send heartbeats
        if (current_time - network->last_heartbeat_time >= MESH_HEARTBEAT_INTERVAL_MS) {
            mesh_send_heartbeats(network);
            network->last_heartbeat_time = current_time;
        }

        // Check if we need to scan for new devices
        if (current_time - network->last_discovery_time >= MESH_DISCOVERY_SCAN_INTERVAL_MS) {
            if (has_available_connections(network->node)) {
                mesh_scan_for_devices(network);
            }
            network->last_discovery_time = current_time;
        }

        // Perform periodic maintenance
        if (current_time - network->last_maintenance_time >= 10000) {  // Every 10 seconds
            mesh_perform_maintenance(network);
            network->last_maintenance_time = current_time;
        }

        // Sleep for a bit
        usleep(100000);  // 100ms
    }

    printf("Mesh worker thread stopped\n");

    return NULL;
}

