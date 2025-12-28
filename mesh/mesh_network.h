#ifndef LOCALNET_MESH_NETWORK_H
#define LOCALNET_MESH_NETWORK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "../routing/routing.h"
#include "../protocol/protocol.h"

/* Forward declarations */
struct bt_transport;
struct bt_device_info;

/* Mesh Network Configuration */
#define MESH_MAX_MESSAGE_SIZE 4096
#define MESH_DEFAULT_TTL 15
#define MESH_ROUTE_REQUEST_TIMEOUT_MS 10000
#define MESH_MAX_PENDING_MESSAGES 50
#define MESH_HEARTBEAT_INTERVAL_MS 30000
#define MESH_DISCOVERY_SCAN_INTERVAL_MS 60000

/* Message Delivery Status */
enum mesh_delivery_status {
    MESH_DELIVERY_PENDING = 0,
    MESH_DELIVERY_SUCCESS,
    MESH_DELIVERY_FAILED,
    MESH_DELIVERY_NO_ROUTE,
    MESH_DELIVERY_TIMEOUT,
    MESH_DELIVERY_TTL_EXPIRED
};

/* Pending Route Request */
struct pending_route_request {
    uint32_t request_id;
    uint32_t destination_id;
    uint32_t timestamp;
    uint8_t *pending_data;
    size_t pending_data_len;
    bool is_active;
    void (*callback)(uint32_t destination_id, enum mesh_delivery_status status, void *user_data);
    void *callback_data;
};

/* Mesh Network Context */
struct mesh_network {
    struct mesh_node *node;
    struct bt_transport *transport;

    /* Sequence number for messages */
    uint16_t sequence_counter;

    /* Pending route requests with queued data */
    struct pending_route_request pending_requests[MESH_MAX_PENDING_MESSAGES];
    size_t pending_request_count;

    /* Network state */
    bool running;
    bool initialized;

    /* Timers */
    uint32_t last_heartbeat_time;
    uint32_t last_discovery_time;
    uint32_t last_maintenance_time;

    /* Callbacks */
    void (*on_message_received)(struct mesh_network *network, uint32_t source_id,
                                const uint8_t *data, size_t len, void *user_data);
    void (*on_node_joined)(struct mesh_network *network, uint32_t device_id, void *user_data);
    void (*on_node_left)(struct mesh_network *network, uint32_t device_id, void *user_data);
    void (*on_route_discovered)(struct mesh_network *network, uint32_t destination_id,
                                uint8_t hop_count, void *user_data);
    void (*on_route_failed)(struct mesh_network *network, uint32_t destination_id, void *user_data);
    void *user_data;

    /* Thread synchronization */
    pthread_mutex_t lock;
    pthread_t worker_thread;
    bool worker_running;
};

/* ============== Core API ============== */

/**
 * Initialize the mesh network
 * @param node_type Type of this node (EDGE_NODE, FULL_NODE, or GATEWAY_NODE)
 * @return Pointer to mesh network context or NULL on failure
 */
struct mesh_network *mesh_network_init(enum NODE_TYPE node_type);

/**
 * Start the mesh network (begins discovery, listening, etc.)
 * @param network Mesh network context
 * @return 0 on success, -1 on failure
 */
int mesh_network_start(struct mesh_network *network);

/**
 * Stop the mesh network
 * @param network Mesh network context
 */
void mesh_network_stop(struct mesh_network *network);

/**
 * Shutdown and cleanup the mesh network
 * @param network Mesh network context
 */
void mesh_network_shutdown(struct mesh_network *network);

/**
 * Get the local device ID
 * @param network Mesh network context
 * @return Local device ID
 */
uint32_t mesh_get_local_id(struct mesh_network *network);

/* ============== Messaging API ============== */

/**
 * Send a message to a specific destination
 * @param network Mesh network context
 * @param destination_id Destination device ID
 * @param data Message data
 * @param len Length of message data
 * @return 0 on success (message queued), -1 on failure
 */
int mesh_send_message(struct mesh_network *network, uint32_t destination_id,
                      const uint8_t *data, size_t len);

/**
 * Send a message with delivery callback
 * @param network Mesh network context
 * @param destination_id Destination device ID
 * @param data Message data
 * @param len Length of message data
 * @param callback Callback for delivery status
 * @param callback_data User data for callback
 * @return 0 on success (message queued), -1 on failure
 */
int mesh_send_message_async(struct mesh_network *network, uint32_t destination_id,
                            const uint8_t *data, size_t len,
                            void (*callback)(uint32_t dest, enum mesh_delivery_status status, void *user_data),
                            void *callback_data);

/**
 * Broadcast a message to all connected neighbors
 * @param network Mesh network context
 * @param data Message data
 * @param len Length of message data
 * @return Number of neighbors message was sent to
 */
int mesh_broadcast_message(struct mesh_network *network, const uint8_t *data, size_t len);

/* ============== Route Discovery API ============== */

/**
 * Initiate route discovery to a destination
 * @param network Mesh network context
 * @param destination_id Target device ID
 * @return Request ID on success, -1 on failure
 */
int mesh_discover_route(struct mesh_network *network, uint32_t destination_id);

/**
 * Check if a route exists to destination
 * @param network Mesh network context
 * @param destination_id Target device ID
 * @return true if route exists, false otherwise
 */
bool mesh_has_route(struct mesh_network *network, uint32_t destination_id);

/**
 * Get route information for a destination
 * @param network Mesh network context
 * @param destination_id Target device ID
 * @param next_hop Output: next hop device ID
 * @param hop_count Output: number of hops to destination
 * @return 0 on success, -1 if no route exists
 */
int mesh_get_route_info(struct mesh_network *network, uint32_t destination_id,
                        uint32_t *next_hop, uint8_t *hop_count);

/* ============== Network Status API ============== */

/**
 * Get list of connected neighbors
 * @param network Mesh network context
 * @param neighbor_ids Output array for neighbor IDs
 * @param max_neighbors Maximum size of output array
 * @return Number of connected neighbors
 */
int mesh_get_neighbors(struct mesh_network *network, uint32_t *neighbor_ids, size_t max_neighbors);

/**
 * Get neighbor connection quality
 * @param network Mesh network context
 * @param neighbor_id Neighbor device ID
 * @param rssi Output: RSSI value
 * @param link_quality Output: Link quality (0.0 - 1.0)
 * @return 0 on success, -1 if neighbor not found
 */
int mesh_get_neighbor_quality(struct mesh_network *network, uint32_t neighbor_id,
                              int8_t *rssi, float *link_quality);

/**
 * Get number of active connections
 * @param network Mesh network context
 * @return Number of active connections
 */
int mesh_get_connection_count(struct mesh_network *network);

/**
 * Get number of known routes
 * @param network Mesh network context
 * @return Number of valid routes in routing table
 */
int mesh_get_route_count(struct mesh_network *network);

/* ============== Callback Registration ============== */

/**
 * Set message received callback
 * @param network Mesh network context
 * @param callback Callback function
 * @param user_data User data passed to callback
 */
void mesh_set_message_callback(struct mesh_network *network,
                               void (*callback)(struct mesh_network*, uint32_t, const uint8_t*, size_t, void*),
                               void *user_data);

/**
 * Set node joined callback
 * @param network Mesh network context
 * @param callback Callback function
 */
void mesh_set_node_joined_callback(struct mesh_network *network,
                                   void (*callback)(struct mesh_network*, uint32_t, void*));

/**
 * Set node left callback
 * @param network Mesh network context
 * @param callback Callback function
 */
void mesh_set_node_left_callback(struct mesh_network *network,
                                 void (*callback)(struct mesh_network*, uint32_t, void*));

/**
 * Set route discovered callback
 * @param network Mesh network context
 * @param callback Callback function
 */
void mesh_set_route_discovered_callback(struct mesh_network *network,
                                        void (*callback)(struct mesh_network*, uint32_t, uint8_t, void*));

/**
 * Set route failed callback
 * @param network Mesh network context
 * @param callback Callback function
 */
void mesh_set_route_failed_callback(struct mesh_network *network,
                                    void (*callback)(struct mesh_network*, uint32_t, void*));

/* ============== Maintenance Functions ============== */

/**
 * Trigger a network scan for new devices
 * @param network Mesh network context
 * @return Number of devices discovered
 */
int mesh_scan_for_devices(struct mesh_network *network);

/**
 * Send heartbeats to all neighbors
 * @param network Mesh network context
 * @return Number of heartbeats sent
 */
int mesh_send_heartbeats(struct mesh_network *network);

/**
 * Perform network maintenance (expire routes, check connections)
 * @param network Mesh network context
 */
void mesh_perform_maintenance(struct mesh_network *network);

/**
 * Process incoming data (call this from transport layer callback)
 * @param network Mesh network context
 * @param source_device_id Source device ID
 * @param data Received data
 * @param len Length of received data
 */
void mesh_process_incoming_data(struct mesh_network *network, uint32_t source_device_id,
                                const uint8_t *data, size_t len);

/* ============== Debug/Status Functions ============== */

/**
 * Print routing table to stdout
 * @param network Mesh network context
 */
void mesh_print_routing_table(struct mesh_network *network);

/**
 * Print connection table to stdout
 * @param network Mesh network context
 */
void mesh_print_connections(struct mesh_network *network);

/**
 * Get network statistics as a string
 * @param network Mesh network context
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return Number of bytes written
 */
int mesh_get_stats_string(struct mesh_network *network, char *buffer, size_t buffer_size);

#endif // LOCALNET_MESH_NETWORK_H

