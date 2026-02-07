#ifndef LOCALNET_ROUTING_H
#define LOCALNET_ROUTING_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations for protocol structures */
struct route_request;
struct route_reply;

/* Node Types */
enum NODE_TYPE {
    EDGE_NODE = 0,
    FULL_NODE = 1,
    GATEWAY_NODE = 2
};

/* Connection States */
enum CONNECTION_STATE {
    DISCOVERING = 0,
    CONNECTING,
    STABLE,
    DISCONNECTED
};

/* Configurations */
#define MAX_CONNECTIONS_EDGE 4
#define MAX_CONNECTIONS_FULL 16
#define MAX_CONNECTIONS_GATEWAY 20
#define MAX_ROUTING_TABLE_ENTRIES 100
#define MAX_CONNECTION_TABLE_ENTRIES 32
#define MAX_PENDING_ROUTE_REQUESTS 50
#define ROUTE_EXPIRY_SECONDS 500
#define CONNECTION_TIMEOUT_SECONDS 60
#define HEARTBEAT_INTERVAL_SECONDS 10
#define HEARTBEAT_MISSED_THRESHOLD 3
#define DISCOVERY_INITIAL_INTERVAL 30
#define DISCOVERY_LONG_INTERVAL 300
#define DISCOVERY_INITIAL_DURATION 120
#define MAX_HOP_COUNT 15
#define LINK_QUALITY_WINDOW 100

/* Connection Table Entry */
struct connection_entry {
    uint32_t neighbor_id;
    int8_t rssi;
    float link_quality;
    uint32_t last_seen;
    enum CONNECTION_STATE state;
    uint16_t successful_packets;
    uint16_t total_packets;
    uint8_t missed_heartbeats;
};

/* Routing Table Entry */
struct routing_entry {
    uint32_t destination_id;
    uint32_t next_hop;
    uint8_t hop_count;
    float route_cost;
    uint32_t last_updated;
    uint32_t expiry;
    uint8_t is_valid;
};

/* Route Request Tracking */
struct route_request_entry {
    uint32_t request_id;
    uint32_t originator_id;
    uint32_t destination_id;
    uint32_t timestamp;
    uint8_t is_active;
    uint8_t awaiting_reply;        /* 1 if this node initiated the request */
    uint32_t *reverse_path;        /* Path from originator to destination */
    uint8_t reverse_path_len;
};

/* Pending Route Request (for tracking outgoing requests) */
struct pending_route_request {
    uint32_t request_id;
    uint32_t destination_id;
    uint32_t timestamp;
    uint8_t retries;
    uint8_t is_active;
};

#define MAX_PENDING_REQUESTS 16
#define ROUTE_REQUEST_TIMEOUT_SECONDS 10
#define MAX_ROUTE_REQUEST_RETRIES 3

/* Connection Table */
struct connection_table {
    struct connection_entry entries[MAX_CONNECTION_TABLE_ENTRIES];
    size_t count;
};

/* Routing Table */
struct routing_table {
    struct routing_entry entries[MAX_ROUTING_TABLE_ENTRIES];
    size_t count;
};

/* Route Request Cache */
struct route_request_cache {
    struct route_request_entry entries[MAX_PENDING_ROUTE_REQUESTS];
    size_t count;
};

/* Retransmission Configuration */
#define MAX_PENDING_PACKETS 32
#define MAX_RETRANSMISSION_RETRIES 5
#define INITIAL_RETRANSMIT_INTERVAL_MS 500      /* 500ms initial interval */
#define MAX_RETRANSMIT_INTERVAL_MS 30000        /* 30 seconds max interval */
#define RETRANSMIT_BACKOFF_FACTOR 2             /* Exponential backoff multiplier */

/* Pending Packet States */
enum pending_packet_state {
    PACKET_STATE_EMPTY = 0,
    PACKET_STATE_AWAITING_ROUTE,     /* Waiting for route discovery */
    PACKET_STATE_AWAITING_ACK,       /* Sent, waiting for acknowledgement */
    PACKET_STATE_DELIVERED,          /* Successfully acknowledged */
    PACKET_STATE_FAILED              /* Max retries exceeded */
};

/* Pending Packet Entry for retransmission queue */
struct pending_packet {
    uint16_t sequence_number;        /* Packet sequence number */
    uint32_t destination_id;         /* Final destination */
    uint8_t *packet_data;            /* Serialized packet data */
    size_t packet_len;               /* Length of packet data */
    uint32_t created_timestamp;      /* When packet was queued */
    uint32_t next_retry_timestamp;   /* When to retry next */
    uint32_t retry_interval_ms;      /* Current retry interval (grows with backoff) */
    uint8_t retry_count;             /* Number of retries attempted */
    enum pending_packet_state state; /* Current state */
    uint32_t request_id;             /* Associated route request ID (if awaiting route) */
};

/* Pending Packet Queue */
struct pending_packet_queue {
    struct pending_packet packets[MAX_PENDING_PACKETS];
    size_t count;
    uint16_t next_sequence_number;   /* Global sequence counter */
};

/* Mesh Node */
struct mesh_node {
    uint32_t device_id;
    enum NODE_TYPE node_type;
    uint8_t max_connections;
    uint8_t available_connections;
    struct connection_table *connection_table;
    struct routing_table *routing_table;
    struct route_request_cache *request_cache;
    struct pending_packet_queue *packet_queue;     /* Packet forwarding queue */
    struct pending_route_request pending_requests[MAX_PENDING_REQUESTS];
    size_t pending_count;
    uint32_t last_discovery_time;
    uint8_t discovery_active;
};

/* Node Management Functions */
struct mesh_node *create_mesh_node(uint32_t device_id, enum NODE_TYPE node_type);
uint8_t get_max_connections(enum NODE_TYPE node_type);

/* Connection Table Functions */
struct connection_table *create_connection_table(void);
int add_connection(struct connection_table *table, uint32_t neighbor_id, int8_t rssi);
int remove_connection(struct connection_table *table, uint32_t neighbor_id);
struct connection_entry *find_connection(struct connection_table *table, uint32_t neighbor_id);
int update_connection_state(struct connection_table *table, uint32_t neighbor_id, enum CONNECTION_STATE state);
int update_connection_rssi(struct connection_table *table, uint32_t neighbor_id, int8_t rssi);
int update_link_quality(struct connection_table *table, uint32_t neighbor_id, uint8_t success);
void update_last_seen(struct connection_table *table, uint32_t neighbor_id, uint32_t timestamp);
float calculate_link_quality(struct connection_entry *entry);
void check_connection_timeouts(struct connection_table *table, uint32_t current_time);

/* Routing Table Functions */
struct routing_table *create_routing_table(void);
int add_route(struct routing_table *table, uint32_t destination_id, uint32_t next_hop, uint8_t hop_count, float route_cost, uint32_t timestamp);
int remove_route(struct routing_table *table, uint32_t destination_id);
struct routing_entry *find_route(struct routing_table *table, uint32_t destination_id);
struct routing_entry *find_best_route(struct routing_table *table, uint32_t destination_id);
int update_route_cost(struct routing_table *table, uint32_t destination_id, float new_cost);
void maintain_routing_table(struct routing_table *table, uint32_t current_time);
void expire_routes(struct routing_table *table, uint32_t current_time);
float calculate_route_cost(struct connection_table *conn_table, uint32_t *path, uint8_t path_len);

/* Route Request Cache Functions */
struct route_request_cache *create_route_request_cache(void);
int add_route_request(struct route_request_cache *cache, uint32_t request_id, uint32_t originator_id, uint32_t timestamp);
int has_seen_request(struct route_request_cache *cache, uint32_t request_id);
void cleanup_old_requests(struct route_request_cache *cache, uint32_t current_time, uint32_t timeout);

/* Discovery Functions */
int should_send_discovery(struct mesh_node *node, uint32_t current_time);
int has_available_connections(struct mesh_node *node);

/* Heartbeat Functions */
void increment_missed_heartbeat(struct connection_table *table, uint32_t neighbor_id);
void reset_missed_heartbeats(struct connection_table *table, uint32_t neighbor_id);
void check_heartbeat_timeouts(struct mesh_node *node, uint32_t current_time);

/* Check for heartbeat timeouts and return list of timed-out node IDs
 * Returns number of timed-out nodes, fills timed_out_ids array (max max_count entries)
 * Also marks them as DISCONNECTED in the connection table */
size_t check_and_get_heartbeat_timeouts(struct mesh_node *node, uint32_t current_time,
                                         uint32_t *timed_out_ids, size_t max_count);

/* Route Discovery Functions */
int initiate_route_discovery(struct mesh_node *node, uint32_t destination_id,
                              uint32_t **reverse_path_out, uint8_t *path_len_out);
int process_route_request(struct mesh_node *node, uint32_t request_id, uint32_t destination_id,
                          uint8_t hop_count, uint32_t *reverse_path, uint8_t reverse_path_len,
                          uint32_t sender_id);
int process_route_reply(struct mesh_node *node, uint32_t request_id, uint8_t route_cost,
                        const uint32_t *forward_path, uint8_t forward_path_len);

/* Route Request Result Structure */
struct route_request_result {
    int action;                    /* 0=forward, 1=destination reached, 2=cached route, -1=drop */
    uint32_t request_id;
    uint32_t destination_id;
    uint8_t hop_count;
    uint32_t *updated_reverse_path;
    uint8_t updated_path_len;
    uint32_t exclude_neighbor;     /* Neighbor to exclude when forwarding (sender) */
};

/* Route Reply Result Structure */
struct route_reply_result {
    int action;                    /* 0=forward to next, 1=we are originator (done), -1=error */
    uint32_t next_hop;             /* Next hop to forward reply to */
    uint32_t request_id;
    uint8_t route_cost;
    uint32_t *forward_path;
    uint8_t forward_path_len;
};

/* Enhanced Route Discovery Functions */

/**
 * Create a route request message for a destination
 * Returns request_id on success, -1 on failure
 */
int create_route_request(struct mesh_node *node, uint32_t destination_id,
                         struct route_request *req_out);

/**
 * Handle incoming route request
 * Returns result structure with action to take
 */
int handle_route_request(struct mesh_node *node, const struct route_request *req,
                        uint32_t sender_id, struct route_request_result *result);

/**
 * Create a route reply when destination is reached
 * The forward_path is the reverse of the reverse_path
 */
int create_route_reply(struct mesh_node *node, uint32_t request_id,
                      const uint32_t *reverse_path, uint8_t reverse_path_len,
                      struct route_reply *reply_out);

/**
 * Handle incoming route reply
 * Returns result structure with action to take
 */
int handle_route_reply(struct mesh_node *node, const struct route_reply *reply,
                      uint32_t sender_id, struct route_reply_result *result);

/**
 * Add a pending route request (for tracking timeouts)
 */
int add_pending_route_request(struct mesh_node *node, uint32_t request_id,
                              uint32_t destination_id);

/**
 * Remove a pending route request
 */
int remove_pending_route_request(struct mesh_node *node, uint32_t request_id);

/**
 * Check for timed-out route requests
 * Returns number of timed-out requests, fills arrays
 */
size_t check_route_request_timeouts(struct mesh_node *node, uint32_t current_time,
                                   uint32_t *timed_out_destinations, size_t max_count);

/**
 * Get all connected neighbors for broadcasting route requests
 */
size_t get_connected_neighbors(struct mesh_node *node, uint32_t *neighbors,
                               size_t max_count, uint32_t exclude_id);

/* Packet Forwarding Functions */
int forward_packet(struct mesh_node *node, uint32_t destination_id, uint8_t *ttl,
                   uint32_t *next_hop_out);
int should_process_locally(struct mesh_node *node, uint32_t destination_id);

/* ========================================================================== */
/* Packet Forwarding Engine Functions                                          */
/* ========================================================================== */

/**
 * Forwarding Decision Result
 * Returned by the packet forwarding decision function
 */
struct forwarding_decision {
    int action;                      /* 0=forward, 1=local delivery, -1=error, -2=need route */
    uint32_t next_hop;               /* Next hop for forwarding */
    uint8_t error_code;              /* Error code if action is error */
    uint32_t request_id;             /* Route request ID if route discovery initiated */
};

/* Pending Packet Queue Functions */
struct pending_packet_queue *create_pending_packet_queue(void);
void free_pending_packet_queue(struct pending_packet_queue *queue);

/**
 * Queue a packet for transmission with retransmission support
 * Returns sequence number on success, 0 on failure
 */
uint16_t queue_packet_for_transmission(struct pending_packet_queue *queue,
                                       uint32_t destination_id,
                                       const uint8_t *packet_data,
                                       size_t packet_len,
                                       uint32_t current_time_ms);

/**
 * Mark a packet as successfully acknowledged
 * Updates route cost on successful delivery
 */
int acknowledge_packet(struct pending_packet_queue *queue,
                       struct routing_table *routing_table,
                       struct connection_table *conn_table,
                       uint16_t sequence_number,
                       uint32_t sender_id);

/**
 * Associate a route request with pending packets awaiting route
 * Called when route discovery is initiated for a destination
 */
int associate_route_request_with_packets(struct pending_packet_queue *queue,
                                         uint32_t destination_id,
                                         uint32_t request_id);

/**
 * Handle route discovery completion
 * Marks packets as ready to send
 * Returns number of packets ready to send
 */
size_t handle_route_discovery_complete(struct pending_packet_queue *queue,
                                       uint32_t destination_id);

/**
 * Handle route discovery failure
 * Marks associated packets as failed
 */
int handle_route_discovery_failed(struct pending_packet_queue *queue,
                                  uint32_t destination_id);

/**
 * Check for packets that need retransmission
 * Returns number of packets needing retry, fills arrays
 * Also handles dropping packets that exceeded max retries
 */
size_t check_retransmission_timeouts(struct pending_packet_queue *queue,
                                     uint32_t current_time_ms,
                                     uint16_t *retry_sequence_numbers,
                                     size_t max_count);

/**
 * Get a pending packet by sequence number
 * Returns NULL if not found
 */
struct pending_packet *get_pending_packet(struct pending_packet_queue *queue,
                                          uint16_t sequence_number);

/**
 * Update retry timing after retransmission attempt
 * Implements exponential backoff
 */
void update_retry_timing(struct pending_packet *packet, uint32_t current_time_ms);

/**
 * Remove a packet from the queue (after delivery or final failure)
 */
int remove_pending_packet(struct pending_packet_queue *queue, uint16_t sequence_number);

/**
 * Clean up failed/delivered packets from the queue
 * Returns number of packets cleaned up
 */
size_t cleanup_pending_packets(struct pending_packet_queue *queue);

/**
 * Make forwarding decision for a packet
 * Determines if packet should be forwarded, delivered locally, or needs route discovery
 */
int make_forwarding_decision(struct mesh_node *node,
                             uint32_t destination_id,
                             uint8_t *ttl,
                             struct forwarding_decision *decision);

/**
 * Update route cost based on acknowledgement
 * Improves route cost when acks received, degrades on failures
 */
int update_route_cost_on_ack(struct routing_table *table,
                             struct connection_table *conn_table,
                             uint32_t destination_id,
                             uint32_t next_hop,
                             int success);

/**
 * Find a pending route request for a destination
 * Returns the request_id if found, 0 otherwise
 */
uint32_t find_pending_route_request_for_dest(struct mesh_node *node, uint32_t destination_id);

/**
 * Check if there's a pending route discovery for a destination
 */
int has_pending_route_discovery(struct mesh_node *node, uint32_t destination_id);

/* Utility Functions */
void free_connection_table(struct connection_table *table);
void free_mesh_node(struct mesh_node *node);
void free_routing_table(struct routing_table *table);
void free_route_request_cache(struct route_request_cache *cache);

#endif



