#ifndef LOCALNET_ROUTING_H
#define LOCALNET_ROUTING_H

#include <stdint.h>
#include <stddef.h>

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
    uint32_t timestamp;
    uint8_t is_active;
};

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

/* Mesh Node */
struct mesh_node {
    uint32_t device_id;
    enum NODE_TYPE node_type;
    uint8_t max_connections;
    uint8_t available_connections;
    struct connection_table *connection_table;
    struct routing_table *routing_table;
    struct route_request_cache *request_cache;
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

/* Packet Forwarding Functions */
int forward_packet(struct mesh_node *node, uint32_t destination_id, uint8_t *ttl,
                   uint32_t *next_hop_out);
int should_process_locally(struct mesh_node *node, uint32_t destination_id);

/* Utility Functions */
void free_connection_table(struct connection_table *table);
void free_mesh_node(struct mesh_node *node);
void free_routing_table(struct routing_table *table);
void free_route_request_cache(struct route_request_cache *cache);

#endif