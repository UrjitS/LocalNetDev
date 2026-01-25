#include "routing.h"
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include <stdio.h>


uint8_t get_max_connections(const enum NODE_TYPE node_type) {
    switch (node_type) {
        case EDGE_NODE:
            return MAX_CONNECTIONS_EDGE;
        case FULL_NODE:
            return MAX_CONNECTIONS_FULL;
        case GATEWAY_NODE:
            return MAX_CONNECTIONS_GATEWAY;
        default:
            return MAX_CONNECTIONS_EDGE;
    }
}

void free_connection_table(struct connection_table *table) {
    free(table);
}

void free_routing_table(struct routing_table *table) {
    free(table);
}

void free_route_request_cache(struct route_request_cache *cache) {
    free(cache);
}

void free_mesh_node(struct mesh_node *node) {
    if (!node) return;
    free_connection_table(node->connection_table);
    free_routing_table(node->routing_table);
    free_route_request_cache(node->request_cache);
    free(node);
}

/* Node Management Functions */
struct mesh_node *create_mesh_node(const uint32_t device_id, const enum NODE_TYPE node_type) {
    struct mesh_node *node = malloc(sizeof(struct mesh_node));
    if (!node) return NULL;

    node->device_id = device_id;
    node->node_type = node_type;
    node->max_connections = get_max_connections(node_type);
    node->available_connections = node->max_connections;
    node->last_discovery_time = 0;
    node->discovery_active = 1;

    node->connection_table = create_connection_table();
    node->routing_table = create_routing_table();
    node->request_cache = create_route_request_cache();

    if (!node->connection_table || !node->routing_table || !node->request_cache) {
        free_mesh_node(node);
        return NULL;
    }

    return node;
}

/* Connection Table Functions */
struct connection_table *create_connection_table(void) {
    struct connection_table *table = malloc(sizeof(struct connection_table));
    if (!table) return NULL;

    memset(table->entries, 0, sizeof(table->entries));
    table->count = 0;

    return table;
}



int add_connection(struct connection_table *table, const uint32_t neighbor_id, const int8_t rssi) {
    if (!table || table->count >= MAX_CONNECTION_TABLE_ENTRIES) return -1;

    // Check if already exists
    if (find_connection(table, neighbor_id) != NULL) return -1;

    struct connection_entry *entry = &table->entries[table->count];
    entry->neighbor_id = neighbor_id;
    entry->rssi = rssi;
    entry->link_quality = 1.0f;
    entry->last_seen = get_current_timestamp();
    entry->state = CONNECTING;
    entry->successful_packets = 0;
    entry->total_packets = 0;
    entry->missed_heartbeats = 0;

    table->count++;
    return 0;
}

int remove_connection(struct connection_table *table, const uint32_t neighbor_id) {
    if (!table) return -1;

    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].neighbor_id == neighbor_id) {
            // Shift remaining entries
            for (size_t j = i; j < table->count - 1; j++) {
                table->entries[j] = table->entries[j + 1];
            }
            table->count--;
            memset(&table->entries[table->count], 0, sizeof(struct connection_entry));
            return 0;
        }
    }
    return -1;
}

struct connection_entry *find_connection(struct connection_table *table, const uint32_t neighbor_id) {
    if (!table) return NULL;

    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].neighbor_id == neighbor_id) {
            return &table->entries[i];
        }
    }
    return NULL;
}

int update_connection_state(struct connection_table *table, const uint32_t neighbor_id, const enum CONNECTION_STATE state) {
    struct connection_entry *entry = find_connection(table, neighbor_id);
    if (!entry) return -1;

    entry->state = state;
    return 0;
}

int update_connection_rssi(struct connection_table *table, const uint32_t neighbor_id, const int8_t rssi) {
    struct connection_entry *entry = find_connection(table, neighbor_id);
    if (!entry) return -1;

    entry->rssi = rssi;
    return 0;
}

int update_link_quality(struct connection_table *table, const uint32_t neighbor_id, const uint8_t success) {
    struct connection_entry *entry = find_connection(table, neighbor_id);
    if (!entry) return -1;

    // Update packet counts
    if (entry->total_packets < LINK_QUALITY_WINDOW) {
        entry->total_packets++;
        if (success) entry->successful_packets++;
    } else {
        entry->successful_packets = (uint16_t)((float)entry->successful_packets * 0.99f + (success ? 1.0f : 0.0f));
        entry->total_packets = (uint16_t)((float)entry->total_packets * 0.99f + 1.0f);
    }

    entry->link_quality = calculate_link_quality(entry);

    return 0;
}

void update_last_seen(struct connection_table *table, const uint32_t neighbor_id, const uint32_t timestamp) {
    struct connection_entry *entry = find_connection(table, neighbor_id);
    if (entry) {
        entry->last_seen = timestamp;
    }
}

float calculate_link_quality(struct connection_entry *entry) {
    if (!entry || entry->total_packets == 0) return 0.0f;
    return (float)entry->successful_packets / (float)entry->total_packets;
}

void check_connection_timeouts(struct connection_table *table, const uint32_t current_time) {
    if (!table) return;

    for (size_t i = 0; i < table->count; i++) {
        struct connection_entry *entry = &table->entries[i];
        if (current_time - entry->last_seen > CONNECTION_TIMEOUT_SECONDS) {
            entry->state = DISCONNECTED;
        }
    }
}

/* Routing Table Functions */
struct routing_table *create_routing_table(void) {
    struct routing_table *table = malloc(sizeof(struct routing_table));
    if (!table) return NULL;

    memset(table->entries, 0, sizeof(table->entries));
    table->count = 0;

    return table;
}

int add_route(struct routing_table *table, const uint32_t destination_id, const uint32_t next_hop, const uint8_t hop_count, const float route_cost, const uint32_t timestamp) {
    if (!table) return -1;

    // Check if route already exists
    struct routing_entry *existing = find_route(table, destination_id);
    if (existing) {
        // Update existing route if better
        if (route_cost < existing->route_cost) {
            existing->next_hop = next_hop;
            existing->hop_count = hop_count;
            existing->route_cost = route_cost;
            existing->last_updated = timestamp;
            existing->expiry = ROUTE_EXPIRY_SECONDS;
        }
        return 0;
    }

    if (table->count >= MAX_ROUTING_TABLE_ENTRIES) return -1;

    // Add new route
    struct routing_entry *entry = &table->entries[table->count];
    entry->destination_id = destination_id;
    entry->next_hop = next_hop;
    entry->hop_count = hop_count;
    entry->route_cost = route_cost;
    entry->last_updated = timestamp;
    entry->expiry = ROUTE_EXPIRY_SECONDS;
    entry->is_valid = 1;

    table->count++;
    return 0;
}

int remove_route(struct routing_table *table, const uint32_t destination_id) {
    if (!table) return -1;

    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].destination_id == destination_id) {
            // Shift remaining entries
            for (size_t j = i; j < table->count - 1; j++) {
                table->entries[j] = table->entries[j + 1];
            }
            table->count--;
            memset(&table->entries[table->count], 0, sizeof(struct routing_entry));
            return 0;
        }
    }
    return -1;
}

struct routing_entry *find_route(struct routing_table *table, const uint32_t destination_id) {
    if (!table) return NULL;

    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].destination_id == destination_id && table->entries[i].is_valid) {
            return &table->entries[i];
        }
    }
    return NULL;
}

struct routing_entry *find_best_route(struct routing_table *table, const uint32_t destination_id) {
    if (!table) return NULL;

    struct routing_entry *best = NULL;
    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].destination_id == destination_id && table->entries[i].is_valid) {
            if (!best || table->entries[i].route_cost < best->route_cost) {
                best = &table->entries[i];
            }
        }
    }
    return best;
}

int update_route_cost(struct routing_table *table, const uint32_t destination_id, const float new_cost) {
    struct routing_entry *entry = find_route(table, destination_id);
    if (!entry) return -1;

    entry->route_cost = new_cost;
    entry->last_updated = get_current_timestamp();
    return 0;
}

void maintain_routing_table(struct routing_table *table, const uint32_t current_time) {
    if (!table) return;
    expire_routes(table, current_time);
}

void expire_routes(struct routing_table *table, const uint32_t current_time) {
    if (!table) return;

    for (size_t i = 0; i < table->count; i++) {
        struct routing_entry *entry = &table->entries[i];
        const uint32_t age = current_time - entry->last_updated;

        if (age >= entry->expiry) {
            entry->is_valid = 0;
            // TODO Could remove or mark for rediscovery
        }
    }
}

float calculate_route_cost(struct connection_table *conn_table, uint32_t *path, const uint8_t path_len) {
    if (!conn_table || !path || path_len == 0) return 99.9f;

    float total_cost = 0.0f;
    for (uint8_t i = 0; i < path_len - 1; i++) {
        const struct connection_entry *conn = find_connection(conn_table, path[i + 1]);
        if (conn && conn->link_quality > 0.0f) {
            // Hop Quality = 1 / Link Quality
            total_cost += (1.0f / conn->link_quality);
        } else {
            total_cost += 10.0f;
        }
    }
    return total_cost;
}

/* Route Request Cache Functions */
struct route_request_cache *create_route_request_cache(void) {
    struct route_request_cache * rr_cache = malloc(sizeof(struct route_request_cache));
    if (!rr_cache) return NULL;

    memset(rr_cache->entries, 0, sizeof(rr_cache->entries));
    rr_cache->count = 0;

    return rr_cache;
}

int add_route_request(struct route_request_cache *cache, const uint32_t request_id, const uint32_t originator_id, const uint32_t timestamp) {
    if (!cache) return -1;

    // Check if already exists
    if (has_seen_request(cache, request_id)) return -1;

    // Find empty slot or replace oldest
    size_t index = cache->count;
    if (cache->count >= MAX_PENDING_ROUTE_REQUESTS) {
        // Find oldest entry
        uint32_t oldest_time = cache->entries[0].timestamp;
        index = 0;
        for (size_t i = 1; i < MAX_PENDING_ROUTE_REQUESTS; i++) {
            if (cache->entries[i].timestamp < oldest_time) {
                oldest_time = cache->entries[i].timestamp;
                index = i;
            }
        }
    } else {
        cache->count++;
    }

    cache->entries[index].request_id = request_id;
    cache->entries[index].originator_id = originator_id;
    cache->entries[index].timestamp = timestamp;
    cache->entries[index].is_active = 1;

    return 0;
}

int has_seen_request(struct route_request_cache *cache, const uint32_t request_id) {
    if (!cache) return 0;

    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].request_id == request_id && cache->entries[i].is_active) {
            return 1;
        }
    }
    return 0;
}

void cleanup_old_requests(struct route_request_cache *cache, const uint32_t current_time, const uint32_t timeout) {
    if (!cache) return;

    for (size_t i = 0; i < cache->count; i++) {
        if (current_time - cache->entries[i].timestamp > timeout) {
            cache->entries[i].is_active = 0;
        }
    }
}

/* Discovery Functions */
int should_send_discovery(struct mesh_node *node, const uint32_t current_time) {
    if (!node || !has_available_connections(node)) return 0;

    const uint32_t elapsed = current_time - node->last_discovery_time;

    // Initial discovery phase (first 2 minutes)
    // TODO Something should be responsible to set the discovery_active to false otherwise we will always send discovery every 2 mins
    if (node->discovery_active && current_time - node->last_discovery_time < DISCOVERY_INITIAL_DURATION) {
        return elapsed >= DISCOVERY_INITIAL_INTERVAL;
    }

    // Regular discovery (every 5 minutes)
    return elapsed >= DISCOVERY_LONG_INTERVAL;
}

int has_available_connections(struct mesh_node *node) {
    if (!node || !node->connection_table) return 0;

    uint8_t active_connections = 0;
    for (size_t i = 0; i < node->connection_table->count; i++) {
        if (node->connection_table->entries[i].state == STABLE ||
            node->connection_table->entries[i].state == CONNECTING) {
            active_connections++;
        }
    }

    return active_connections < node->max_connections;
}

/* Heartbeat Functions */
void increment_missed_heartbeat(struct connection_table *table, const uint32_t neighbor_id) {
    struct connection_entry *entry = find_connection(table, neighbor_id);
    if (entry) {
        entry->missed_heartbeats++;
        if (entry->missed_heartbeats >= HEARTBEAT_MISSED_THRESHOLD) {
            entry->state = DISCONNECTED;
        }
    }
}

void reset_missed_heartbeats(struct connection_table *table, const uint32_t neighbor_id) {
    struct connection_entry *entry = find_connection(table, neighbor_id);
    if (entry) {
        entry->missed_heartbeats = 0;
    }
}

void check_heartbeat_timeouts(struct mesh_node *node, const uint32_t current_time) {
    if (!node || !node->connection_table) return;

    for (size_t i = 0; i < node->connection_table->count; i++) {
        struct connection_entry *entry = &node->connection_table->entries[i];
        if (entry->state == STABLE) {
            const uint32_t time_since_seen = current_time - entry->last_seen;

            // Check if we should increment missed heartbeats
            const uint32_t expected_heartbeats = time_since_seen / HEARTBEAT_INTERVAL_SECONDS;
            if (expected_heartbeats > 0 && (uint32_t)entry->missed_heartbeats < expected_heartbeats) {
                entry->missed_heartbeats = (uint8_t)expected_heartbeats;

                if (entry->missed_heartbeats >= HEARTBEAT_MISSED_THRESHOLD) {
                    entry->state = DISCONNECTED;
                }
            }
        }
    }
}

size_t check_and_get_heartbeat_timeouts(struct mesh_node *node, const uint32_t current_time,
                                         uint32_t *timed_out_ids, size_t max_count) {
    if (!node || !node->connection_table || !timed_out_ids || max_count == 0) return 0;

    size_t timeout_count = 0;

    for (size_t i = 0; i < node->connection_table->count; i++) {
        struct connection_entry *entry = &node->connection_table->entries[i];

        /* Check all connected states (STABLE and CONNECTING) */
        if (entry->state == STABLE || entry->state == CONNECTING) {
            const uint32_t time_since_seen = current_time - entry->last_seen;

            /* Check if we should increment missed heartbeats */
            const uint32_t expected_heartbeats = time_since_seen / HEARTBEAT_INTERVAL_SECONDS;
            if (expected_heartbeats > 0 && (uint32_t)entry->missed_heartbeats < expected_heartbeats) {
                entry->missed_heartbeats = (uint8_t)expected_heartbeats;

                if (entry->missed_heartbeats >= HEARTBEAT_MISSED_THRESHOLD) {
                    entry->state = DISCONNECTED;

                    /* Add to output list if we have room */
                    if (timeout_count < max_count) {
                        timed_out_ids[timeout_count] = entry->neighbor_id;
                        timeout_count++;
                    }
                }
            }
        }
    }

    return timeout_count;
}

/* Route Discovery Functions */
int initiate_route_discovery(struct mesh_node *node, const uint32_t destination_id, uint32_t **reverse_path_out, uint8_t *path_len_out) {
    if (!node || !reverse_path_out || !path_len_out) return -1;

    const struct routing_entry *exists = find_route(node->routing_table, destination_id);
    if (exists && exists->is_valid) {
        return 0;
    }

    // Allocate reverse path
    uint32_t *reverse_path = malloc(sizeof(uint32_t) * (MAX_HOP_COUNT + 1));
    if (!reverse_path) return -1;

    // Add this node
    reverse_path[0] = node->device_id;
    *reverse_path_out = reverse_path;
    *path_len_out = 1;

    // Generate request ID and add to cache
    const uint32_t request_id = generate_request_id();
    add_route_request(node->request_cache, request_id, node->device_id, get_current_timestamp());

    return (int)request_id;
}

int process_route_request(struct mesh_node *node, const uint32_t request_id, const uint32_t destination_id,
                          uint8_t hop_count, uint32_t *reverse_path, uint8_t reverse_path_len,
                          uint32_t sender_id) {
    if (!node || !reverse_path) return -1;

    // Check if already seen this request
    if (has_seen_request(node->request_cache, request_id)) {
        return -1;  // Drop duplicate
    }

    // Add to request cache
    add_route_request(node->request_cache, request_id, reverse_path[0], get_current_timestamp());

    // Increment hop count
    hop_count++;

    // Check if we are the destination
    if (destination_id == node->device_id) {
        // TODO Send route reply
        return 1;
    }

    // Check if we have route to destination (for FULL_NODE and GATEWAY_NODE)
    if (node->node_type != EDGE_NODE) {
        const struct routing_entry *route = find_route(node->routing_table, destination_id);
        if (route && route->is_valid) {
            //TODO  Can send cached route reply
            return 2;
        }
    }

    // Check hop count limit
    if (hop_count >= MAX_HOP_COUNT) {
        return -1;
    }

    // TODO Forward request & ADD this node to path
    return 0;
}

int process_route_reply(struct mesh_node *node, uint32_t request_id, const uint8_t route_cost,
                        const uint32_t *forward_path, const uint8_t forward_path_len) {
    if (!node || !forward_path || forward_path_len < 2) return -1;

    // The forward path should contain: [originator, ..., us, ..., destination]
    // We need to find our position and add route to destination through next hop

    // Find our position in the path
    int our_position = -1;
    for (uint8_t i = 0; i < forward_path_len; i++) {
        if (forward_path[i] == node->device_id) {
            our_position = i;
            break;
        }
    }

    if (our_position < 0 || our_position >= forward_path_len - 1) {
        return -1;  // We're not in path or we're the destination
    }

    // Next hop is the next node in the forward path
    uint32_t next_hop = forward_path[our_position + 1];
    uint32_t destination_id = forward_path[forward_path_len - 1];

    // Calculate hop count from us to destination
    uint8_t hop_count = forward_path_len - our_position - 1;

    // Calculate route cost
    float cost = (float)route_cost;

    // Add or update route
    add_route(node->routing_table, destination_id, next_hop, hop_count, cost, get_current_timestamp());

    return 0;
}

/* Packet Forwarding Functions */
int forward_packet(struct mesh_node *node, const uint32_t destination_id, uint8_t *ttl,
                   uint32_t *next_hop_out) {
    if (!node || !ttl || !next_hop_out) return -1;

    // Check if this is for us
    if (should_process_locally(node, destination_id)) {
        return 1;  // Process locally
    }

    // Check TTL
    if (*ttl <= 0) {
        return -1;  // TTL expired
    }

    // Decrement TTL
    (*ttl)--;

    // Find route to destination
    struct routing_entry *route = find_best_route(node->routing_table, destination_id);
    if (!route || !route->is_valid) {
        return -2;  // No route found - need route discovery
    }

    *next_hop_out = route->next_hop;
    return 0;  // Forward to next hop
}

int should_process_locally(struct mesh_node *node, const uint32_t destination_id) {
    if (!node) return 0;
    return node->device_id == destination_id;
}
