#include "routing.h"
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "protocol.h"
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
    free_pending_packet_queue(node->packet_queue);
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
    node->pending_count = 0;
    memset(node->pending_requests, 0, sizeof(node->pending_requests));

    node->connection_table = create_connection_table();
    node->routing_table = create_routing_table();
    node->request_cache = create_route_request_cache();
    node->packet_queue = create_pending_packet_queue();

    if (!node->connection_table || !node->routing_table || !node->request_cache || !node->packet_queue) {
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

/* ========================================================================== */
/* Enhanced Route Discovery Implementation                                     */
/* ========================================================================== */

int create_route_request(struct mesh_node *node, const uint32_t destination_id,
                         struct route_request *req_out) {
    if (!node || !req_out) return -1;

    /* Check if we already have a valid route */
    const struct routing_entry *existing = find_route(node->routing_table, destination_id);
    if (existing && existing->is_valid) {
        return 0;  /* Already have route, no need for discovery */
    }

    /* Generate request ID */
    const uint32_t request_id = generate_request_id();

    /* Add to request cache */
    add_route_request(node->request_cache, request_id, node->device_id, get_current_timestamp());

    /* Add to pending requests for timeout tracking */
    add_pending_route_request(node, request_id, destination_id);

    /* Build the route request */
    req_out->request_id = request_id;
    req_out->destination_id = destination_id;
    req_out->hop_count = 0;
    req_out->reverse_path_len = 1;

    /* Allocate and set reverse path with originator (this node) */
    req_out->reverse_path = malloc(sizeof(uint32_t) * (MAX_HOP_COUNT + 1));
    if (!req_out->reverse_path) return -1;

    req_out->reverse_path[0] = node->device_id;

    return (int)request_id;
}

int handle_route_request(struct mesh_node *node, const struct route_request *req,
                        const uint32_t sender_id, struct route_request_result *result) {
    if (!node || !req || !result) return -1;

    memset(result, 0, sizeof(*result));
    result->request_id = req->request_id;
    result->destination_id = req->destination_id;
    result->exclude_neighbor = sender_id;

    /* Check if we've already processed this request */
    if (has_seen_request(node->request_cache, req->request_id)) {
        result->action = -1;  /* Drop duplicate */
        return -1;
    }

    /* Add to request cache to prevent processing duplicates */
    uint32_t originator_id = 0;
    if (req->reverse_path_len > 0 && req->reverse_path) {
        originator_id = req->reverse_path[0];
    }
    add_route_request(node->request_cache, req->request_id, originator_id, get_current_timestamp());

    /* Increment hop count */
    const uint8_t new_hop_count = req->hop_count + 1;
    result->hop_count = new_hop_count;

    /* Check if we are the destination */
    if (req->destination_id == node->device_id) {
        result->action = 1;  /* We are destination - generate route reply */

        /* Build updated reverse path including us */
        result->updated_path_len = req->reverse_path_len + 1;
        result->updated_reverse_path = malloc(sizeof(uint32_t) * result->updated_path_len);
        if (!result->updated_reverse_path) {
            result->action = -1;
            return -1;
        }

        /* Copy existing path and add ourselves at the end */
        if (req->reverse_path && req->reverse_path_len > 0) {
            memcpy(result->updated_reverse_path, req->reverse_path,
                   req->reverse_path_len * sizeof(uint32_t));
        }
        result->updated_reverse_path[result->updated_path_len - 1] = node->device_id;

        /* Add route back to originator through sender */
        if (originator_id != 0 && originator_id != node->device_id) {
            add_route(node->routing_table, originator_id, sender_id,
                     new_hop_count, (float)new_hop_count, get_current_timestamp());
        }

        return 1;
    }

    /* Check if we have a cached route to the destination (for FULL_NODE and GATEWAY_NODE) */
    if (node->node_type != EDGE_NODE) {
        const struct routing_entry *cached_route = find_route(node->routing_table, req->destination_id);
        if (cached_route && cached_route->is_valid) {
            result->action = 2;  /* Can reply with cached route */

            /* Build updated path including us */
            result->updated_path_len = req->reverse_path_len + 1;
            result->updated_reverse_path = malloc(sizeof(uint32_t) * result->updated_path_len);
            if (!result->updated_reverse_path) {
                result->action = -1;
                return -1;
            }

            if (req->reverse_path && req->reverse_path_len > 0) {
                memcpy(result->updated_reverse_path, req->reverse_path,
                       req->reverse_path_len * sizeof(uint32_t));
            }
            result->updated_reverse_path[result->updated_path_len - 1] = node->device_id;

            /* Add route back to originator */
            if (originator_id != 0 && originator_id != node->device_id) {
                add_route(node->routing_table, originator_id, sender_id,
                         new_hop_count, (float)new_hop_count, get_current_timestamp());
            }

            return 2;
        }
    }

    /* Check hop count limit */
    if (new_hop_count >= MAX_HOP_COUNT) {
        result->action = -1;  /* TTL exceeded */
        return -1;
    }

    /* Forward the request */
    result->action = 0;

    /* Build updated reverse path including us */
    result->updated_path_len = req->reverse_path_len + 1;
    result->updated_reverse_path = malloc(sizeof(uint32_t) * result->updated_path_len);
    if (!result->updated_reverse_path) {
        result->action = -1;
        return -1;
    }

    if (req->reverse_path && req->reverse_path_len > 0) {
        memcpy(result->updated_reverse_path, req->reverse_path,
               req->reverse_path_len * sizeof(uint32_t));
    }
    result->updated_reverse_path[result->updated_path_len - 1] = node->device_id;

    /* Add route back to originator through sender */
    if (originator_id != 0 && originator_id != node->device_id) {
        add_route(node->routing_table, originator_id, sender_id,
                 new_hop_count, (float)new_hop_count, get_current_timestamp());
    }

    return 0;
}

int create_route_reply(struct mesh_node *node, const uint32_t request_id,
                      const uint32_t *reverse_path, const uint8_t reverse_path_len,
                      struct route_reply *reply_out) {
    if (!node || !reverse_path || reverse_path_len < 1 || !reply_out) return -1;

    reply_out->request_id = request_id;
    reply_out->route_cost = reverse_path_len - 1;  /* Number of hops */
    reply_out->forward_path_len = reverse_path_len;

    /* Allocate forward path */
    reply_out->forward_path = malloc(sizeof(uint32_t) * reverse_path_len);
    if (!reply_out->forward_path) return -1;

    /* Forward path is the same as reverse path (originator -> destination) */
    /* The reverse path was built in order: [originator, hop1, hop2, ..., destination] */
    memcpy(reply_out->forward_path, reverse_path, reverse_path_len * sizeof(uint32_t));

    return 0;
}

int handle_route_reply(struct mesh_node *node, const struct route_reply *reply,
                      const uint32_t sender_id, struct route_reply_result *result) {
    if (!node || !reply || !result) return -1;

    memset(result, 0, sizeof(*result));
    result->request_id = reply->request_id;
    result->route_cost = reply->route_cost;

    if (!reply->forward_path || reply->forward_path_len < 2) {
        result->action = -1;
        return -1;
    }

    /* Find our position in the forward path */
    int our_position = -1;
    for (uint8_t i = 0; i < reply->forward_path_len; i++) {
        if (reply->forward_path[i] == node->device_id) {
            our_position = (int)i;
            break;
        }
    }

    if (our_position < 0) {
        /* We're not in the path - this reply is not for us */
        result->action = -1;
        return -1;
    }

    /* Add route to the destination (last node in forward path) */
    const uint32_t destination_id = reply->forward_path[reply->forward_path_len - 1];

    if (destination_id != node->device_id && our_position < reply->forward_path_len - 1) {
        /* Next hop toward destination */
        const uint32_t next_hop_to_dest = reply->forward_path[our_position + 1];
        const uint8_t hops_to_dest = reply->forward_path_len - our_position - 1;
        const float cost = (float)hops_to_dest;

        add_route(node->routing_table, destination_id, next_hop_to_dest,
                 hops_to_dest, cost, get_current_timestamp());
    }

    /* Check if we are the originator (first node in path) */
    if (our_position == 0) {
        /* We originated this request - route discovery complete */
        result->action = 1;

        /* Remove from pending requests */
        remove_pending_route_request(node, reply->request_id);

        return 1;
    }

    /* We are an intermediate node - forward toward originator */
    result->action = 0;

    /* Next hop toward originator is the previous node in path */
    result->next_hop = reply->forward_path[our_position - 1];

    /* Copy forward path for forwarding */
    result->forward_path_len = reply->forward_path_len;
    result->forward_path = malloc(sizeof(uint32_t) * reply->forward_path_len);
    if (!result->forward_path) {
        result->action = -1;
        return -1;
    }
    memcpy(result->forward_path, reply->forward_path,
           reply->forward_path_len * sizeof(uint32_t));

    return 0;
}

int add_pending_route_request(struct mesh_node *node, const uint32_t request_id,
                              const uint32_t destination_id) {
    if (!node) return -1;

    /* Check if already tracking this destination */
    for (size_t i = 0; i < node->pending_count; i++) {
        if (node->pending_requests[i].is_active &&
            node->pending_requests[i].destination_id == destination_id) {
            return -1;  /* Already pending for this destination */
        }
    }

    /* Find empty slot */
    size_t index = node->pending_count;
    if (node->pending_count >= MAX_PENDING_REQUESTS) {
        /* Find inactive slot or oldest entry */
        uint32_t oldest_time = UINT32_MAX;
        for (size_t i = 0; i < MAX_PENDING_REQUESTS; i++) {
            if (!node->pending_requests[i].is_active) {
                index = i;
                break;
            }
            if (node->pending_requests[i].timestamp < oldest_time) {
                oldest_time = node->pending_requests[i].timestamp;
                index = i;
            }
        }
    } else {
        node->pending_count++;
    }

    node->pending_requests[index].request_id = request_id;
    node->pending_requests[index].destination_id = destination_id;
    node->pending_requests[index].timestamp = get_current_timestamp();
    node->pending_requests[index].retries = 0;
    node->pending_requests[index].is_active = 1;

    return 0;
}

int remove_pending_route_request(struct mesh_node *node, const uint32_t request_id) {
    if (!node) return -1;

    for (size_t i = 0; i < node->pending_count; i++) {
        if (node->pending_requests[i].request_id == request_id &&
            node->pending_requests[i].is_active) {
            node->pending_requests[i].is_active = 0;
            return 0;
        }
    }
    return -1;
}

size_t check_route_request_timeouts(struct mesh_node *node, const uint32_t current_time,
                                   uint32_t *timed_out_destinations, const size_t max_count) {
    if (!node || !timed_out_destinations || max_count == 0) return 0;

    size_t timeout_count = 0;

    for (size_t i = 0; i < node->pending_count && timeout_count < max_count; i++) {
        struct pending_route_request *pending = &node->pending_requests[i];
        if (!pending->is_active) continue;

        const uint32_t elapsed = current_time - pending->timestamp;
        if (elapsed >= ROUTE_REQUEST_TIMEOUT_SECONDS) {
            if (pending->retries < MAX_ROUTE_REQUEST_RETRIES) {
                /* Mark for retry */
                pending->retries++;
                pending->timestamp = current_time;
                timed_out_destinations[timeout_count++] = pending->destination_id;
            } else {
                /* Max retries exceeded - give up */
                pending->is_active = 0;
            }
        }
    }

    return timeout_count;
}

size_t get_connected_neighbors(struct mesh_node *node, uint32_t *neighbors,
                               const size_t max_count, const uint32_t exclude_id) {
    if (!node || !node->connection_table || !neighbors || max_count == 0) return 0;

    size_t count = 0;

    for (size_t i = 0; i < node->connection_table->count && count < max_count; i++) {
        const struct connection_entry *entry = &node->connection_table->entries[i];
        if (entry->state == STABLE && entry->neighbor_id != exclude_id) {
            neighbors[count++] = entry->neighbor_id;
        }
    }

    return count;
}

/* ========================================================================== */
/* Packet Forwarding Engine Implementation                                     */
/* ========================================================================== */

struct pending_packet_queue *create_pending_packet_queue(void) {
    struct pending_packet_queue *queue = malloc(sizeof(struct pending_packet_queue));
    if (!queue) return NULL;

    memset(queue->packets, 0, sizeof(queue->packets));
    queue->count = 0;
    queue->next_sequence_number = 1;  /* Start from 1, 0 is reserved for invalid */

    return queue;
}

void free_pending_packet_queue(struct pending_packet_queue *queue) {
    if (!queue) return;

    /* Free all pending packet data */
    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        if (queue->packets[i].packet_data) {
            free(queue->packets[i].packet_data);
            queue->packets[i].packet_data = NULL;
        }
    }

    free(queue);
}

uint16_t queue_packet_for_transmission(struct pending_packet_queue *queue,
                                       const uint32_t destination_id,
                                       const uint8_t *packet_data,
                                       const size_t packet_len,
                                       const uint32_t current_time_ms) {
    if (!queue || !packet_data || packet_len == 0) return 0;

    /* Find empty slot */
    struct pending_packet *slot = NULL;
    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        if (queue->packets[i].state == PACKET_STATE_EMPTY ||
            queue->packets[i].state == PACKET_STATE_DELIVERED ||
            queue->packets[i].state == PACKET_STATE_FAILED) {
            /* Clear old data if present */
            if (queue->packets[i].packet_data) {
                free(queue->packets[i].packet_data);
            }
            slot = &queue->packets[i];
            break;
        }
    }

    if (!slot) {
        /* No empty slot available */
        return 0;
    }

    /* Allocate and copy packet data */
    slot->packet_data = malloc(packet_len);
    if (!slot->packet_data) return 0;
    memcpy(slot->packet_data, packet_data, packet_len);

    /* Initialize packet entry */
    slot->sequence_number = queue->next_sequence_number++;
    if (queue->next_sequence_number == 0) queue->next_sequence_number = 1;  /* Skip 0 */
    slot->destination_id = destination_id;
    slot->packet_len = packet_len;
    slot->created_timestamp = current_time_ms;
    slot->next_retry_timestamp = current_time_ms + INITIAL_RETRANSMIT_INTERVAL_MS;
    slot->retry_interval_ms = INITIAL_RETRANSMIT_INTERVAL_MS;
    slot->retry_count = 0;
    slot->state = PACKET_STATE_AWAITING_ACK;
    slot->request_id = 0;

    queue->count++;

    return slot->sequence_number;
}

int acknowledge_packet(struct pending_packet_queue *queue,
                       struct routing_table *routing_table,
                       struct connection_table *conn_table,
                       const uint16_t sequence_number,
                       const uint32_t sender_id) {
    if (!queue) return -1;

    struct pending_packet *packet = get_pending_packet(queue, sequence_number);
    if (!packet) return -1;

    /* Update route cost on successful acknowledgement */
    if (routing_table && conn_table) {
        update_route_cost_on_ack(routing_table, conn_table, packet->destination_id, sender_id, 1);
    }

    /* Mark as delivered */
    packet->state = PACKET_STATE_DELIVERED;

    return 0;
}

int associate_route_request_with_packets(struct pending_packet_queue *queue,
                                         const uint32_t destination_id,
                                         const uint32_t request_id) {
    if (!queue) return -1;

    int count = 0;
    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        struct pending_packet *packet = &queue->packets[i];
        if (packet->state == PACKET_STATE_AWAITING_ROUTE &&
            packet->destination_id == destination_id) {
            packet->request_id = request_id;
            count++;
        }
    }

    return count;
}

size_t handle_route_discovery_complete(struct pending_packet_queue *queue,
                                       const uint32_t destination_id) {
    if (!queue) return 0;

    size_t count = 0;
    const uint32_t current_time = get_current_timestamp() * 1000;  /* Convert to ms */

    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        struct pending_packet *packet = &queue->packets[i];
        if (packet->state == PACKET_STATE_AWAITING_ROUTE &&
            packet->destination_id == destination_id) {
            /* Mark as ready for transmission */
            packet->state = PACKET_STATE_AWAITING_ACK;
            packet->next_retry_timestamp = current_time;  /* Send immediately */
            packet->retry_interval_ms = INITIAL_RETRANSMIT_INTERVAL_MS;
            packet->retry_count = 0;
            count++;
        }
    }

    return count;
}

int handle_route_discovery_failed(struct pending_packet_queue *queue,
                                  const uint32_t destination_id) {
    if (!queue) return -1;

    int count = 0;
    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        struct pending_packet *packet = &queue->packets[i];
        if (packet->state == PACKET_STATE_AWAITING_ROUTE &&
            packet->destination_id == destination_id) {
            packet->state = PACKET_STATE_FAILED;
            count++;
        }
    }

    return count;
}

size_t check_retransmission_timeouts(struct pending_packet_queue *queue,
                                     const uint32_t current_time_ms,
                                     uint16_t *retry_sequence_numbers,
                                     const size_t max_count) {
    if (!queue || !retry_sequence_numbers || max_count == 0) return 0;

    size_t retry_count = 0;

    for (size_t i = 0; i < MAX_PENDING_PACKETS && retry_count < max_count; i++) {
        struct pending_packet *packet = &queue->packets[i];

        if (packet->state != PACKET_STATE_AWAITING_ACK) continue;

        /* Check if retry time has been reached */
        if (current_time_ms >= packet->next_retry_timestamp) {
            if (packet->retry_count >= MAX_RETRANSMISSION_RETRIES) {
                /* Max retries exceeded - mark as failed */
                packet->state = PACKET_STATE_FAILED;
                continue;
            }

            /* Mark for retry */
            retry_sequence_numbers[retry_count++] = packet->sequence_number;
        }
    }

    return retry_count;
}

struct pending_packet *get_pending_packet(struct pending_packet_queue *queue,
                                          const uint16_t sequence_number) {
    if (!queue || sequence_number == 0) return NULL;

    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        if (queue->packets[i].sequence_number == sequence_number &&
            queue->packets[i].state != PACKET_STATE_EMPTY) {
            return &queue->packets[i];
        }
    }

    return NULL;
}

void update_retry_timing(struct pending_packet *packet, const uint32_t current_time_ms) {
    if (!packet) return;

    packet->retry_count++;

    /* Exponential backoff with cap */
    packet->retry_interval_ms *= RETRANSMIT_BACKOFF_FACTOR;
    if (packet->retry_interval_ms > MAX_RETRANSMIT_INTERVAL_MS) {
        packet->retry_interval_ms = MAX_RETRANSMIT_INTERVAL_MS;
    }

    packet->next_retry_timestamp = current_time_ms + packet->retry_interval_ms;
}

int remove_pending_packet(struct pending_packet_queue *queue, const uint16_t sequence_number) {
    if (!queue) return -1;

    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        if (queue->packets[i].sequence_number == sequence_number) {
            if (queue->packets[i].packet_data) {
                free(queue->packets[i].packet_data);
            }
            memset(&queue->packets[i], 0, sizeof(struct pending_packet));
            queue->count--;
            return 0;
        }
    }

    return -1;
}

size_t cleanup_pending_packets(struct pending_packet_queue *queue) {
    if (!queue) return 0;

    size_t cleaned = 0;
    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        struct pending_packet *packet = &queue->packets[i];
        if (packet->state == PACKET_STATE_DELIVERED ||
            packet->state == PACKET_STATE_FAILED) {
            if (packet->packet_data) {
                free(packet->packet_data);
            }
            memset(packet, 0, sizeof(struct pending_packet));
            cleaned++;
            queue->count--;
        }
    }

    return cleaned;
}

int make_forwarding_decision(struct mesh_node *node,
                             const uint32_t destination_id,
                             uint8_t *ttl,
                             struct forwarding_decision *decision) {
    if (!node || !ttl || !decision) return -1;

    memset(decision, 0, sizeof(*decision));

    /* Check if packet is for us */
    if (should_process_locally(node, destination_id)) {
        decision->action = 1;  /* Local delivery */
        return 0;
    }

    /* Check TTL */
    if (*ttl <= 0) {
        decision->action = -1;
        decision->error_code = 0x03;  /* TTL Expired */
        return -1;
    }

    /* Decrement TTL */
    (*ttl)--;

    /* Look up route to destination */
    struct routing_entry *route = find_best_route(node->routing_table, destination_id);
    if (route && route->is_valid) {
        decision->action = 0;  /* Forward to next hop */
        decision->next_hop = route->next_hop;
        return 0;
    }

    /* No route found - check if we already have a pending route discovery */
    if (has_pending_route_discovery(node, destination_id)) {
        decision->action = -2;  /* Already discovering route */
        decision->request_id = find_pending_route_request_for_dest(node, destination_id);
        return 0;
    }

    /* Need to initiate route discovery */
    decision->action = -2;  /* Need route discovery */
    decision->error_code = 0x01;  /* Route not found */

    return 0;
}

int update_route_cost_on_ack(struct routing_table *table,
                             struct connection_table *conn_table,
                             const uint32_t destination_id,
                             const uint32_t next_hop,
                             const int success) {
    if (!table) return -1;

    struct routing_entry *route = find_route(table, destination_id);
    if (!route) return -1;

    /* Update link quality for the next hop connection */
    if (conn_table) {
        update_link_quality(conn_table, next_hop, success ? 1 : 0);

        /* Recalculate route cost based on updated link quality */
        struct connection_entry *conn = find_connection(conn_table, next_hop);
        if (conn && conn->link_quality > 0.0f) {
            /* Route cost is affected by link quality */
            /* New cost = hop_count + (1/link_quality - 1) as adjustment */
            float new_cost = (float)route->hop_count;
            if (conn->link_quality < 1.0f) {
                new_cost += (1.0f / conn->link_quality) - 1.0f;
            }
            route->route_cost = new_cost;
        }
    }

    route->last_updated = get_current_timestamp();

    return 0;
}

uint32_t find_pending_route_request_for_dest(struct mesh_node *node, const uint32_t destination_id) {
    if (!node) return 0;

    for (size_t i = 0; i < node->pending_count; i++) {
        if (node->pending_requests[i].is_active &&
            node->pending_requests[i].destination_id == destination_id) {
            return node->pending_requests[i].request_id;
        }
    }

    return 0;
}

int has_pending_route_discovery(struct mesh_node *node, const uint32_t destination_id) {
    return find_pending_route_request_for_dest(node, destination_id) != 0;
}

