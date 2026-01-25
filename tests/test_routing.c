#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "utils.h"
#include "../routing/routing.h"

/* Test Node Creation */
void test_node_creation() {
    printf("Testing node creation...\n");

    struct mesh_node *edge_node = create_mesh_node(0x123456, EDGE_NODE);
    assert(edge_node != NULL);
    assert(edge_node->device_id == 0x123456);
    assert(edge_node->node_type == EDGE_NODE);
    assert(edge_node->max_connections == MAX_CONNECTIONS_EDGE);

    struct mesh_node *full_node = create_mesh_node(0x123457, FULL_NODE);
    assert(full_node != NULL);
    assert(full_node->max_connections == MAX_CONNECTIONS_FULL);

    struct mesh_node *gateway_node = create_mesh_node(0x123458, GATEWAY_NODE);
    assert(gateway_node != NULL);
    assert(gateway_node->max_connections == MAX_CONNECTIONS_GATEWAY);

    free_mesh_node(edge_node);
    free_mesh_node(full_node);
    free_mesh_node(gateway_node);
    printf("Test passed: Node creation\n\n");
}

/* Test Connection Management */
void test_connection_management() {
    printf("Testing connection management...\n");

    struct connection_table *table = create_connection_table();
    assert(table != NULL);
    assert(table->count == 0);

    // Add connections
    int result = add_connection(table, 0x111111, -60);
    assert(result == 0);
    assert(table->count == 1);

    // Find connection
    const struct connection_entry *entry = find_connection(table, 0x111111);
    assert(entry != NULL);
    assert(entry->neighbor_id == 0x111111);
    assert(entry->rssi == -60);
    assert(entry->state == CONNECTING);

    // Update connection state
    result = update_connection_state(table, 0x111111, STABLE);
    assert(result == 0);
    assert(entry->state == STABLE);

    // Update RSSI
    result = update_connection_rssi(table, 0x111111, -65);
    assert(result == 0);
    assert(entry->rssi == -65);

    // Update link quality
    for (int i = 0; i < 10; i++) {
        update_link_quality(table, 0x111111, 1);
    }
    assert(entry->link_quality == 1.0f);

    // Simulate some failures
    for (int i = 0; i < 5; i++) {
        update_link_quality(table, 0x111111, 0);
    }
    const float expected_quality = 10.0f / 15.0f;
    assert(entry->link_quality == expected_quality);

    // Remove connection
    result = remove_connection(table, 0x111111);
    assert(result == 0);
    assert(table->count == 0);

    free_connection_table(table);
    printf("Test passed: Connection management\n\n");
}

/* Test Routing Table */
void test_routing_table() {
    printf("Testing routing table...\n");

    struct routing_table *table = create_routing_table();
    assert(table != NULL);
    assert(table->count == 0);

    const uint32_t timestamp = get_current_timestamp();

    // Add route
    int result = add_route(table, 0x222222, 0x111111, 3, 2.5f, timestamp);
    assert(result == 0);
    assert(table->count == 1);

    // Find route
    const struct routing_entry *entry = find_route(table, 0x222222);
    assert(entry != NULL);
    assert(entry->destination_id == 0x222222);
    assert(entry->next_hop == 0x111111);
    assert(entry->hop_count == 3);
    assert(entry->route_cost == 2.5f);

    // Add better route
    result = add_route(table, 0x222222, 0x333333, 2, 1.8f, timestamp);
    assert(result == 0);
    assert(table->count == 1);
    entry = find_route(table, 0x222222);
    assert(entry->next_hop == 0x333333);
    assert(entry->route_cost == 1.8f); // Should update cost

    // Add route with worse cost
    add_route(table, 0x222222, 0x444444, 5, 5.0f, timestamp);
    entry = find_route(table, 0x222222);
    assert(entry->next_hop == 0x333333);  // Should be the better route

    // Test find_best_route
    const struct routing_entry *best = find_best_route(table, 0x222222);
    assert(best != NULL);
    assert(best->route_cost == 1.8f);

    // Remove route
    result = remove_route(table, 0x222222);
    assert(result == 0);
    assert(table->count == 0);

    free_routing_table(table);
    printf("Test passed: Routing table\n\n");
}

/* Test Route Discovery */
void test_route_discovery() {
    printf("Testing route discovery...\n");

    struct mesh_node *node = create_mesh_node(0x123456, FULL_NODE);
    assert(node != NULL);

    // Initiate route discovery
    uint32_t *reverse_path = NULL;
    uint8_t path_len = 0;
    const int request_id = initiate_route_discovery(node, 0x654321, &reverse_path, &path_len);
    assert(request_id > 0);
    assert(reverse_path != NULL);
    assert(path_len == 1);
    assert(reverse_path[0] == node->device_id);

    // Check request is cached
    const int seen = has_seen_request(node->request_cache, request_id);
    assert(seen == 1);

    // Intermediate nodes
    uint32_t test_path[] = {0x123456, 0x111111};
    int process_result = process_route_request(node, request_id + 1, 0x654321, 0, test_path, 2, 0x111111);
    // Should forward
    assert(process_result == 0);

    // Process duplicate request
    process_result = process_route_request(node, request_id + 1, 0x654321, 0, test_path, 2, 0x111111);
    // Should drop
    assert(process_result == -1);

    free(reverse_path);
    free_mesh_node(node);
    printf("Test passed: Route discovery\n\n");
}

/* Test Packet Forwarding */
void test_packet_forwarding() {
    printf("Testing packet forwarding...\n");

    struct mesh_node *node = create_mesh_node(0x123456, FULL_NODE);
    assert(node != NULL);

    // Add a route to the routing table
    const uint32_t timestamp = get_current_timestamp();
    add_route(node->routing_table, 0x654321, 0x111111, 3, 2.5f, timestamp);

    // Test forwarding to destination with route
    uint8_t ttl = 10;
    uint32_t next_hop = 0;
    int result = forward_packet(node, 0x654321, &ttl, &next_hop);
    assert(result == 0);  // Should forward
    assert(ttl == 9);     // TTL decremented
    assert(next_hop == 0x111111);  // Next hop from routing table

    // Test forwarding to self
    result = forward_packet(node, node->device_id, &ttl, &next_hop);
    assert(result == 1);  // Should process locally

    // Test TTL expiry
    ttl = 1;
    result = forward_packet(node, 0x654321, &ttl, &next_hop);
    assert(result == 0);  // Should forward
    assert(ttl == 0);

    ttl = 0;
    result = forward_packet(node, 0x654321, &ttl, &next_hop);
    assert(result == -1);  // TTL expired

    // Test no route available
    ttl = 10;
    result = forward_packet(node, 0x999999, &ttl, &next_hop);
    assert(result == -2);  // No route found

    free_mesh_node(node);
    printf("Test passed: Packet forwarding\n\n");
}

/* Test Heartbeat and Timeouts */
void test_heartbeat() {
    printf("Testing heartbeat mechanism...\n");

    struct connection_table *table = create_connection_table();
    add_connection(table, 0x111111, -60);
    update_connection_state(table, 0x111111, STABLE);

    const struct connection_entry *entry = find_connection(table, 0x111111);
    assert(entry->missed_heartbeats == 0);

    // Increment missed heartbeats
    increment_missed_heartbeat(table, 0x111111);
    assert(entry->missed_heartbeats == 1);
    assert(entry->state == STABLE);

    increment_missed_heartbeat(table, 0x111111);
    assert(entry->missed_heartbeats == 2);
    assert(entry->state == STABLE);

    increment_missed_heartbeat(table, 0x111111);
    assert(entry->missed_heartbeats == 3);
    assert(entry->state == DISCONNECTED);

    // Reset heartbeats
    update_connection_state(table, 0x111111, STABLE);
    reset_missed_heartbeats(table, 0x111111);
    assert(entry->missed_heartbeats == 0);
    assert(entry->state == STABLE);

    free_connection_table(table);
    printf("Test passed: Heartbeats\n\n");
}

/* Test Discovery Timing */
void test_discovery_timing() {
    printf("Testing discovery timing...\n");

    struct mesh_node *node = create_mesh_node(0x123456, FULL_NODE);
    assert(node != NULL);

    const uint32_t current_time = get_current_timestamp();

    // Should send discovery initially
    int should_discover = should_send_discovery(node, current_time);
    assert(should_discover == 1);

    node->last_discovery_time = current_time;

    // Should not send discovery immediately after
    should_discover = should_send_discovery(node, current_time + 10);
    assert(should_discover == 0);

    // Should send after interval
    should_discover = should_send_discovery(node, current_time + DISCOVERY_INITIAL_INTERVAL + 1);
    assert(should_discover == 1);

    // Test when connections are full
    for (int i = 0; i < node->max_connections; i++) {
        add_connection(node->connection_table, 0x100000 + i, -60);
        update_connection_state(node->connection_table, 0x100000 + i, STABLE);
    }

    should_discover = should_send_discovery(node, current_time + DISCOVERY_INITIAL_INTERVAL + 1);
    assert(should_discover == 0);

    free_mesh_node(node);
    printf("Test passed: Discovery timing\n\n");
}

/* Test Link Quality Calculation */
void test_link_quality() {
    printf("Testing link quality calculation...\n");

    struct connection_table *table = create_connection_table();
    add_connection(table, 0x111111, -60);

    const struct connection_entry *entry = find_connection(table, 0x111111);

    // 100% success rate
    for (int i = 0; i < 50; i++) {
        update_link_quality(table, 0x111111, 1);
    }
    assert(entry->link_quality >= 0.99f);

    // 50% success rate
    for (int i = 0; i < 50; i++) {
        update_link_quality(table, 0x111111, 0);
    }

    free_connection_table(table);
    printf("Test passed: Link quality calculation\n\n");
}

/* Test Complete Mesh Network Scenario */
void test_mesh_network_scenario() {
    printf("Testing complete mesh network scenario...\n");

    // Mesh network with 3 nodes
    struct mesh_node *node1 = create_mesh_node(0x001, FULL_NODE);
    struct mesh_node *node2 = create_mesh_node(0x002, FULL_NODE);
    struct mesh_node *node3 = create_mesh_node(0x003, EDGE_NODE);


    // Node 1 connects to Node 2
    add_connection(node1->connection_table, 0x002, -60);
    update_connection_state(node1->connection_table, 0x002, STABLE);

    // Node 2 connects to Node 1 and Node 3
    add_connection(node2->connection_table, 0x001, -60);
    update_connection_state(node2->connection_table, 0x001, STABLE);
    add_connection(node2->connection_table, 0x003, -65);
    update_connection_state(node2->connection_table, 0x003, STABLE);

    // Node 3 connects to Node 2
    add_connection(node3->connection_table, 0x002, -65);
    update_connection_state(node3->connection_table, 0x002, STABLE);


    // Node 1 discovers route to Node 3 through Node 2
    const uint32_t timestamp = get_current_timestamp();
    add_route(node1->routing_table, 0x003, 0x002, 2, 2.0f, timestamp);

    // Node 2 has routes to both neighbors
    add_route(node2->routing_table, 0x001, 0x001, 1, 1.0f, timestamp);
    add_route(node2->routing_table, 0x003, 0x003, 1, 1.0f, timestamp);

    // Node 3 has route to Node 1 through Node 2
    add_route(node3->routing_table, 0x001, 0x002, 2, 2.0f, timestamp);


    // Test packet forwarding from Node 1 to Node 3
    uint8_t ttl = 10;
    uint32_t next_hop;
    const int result = forward_packet(node1, 0x003, &ttl, &next_hop);
    assert(result == 0);
    assert(next_hop == 0x002);

    // Update link qualities
    for (int i = 0; i < 10; i++) {
        update_link_quality(node1->connection_table, 0x002, 1);
        update_link_quality(node2->connection_table, 0x001, 1);
        update_link_quality(node2->connection_table, 0x003, 1);
        update_link_quality(node3->connection_table, 0x002, 1);
    }

    free_mesh_node(node1);
    free_mesh_node(node2);
    free_mesh_node(node3);
    printf("Test passed: Complete mesh network scenario\n\n");
}

int main() {
    test_node_creation();
    test_connection_management();
    test_routing_table();
    test_route_discovery();
    test_packet_forwarding();
    test_heartbeat();
    test_discovery_timing();
    test_link_quality();
    test_mesh_network_scenario();

    printf("ALL PROTOCOL TESTS PASSED\n");

    return EXIT_SUCCESS;
}

