#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "utils.h"
#include "../routing/routing.h"
#include "../protocol/protocol.h"

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

/* Test Enhanced Route Request Creation */
void test_create_route_request() {
    printf("Testing create_route_request...\n");

    struct mesh_node *node = create_mesh_node(0xABCDEF, FULL_NODE);
    assert(node != NULL);

    struct route_request req;
    memset(&req, 0, sizeof(req));

    int result = create_route_request(node, 0x123456, &req);
    assert(result > 0);  // Returns request_id on success
    assert(req.destination_id == 0x123456);
    assert(req.hop_count == 0);
    assert(req.reverse_path_len == 1);
    assert(req.reverse_path != NULL);
    assert(req.reverse_path[0] == node->device_id);

    // Verify it's added to pending requests
    assert(node->pending_count == 1);
    assert(node->pending_requests[0].is_active == 1);
    assert(node->pending_requests[0].destination_id == 0x123456);

    free(req.reverse_path);
    free_mesh_node(node);
    printf("Test passed: Create route request\n\n");
}

/* Test Handle Route Request - Destination Case */
void test_handle_route_request_destination() {
    printf("Testing handle_route_request (destination case)...\n");

    // Create destination node
    struct mesh_node *dest_node = create_mesh_node(0x654321, FULL_NODE);
    assert(dest_node != NULL);

    // Build incoming route request
    struct route_request req = {
        .request_id = 0x11111111,
        .destination_id = 0x654321,  // This node
        .hop_count = 2,
        .reverse_path_len = 3,
        .reverse_path = NULL
    };
    req.reverse_path = malloc(3 * sizeof(uint32_t));
    req.reverse_path[0] = 0xABCDEF;  // Originator
    req.reverse_path[1] = 0x111111;  // Intermediate
    req.reverse_path[2] = 0x222222;  // Sender

    struct route_request_result result;
    int action = handle_route_request(dest_node, &req, 0x222222, &result);

    assert(action == 1);  // We are destination
    assert(result.action == 1);
    assert(result.updated_path_len == 4);  // Original 3 + us
    assert(result.updated_reverse_path != NULL);
    assert(result.updated_reverse_path[3] == dest_node->device_id);

    // Check route to originator was added
    struct routing_entry *route = find_route(dest_node->routing_table, 0xABCDEF);
    assert(route != NULL);
    assert(route->next_hop == 0x222222);  // Through sender

    free(req.reverse_path);
    if (result.updated_reverse_path) free(result.updated_reverse_path);
    free_mesh_node(dest_node);
    printf("Test passed: Handle route request (destination)\n\n");
}

/* Test Handle Route Request - Intermediate Node Case */
void test_handle_route_request_intermediate() {
    printf("Testing handle_route_request (intermediate case)...\n");

    struct mesh_node *node = create_mesh_node(0x222222, FULL_NODE);
    assert(node != NULL);

    struct route_request req = {
        .request_id = 0x22222222,
        .destination_id = 0x999999,  // Not us
        .hop_count = 1,
        .reverse_path_len = 2,
        .reverse_path = NULL
    };
    req.reverse_path = malloc(2 * sizeof(uint32_t));
    req.reverse_path[0] = 0xABCDEF;  // Originator
    req.reverse_path[1] = 0x111111;  // Sender

    struct route_request_result result;
    int action = handle_route_request(node, &req, 0x111111, &result);

    assert(action == 0);  // Forward
    assert(result.action == 0);
    assert(result.hop_count == 2);  // Incremented
    assert(result.updated_path_len == 3);  // Added us
    assert(result.updated_reverse_path != NULL);
    assert(result.updated_reverse_path[2] == node->device_id);
    assert(result.exclude_neighbor == 0x111111);

    free(req.reverse_path);
    if (result.updated_reverse_path) free(result.updated_reverse_path);
    free_mesh_node(node);
    printf("Test passed: Handle route request (intermediate)\n\n");
}

/* Test Handle Route Request - Cached Route Case */
void test_handle_route_request_cached() {
    printf("Testing handle_route_request (cached route case)...\n");

    struct mesh_node *node = create_mesh_node(0x222222, FULL_NODE);
    assert(node != NULL);

    // Add a cached route to destination
    add_route(node->routing_table, 0x999999, 0x333333, 2, 2.0f, get_current_timestamp());

    struct route_request req = {
        .request_id = 0x33333333,
        .destination_id = 0x999999,
        .hop_count = 1,
        .reverse_path_len = 2,
        .reverse_path = NULL
    };
    req.reverse_path = malloc(2 * sizeof(uint32_t));
    req.reverse_path[0] = 0xABCDEF;
    req.reverse_path[1] = 0x111111;

    struct route_request_result result;
    int action = handle_route_request(node, &req, 0x111111, &result);

    assert(action == 2);  // Cached route reply
    assert(result.action == 2);

    free(req.reverse_path);
    if (result.updated_reverse_path) free(result.updated_reverse_path);
    free_mesh_node(node);
    printf("Test passed: Handle route request (cached)\n\n");
}

/* Test Create Route Reply */
void test_create_route_reply() {
    printf("Testing create_route_reply...\n");

    struct mesh_node *node = create_mesh_node(0x654321, FULL_NODE);
    assert(node != NULL);

    // Reverse path: originator -> intermediate -> destination
    uint32_t reverse_path[] = {0xABCDEF, 0x111111, 0x654321};

    struct route_reply reply;
    int result = create_route_reply(node, 0x12345678, reverse_path, 3, &reply);

    assert(result == 0);
    assert(reply.request_id == 0x12345678);
    assert(reply.route_cost == 2);  // 3 nodes - 1 = 2 hops
    assert(reply.forward_path_len == 3);
    assert(reply.forward_path != NULL);
    // Forward path should be same as reverse path (originator -> dest)
    assert(reply.forward_path[0] == 0xABCDEF);
    assert(reply.forward_path[1] == 0x111111);
    assert(reply.forward_path[2] == 0x654321);

    free(reply.forward_path);
    free_mesh_node(node);
    printf("Test passed: Create route reply\n\n");
}

/* Test Handle Route Reply - Originator Case */
void test_handle_route_reply_originator() {
    printf("Testing handle_route_reply (originator case)...\n");

    struct mesh_node *node = create_mesh_node(0xABCDEF, FULL_NODE);
    assert(node != NULL);

    // Add pending request
    add_pending_route_request(node, 0x12345678, 0x654321);

    // Forward path: us -> intermediate -> destination
    struct route_reply reply = {
        .request_id = 0x12345678,
        .route_cost = 2,
        .forward_path_len = 3,
        .forward_path = NULL
    };
    reply.forward_path = malloc(3 * sizeof(uint32_t));
    reply.forward_path[0] = 0xABCDEF;  // Us (originator)
    reply.forward_path[1] = 0x111111;  // Intermediate
    reply.forward_path[2] = 0x654321;  // Destination

    struct route_reply_result result;
    int action = handle_route_reply(node, &reply, 0x111111, &result);

    assert(action == 1);  // We are originator, done
    assert(result.action == 1);

    // Check route to destination was added
    struct routing_entry *route = find_route(node->routing_table, 0x654321);
    assert(route != NULL);
    assert(route->next_hop == 0x111111);
    assert(route->hop_count == 2);

    // Check pending request was removed
    int found = 0;
    for (size_t i = 0; i < node->pending_count; i++) {
        if (node->pending_requests[i].request_id == 0x12345678 &&
            node->pending_requests[i].is_active) {
            found = 1;
        }
    }
    assert(found == 0);  // Should be removed

    free(reply.forward_path);
    if (result.forward_path) free(result.forward_path);
    free_mesh_node(node);
    printf("Test passed: Handle route reply (originator)\n\n");
}

/* Test Handle Route Reply - Intermediate Node Case */
void test_handle_route_reply_intermediate() {
    printf("Testing handle_route_reply (intermediate case)...\n");

    struct mesh_node *node = create_mesh_node(0x111111, FULL_NODE);
    assert(node != NULL);

    // Forward path: originator -> us -> destination
    struct route_reply reply = {
        .request_id = 0x12345678,
        .route_cost = 2,
        .forward_path_len = 3,
        .forward_path = NULL
    };
    reply.forward_path = malloc(3 * sizeof(uint32_t));
    reply.forward_path[0] = 0xABCDEF;  // Originator
    reply.forward_path[1] = 0x111111;  // Us
    reply.forward_path[2] = 0x654321;  // Destination

    struct route_reply_result result;
    int action = handle_route_reply(node, &reply, 0x654321, &result);

    assert(action == 0);  // Forward to originator
    assert(result.action == 0);
    assert(result.next_hop == 0xABCDEF);  // Previous node in path

    // Check route to destination was added
    struct routing_entry *route = find_route(node->routing_table, 0x654321);
    assert(route != NULL);
    assert(route->next_hop == 0x654321);
    assert(route->hop_count == 1);

    free(reply.forward_path);
    if (result.forward_path) free(result.forward_path);
    free_mesh_node(node);
    printf("Test passed: Handle route reply (intermediate)\n\n");
}

/* Test Pending Route Request Management */
void test_pending_route_requests() {
    printf("Testing pending route request management...\n");

    struct mesh_node *node = create_mesh_node(0x123456, FULL_NODE);
    assert(node != NULL);

    // Add pending request
    int result = add_pending_route_request(node, 0xAAAAAAAA, 0x111111);
    assert(result == 0);
    assert(node->pending_count == 1);
    assert(node->pending_requests[0].is_active == 1);
    assert(node->pending_requests[0].request_id == 0xAAAAAAAA);
    assert(node->pending_requests[0].destination_id == 0x111111);

    // Try adding duplicate for same destination
    result = add_pending_route_request(node, 0xBBBBBBBB, 0x111111);
    assert(result == -1);  // Should fail

    // Add another request for different destination
    result = add_pending_route_request(node, 0xCCCCCCCC, 0x222222);
    assert(result == 0);
    assert(node->pending_count == 2);

    // Remove first request
    result = remove_pending_route_request(node, 0xAAAAAAAA);
    assert(result == 0);

    free_mesh_node(node);
    printf("Test passed: Pending route request management\n\n");
}

/* Test Route Request Timeouts */
void test_route_request_timeouts() {
    printf("Testing route request timeouts...\n");

    struct mesh_node *node = create_mesh_node(0x123456, FULL_NODE);
    assert(node != NULL);

    uint32_t current_time = get_current_timestamp();

    // Add pending request with old timestamp
    node->pending_requests[0].request_id = 0xDDDDDDDD;
    node->pending_requests[0].destination_id = 0x333333;
    node->pending_requests[0].timestamp = current_time - ROUTE_REQUEST_TIMEOUT_SECONDS - 1;
    node->pending_requests[0].retries = 0;
    node->pending_requests[0].is_active = 1;
    node->pending_count = 1;

    // Check for timeouts
    uint32_t timed_out[10];
    size_t timeout_count = check_route_request_timeouts(node, current_time, timed_out, 10);

    assert(timeout_count == 1);
    assert(timed_out[0] == 0x333333);
    assert(node->pending_requests[0].retries == 1);
    assert(node->pending_requests[0].is_active == 1);  // Still active for retry

    // Exhaust retries
    for (int i = 0; i < MAX_ROUTE_REQUEST_RETRIES; i++) {
        node->pending_requests[0].timestamp = current_time - ROUTE_REQUEST_TIMEOUT_SECONDS - 1;
        check_route_request_timeouts(node, current_time, timed_out, 10);
    }

    // After max retries, should be inactive
    assert(node->pending_requests[0].is_active == 0);

    free_mesh_node(node);
    printf("Test passed: Route request timeouts\n\n");
}

/* Test Get Connected Neighbors */
void test_get_connected_neighbors() {
    printf("Testing get_connected_neighbors...\n");

    struct mesh_node *node = create_mesh_node(0x123456, FULL_NODE);
    assert(node != NULL);

    // Add some connections
    add_connection(node->connection_table, 0x111111, -60);
    update_connection_state(node->connection_table, 0x111111, STABLE);
    add_connection(node->connection_table, 0x222222, -65);
    update_connection_state(node->connection_table, 0x222222, STABLE);
    add_connection(node->connection_table, 0x333333, -70);
    update_connection_state(node->connection_table, 0x333333, CONNECTING);  // Not stable

    uint32_t neighbors[10];
    size_t count = get_connected_neighbors(node, neighbors, 10, 0);

    assert(count == 2);  // Only stable connections

    // Test with exclude
    count = get_connected_neighbors(node, neighbors, 10, 0x111111);
    assert(count == 1);
    assert(neighbors[0] == 0x222222);

    free_mesh_node(node);
    printf("Test passed: Get connected neighbors\n\n");
}

/* Test Full Route Discovery Scenario */
void test_full_route_discovery_scenario() {
    printf("Testing full route discovery scenario...\n");

    // Network: Node A <-> Node B <-> Node C
    struct mesh_node *nodeA = create_mesh_node(0xAAAA, FULL_NODE);
    struct mesh_node *nodeB = create_mesh_node(0xBBBB, FULL_NODE);
    struct mesh_node *nodeC = create_mesh_node(0xCCCC, FULL_NODE);

    // Setup connections
    add_connection(nodeA->connection_table, 0xBBBB, -60);
    update_connection_state(nodeA->connection_table, 0xBBBB, STABLE);
    add_connection(nodeB->connection_table, 0xAAAA, -60);
    update_connection_state(nodeB->connection_table, 0xAAAA, STABLE);
    add_connection(nodeB->connection_table, 0xCCCC, -65);
    update_connection_state(nodeB->connection_table, 0xCCCC, STABLE);
    add_connection(nodeC->connection_table, 0xBBBB, -65);
    update_connection_state(nodeC->connection_table, 0xBBBB, STABLE);

    // Step 1: Node A initiates route discovery to Node C
    struct route_request req;
    memset(&req, 0, sizeof(req));
    int request_id = create_route_request(nodeA, 0xCCCC, &req);
    assert(request_id > 0);

    // Step 2: Node B receives the request from A
    struct route_request_result resultB;
    int actionB = handle_route_request(nodeB, &req, 0xAAAA, &resultB);
    assert(actionB == 0);  // Forward
    assert(resultB.updated_path_len == 2);

    // Step 3: Node C receives the request from B
    struct route_request reqToC = {
        .request_id = req.request_id,
        .destination_id = 0xCCCC,
        .hop_count = resultB.hop_count,
        .reverse_path_len = resultB.updated_path_len,
        .reverse_path = resultB.updated_reverse_path
    };
    struct route_request_result resultC;
    int actionC = handle_route_request(nodeC, &reqToC, 0xBBBB, &resultC);
    assert(actionC == 1);  // We are destination

    // Step 4: Node C creates route reply
    struct route_reply reply;
    int replyResult = create_route_reply(nodeC, req.request_id,
                                         resultC.updated_reverse_path,
                                         resultC.updated_path_len, &reply);
    assert(replyResult == 0);
    assert(reply.forward_path_len == 3);  // A -> B -> C

    // Step 5: Node B receives the reply
    struct route_reply_result replyResultB;
    int replyActionB = handle_route_reply(nodeB, &reply, 0xCCCC, &replyResultB);
    assert(replyActionB == 0);  // Forward to A

    // Node B should now have route to C
    struct routing_entry *routeBC = find_route(nodeB->routing_table, 0xCCCC);
    assert(routeBC != NULL);
    assert(routeBC->next_hop == 0xCCCC);

    // Step 6: Node A receives the reply
    struct route_reply_result replyResultA;
    int replyActionA = handle_route_reply(nodeA, &reply, 0xBBBB, &replyResultA);
    assert(replyActionA == 1);  // Done

    // Node A should now have route to C through B
    struct routing_entry *routeAC = find_route(nodeA->routing_table, 0xCCCC);
    assert(routeAC != NULL);
    assert(routeAC->next_hop == 0xBBBB);
    assert(routeAC->hop_count == 2);

    // Cleanup
    free(req.reverse_path);
    if (resultB.updated_reverse_path) free(resultB.updated_reverse_path);
    if (resultC.updated_reverse_path) free(resultC.updated_reverse_path);
    free(reply.forward_path);
    if (replyResultB.forward_path) free(replyResultB.forward_path);
    if (replyResultA.forward_path) free(replyResultA.forward_path);

    free_mesh_node(nodeA);
    free_mesh_node(nodeB);
    free_mesh_node(nodeC);

    printf("Test passed: Full route discovery scenario\n\n");
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
    test_create_route_request();
    test_handle_route_request_destination();
    test_handle_route_request_intermediate();
    test_handle_route_request_cached();
    test_create_route_reply();
    test_handle_route_reply_originator();
    test_handle_route_reply_intermediate();
    test_pending_route_requests();
    test_route_request_timeouts();
    test_get_connected_neighbors();
    test_full_route_discovery_scenario();
    test_packet_forwarding();
    test_heartbeat();
    test_discovery_timing();
    test_link_quality();
    test_mesh_network_scenario();

    printf("ALL ROUTING TESTS PASSED\n");

    return EXIT_SUCCESS;
}

