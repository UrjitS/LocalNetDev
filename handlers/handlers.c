#include "handlers.h"
#include "protocol.h"
#include "routing.h"
#include "utils.h"
#include "logger.h"
#include <string.h>
#include <stdlib.h>

#define HANDLER_TAG "HANDLER"

/**
 * Process an incoming packet and determine what action to take.
 */
int handle_incoming_packet(struct mesh_node *mesh_node,
                           const uint8_t *data, size_t data_len,
                           uint32_t sender_id,
                           struct handler_result *result) {
    if (!data || data_len == 0 || !result) {
        return -1;
    }

    /* Initialize result */
    memset(result, 0, sizeof(*result));
    result->action = HANDLER_ACTION_NONE;

    /* Parse header */
    struct header header;
    if (parse_header(data, data_len, &header) != 0) {
        log_error(HANDLER_TAG, "Failed to parse packet header");
        result->action = HANDLER_ACTION_ERROR;
        return -1;
    }

    /* Parse network header */
    struct network network;
    if (data_len < 16 || parse_network(data + 8, data_len - 8, &network) != 0) {
        log_error(HANDLER_TAG, "Failed to parse network header");
        result->action = HANDLER_ACTION_ERROR;
        return -1;
    }

    /* Use source_id from packet if sender_id not provided */
    if (sender_id == 0) {
        sender_id = network.source_id;
    }
    result->source_id = network.source_id;

    /* Handle message based on type */
    switch (header.message_type) {
        case MSG_HEARTBEAT: {
            struct heartbeat heartbeat;
            if (parse_heartbeat(data + 16, data_len - 16, &heartbeat) != 0) {
                log_error(HANDLER_TAG, "Failed to parse heartbeat");
                result->action = HANDLER_ACTION_ERROR;
                return -1;
            }

            log_info(HANDLER_TAG, "Received heartbeat from 0x%08X (status: %u, connections: %u)",
                     network.source_id, heartbeat.device_status, heartbeat.active_connection_number);

            /* Update mesh node connection info if available */
            if (mesh_node && mesh_node->connection_table) {
                reset_missed_heartbeats(mesh_node->connection_table, network.source_id);
                update_last_seen(mesh_node->connection_table, network.source_id, heartbeat.timestamp);
            }

            result->action = HANDLER_ACTION_NONE;
            break;
        }

        case MSG_ROUTE_REQUEST: {
            struct route_request req = {0};
            if (parse_route_request(data + 16, data_len - 16, &req) != 0) {
                log_error(HANDLER_TAG, "Failed to parse route request");
                result->action = HANDLER_ACTION_ERROR;
                return -1;
            }

            log_info(HANDLER_TAG, "Received route request from 0x%08X for dest 0x%08X (hops: %u)",
                     network.source_id, req.destination_id, req.hop_count);

            if (mesh_node) {
                struct route_request_result rr_result;
                const int action = handle_route_request(mesh_node, &req, sender_id, &rr_result);

                if (action == 1 || action == 2) {
                    /* We are the destination or have cached route - send route reply */
                    if (action == 1) {
                        log_info(HANDLER_TAG, "We are the destination - sending route reply");
                    } else {
                        log_info(HANDLER_TAG, "Have cached route - sending route reply");
                    }

                    struct route_reply reply;
                    if (create_route_reply(mesh_node, req.request_id,
                                           rr_result.updated_reverse_path, rr_result.updated_path_len,
                                           &reply) == 0) {
                        if (rr_result.updated_path_len >= 2) {
                            result->action = HANDLER_ACTION_SEND_REPLY;
                            result->target_node = rr_result.updated_reverse_path[rr_result.updated_path_len - 2];
                            result->request_id = reply.request_id;
                            result->route_cost = reply.route_cost;
                            result->forward_path = reply.forward_path;  /* Transfer ownership */
                            result->forward_path_len = reply.forward_path_len;
                        } else {
                            if (reply.forward_path) free(reply.forward_path);
                        }
                    }
                } else if (action == 0) {
                    /* Forward the request to all neighbors except sender */
                    log_info(HANDLER_TAG, "Forwarding route request (hops: %u)", rr_result.hop_count);
                    result->action = HANDLER_ACTION_FORWARD_REQUEST;
                    result->request_id = req.request_id;
                    result->destination_id = req.destination_id;
                    result->hop_count = rr_result.hop_count;
                    result->exclude_neighbor = rr_result.exclude_neighbor;

                    /* Copy the updated reverse path */
                    if (rr_result.updated_reverse_path && rr_result.updated_path_len > 0) {
                        result->reverse_path = malloc(rr_result.updated_path_len * sizeof(uint32_t));
                        if (result->reverse_path) {
                            memcpy(result->reverse_path, rr_result.updated_reverse_path,
                                   rr_result.updated_path_len * sizeof(uint32_t));
                            result->reverse_path_len = rr_result.updated_path_len;
                        }
                    }
                }

                if (rr_result.updated_reverse_path) free(rr_result.updated_reverse_path);
            }
            if (req.reverse_path) free(req.reverse_path);
            break;
        }

        case MSG_ROUTE_REPLY: {
            struct route_reply reply = {0};
            if (parse_route_reply(data + 16, data_len - 16, &reply) != 0) {
                log_error(HANDLER_TAG, "Failed to parse route reply");
                result->action = HANDLER_ACTION_ERROR;
                return -1;
            }

            log_info(HANDLER_TAG, "Received route reply from 0x%08X (cost: %u, path_len: %u)",
                     network.source_id, reply.route_cost, reply.forward_path_len);

            if (mesh_node) {
                struct route_reply_result rr_result;
                const int action = handle_route_reply(mesh_node, &reply, sender_id, &rr_result);

                if (action == 1) {
                    /* We are the originator - route discovery complete */
                    log_info(HANDLER_TAG, "Route discovery complete for dest 0x%08X",
                             reply.forward_path[reply.forward_path_len - 1]);
                    result->action = HANDLER_ACTION_ROUTE_COMPLETE;
                    result->destination_id = reply.forward_path[reply.forward_path_len - 1];
                } else if (action == 0) {
                    /* Forward reply toward originator */
                    log_info(HANDLER_TAG, "Forwarding route reply to 0x%08X", rr_result.next_hop);
                    result->action = HANDLER_ACTION_FORWARD_REPLY;
                    result->target_node = rr_result.next_hop;
                    result->request_id = rr_result.request_id;
                    result->route_cost = rr_result.route_cost;

                    /* Copy the forward path */
                    if (rr_result.forward_path && rr_result.forward_path_len > 0) {
                        result->forward_path = malloc(rr_result.forward_path_len * sizeof(uint32_t));
                        if (result->forward_path) {
                            memcpy(result->forward_path, rr_result.forward_path,
                                   rr_result.forward_path_len * sizeof(uint32_t));
                            result->forward_path_len = rr_result.forward_path_len;
                        }
                    }
                    if (rr_result.forward_path) free(rr_result.forward_path);
                }
            }
            if (reply.forward_path) free(reply.forward_path);
            break;
        }

        default:
            /* Unknown or data message type - let caller handle it */
            result->action = HANDLER_ACTION_CALL_DATA_CALLBACK;
            break;
    }

    return 0;
}

/**
 * Free any allocated memory in a handler result.
 */
void free_handler_result(struct handler_result *result) {
    if (!result) return;

    if (result->forward_path) {
        free(result->forward_path);
        result->forward_path = NULL;
    }
    if (result->reverse_path) {
        free(result->reverse_path);
        result->reverse_path = NULL;
    }
}
