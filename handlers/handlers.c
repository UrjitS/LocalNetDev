#include "handlers.h"
#include "protocol.h"
#include "routing.h"
#include "logger.h"
#include <string.h>
#include <stdlib.h>

#define HANDLER_TAG "HANDLER"

/**
 * Handle an incoming acknowledgement
 */
int handle_acknowledgement(struct mesh_node *mesh_node, const struct acknowledgement *ack, const uint32_t sender_id) {
    if (!mesh_node || !ack) return -1;

    log_info(HANDLER_TAG, "Processing ACK for seq %u from 0x%08X (status: %u)",
             ack->sequence_number, sender_id, ack->status_code);

    if (ack->status_code == SUCCESS) {
        // Successful delivery - acknowledge packet and update route cost
        if (mesh_node->packet_queue) {
            acknowledge_packet(mesh_node->packet_queue,
                              mesh_node->routing_table,
                              mesh_node->connection_table,
                              ack->sequence_number,
                              sender_id);
        }

        // Update link quality for successful transmission
        if (mesh_node->connection_table) {
            update_link_quality(mesh_node->connection_table, sender_id, 1);
        }
    } else {
        // Failed delivery - update link quality
        if (mesh_node->connection_table) {
            update_link_quality(mesh_node->connection_table, sender_id, 0);
        }

        // Handle specific error codes
        switch (ack->status_code) {
            case ROUTE_NOT_FOUND:
                log_warn(HANDLER_TAG, "ACK reports route not found for seq %u", ack->sequence_number);
                break;
            case DEST_UNREACHABLE:
                log_warn(HANDLER_TAG, "ACK reports destination unreachable for seq %u", ack->sequence_number);
                break;
            case TTL_EXPIRED:
                log_warn(HANDLER_TAG, "ACK reports TTL expired for seq %u", ack->sequence_number);
                break;
            default:
                log_warn(HANDLER_TAG, "ACK reports error %u for seq %u", ack->status_code, ack->sequence_number);
                break;
        }
    }

    return 0;
}

/**
 * Create an acknowledgement packet
 */
size_t create_acknowledgement_packet(const uint16_t sequence_number,
                                     const uint8_t status_code,
                                     uint8_t *buffer,
                                     const size_t buffer_size,
                                     const uint32_t source_id,
                                     const uint32_t dest_id) {
    if (!buffer || buffer_size < 32) return 0;

    // Build acknowledgement structure
    struct acknowledgement ack = {
        .sequence_number = sequence_number,
        .status_code = status_code,
        .received_fragment_count = 0,
        .received_fragment_list = NULL
    };

    // Build header
    struct header header = {
        .protocol_version = 1,  // PROTOCOL_VERSION
        .message_type = MSG_ACKNOWLEDGEMENT,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = MAX_HOP_COUNT,
        .payload_length = 0,  // Will be set after serializing payload
        .sequence_number = 0
    };

    struct network network = {
        .source_id = source_id,
        .destination_id = dest_id
    };

    // Serialize acknowledgement payload
    uint8_t payload_buffer[16];
    const size_t payload_len = serialize_acknowledgement(&ack, payload_buffer, sizeof(payload_buffer));
    if (payload_len == 0) return 0;

    header.payload_length = (uint16_t)payload_len;

    // Create packet
    const struct packet packet = {
        .header = &header,
        .network = &network,
        .payload = payload_buffer,
        .security = NULL
    };

    // Serialize complete packet
    return serialize_packet(&packet, buffer, buffer_size);
}

/**
 * Process an incoming packet and determine what action to take.
 */
int handle_incoming_packet(struct mesh_node *mesh_node, const uint8_t *data, const size_t data_len, uint32_t sender_id, struct handler_result *result) {
    if (!data || data_len == 0 || !result) {
        return -1;
    }

    // Initialize result
    memset(result, 0, sizeof(*result));
    result->action = HANDLER_ACTION_NONE;

    // Parse header
    struct header header;
    if (parse_header(data, data_len, &header) != 0) {
        log_error(HANDLER_TAG, "Failed to parse packet header");
        result->action = HANDLER_ACTION_ERROR;
        return -1;
    }

    // Parse network header
    struct network network;
    if (data_len < 16 || parse_network(data + 8, data_len - 8, &network) != 0) {
        log_error(HANDLER_TAG, "Failed to parse network header");
        result->action = HANDLER_ACTION_ERROR;
        return -1;
    }

    // Use source_id from packet if sender_id not provided
    if (sender_id == 0) {
        sender_id = network.source_id;
    }
    result->source_id = network.source_id;

    // Handle message based on type
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

            // Update mesh node connection info if available
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
                    // We are the destination or have cached route - send route reply
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
                            result->forward_path = reply.forward_path;  // Transfer ownership
                            result->forward_path_len = reply.forward_path_len;
                        } else {
                            if (reply.forward_path) free(reply.forward_path);
                        }
                    }
                } else if (action == 0) {
                    // Forward the request to all neighbors except sender
                    log_info(HANDLER_TAG, "Forwarding route request (hops: %u)", rr_result.hop_count);
                    result->action = HANDLER_ACTION_FORWARD_REQUEST;
                    result->request_id = req.request_id;
                    result->destination_id = req.destination_id;
                    result->hop_count = rr_result.hop_count;
                    result->exclude_neighbor = rr_result.exclude_neighbor;

                    // Copy the updated reverse path
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

            log_info(HANDLER_TAG, "Received route reply from 0x%08X (cost: %u, path_len: %u)", network.source_id, reply.route_cost, reply.forward_path_len);

            if (mesh_node) {
                struct route_reply_result rr_result;
                const int action = handle_route_reply(mesh_node, &reply, sender_id, &rr_result);

                if (action == 1) {
                    // We are the originator - route discovery complete
                    log_info(HANDLER_TAG, "Route discovery complete for dest 0x%08X", reply.forward_path[reply.forward_path_len - 1]);
                    result->action = HANDLER_ACTION_ROUTE_COMPLETE;
                    result->destination_id = reply.forward_path[reply.forward_path_len - 1];

                    // Handle any packets that were waiting for this route
                    if (mesh_node->packet_queue) {
                        const size_t ready = handle_route_discovery_complete(mesh_node->packet_queue,
                                                                             result->destination_id);
                        if (ready > 0) {
                            log_info(HANDLER_TAG, "%zu packets ready to send after route discovery", ready);
                        }
                    }
                } else if (action == 0) {
                    // Forward reply toward originator
                    log_info(HANDLER_TAG, "Forwarding route reply to 0x%08X", rr_result.next_hop);
                    result->action = HANDLER_ACTION_FORWARD_REPLY;
                    result->target_node = rr_result.next_hop;
                    result->request_id = rr_result.request_id;
                    result->route_cost = rr_result.route_cost;

                    // Copy the forward path
                    if (rr_result.forward_path && rr_result.forward_path_len > 0) {
                        result->forward_path = malloc(rr_result.forward_path_len * sizeof(uint32_t));
                        if (result->forward_path) {
                            memcpy(result->forward_path, rr_result.forward_path, rr_result.forward_path_len * sizeof(uint32_t));
                            result->forward_path_len = rr_result.forward_path_len;
                        }
                    }
                    if (rr_result.forward_path) free(rr_result.forward_path);
                }
            }
            if (reply.forward_path) free(reply.forward_path);
            break;
        }

        case MSG_ACKNOWLEDGEMENT: {
            struct acknowledgement ack = {0};
            if (parse_acknowledgement(data + 16, data_len - 16, &ack) != 0) {
                log_error(HANDLER_TAG, "Failed to parse acknowledgement");
                result->action = HANDLER_ACTION_ERROR;
                return -1;
            }

            log_info(HANDLER_TAG, "Received ACK from 0x%08X for seq %u (status: %u)",
                     network.source_id, ack.sequence_number, ack.status_code);

            // Process the acknowledgement
            if (mesh_node) {
                handle_acknowledgement(mesh_node, &ack, sender_id);
            }

            result->action = HANDLER_ACTION_NONE;

            if (ack.received_fragment_list) free(ack.received_fragment_list);
            break;
        }

        case MSG_DATA: {
            // Handle data packet forwarding
            if (!mesh_node) {
                result->action = HANDLER_ACTION_CALL_DATA_CALLBACK;
                break;
            }

            log_info(HANDLER_TAG, "Received data packet from 0x%08X to 0x%08X (seq: %u, TTL: %u)",
                     network.source_id, network.destination_id,
                     header.sequence_number, header.time_to_live);

            // Make forwarding decision
            struct forwarding_decision decision;
            uint8_t ttl = header.time_to_live;
            make_forwarding_decision(mesh_node, network.destination_id, &ttl, &decision);

            if (decision.action == 1) {
                // Local delivery - this packet is for us
                log_info(HANDLER_TAG, "Data packet is for us (seq: %u), delivering to application", header.sequence_number);
                result->action = HANDLER_ACTION_CALL_DATA_CALLBACK;
                result->sequence_number = header.sequence_number;

                // Send ACK back to source
                if (header.sequence_number != 0) {
                    result->action = HANDLER_ACTION_SEND_ACK;
                    result->target_node = network.source_id;
                    result->sequence_number = header.sequence_number;
                    result->status_code = SUCCESS;
                }
            } else if (decision.action == 0) {
                // Forward to next hop
                log_info(HANDLER_TAG, "Forwarding data packet to next hop 0x%08X (TTL: %u)",
                         decision.next_hop, ttl);
                result->action = HANDLER_ACTION_FORWARD_DATA;
                result->next_hop = decision.next_hop;
                result->ttl = ttl;
                result->destination_id = network.destination_id;
                result->sequence_number = header.sequence_number;

                // Copy packet data for forwarding (with updated TTL)
                result->packet_data = malloc(data_len);
                if (result->packet_data) {
                    memcpy(result->packet_data, data, data_len);
                    result->packet_len = data_len;
                    // Update TTL in the copied packet
                    result->packet_data[3] = ttl;
                }
            } else if (decision.action == -1) {
                // TTL expired
                log_warn(HANDLER_TAG, "TTL expired for packet from 0x%08X to 0x%08X",
                         network.source_id, network.destination_id);
                result->action = HANDLER_ACTION_TTL_EXPIRED;
                result->target_node = network.source_id;
                result->sequence_number = header.sequence_number;
                result->status_code = TTL_EXPIRED;
            } else if (decision.action == -2) {
                // Need route discovery
                log_info(HANDLER_TAG, "No route to 0x%08X, need route discovery",
                         network.destination_id);
                result->action = HANDLER_ACTION_INITIATE_ROUTE_DISCOVERY;
                result->destination_id = network.destination_id;
                result->request_id = decision.request_id;  // Existing request if any

                // Queue packet for later transmission
                if (mesh_node->packet_queue) {
                    // Copy packet data for queuing
                    result->packet_data = malloc(data_len);
                    if (result->packet_data) {
                        memcpy(result->packet_data, data, data_len);
                        result->packet_len = data_len;
                    }
                }
            }
            break;
        }

        default:
            // Unknown or other message type - let caller handle it
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
    if (result->packet_data) {
        free(result->packet_data);
        result->packet_data = NULL;
    }
}
