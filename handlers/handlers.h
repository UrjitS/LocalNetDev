#ifndef LOCALNET_HANDLERS_H
#define LOCALNET_HANDLERS_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
struct mesh_node;
struct acknowledgement;

/**
 * Message Handler Action Types
 * These define what the caller should do after processing a message.
 */
enum handler_action {
    HANDLER_ACTION_NONE = 0,
    HANDLER_ACTION_SEND_REPLY,
    HANDLER_ACTION_FORWARD_REQUEST,
    HANDLER_ACTION_FORWARD_REPLY,
    HANDLER_ACTION_ROUTE_COMPLETE,
    HANDLER_ACTION_CALL_DATA_CALLBACK,
    HANDLER_ACTION_SEND_ACK,              /* Send acknowledgement */
    HANDLER_ACTION_FORWARD_DATA,          /* Forward data packet to next hop */
    HANDLER_ACTION_INITIATE_ROUTE_DISCOVERY, /* Need route discovery before forwarding */
    HANDLER_ACTION_TTL_EXPIRED,           /* TTL expired - send error to source */
    HANDLER_ACTION_DEST_UNREACHABLE,      /* Destination unreachable */
    HANDLER_ACTION_ERROR
};

/**
 * Message Handler Result
 * Contains the result of processing a message and any data needed for follow-up actions.
 */
struct handler_result {
    enum handler_action action;

    /* For route reply actions */
    uint32_t target_node;
    uint32_t request_id;
    uint8_t route_cost;
    uint32_t *forward_path;
    uint8_t forward_path_len;

    /* For route request forwarding */
    uint32_t destination_id;
    uint8_t hop_count;
    uint32_t *reverse_path;
    uint8_t reverse_path_len;
    uint32_t exclude_neighbor;

    /* For data callback */
    uint32_t source_id;

    /* For packet forwarding */
    uint32_t next_hop;               /* Next hop for forwarding */
    uint16_t sequence_number;        /* Sequence number for ACK */
    uint8_t status_code;             /* Status code for ACK or error */
    uint8_t *packet_data;            /* Packet data for forwarding */
    size_t packet_len;               /* Length of packet data */
    uint8_t ttl;                     /* TTL for forwarded packet */
};

/**
 * Process an incoming packet and determine what action to take.
 *
 * This function handles:
 * - MSG_HEARTBEAT: Updates connection table, returns HANDLER_ACTION_NONE
 * - MSG_ROUTE_REQUEST: Processes request, returns appropriate action
 * - MSG_ROUTE_REPLY: Processes reply, returns appropriate action
 * - MSG_ACKNOWLEDGEMENT: Processes ACK, updates retransmission queue
 * - MSG_DATA: Determines forwarding or local delivery
 * - Other types: Returns HANDLER_ACTION_CALL_DATA_CALLBACK
 *
 * @param mesh_node     The mesh node context (can be NULL for basic processing)
 * @param data          Raw packet data
 * @param data_len      Length of packet data
 * @param sender_id     Device ID of the sender (0 if unknown, will be parsed from packet)
 * @param result        Output parameter for the result
 * @return              0 on success, -1 on parse error
 */
int handle_incoming_packet(struct mesh_node *mesh_node, const uint8_t *data, size_t data_len, uint32_t sender_id, struct handler_result *result);

/**
 * Handle an incoming acknowledgement
 * Updates pending packet queue and route costs
 *
 * @param mesh_node     The mesh node context
 * @param ack           The parsed acknowledgement
 * @param sender_id     Device ID of the sender
 * @return              0 on success, -1 on error
 */
int handle_acknowledgement(struct mesh_node *mesh_node, const struct acknowledgement *ack, uint32_t sender_id);

/**
 * Create an acknowledgement message for a received packet
 *
 * @param sequence_number  The sequence number to acknowledge
 * @param status_code      Status code (SUCCESS, etc.)
 * @param buffer           Output buffer for serialized ACK
 * @param buffer_size      Size of output buffer
 * @param source_id        Source ID (this node)
 * @param dest_id          Destination ID (original sender)
 * @return                 Number of bytes written, 0 on error
 */
size_t create_acknowledgement_packet(uint16_t sequence_number,
                                     uint8_t status_code,
                                     uint8_t *buffer,
                                     size_t buffer_size,
                                     uint32_t source_id,
                                     uint32_t dest_id);

/**
 * Free any allocated memory in a handler result.
 * Call this after processing the result.
 */
void free_handler_result(struct handler_result *result);

#endif /* LOCALNET_HANDLERS_H */
