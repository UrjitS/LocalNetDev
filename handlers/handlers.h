#ifndef LOCALNET_HANDLERS_H
#define LOCALNET_HANDLERS_H

#include <stdint.h>
#include <stddef.h>

struct mesh_node;

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
};

/**
 * Process an incoming packet and determine what action to take.
 *
 * This function handles:
 * - MSG_HEARTBEAT: Updates connection table, returns HANDLER_ACTION_NONE
 * - MSG_ROUTE_REQUEST: Processes request, returns appropriate action
 * - MSG_ROUTE_REPLY: Processes reply, returns appropriate action
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
 * Free any allocated memory in a handler result.
 * Call this after processing the result.
 */
void free_handler_result(struct handler_result *result);

#endif /* LOCALNET_HANDLERS_H */
