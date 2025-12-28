#ifndef LOCALNET_PROTOCOL_H
#define LOCALNET_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

// Maximum payload per fragment
#define MAX_PAYLOAD_PER_FRAGMENT 200


/**
 * Data Frame Structure
 *
 * Header total size: 8 bytes
 *
 **/
struct header {
    // First byte: 4 bits protocol version, 4 bits message type
    uint8_t protocol_version : 4;
    uint8_t message_type : 4;
    // Second byte: 1 bit fragmentation flag, 7 bits fragmentation number
    uint8_t fragmentation_flag : 1;
    uint8_t fragmentation_number : 7;
    // The total number of fragments for the message. 8 bits
    uint8_t total_fragments;
    // Max hop count. 8 bits
    uint8_t time_to_live;
    // Size of payload. 16 bits
    uint16_t payload_length;
    // Message sequence number. 16 bits
    uint16_t sequence_number;
};

/* Network header: 8 bytes */
struct network {
    // Origin device unique identifier. 32 bits
    uint32_t source_id;
    // Destination device identifier. 32 bits
    uint32_t destination_id;
};

/* Security block (1 + 4 + 7 + 12 = 24 bytes) */
struct security {
    // Which session key to use. 8 bits (1 byte)
    uint8_t key_id;
    // Increasing counter to prevent replay attacks. 4 bytes
    uint32_t frame_counter;
    // Ensures unique Initialization Vector. 7 bytes
    uint8_t nonce[7];
    // Message Authentication Code for integrity. 12 bytes
    uint8_t mac[12];
};

/* Packet */
struct packet {
    struct header *header;
    struct network *network;
    // Payload pointer, payload_length in header must be <= MAX_PAYLOAD_PER_FRAGMENT
    uint8_t *payload;
    struct security *security;
};


/**
 * Control Frame Structures
 **/

struct discovery_message {
    uint8_t available_connections;
    uint32_t timestamp;
};

/* Route request: reverse_path is variable length array of 32-bit device ids */
struct route_request {
    uint32_t request_id;
    uint32_t destination_id;
    uint8_t hop_count;
    uint8_t reverse_path_len; // Number of entries in reverse_path
    uint32_t *reverse_path;   // Pointer to array of device IDs (reverse path)
};

/* Route reply: forward_path is variable length array of 32-bit device ids */
struct route_reply {
    uint32_t request_id;
    uint8_t route_cost;
    uint8_t forward_path_len; // Number of entries in forward_path
    uint32_t *forward_path;   // Pointer to array of device IDs (forward path)
};

struct heartbeat {
    uint8_t device_status;
    uint8_t active_connection_number;
    uint32_t timestamp;
};

/* Acknowledgement: received_fragment_list is a list of received fragment indices */
struct acknowledgement {
    uint16_t sequence_number;
    uint8_t status_code;
    uint8_t received_fragment_count;
    uint8_t *received_fragment_list;
};

/* Key exchange message: public key is 32 bytes */
struct key_exchange_message {
    uint8_t public_key[32];
    uint32_t timestamp;
};


/* Status codes */
enum STATUS_CODE {
    SUCCESS = 0x00,
    ROUTE_NOT_FOUND = 0x01,
    DEST_UNREACHABLE = 0x02,
    TTL_EXPIRED = 0x03,
    AUTHENTICATION_FAILED = 0x04,
    FRAGMENTATION_ERROR = 0x05,
    INVALID_MESSAGE = 0x06
};

/* Message types */
enum MESSAGE_TYPE {
    MSG_DATA = 0x0,
    MSG_DISCOVERY = 0x1,
    MSG_ROUTE_REQUEST = 0x2,
    MSG_ROUTE_REPLY = 0x3,
    MSG_HEARTBEAT = 0x4,
    MSG_ACKNOWLEDGEMENT = 0x5,
    MSG_KEY_EXCHANGE = 0x6
};

/* Fragment reassembly state */
struct fragment_buffer {
    uint16_t sequence_number;
    uint8_t total_fragments;
    uint8_t received_count;
    uint8_t *received_flags;  // Bitmap of received fragments
    uint8_t **fragments;      // Array of fragment payloads
    uint16_t *fragment_sizes; // Size of each fragment
    uint32_t timestamp;       // For timeout tracking
};

/* Serialization functions */
size_t serialize_header(const struct header *hdr, uint8_t *buffer, size_t buffer_size);
size_t serialize_network(const struct network *net, uint8_t *buffer, size_t buffer_size);
size_t serialize_security(const struct security *sec, uint8_t *buffer, size_t buffer_size);
size_t serialize_discovery(const struct discovery_message *disc, uint8_t *buffer, size_t buffer_size);
size_t serialize_route_request(const struct route_request *req, uint8_t *buffer, size_t buffer_size);
size_t serialize_route_reply(const struct route_reply *rep, uint8_t *buffer, size_t buffer_size);
size_t serialize_heartbeat(const struct heartbeat *hb, uint8_t *buffer, size_t buffer_size);
size_t serialize_acknowledgement(const struct acknowledgement *ack, uint8_t *buffer, size_t buffer_size);
size_t serialize_key_exchange(const struct key_exchange_message *kex, uint8_t *buffer, size_t buffer_size);
size_t serialize_packet(const struct packet *pkt, uint8_t *buffer, size_t buffer_size);

/* Parsing functions */
int parse_header(const uint8_t *buffer, size_t buffer_size, struct header *hdr);
int parse_network(const uint8_t *buffer, size_t buffer_size, struct network *net);
int parse_security(const uint8_t *buffer, size_t buffer_size, struct security *sec);
int parse_discovery(const uint8_t *buffer, size_t buffer_size, struct discovery_message *disc);
int parse_route_request(const uint8_t *buffer, size_t buffer_size, struct route_request *req);
int parse_route_reply(const uint8_t *buffer, size_t buffer_size, struct route_reply *rep);
int parse_heartbeat(const uint8_t *buffer, size_t buffer_size, struct heartbeat *hb);
int parse_acknowledgement(const uint8_t *buffer, size_t buffer_size, struct acknowledgement *ack);
int parse_key_exchange(const uint8_t *buffer, size_t buffer_size, struct key_exchange_message *kex);
int parse_packet(const uint8_t *buffer, size_t buffer_size, struct packet *pkt);

/* Fragmentation functions */
int fragment_payload(const uint8_t *payload, size_t payload_size,
                     struct packet ***fragments_out, size_t *fragment_count_out,
                     uint32_t source_id, uint32_t dest_id, uint16_t sequence_number);
void free_fragments(struct packet **fragments, size_t fragment_count);

/* Reassembly functions */
struct fragment_buffer *create_fragment_buffer(uint16_t sequence_number, uint8_t total_fragments);
void free_fragment_buffer(struct fragment_buffer *fragment_buffer);
int add_fragment(struct fragment_buffer *fragment_buffer, uint8_t fragment_num, const uint8_t *payload, uint16_t payload_size);
int is_complete(const struct fragment_buffer *fragment_buffer);
size_t reassemble_payload(const struct fragment_buffer *fragment_buffer, uint8_t *output, size_t output_size);

/* Utility functions */
uint16_t calculate_checksum(const uint8_t *data, size_t length);

#endif