#include "protocol.h"
#include <string.h>
#include <stdlib.h>

/* Utility functions */
uint16_t calculate_checksum(const uint8_t *data, const size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i++) {
        sum += data[i];
    }

    // Keep lower 16 bits
    return (uint16_t)(sum & 0xFFFF);
}

/* Serialization functions */
size_t serialize_header(const struct header *hdr, uint8_t *buffer, const size_t buffer_size) {
    if (!hdr || !buffer || buffer_size < sizeof(struct header)) return 0;

    buffer[0] = (hdr->protocol_version & 0x0F) | ((hdr->message_type & 0x0F) << 4);
    buffer[1] = (hdr->fragmentation_flag & 0x01) | ((hdr->fragmentation_number & 0x7F) << 1);
    buffer[2] = hdr->total_fragments;
    buffer[3] = hdr->time_to_live;
    buffer[4] = (hdr->payload_length >> 8) & 0xFF;
    buffer[5] = hdr->payload_length & 0xFF;
    buffer[6] = (hdr->sequence_number >> 8) & 0xFF;
    buffer[7] = hdr->sequence_number & 0xFF;

    return sizeof(struct header);
}

size_t serialize_network(const struct network *net, uint8_t *buffer, const size_t buffer_size) {
    if (!net || !buffer || buffer_size < sizeof(struct network)) return 0;

    buffer[0] = (net->source_id >> 24) & 0xFF;
    buffer[1] = (net->source_id >> 16) & 0xFF;
    buffer[2] = (net->source_id >> 8) & 0xFF;
    buffer[3] = net->source_id & 0xFF;
    buffer[4] = (net->destination_id >> 24) & 0xFF;
    buffer[5] = (net->destination_id >> 16) & 0xFF;
    buffer[6] = (net->destination_id >> 8) & 0xFF;
    buffer[7] = net->destination_id & 0xFF;

    return sizeof(struct network);
}

size_t serialize_security(const struct security *sec, uint8_t *buffer, const size_t buffer_size) {
    if (!sec || !buffer || buffer_size < 24) return 0;

    buffer[0] = sec->key_id;
    buffer[1] = (sec->frame_counter >> 24) & 0xFF;
    buffer[2] = (sec->frame_counter >> 16) & 0xFF;
    buffer[3] = (sec->frame_counter >> 8) & 0xFF;
    buffer[4] = sec->frame_counter & 0xFF;
    memcpy(&buffer[5], sec->nonce, 7);
    memcpy(&buffer[12], sec->mac, 12);

    return 24;
}

size_t serialize_discovery(const struct discovery_message *disc, uint8_t *buffer, const size_t buffer_size) {
    if (!disc || !buffer || buffer_size < sizeof(struct discovery_message)) return 0;

    buffer[0] = disc->available_connections;
    buffer[1] = (disc->timestamp >> 24) & 0xFF;
    buffer[2] = (disc->timestamp >> 16) & 0xFF;
    buffer[3] = (disc->timestamp >> 8) & 0xFF;
    buffer[4] = disc->timestamp & 0xFF;

    return sizeof(struct discovery_message);
}

size_t serialize_route_request(const struct route_request *req, uint8_t *buffer, const size_t buffer_size) {
    if (!req || !buffer) return 0;

    const size_t total_size = 10 + (req->reverse_path_len * 4);
    if (buffer_size < total_size) return 0;

    buffer[0] = (req->request_id >> 24) & 0xFF;
    buffer[1] = (req->request_id >> 16) & 0xFF;
    buffer[2] = (req->request_id >> 8) & 0xFF;
    buffer[3] = req->request_id & 0xFF;
    buffer[4] = (req->destination_id >> 24) & 0xFF;
    buffer[5] = (req->destination_id >> 16) & 0xFF;
    buffer[6] = (req->destination_id >> 8) & 0xFF;
    buffer[7] = req->destination_id & 0xFF;
    buffer[8] = req->hop_count;
    buffer[9] = req->reverse_path_len;

    for (uint8_t i = 0; i < req->reverse_path_len; i++) {
        const size_t offset = 10 + (i * 4);
        buffer[offset] = (req->reverse_path[i] >> 24) & 0xFF;
        buffer[offset + 1] = (req->reverse_path[i] >> 16) & 0xFF;
        buffer[offset + 2] = (req->reverse_path[i] >> 8) & 0xFF;
        buffer[offset + 3] = req->reverse_path[i] & 0xFF;
    }

    return total_size;
}

size_t serialize_route_reply(const struct route_reply *rep, uint8_t *buffer, const size_t buffer_size) {
    if (!rep || !buffer) return 0;

    const size_t total_size = 6 + (rep->forward_path_len * 4);
    if (buffer_size < total_size) return 0;

    buffer[0] = (rep->request_id >> 24) & 0xFF;
    buffer[1] = (rep->request_id >> 16) & 0xFF;
    buffer[2] = (rep->request_id >> 8) & 0xFF;
    buffer[3] = rep->request_id & 0xFF;
    buffer[4] = rep->route_cost;
    buffer[5] = rep->forward_path_len;

    for (uint8_t i = 0; i < rep->forward_path_len; i++) {
        const size_t offset = 6 + (i * 4);
        buffer[offset] = (rep->forward_path[i] >> 24) & 0xFF;
        buffer[offset + 1] = (rep->forward_path[i] >> 16) & 0xFF;
        buffer[offset + 2] = (rep->forward_path[i] >> 8) & 0xFF;
        buffer[offset + 3] = rep->forward_path[i] & 0xFF;
    }

    return total_size;
}

size_t serialize_heartbeat(const struct heartbeat *hb, uint8_t *buffer, const size_t buffer_size) {
    if (!hb || !buffer || buffer_size < sizeof(struct heartbeat)) return 0;

    buffer[0] = hb->device_status;
    buffer[1] = hb->active_connection_number;
    buffer[2] = (hb->timestamp >> 24) & 0xFF;
    buffer[3] = (hb->timestamp >> 16) & 0xFF;
    buffer[4] = (hb->timestamp >> 8) & 0xFF;
    buffer[5] = hb->timestamp & 0xFF;

    return sizeof(struct heartbeat);
}

size_t serialize_acknowledgement(const struct acknowledgement *ack, uint8_t *buffer, const size_t buffer_size) {
    if (!ack || !buffer) return 0;

    const size_t total_size = 4 + ack->received_fragment_count;
    if (buffer_size < total_size) return 0;

    buffer[0] = (ack->sequence_number >> 8) & 0xFF;
    buffer[1] = ack->sequence_number & 0xFF;
    buffer[2] = ack->status_code;
    buffer[3] = ack->received_fragment_count;

    if (ack->received_fragment_list) {
        memcpy(&buffer[4], ack->received_fragment_list, ack->received_fragment_count);
    }

    return total_size;
}

size_t serialize_key_exchange(const struct key_exchange_message *kex, uint8_t *buffer, const size_t buffer_size) {
    if (!kex || !buffer || buffer_size < sizeof(struct key_exchange_message)) return 0;

    memcpy(buffer, kex->public_key, 32);
    buffer[32] = (kex->timestamp >> 24) & 0xFF;
    buffer[33] = (kex->timestamp >> 16) & 0xFF;
    buffer[34] = (kex->timestamp >> 8) & 0xFF;
    buffer[35] = kex->timestamp & 0xFF;

    return sizeof(struct key_exchange_message);
}

size_t serialize_packet(const struct packet *pkt, uint8_t *buffer, const size_t buffer_size) {
    if (!pkt || !buffer || !pkt->header || !pkt->network) return 0;

    size_t offset = 0;

    // Serialize header
    size_t written = serialize_header(pkt->header, buffer + offset, buffer_size - offset);
    if (written == 0) return 0;
    offset += written;

    // Serialize network
    written = serialize_network(pkt->network, buffer + offset, buffer_size - offset);
    if (written == 0) return 0;
    offset += written;

    // Serialize payload
    if (pkt->payload && pkt->header->payload_length > 0) {
        if (buffer_size - offset < pkt->header->payload_length) return 0;
        memcpy(buffer + offset, pkt->payload, pkt->header->payload_length);
        offset += pkt->header->payload_length;
    }

    // Serialize security (if present)
    if (pkt->security) {
        written = serialize_security(pkt->security, buffer + offset, buffer_size - offset);
        if (written == 0) return 0;
        offset += written;
    }

    return offset;
}

/* Parsing functions */
int parse_header(const uint8_t *buffer, const size_t buffer_size, struct header *hdr) {
    if (!buffer || !hdr || buffer_size < sizeof(struct header)) return -1;

    hdr->protocol_version = buffer[0] & 0x0F;
    hdr->message_type = (buffer[0] >> 4) & 0x0F;
    hdr->fragmentation_flag = buffer[1] & 0x01;
    hdr->fragmentation_number = (buffer[1] >> 1) & 0x7F;
    hdr->total_fragments = buffer[2];
    hdr->time_to_live = buffer[3];
    hdr->payload_length = ((uint16_t)buffer[4] << 8) | buffer[5];
    hdr->sequence_number = ((uint16_t)buffer[6] << 8) | buffer[7];

    return 0;
}

int parse_network(const uint8_t *buffer, const size_t buffer_size, struct network *net) {
    if (!buffer || !net || buffer_size < sizeof(struct network)) return -1;

    net->source_id = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                     ((uint32_t)buffer[2] << 8) | buffer[3];
    net->destination_id = ((uint32_t)buffer[4] << 24) | ((uint32_t)buffer[5] << 16) |
                          ((uint32_t)buffer[6] << 8) | buffer[7];

    return 0;
}

int parse_security(const uint8_t *buffer, const size_t buffer_size, struct security *sec) {
    if (!buffer || !sec || buffer_size < 24) return -1;

    sec->key_id = buffer[0];
    sec->frame_counter = ((uint32_t)buffer[1] << 24) | ((uint32_t)buffer[2] << 16) |
                         ((uint32_t)buffer[3] << 8) | buffer[4];
    memcpy(sec->nonce, &buffer[5], 7);
    memcpy(sec->mac, &buffer[12], 12);

    return 0;
}

int parse_discovery(const uint8_t *buffer, const size_t buffer_size, struct discovery_message *disc) {
    if (!buffer || !disc || buffer_size < sizeof(struct discovery_message)) return -1;

    disc->available_connections = buffer[0];
    disc->timestamp = ((uint32_t)buffer[1] << 24) | ((uint32_t)buffer[2] << 16) |
                      ((uint32_t)buffer[3] << 8) | buffer[4];

    return 0;
}

int parse_route_request(const uint8_t *buffer, const size_t buffer_size, struct route_request *req) {
    if (!buffer || !req || buffer_size < 10) return -1;

    req->request_id = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                      ((uint32_t)buffer[2] << 8) | buffer[3];
    req->destination_id = ((uint32_t)buffer[4] << 24) | ((uint32_t)buffer[5] << 16) |
                          ((uint32_t)buffer[6] << 8) | buffer[7];
    req->hop_count = buffer[8];
    req->reverse_path_len = buffer[9];

    const size_t total_size = 10 + (req->reverse_path_len * 4);
    if (buffer_size < total_size) return -1;

    if (req->reverse_path_len > 0) {
        req->reverse_path = (uint32_t *)malloc(req->reverse_path_len * sizeof(uint32_t));
        if (!req->reverse_path) return -1;

        for (uint8_t i = 0; i < req->reverse_path_len; i++) {
            const size_t offset = 10 + (i * 4);
            req->reverse_path[i] = ((uint32_t)buffer[offset] << 24) |
                                   ((uint32_t)buffer[offset + 1] << 16) |
                                   ((uint32_t)buffer[offset + 2] << 8) |
                                   buffer[offset + 3];
        }
    } else {
        req->reverse_path = NULL;
    }

    return 0;
}

int parse_route_reply(const uint8_t *buffer, const size_t buffer_size, struct route_reply *rep) {
    if (!buffer || !rep || buffer_size < 6) return -1;

    rep->request_id = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                      ((uint32_t)buffer[2] << 8) | buffer[3];
    rep->route_cost = buffer[4];
    rep->forward_path_len = buffer[5];

    const size_t total_size = 6 + (rep->forward_path_len * 4);
    if (buffer_size < total_size) return -1;

    if (rep->forward_path_len > 0) {
        rep->forward_path = (uint32_t *)malloc(rep->forward_path_len * sizeof(uint32_t));
        if (!rep->forward_path) return -1;

        for (uint8_t i = 0; i < rep->forward_path_len; i++) {
            const size_t offset = 6 + (i * 4);
            rep->forward_path[i] = ((uint32_t)buffer[offset] << 24) |
                                   ((uint32_t)buffer[offset + 1] << 16) |
                                   ((uint32_t)buffer[offset + 2] << 8) |
                                   buffer[offset + 3];
        }
    } else {
        rep->forward_path = NULL;
    }

    return 0;
}

int parse_heartbeat(const uint8_t *buffer, const size_t buffer_size, struct heartbeat *hb) {
    if (!buffer || !hb || buffer_size < sizeof(struct heartbeat)) return -1;

    hb->device_status = buffer[0];
    hb->active_connection_number = buffer[1];
    hb->timestamp = ((uint32_t)buffer[2] << 24) | ((uint32_t)buffer[3] << 16) |
                    ((uint32_t)buffer[4] << 8) | buffer[5];

    return 0;
}

int parse_acknowledgement(const uint8_t *buffer, const size_t buffer_size, struct acknowledgement *ack) {
    if (!buffer || !ack || buffer_size < 4) return -1;

    ack->sequence_number = ((uint16_t)buffer[0] << 8) | buffer[1];
    ack->status_code = buffer[2];
    ack->received_fragment_count = buffer[3];

    const size_t total_size = 4 + ack->received_fragment_count;
    if (buffer_size < total_size) return -1;

    if (ack->received_fragment_count > 0) {
        ack->received_fragment_list = (uint8_t *)malloc(ack->received_fragment_count);
        if (!ack->received_fragment_list) return -1;
        memcpy(ack->received_fragment_list, &buffer[4], ack->received_fragment_count);
    } else {
        ack->received_fragment_list = NULL;
    }

    return 0;
}

int parse_key_exchange(const uint8_t *buffer, const size_t buffer_size, struct key_exchange_message *kex) {
    if (!buffer || !kex || buffer_size < sizeof(struct key_exchange_message)) return -1;

    memcpy(kex->public_key, buffer, 32);
    kex->timestamp = ((uint32_t)buffer[32] << 24) | ((uint32_t)buffer[33] << 16) |
                     ((uint32_t)buffer[34] << 8) | buffer[35];

    return 0;
}

int parse_packet(const uint8_t *buffer, const size_t buffer_size, struct packet *pkt) {
    if (!buffer || !pkt || buffer_size < 16) return -1;

    size_t offset = 0;

    // Parse header
    pkt->header = (struct header *)malloc(sizeof(struct header));
    if (!pkt->header) return -1;
    if (parse_header(buffer + offset, buffer_size - offset, pkt->header) != 0) {
        free(pkt->header);
        return -1;
    }
    offset += 8;

    // Parse network
    pkt->network = (struct network *)malloc(sizeof(struct network));
    if (!pkt->network) {
        free(pkt->header);
        return -1;
    }
    if (parse_network(buffer + offset, buffer_size - offset, pkt->network) != 0) {
        free(pkt->header);
        free(pkt->network);
        return -1;
    }
    offset += 8;

    // Parse payload
    if (pkt->header->payload_length > 0) {
        if (buffer_size - offset < pkt->header->payload_length) {
            free(pkt->header);
            free(pkt->network);
            return -1;
        }
        pkt->payload = (uint8_t *)malloc(pkt->header->payload_length);
        if (!pkt->payload) {
            free(pkt->header);
            free(pkt->network);
            return -1;
        }
        memcpy(pkt->payload, buffer + offset, pkt->header->payload_length);
        offset += pkt->header->payload_length;
    } else {
        pkt->payload = NULL;
    }

    // Parse security (if data remains)
    if (buffer_size - offset >= 24) {
        pkt->security = (struct security *)malloc(sizeof(struct security));
        if (!pkt->security) {
            free(pkt->header);
            free(pkt->network);
            free(pkt->payload);
            return -1;
        }
        if (parse_security(buffer + offset, buffer_size - offset, pkt->security) != 0) {
            free(pkt->header);
            free(pkt->network);
            free(pkt->payload);
            free(pkt->security);
            return -1;
        }
    } else {
        pkt->security = NULL;
    }

    return 0;
}

/* Fragmentation functions */
int fragment_payload(const uint8_t *payload, const size_t payload_size,
                     struct packet ***fragments_out, size_t *fragment_count_out,
                     const uint32_t source_id, const uint32_t dest_id, const uint16_t sequence_number) {
    if (!payload || !fragments_out || !fragment_count_out || payload_size == 0) return -1;

    const size_t max_frag_size = MAX_PAYLOAD_PER_FRAGMENT;
    const size_t num_fragments = (payload_size + max_frag_size - 1) / max_frag_size;

    if (num_fragments > 255) return -1; // Too many fragments

    struct packet **fragments = malloc(num_fragments * sizeof(struct packet *));
    if (!fragments) return -1;

    for (size_t i = 0; i < num_fragments; i++) {
        fragments[i] = (struct packet *)malloc(sizeof(struct packet));
        if (!fragments[i]) {
            for (size_t j = 0; j < i; j++) {
                free(fragments[j]->header);
                free(fragments[j]->network);
                free(fragments[j]->payload);
                free(fragments[j]);
            }
            free(fragments);
            return -1;
        }

        // Allocate and fill header
        fragments[i]->header = (struct header *)malloc(sizeof(struct header));
        fragments[i]->header->protocol_version = 1;
        fragments[i]->header->message_type = MSG_DATA;
        fragments[i]->header->fragmentation_flag = (num_fragments > 1) ? 1 : 0;
        fragments[i]->header->fragmentation_number = (uint8_t)i;
        fragments[i]->header->total_fragments = (uint8_t)num_fragments;
        fragments[i]->header->time_to_live = 64;
        fragments[i]->header->sequence_number = sequence_number;

        // Allocate and fill network
        fragments[i]->network = (struct network *)malloc(sizeof(struct network));
        fragments[i]->network->source_id = source_id;
        fragments[i]->network->destination_id = dest_id;

        // Calculate payload size for this fragment
        const size_t offset = i * max_frag_size;
        const size_t frag_payload_size = (offset + max_frag_size > payload_size) ?
                                   (payload_size - offset) : max_frag_size;

        fragments[i]->header->payload_length = (uint16_t)frag_payload_size;

        // Allocate and copy payload
        fragments[i]->payload = (uint8_t *)malloc(frag_payload_size);
        memcpy(fragments[i]->payload, payload + offset, frag_payload_size);

        fragments[i]->security = NULL;
    }

    *fragments_out = fragments;
    *fragment_count_out = num_fragments;

    return 0;
}

void free_fragments(struct packet **fragments, const size_t fragment_count) {
    if (!fragments) return;

    for (size_t i = 0; i < fragment_count; i++) {
        if (fragments[i]) {
            free(fragments[i]->header);
            free(fragments[i]->network);
            free(fragments[i]->payload);
            free(fragments[i]->security);
            free(fragments[i]);
        }
    }
    free(fragments);
}

/* Reassembly functions */
struct fragment_buffer *create_fragment_buffer(const uint16_t sequence_number, const uint8_t total_fragments) {
    if (total_fragments == 0) return NULL;

    struct fragment_buffer *fb = malloc(sizeof(struct fragment_buffer));
    if (!fb) return NULL;

    fb->sequence_number = sequence_number;
    fb->total_fragments = total_fragments;
    fb->received_count = 0;
    fb->timestamp = 0; // TODO

    fb->received_flags = (uint8_t *)calloc(total_fragments, 1);
    fb->fragments = (uint8_t **)calloc(total_fragments, sizeof(uint8_t *));
    fb->fragment_sizes = (uint16_t *)calloc(total_fragments, sizeof(uint16_t));

    if (!fb->received_flags || !fb->fragments || !fb->fragment_sizes) {
        free(fb->received_flags);
        free(fb->fragments);
        free(fb->fragment_sizes);
        free(fb);
        return NULL;
    }

    return fb;
}

void free_fragment_buffer(struct fragment_buffer *fragment_buffer) {
    if (!fragment_buffer) return;

    if (fragment_buffer->fragments) {
        for (uint8_t i = 0; i < fragment_buffer->total_fragments; i++) {
            free(fragment_buffer->fragments[i]);
        }
        free(fragment_buffer->fragments);
    }

    free(fragment_buffer->received_flags);
    free(fragment_buffer->fragment_sizes);
    free(fragment_buffer);
}

int add_fragment(struct fragment_buffer *fragment_buffer, const uint8_t fragment_num, const uint8_t *payload, const uint16_t payload_size) {
    if (!fragment_buffer || !payload || fragment_num >= fragment_buffer->total_fragments) return -1;

    // Check if already received
    if (fragment_buffer->received_flags[fragment_num]) return 0;

    // Allocate and copy fragment
    fragment_buffer->fragments[fragment_num] = (uint8_t *)malloc(payload_size);
    if (!fragment_buffer->fragments[fragment_num]) return -1;

    memcpy(fragment_buffer->fragments[fragment_num], payload, payload_size);
    fragment_buffer->fragment_sizes[fragment_num] = payload_size;
    fragment_buffer->received_flags[fragment_num] = 1;
    fragment_buffer->received_count++;

    return 0;
}

int is_complete(const struct fragment_buffer *fragment_buffer) {
    if (!fragment_buffer) return 0;
    return fragment_buffer->received_count == fragment_buffer->total_fragments;
}

size_t reassemble_payload(const struct fragment_buffer *fragment_buffer, uint8_t *output, const size_t output_size) {
    if (!fragment_buffer || !output || !is_complete(fragment_buffer)) return 0;

    size_t total_size = 0;
    for (uint8_t i = 0; i < fragment_buffer->total_fragments; i++) {
        total_size += fragment_buffer->fragment_sizes[i];
    }

    if (output_size < total_size) return 0;

    size_t offset = 0;
    for (uint8_t i = 0; i < fragment_buffer->total_fragments; i++) {
        memcpy(output + offset, fragment_buffer->fragments[i], fragment_buffer->fragment_sizes[i]);
        offset += fragment_buffer->fragment_sizes[i];
    }

    return total_size;
}
