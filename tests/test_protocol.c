#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "protocol.h"

/*
    Free dynamic memory from a Data Packet
*/
static void free_parsed_packet(struct packet *p) {
    free(p->header);
    free(p->network);
    free(p->payload);
    free(p->security);
}

/*
    Serialize and Deserialize a Discovery Message.
*/
static void test_discovery_roundtrip(void) {
    const struct discovery_message out = { .available_connections = 5, .timestamp = 0x12345678 };
    uint8_t buf[16];
    const size_t n = serialize_discovery(&out, buf, sizeof(buf));
    assert(n == sizeof(struct discovery_message));
    struct discovery_message in;
    assert(parse_discovery(buf, n, &in) == 0);
    assert(in.available_connections == out.available_connections);
    assert(in.timestamp == out.timestamp);
}

/*
    Serialize and Deserialize a Route Request Message.
*/
static void test_route_request_roundtrip(void) {
    uint32_t path[] = { 0x11111111, 0x22222222, 0x33333333 };
    const struct route_request out = {
        .request_id = 0x0000000A,
        .destination_id = 0x0000000A,
        .hop_count = 3,
        .reverse_path_len = 3,
        .reverse_path = path
    };
    uint8_t buf[64];
    const size_t n = serialize_route_request(&out, buf, sizeof(buf));
    assert(n == 10 + 3*4);
    struct route_request in;
    assert(parse_route_request(buf, n, &in) == 0);
    assert(in.request_id == out.request_id);
    assert(in.destination_id == out.destination_id);
    assert(in.hop_count == out.hop_count);
    assert(in.reverse_path_len == out.reverse_path_len);
    for (uint8_t i = 0; i < in.reverse_path_len; i++) {
        assert(in.reverse_path[i] == path[i]);
    }
    free(in.reverse_path);
}

/*
    Serialize and Deserialize a Route Reply Message.
*/
static void test_route_reply_roundtrip(void) {
    uint32_t path[] = { 0x11111111, 0x22222222 };
    const struct route_reply out = {
        .request_id = 0x0000000B,
        .route_cost = 2,
        .forward_path_len = 2,
        .forward_path = path
    };
    uint8_t buf[64];
    const size_t n = serialize_route_reply(&out, buf, sizeof(buf));
    assert(n == 6 + 2*4);
    struct route_reply in;
    assert(parse_route_reply(buf, n, &in) == 0);
    assert(in.request_id == out.request_id);
    assert(in.route_cost == out.route_cost);
    assert(in.forward_path_len == out.forward_path_len);
    for (uint8_t i = 0; i < in.forward_path_len; i++) {
        assert(in.forward_path[i] == path[i]);
    }
    free(in.forward_path);
}

/*
    Serialize and Deserialize a HeartBeat Message.
*/
static void test_heartbeat_roundtrip(void) {
    const struct heartbeat out = { .device_status = 2, .active_connection_number = 4, .timestamp = 0x0000000A };
    uint8_t buf[16];
    const size_t n = serialize_heartbeat(&out, buf, sizeof(buf));
    assert(n == sizeof(struct heartbeat));
    struct heartbeat in;
    assert(parse_heartbeat(buf, n, &in) == 0);
    assert(in.device_status == out.device_status);
    assert(in.active_connection_number == out.active_connection_number);
    assert(in.timestamp == out.timestamp);
}

/*
    Serialize and Deserialize an Ack Message.
*/
static void test_acknowledgement_roundtrip(void) {
    uint8_t received[] = { 0, 2, 4, 6 };
    const struct acknowledgement out = {
        .sequence_number = 0x0001,
        .status_code = SUCCESS,
        .received_fragment_count = sizeof(received),
        .received_fragment_list = received
    };
    uint8_t buf[32];
    const size_t n = serialize_acknowledgement(&out, buf, sizeof(buf));
    assert(n == 4 + out.received_fragment_count);
    struct acknowledgement in;
    assert(parse_acknowledgement(buf, n, &in) == 0);
    assert(in.sequence_number == out.sequence_number);
    assert(in.status_code == out.status_code);
    assert(in.received_fragment_count == out.received_fragment_count);
    assert(memcmp(in.received_fragment_list, received, in.received_fragment_count) == 0);
    free(in.received_fragment_list);
}

/*
    Serialize and Deserialize a Key Exchange Message.
*/
static void test_key_exchange_roundtrip(void) {
    struct key_exchange_message out;
    for (int i = 0; i < 32; ++i) out.public_key[i] = (uint8_t)i;
    out.timestamp = 0x0000000A;
    uint8_t buf[40];
    const size_t n = serialize_key_exchange(&out, buf, sizeof(buf));
    assert(n == sizeof(struct key_exchange_message));
    struct key_exchange_message in;
    assert(parse_key_exchange(buf, n, &in) == 0);
    assert(in.timestamp == out.timestamp);
    assert(memcmp(in.public_key, out.public_key, 32) == 0);
}

/*
    Serialize and Deserialize a Packet.
*/
static void test_packet_roundtrip(void) {
    struct packet out_pkt;
    struct header hdr;
    struct network net;
    struct security sec;
    uint8_t payload[50];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i + 1);

    hdr.protocol_version = 1;
    hdr.message_type = MSG_DATA;
    hdr.fragmentation_flag = 0;
    hdr.fragmentation_number = 0;
    hdr.total_fragments = 1;
    hdr.time_to_live = 64;
    hdr.payload_length = (uint16_t)sizeof(payload);
    hdr.sequence_number = 0x0001;

    net.source_id = 0x00000123;
    net.destination_id = 0x00000456;

    sec.key_id = 7;
    sec.frame_counter = 0x00000001;
    for (int i = 0; i < 7; ++i) sec.nonce[i] = (uint8_t)(i + 10);
    for (int i = 0; i < 12; ++i) sec.mac[i] = (uint8_t)(i + 20);

    out_pkt.header = &hdr;
    out_pkt.network = &net;
    out_pkt.payload = payload;
    out_pkt.security = &sec;

    uint8_t buf[8 + 8 + 50 + 24];
    const size_t n = serialize_packet(&out_pkt, buf, sizeof(buf));
    assert(n == sizeof(buf));

    struct packet in_pkt = {0};
    assert(parse_packet(buf, n, &in_pkt) == 0);

    assert(in_pkt.header->protocol_version == hdr.protocol_version);
    assert(in_pkt.header->message_type == hdr.message_type);
    assert(in_pkt.header->payload_length == hdr.payload_length);
    assert(in_pkt.header->sequence_number == hdr.sequence_number);
    assert(in_pkt.network->source_id == net.source_id);
    assert(in_pkt.network->destination_id == net.destination_id);
    assert(in_pkt.security != NULL);
    assert(in_pkt.security->key_id == sec.key_id);
    assert(memcmp(in_pkt.payload, payload, sizeof(payload)) == 0);

    free_parsed_packet(&in_pkt);
}

/*
    Test Serialize and Deserialize for a fragmented packet.
*/
static void test_fragmentation_and_reassembly(void) {
    const size_t payload_len = 450; // > 200 to force fragmentation into 3 fragments
    uint8_t *payload = malloc(payload_len);
    assert(payload);
    for (size_t i = 0; i < payload_len; i++) payload[i] = (uint8_t)(i & 0xFF);

    struct packet **fragments = NULL;
    size_t fragment_count = 0;
    const int r = fragment_payload(payload, payload_len, &fragments, &fragment_count, 0x0001, 0x0002, 0xABCD);
    assert(r == 0);
    assert(fragment_count == 3);

    // Create fragment buffer and add fragments out of order
    struct fragment_buffer *fb = create_fragment_buffer(0xABCD, (uint8_t)fragment_count);
    assert(fb != NULL);

    // add fragment 2, then 0, then 1 to test ordering
    assert(add_fragment(fb, fragments[2]->header->fragmentation_number, fragments[2]->payload, fragments[2]->header->payload_length) == 0);
    assert(add_fragment(fb, fragments[0]->header->fragmentation_number, fragments[0]->payload, fragments[0]->header->payload_length) == 0);
    assert(add_fragment(fb, fragments[1]->header->fragmentation_number, fragments[1]->payload, fragments[1]->header->payload_length) == 0);

    assert(is_complete(fb) == 1);

    uint8_t *reassembled = malloc(payload_len);
    assert(reassembled);
    const size_t got = reassemble_payload(fb, reassembled, payload_len);
    assert(got == payload_len);
    assert(memcmp(reassembled, payload, payload_len) == 0);

    free(reassembled);
    free(payload);
    free_fragment_buffer(fb);
    free_fragments(fragments, fragment_count);
}

int main(void) {
    test_discovery_roundtrip();
    test_route_request_roundtrip();
    test_route_reply_roundtrip();
    test_heartbeat_roundtrip();
    test_acknowledgement_roundtrip();
    test_key_exchange_roundtrip();
    test_packet_roundtrip();
    test_fragmentation_and_reassembly();

    printf("ALL PROTOCOL TESTS PASSED\n");

    return EXIT_SUCCESS;
}

