#include "utils.h"
#include <stdint.h>
#include "routing.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

uint32_t get_current_timestamp(void) {
    return (uint32_t)time(NULL);
}

uint32_t generate_request_id(void) {
    return (uint32_t)rand(); // NOLINT(cert-msc30-c, cert-msc50-cpp)
}

const char * node_type_to_string(const enum NODE_TYPE type) {
    switch (type) {
        case EDGE_NODE: return "EDGE";
        case FULL_NODE: return "FULL";
        case GATEWAY_NODE: return "GATEWAY";
        default: return "UNKNOWN";
    }
}

uint32_t mac_to_device_id(const char * mac) {
    if (!mac) return 0;

    unsigned long bytes[6];
    char * end = NULL;

    for (int i = 0; i < 6; i++) {
        if (!isxdigit((unsigned char)mac[0]) ||
            !isxdigit((unsigned char)mac[1])) {
            return 0;
            }

        bytes[i] = strtoul(mac, &end, 16);

        if (end != mac + 2 || bytes[i] > 0xFF) {
            return 0;
        }

        mac = end;

        if (i < 5) {
            if (*mac != ':') {
                return 0;
            }
            mac++;
        }
    }

    return ((uint32_t)bytes[2] << 24) |
           ((uint32_t)bytes[3] << 16) |
           ((uint32_t)bytes[4] << 8)  |
           ((uint32_t)bytes[5]);
}

int read_stdin_line(char * buffer, const size_t size) {
    if (!buffer || size == 0) {
        return -1;
    }

    if (fgets(buffer, (int)size, stdin) == NULL) {
        return -1;
    }

    // Remove trailing newline and carriage return
    buffer[strcspn(buffer, "\n\r")] = '\0';

    return 0;
}

int parse_node_id(const char * input, uint32_t * node_id) {
    if (!input || !node_id) {
        return -1;
    }

    char * end_ptr;
    const unsigned long parsed = strtoul(input, &end_ptr, 0);

    // Check if parse was successful and entire string was consumed
    if (end_ptr == input || *end_ptr != '\0') {
        return -1;
    }

    *node_id = (uint32_t)parsed;
    return 0;
}

int validate_destination_id(const uint32_t dest_id, const uint32_t self_id) {
    if (dest_id == 0 || dest_id == self_id) {
        return -1;
    }
    return 0;
}

