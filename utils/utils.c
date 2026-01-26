#include "utils.h"
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

/* Utility Functions */
uint32_t get_current_timestamp(void) {
    return (uint32_t)time(NULL);
}

uint32_t generate_request_id(void) {
    return (uint32_t)rand(); // NOLINT(cert-msc30-c, cert-msc50-cpp)
}

uint32_t mac_to_device_id(const char *mac) {
    if (!mac) return 0;

    unsigned long bytes[6];
    char *end = NULL;

    for (int i = 0; i < 6; i++) {
        // Require exactly two hex digits
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

    return ((uint32_t)bytes[3] << 16) |
           ((uint32_t)bytes[4] << 8)  |
           ((uint32_t)bytes[5]);
}
