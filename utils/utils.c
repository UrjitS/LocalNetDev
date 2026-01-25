#include "utils.h"
#include <stdint.h>
#include <time.h>
#include <stdlib.h>

/* Utility Functions */
uint32_t get_current_timestamp(void) {
    return (uint32_t)time(NULL);
}

uint32_t generate_request_id(void) {
    return (uint32_t)rand(); // NOLINT(cert-msc30-c, cert-msc50-cpp)
}
