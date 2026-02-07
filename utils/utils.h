#ifndef LOCALNET_UTILS_H
#define LOCALNET_UTILS_H


#define FUNC_RETURN_FAIL (-1)
#define FUNC_RETURN_SUCCESS (1)

#define TAG "LOCALNET"
#include "routing.h"
#include <stdint.h>

uint32_t get_current_timestamp(void);
uint32_t generate_request_id(void);
const char * node_type_to_string(enum NODE_TYPE type);


/**
 * Convert a MAC address string to a device ID
 * Uses the last 3 octets of the MAC address
 * @param mac MAC address in format "XX:XX:XX:XX:XX:XX"
 * @return Device ID derived from MAC, or 0 on failure
 */
uint32_t mac_to_device_id(const char *mac);

#endif //LOCALNET_UTILS_H