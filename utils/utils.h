#ifndef LOCALNET_UTILS_H
#define LOCALNET_UTILS_H


#define FUNC_RETURN_FAIL (-1)
#define FUNC_RETURN_SUCCESS (1)

#define TAG "LOCALNET"
#include "routing.h"
#include <stdint.h>
#include <stddef.h>

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

/**
 * Read a line from stdin and remove trailing newline
* @param buffer Buffer to store the input
* @param size Size of the buffer
* @return 0 on success, -1 on error
*/
int read_stdin_line(char * buffer, size_t size);

/**
 *  Parse a hex node ID from a string
 * @param input Input string (e.g., "0x12345678")
 * @param node_id Output parameter for parsed node ID
 * @return 0 on success, -1 on parse error
*/
int parse_node_id(const char * input, uint32_t * node_id);

/**
 * Validate that a destination node ID is valid (not 0 or self)
 * @param dest_id Destination node ID to validate
 * @param self_id This node's ID
 * @return 0 if valid, -1 if invalid
*/
int validate_destination_id(uint32_t dest_id, uint32_t self_id);

#endif //LOCALNET_UTILS_H