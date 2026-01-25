#ifndef LOCALNET_UTILS_H
#define LOCALNET_UTILS_H


#define FUNC_RETURN_FAIL (-1)
#define FUNC_RETURN_SUCCESS (1)

#define TAG "LOCALNET"

#include <stdint.h>

uint32_t get_current_timestamp(void);
uint32_t generate_request_id(void);

#endif //LOCALNET_UTILS_H