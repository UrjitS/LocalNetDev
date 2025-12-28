#ifndef LOCALNET_BLUETOOTH_TRANSPORT_H
#define LOCALNET_BLUETOOTH_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

/* Bluetooth Transport Configuration */
#define BT_MAX_DEVICES 20
#define BT_SCAN_TIME 5
#define BT_RFCOMM_CHANNEL BTPROTO_RFCOMM
#define BT_RECV_BUFFER_SIZE 1024
#define BT_CONNECTION_TIMEOUT_MS 5000
#define BT_MAX_RETRIES 3

/* Bluetooth Address Length */
#define BT_ADDR_LEN 6

/* Bluetooth Device Information */
struct bt_device_info {
    uint8_t bdaddr[BT_ADDR_LEN];
    char name[248];
    int8_t rssi;
    uint32_t device_id;  // Derived from Bluetooth address
    bool is_connected;
    int socket_fd;
};

/* Bluetooth Transport Context */
struct bt_transport {
    int hci_socket;
    int dev_id;
    int listen_socket;
    uint8_t local_bdaddr[BT_ADDR_LEN];
    uint32_t local_device_id;
    char local_name[248];

    /* Connected devices */
    struct bt_device_info devices[BT_MAX_DEVICES];
    size_t device_count;

    /* Listener thread */
    bool running;
    bool listener_active;

    /* Callbacks */
    void (*on_device_discovered)(struct bt_transport *transport, struct bt_device_info *device, void *user_data);
    void (*on_device_connected)(struct bt_transport *transport, struct bt_device_info *device, void *user_data);
    void (*on_device_disconnected)(struct bt_transport *transport, struct bt_device_info *device, void *user_data);
    void (*on_data_received)(struct bt_transport *transport, struct bt_device_info *device,
                            const uint8_t *data, size_t len, void *user_data);
    void *user_data;
};

/* Bluetooth Transport Functions */

/**
 * Initialize Bluetooth transport layer
 * @return Pointer to bt_transport context or NULL on failure
 */
struct bt_transport *bt_transport_init(void);

/**
 * Shutdown Bluetooth transport and cleanup resources
 * @param transport Transport context
 */
void bt_transport_shutdown(struct bt_transport *transport);

/**
 * Set device discoverable mode
 * @param transport Transport context
 * @param discoverable true to make device discoverable
 * @return 0 on success, -1 on failure
 */
int bt_set_discoverable(struct bt_transport *transport, bool discoverable);

/**
 * Scan for nearby Bluetooth devices
 * @param transport Transport context
 * @param devices Array to store discovered devices
 * @param max_devices Maximum number of devices to discover
 * @return Number of devices found, -1 on error
 */
int bt_scan_devices(struct bt_transport *transport, struct bt_device_info *devices, size_t max_devices);

/**
 * Connect to a Bluetooth device
 * @param transport Transport context
 * @param device Device to connect to (will be updated with connection info)
 * @return 0 on success, -1 on failure
 */
int bt_connect(struct bt_transport *transport, struct bt_device_info *device);

/**
 * Disconnect from a Bluetooth device
 * @param transport Transport context
 * @param device Device to disconnect
 * @return 0 on success, -1 on failure
 */
int bt_disconnect(struct bt_transport *transport, struct bt_device_info *device);

/**
 * Send data to a connected device
 * @param transport Transport context
 * @param device Target device
 * @param data Data to send
 * @param len Length of data
 * @return Number of bytes sent, -1 on error
 */
ssize_t bt_send(struct bt_transport *transport, struct bt_device_info *device,
                const uint8_t *data, size_t len);

/**
 * Broadcast data to all connected devices
 * @param transport Transport context
 * @param data Data to broadcast
 * @param len Length of data
 * @param exclude_device Device to exclude from broadcast (can be NULL)
 * @return Number of devices message was sent to
 */
int bt_broadcast(struct bt_transport *transport, const uint8_t *data, size_t len,
                 struct bt_device_info *exclude_device);

/**
 * Start the listener for incoming connections
 * @param transport Transport context
 * @return 0 on success, -1 on failure
 */
int bt_start_listener(struct bt_transport *transport);

/**
 * Stop the listener
 * @param transport Transport context
 */
void bt_stop_listener(struct bt_transport *transport);

/**
 * Find device by device ID
 * @param transport Transport context
 * @param device_id Device ID to find
 * @return Pointer to device info or NULL if not found
 */
struct bt_device_info *bt_find_device(struct bt_transport *transport, uint32_t device_id);

/**
 * Find device by Bluetooth address
 * @param transport Transport context
 * @param bdaddr Bluetooth address
 * @return Pointer to device info or NULL if not found
 */
struct bt_device_info *bt_find_device_by_addr(struct bt_transport *transport, const uint8_t *bdaddr);

/**
 * Convert Bluetooth address to device ID (32-bit hash)
 * @param bdaddr Bluetooth address (6 bytes)
 * @return 32-bit device ID
 */
uint32_t bt_addr_to_device_id(const uint8_t *bdaddr);

/**
 * Convert Bluetooth address to string
 * @param bdaddr Bluetooth address
 * @param str Output string buffer (at least 18 bytes)
 */
void bt_addr_to_str(const uint8_t *bdaddr, char *str);

/**
 * Convert string to Bluetooth address
 * @param str Bluetooth address string
 * @param bdaddr Output Bluetooth address
 * @return 0 on success, -1 on failure
 */
int bt_str_to_addr(const char *str, uint8_t *bdaddr);

/**
 * Set transport callbacks
 * @param transport Transport context
 * @param on_discovered Device discovered callback
 * @param on_connected Device connected callback
 * @param on_disconnected Device disconnected callback
 * @param on_data Data received callback
 * @param user_data User data passed to callbacks
 */
void bt_set_callbacks(struct bt_transport *transport,
                      void (*on_discovered)(struct bt_transport*, struct bt_device_info*, void*),
                      void (*on_connected)(struct bt_transport*, struct bt_device_info*, void*),
                      void (*on_disconnected)(struct bt_transport*, struct bt_device_info*, void*),
                      void (*on_data)(struct bt_transport*, struct bt_device_info*, const uint8_t*, size_t, void*),
                      void *user_data);

#endif // LOCALNET_BLUETOOTH_TRANSPORT_H

