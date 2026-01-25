#ifndef LOCALNET_BLUETOOTH_H
#define LOCALNET_BLUETOOTH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <glib.h>
#include "adapter.h"
#include "device.h"
#include "logger.h"
#include "agent.h"
#include "application.h"
#include "advertisement.h"
#include "characteristic.h"
#include "routing.h"
#include "protocol.h"

#define BT_TAG "LocalNet-BT"
#define LOCAL_NET_SERVICE_UUID "00001234-0000-1000-8000-00805f9b34fb"
#define LOCAL_NET_DATA_CHAR_UUID "00001235-0000-1000-8000-00805f9b34fb"
#define LOCAL_NET_CTRL_CHAR_UUID "00001236-0000-1000-8000-00805f9b34fb"
#define MAX_BLE_PAYLOAD_SIZE 512
#define LOCAL_NET_DEVICE_PREFIX "LocalNet-"
#define DISCOVERY_SCAN_INTERVAL_MS 30000
#define RECONNECT_ATTEMPT_INTERVAL_MS 10000
#define CONNECTION_RETRY_COOLDOWN_MS 15000   /* Wait 15 seconds before retrying a failed connection */
#define MAX_DISCOVERED_DEVICES 32
#define MAX_INCOMING_CLIENTS 16

/* BLE Connection State */
typedef enum {
    BLE_STATE_IDLE = 0,
    BLE_STATE_SCANNING,
    BLE_STATE_CONNECTING,
    BLE_STATE_CONNECTED,
    BLE_STATE_DISCONNECTING
} ble_state_t;

/* Discovered device entry */
typedef struct {
    Device *device;
    uint32_t device_id;
    char address[18];          /* MAC address string */
    int8_t rssi;
    uint32_t last_seen;
    uint32_t last_connect_attempt;  /* Timestamp of last connection attempt */
    gboolean is_connected;
    gboolean connection_pending;
} discovered_device_t;

/* Incoming client entry - tracks devices that connected to our GATT server */
typedef struct {
    Device *device;            /* Device object for tracking disconnection */
    char address[18];          /* MAC address string */
    uint32_t device_id;        /* Derived device ID */
    uint32_t last_seen;        /* Last activity timestamp */
    gboolean is_connected;     /* Connection state */
} incoming_client_t;

/* Callback function types */
typedef void (*on_data_received_cb)(uint32_t sender_id, const uint8_t *data, size_t len);
typedef void (*on_node_connected_cb)(uint32_t node_id);
typedef void (*on_node_disconnected_cb)(uint32_t node_id);
typedef void (*on_node_discovered_cb)(uint32_t node_id, int8_t rssi);

/* BLE Node Manager - central structure for managing BLE mesh operations */
typedef struct {
    Adapter *adapter;
    Agent *agent;
    Application *app;
    Advertisement *advertisement;
    GMainLoop *main_loop;
    GDBusConnection *dbus_connection;

    struct mesh_node *mesh_node;

    /* Discovered devices (outgoing connections) */
    discovered_device_t discovered_devices[MAX_DISCOVERED_DEVICES];
    size_t discovered_count;

    /* Incoming clients (devices connected to our GATT server) */
    incoming_client_t incoming_clients[MAX_INCOMING_CLIENTS];
    size_t incoming_count;

    /* State */
    ble_state_t state;
    gboolean advertising;
    gboolean scanning;
    gboolean running;

    /* Callbacks */
    on_data_received_cb data_callback;
    on_node_connected_cb connected_callback;
    on_node_disconnected_cb disconnected_callback;
    on_node_discovered_cb discovered_callback;

    /* Timers */
    guint discovery_timer_id;
    guint reconnect_timer_id;
    guint heartbeat_timer_id;
} ble_node_manager_t;

/* Initialization and cleanup */
ble_node_manager_t *ble_init(uint32_t device_id, enum NODE_TYPE node_type);
void ble_cleanup(ble_node_manager_t *manager);
int ble_start(ble_node_manager_t *manager);
void ble_stop(ble_node_manager_t *manager);

/* Node discovery */
int ble_start_discovery(ble_node_manager_t *manager);
void ble_stop_discovery(ble_node_manager_t *manager);
int ble_is_discovering(const ble_node_manager_t *manager);

/* Advertising (peripheral mode) */
int ble_start_advertising(ble_node_manager_t *manager);
void ble_stop_advertising(ble_node_manager_t *manager);
int ble_is_advertising(const ble_node_manager_t *manager);

/* Connection management */
int ble_connect_to_node(ble_node_manager_t *manager, uint32_t device_id);
int ble_disconnect_from_node(ble_node_manager_t *manager, uint32_t device_id);
int ble_get_connected_count(ble_node_manager_t *manager);

/* Data transmission */
int ble_send_data(ble_node_manager_t *manager, uint32_t dest_id, const uint8_t *data, size_t len);
int ble_broadcast_data(ble_node_manager_t *manager, const uint8_t *data, size_t len);

/* Callback registration */
void ble_set_data_callback(ble_node_manager_t *manager, on_data_received_cb callback);
void ble_set_connected_callback(ble_node_manager_t *manager, on_node_connected_cb callback);
void ble_set_disconnected_callback(ble_node_manager_t *manager, on_node_disconnected_cb callback);
void ble_set_discovered_callback(ble_node_manager_t *manager, on_node_discovered_cb callback);

/* Utility functions */
uint32_t ble_extract_device_id(const char *device_name);
uint32_t ble_mac_to_device_id(const char *mac);
char *ble_generate_device_name(uint32_t device_id);
discovered_device_t *ble_find_discovered_device(ble_node_manager_t *manager, uint32_t device_id);
discovered_device_t *ble_find_device_by_ptr(ble_node_manager_t *manager, Device *device);
incoming_client_t *ble_find_or_add_incoming_client(ble_node_manager_t *manager, const char *address);
int ble_get_adapter_address(char *address, size_t len);

/* Connection info for display */
void ble_print_connection_table(ble_node_manager_t *manager);

/* Main loop integration */
GMainLoop *ble_get_main_loop(const ble_node_manager_t *manager);
void ble_run_main_loop(const ble_node_manager_t *manager);
void ble_quit_main_loop(const ble_node_manager_t *manager);

#endif //LOCALNET_BLUETOOTH_H

