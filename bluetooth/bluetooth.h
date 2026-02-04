#ifndef LOCALNET_BLUETOOTH_H
#define LOCALNET_BLUETOOTH_H

#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include "device.h"
#include "agent.h"

struct mesh_node;

#define LOCAL_NET_SERVICE_UUID "00001234-0000-1000-8000-00805f9b34fb"
#define LOCAL_NET_DATA_CHAR_UUID "00001235-0000-1000-8000-00805f9b34fb"
#define LOCAL_NET_CTRL_CHAR_UUID "00001236-0000-1000-8000-00805f9b34fb"
#define BT_TAG "LOCALNET-BT"
#define LOCALNET_PREFIX "LOCALNET-"
#define HEARTBEAT_TIMEOUT_SECONDS 30
#define RECONNECT_DELAY_MS 5000
#define PROTOCOL_VERSION 1
#define MAX_BLE_PAYLOAD_SIZE 512
#define MAX_DISCOVERED_DEVICES 32
#define MAX_NAME_SIZE 32

typedef void (*ble_discovered_callback)(uint32_t node_id, int16_t rssi);
typedef void (*ble_connected_callback)(uint32_t node_id);
typedef void (*ble_disconnected_callback)(uint32_t node_id);
typedef void (*ble_data_callback)(uint32_t sender_id, const uint8_t *data, size_t len);

// Connected Device Entry (Binc)
typedef struct {
    uint32_t device_id;
    char mac_address[18];
    Device *device;
    gboolean is_connected;
    gboolean we_initiated;
    int16_t rssi;
    uint64_t last_heartbeat;
    uint64_t last_seen;
} tracked_device_t;

// BLE Node Manager
typedef struct ble_node_manager {
    Adapter *adapter;
    Agent *agent;
    Application *app;
    Advertisement *advertisement;
    GMainLoop *loop;
    GDBusConnection *dbus_connection;

    struct mesh_node *mesh_node;
    uint32_t device_id;
    char local_name[MAX_NAME_SIZE];

    // Tracked devices
    tracked_device_t *discovered_devices;
    guint discovered_count;

    gboolean running;

    ble_data_callback data_callback;
    ble_connected_callback connected_callback;
    ble_disconnected_callback disconnected_callback;
    ble_discovered_callback discovered_callback;

    guint heartbeat_source;
} ble_node_manager_t;

// Initialization and cleanup
ble_node_manager_t *ble_init(struct mesh_node *mesh_node, uint32_t device_id, ble_discovered_callback discovered_cb, ble_connected_callback connected_cb, ble_disconnected_callback disconnected_cb, ble_data_callback data_cb);
gboolean ble_start(ble_node_manager_t *manager);
void ble_stop(ble_node_manager_t *manager);
void ble_cleanup(ble_node_manager_t *manager);

// Main loop
void ble_run_loop(ble_node_manager_t *manager);
void ble_quit_loop(ble_node_manager_t *manager);

// Data transmission
gboolean ble_send_data(ble_node_manager_t *manager, uint32_t dest_id, const uint8_t *data, size_t len);
gboolean ble_broadcast_data(ble_node_manager_t *manager, const uint8_t *data, size_t len);

// Connection info
guint ble_get_connected_count(ble_node_manager_t *manager);
void ble_get_connection_table(ble_node_manager_t *manager, uint32_t *devices, guint *count, guint max_count);
void ble_print_connection_table(ble_node_manager_t *manager);

// Route discovery callbacks
typedef void (*ble_route_found_callback)(uint32_t destination_id, uint32_t next_hop, uint8_t hop_count);
typedef void (*ble_route_failed_callback)(uint32_t destination_id);

/**
 * Initiate route discovery for a destination
 * Returns request_id on success, 0 on failure
 */
uint32_t ble_initiate_route_discovery(ble_node_manager_t *manager, uint32_t destination_id);

/**
 * Send a route request to all connected neighbors
 */
gboolean ble_broadcast_route_request(ble_node_manager_t *manager, uint32_t request_id,
                                     uint32_t destination_id, uint8_t hop_count,
                                     const uint32_t *reverse_path, uint8_t reverse_path_len,
                                     uint32_t exclude_id);

/**
 * Send a route reply to a specific neighbor
 */
gboolean ble_send_route_reply(ble_node_manager_t *manager, uint32_t target_id,
                              uint32_t request_id, uint8_t route_cost,
                              const uint32_t *forward_path, uint8_t forward_path_len);

#endif // LOCALNET_BLUETOOTH_H
