/**
 * LocalNet Bluetooth Module
 *
 * This module handles BLE communication for the LocalNet mesh network.
 * Each device operates as both a GATT server and client, capable of:
 * - Advertising its presence
 * - Scanning for other LocalNet devices
 * - Connecting to multiple peers simultaneously
 *
 * Pairing uses the "Just Works" method (no PIN required).
 */

#include "bluetooth.h"
#include <string.h>
#include <stdlib.h>
#include "application.h"
#include "advertisement.h"
#include "characteristic.h"
#include "adapter.h"
#include "logger.h"
#include "protocol.h"
#include "routing.h"
#include "utils.h"

/* ============================================================================
 * Module State
 * ========================================================================== */

static ble_node_manager_t *g_manager = NULL;

/* ============================================================================
 * Forward Declarations
 * ========================================================================== */

/* Adapter callbacks */
static void on_scan_result(Adapter *adapter, Device *device);
static void on_discovery_state_changed(Adapter *adapter, DiscoveryState state, const GError *error);
static void on_remote_central_connected(Adapter *adapter, Device *device);

/* Device callbacks */
static void on_connection_state_changed(Device *device, ConnectionState state, const GError *error);
static void on_services_resolved(Device *device);
static void on_notify(Device *device, Characteristic *characteristic, const GByteArray *byteArray);
static void on_write_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error);

/* Agent callback */
static gboolean on_request_authorization(Device *device);

/* Application callbacks */
static const char *on_local_char_read(const Application *app, const char *address, const char *service_uuid, const char *char_uuid, guint16 offset, guint16 mtu);
static const char *on_local_char_write(const Application *app, const char *address, const char *service_uuid, const char *char_uuid, GByteArray *byteArray, guint16 offset, guint16 mtu);

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

static uint32_t extract_device_id_from_name(const char *name) {
    if (!name) return 0;
    if (g_str_has_prefix(name, LOCALNET_PREFIX)) {
        const char *hex = name + strlen(LOCALNET_PREFIX);
        return (uint32_t)strtoul(hex, NULL, 16);
    }
    return 0;
}

static gboolean is_localnet_device(const char *name) {
    return name && g_str_has_prefix(name, LOCALNET_PREFIX);
}

/* ============================================================================
 * Device Tracking
 * ========================================================================== */

static tracked_device_t *find_device_by_id(uint32_t device_id) {
    if (!g_manager || device_id == 0) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].device_id == device_id) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t *find_device_by_mac(const char *mac) {
    if (!g_manager || !mac) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_str_equal(g_manager->discovered_devices[i].mac_address, mac)) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t *find_device_by_ptr(Device *device) {
    if (!g_manager || !device) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].device == device) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t *add_or_update_device(uint32_t device_id, const char *mac, Device *device) {
    if (!g_manager) return NULL;

    /* Check if device already exists */
    tracked_device_t *tracked = NULL;
    if (device_id != 0) {
        tracked = find_device_by_id(device_id);
    }
    if (!tracked && mac) {
        tracked = find_device_by_mac(mac);
    }

    if (tracked) {
        /* Update existing entry - always update device pointer if provided */
        if (device) {
            tracked->device = device;
        }
        if (mac && mac[0] != '\0') {
            strncpy(tracked->mac_address, mac, sizeof(tracked->mac_address) - 1);
            tracked->mac_address[sizeof(tracked->mac_address) - 1] = '\0';
        }
        if (device_id != 0) {
            tracked->device_id = device_id;
        }
        tracked->last_seen = get_current_timestamp();
        return tracked;
    }

    /* Add new device */
    if (g_manager->discovered_count >= MAX_DISCOVERED_DEVICES) {
        log_error(BT_TAG, "Device table full, cannot add new device");
        return NULL;
    }

    tracked = &g_manager->discovered_devices[g_manager->discovered_count++];
    memset(tracked, 0, sizeof(*tracked));
    tracked->device_id = device_id;
    tracked->device = device;
    if (mac) {
        strncpy(tracked->mac_address, mac, sizeof(tracked->mac_address) - 1);
        tracked->mac_address[sizeof(tracked->mac_address) - 1] = '\0';
    }
    tracked->last_seen = get_current_timestamp();
    tracked->last_heartbeat = get_current_timestamp();

    return tracked;
}

static guint count_connected(void) {
    if (!g_manager) return 0;
    guint count = 0;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].is_connected) count++;
    }
    return count;
}

/* ============================================================================
 * Advertising Control
 * ========================================================================== */

static void start_advertising(void) {
    if (!g_manager || !g_manager->adapter) return;

    /* Stop existing advertisement if any */
    if (g_manager->advertisement) {
        binc_adapter_stop_advertising(g_manager->adapter, g_manager->advertisement);
        binc_advertisement_free(g_manager->advertisement);
        g_manager->advertisement = NULL;
    }

    /* Create new advertisement */
    g_manager->advertisement = binc_advertisement_create();
    binc_advertisement_set_local_name(g_manager->advertisement, g_manager->local_name);

    GPtrArray *services = g_ptr_array_new();
    g_ptr_array_add(services, LOCAL_NET_SERVICE_UUID);
    binc_advertisement_set_services(g_manager->advertisement, services);
    g_ptr_array_free(services, TRUE);

    binc_adapter_start_advertising(g_manager->adapter, g_manager->advertisement);
    log_debug(BT_TAG, "Started advertising as %s", g_manager->local_name);
}

static void stop_advertising(void) {
    if (!g_manager || !g_manager->adapter || !g_manager->advertisement) return;
    binc_adapter_stop_advertising(g_manager->adapter, g_manager->advertisement);
    log_debug(BT_TAG, "Stopped advertising");
}

/* ============================================================================
 * Discovery Control
 * ========================================================================== */

static void start_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    binc_adapter_set_discovery_filter(g_manager->adapter, -100, NULL, NULL);
    binc_adapter_start_discovery(g_manager->adapter);
    log_debug(BT_TAG, "Started discovery");
}

static void stop_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    binc_adapter_stop_discovery(g_manager->adapter);
    log_debug(BT_TAG, "Stopped discovery");
}

/* ============================================================================
 * Connection Management
 * ========================================================================== */

static void connect_to_device(tracked_device_t *tracked) {
    if (!g_manager || !tracked || !tracked->device) return;
    if (tracked->is_connected || tracked->is_connecting) return;

    /* Implement connection backoff - don't retry too quickly */
    uint64_t now = get_current_timestamp();
    uint64_t backoff_seconds = (tracked->connection_attempts < 5) ?
                               (tracked->connection_attempts * 2 + 1) : 10;

    if (tracked->last_connect_attempt != 0 &&
        (now - tracked->last_connect_attempt) < backoff_seconds) {
        return;
    }

    log_info(BT_TAG, "Initiating connection to 0x%08X (attempt %u)",
             tracked->device_id, tracked->connection_attempts + 1);

    /* Set up device callbacks */
    binc_device_set_connection_state_change_cb(tracked->device, &on_connection_state_changed);
    binc_device_set_services_resolved_cb(tracked->device, &on_services_resolved);
    binc_device_set_notify_char_cb(tracked->device, &on_notify);
    binc_device_set_write_char_cb(tracked->device, &on_write_characteristic);

    tracked->we_initiated = TRUE;
    tracked->is_connecting = TRUE;
    tracked->last_connect_attempt = now;
    tracked->connection_attempts++;

    binc_device_connect(tracked->device);
}

/* ============================================================================
 * Message Handling
 * ========================================================================== */

static void process_received_data(uint32_t sender_id, const uint8_t *data, size_t len, tracked_device_t *tracked) {
    (void)sender_id;
    if (!data || len == 0) return;

    /* Update heartbeat timestamp */
    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
    }

    /* Parse packet header */
    struct header header;
    if (parse_header(data, len, &header) != 0) {
        log_error(BT_TAG, "Failed to parse packet header");
        return;
    }

    /* Parse network header */
    struct network network;
    if (len < 16 || parse_network(data + 8, len - 8, &network) != 0) {
        log_error(BT_TAG, "Failed to parse network header");
        return;
    }

    if (header.message_type == MSG_HEARTBEAT) {
        struct heartbeat heartbeat;
        if (parse_heartbeat(data + 16, len - 16, &heartbeat) == 0) {
            log_debug(BT_TAG, "Heartbeat from 0x%08X (status: %u, connections: %u)",
                     network.source_id, heartbeat.device_status, heartbeat.active_connection_number);

            /* Update device ID if we didn't know it */
            if (tracked && tracked->device_id == 0 && network.source_id != 0) {
                tracked->device_id = network.source_id;
            }

            /* Update mesh node connection info */
            if (g_manager->mesh_node && g_manager->mesh_node->connection_table) {
                reset_missed_heartbeats(g_manager->mesh_node->connection_table, network.source_id);
                update_last_seen(g_manager->mesh_node->connection_table, network.source_id, heartbeat.timestamp);
            }
        }
    } else if (g_manager->data_callback) {
        g_manager->data_callback(network.source_id, data, len);
    }
}

/* ============================================================================
 * Heartbeat
 * ========================================================================== */

static gboolean heartbeat_callback(gpointer user_data) {
    (void)user_data;

    if (!g_manager || !g_manager->running) return FALSE;

    uint32_t now = get_current_timestamp();

    /* Check for heartbeat timeouts */
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t *tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected) continue;

        if (now - tracked->last_heartbeat > HEARTBEAT_TIMEOUT_SECONDS) {
            log_info(BT_TAG, "Heartbeat timeout for 0x%08X, disconnecting", tracked->device_id);
            tracked->is_connected = FALSE;

            if (tracked->device && tracked->we_initiated) {
                binc_device_disconnect(tracked->device);
            }

            if (g_manager->disconnected_callback) {
                g_manager->disconnected_callback(tracked->device_id);
            }
        }
    }

    /* Build heartbeat message */
    struct heartbeat hb = {
        .device_status = 0x01,
        .active_connection_number = (uint8_t)count_connected(),
        .timestamp = now
    };

    struct header header = {
        .protocol_version = PROTOCOL_VERSION,
        .message_type = MSG_HEARTBEAT,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = 1,
        .payload_length = sizeof(struct heartbeat),
        .sequence_number = 0
    };

    struct network network = {
        .source_id = g_manager->device_id,
        .destination_id = 0  /* Broadcast */
    };

    /* Serialize heartbeat payload */
    uint8_t payload[16];
    size_t payload_len = serialize_heartbeat(&hb, payload, sizeof(payload));
    if (payload_len == 0) {
        log_error(BT_TAG, "Failed to serialize heartbeat");
        return TRUE;
    }

    /* Create and serialize packet */
    struct packet packet = {
        .header = &header,
        .network = &network,
        .payload = payload,
        .security = NULL
    };

    uint8_t buffer[64];
    size_t len = serialize_packet(&packet, buffer, sizeof(buffer));
    if (len == 0) {
        log_error(BT_TAG, "Failed to serialize heartbeat packet");
        return TRUE;
    }

    guint sent_count = 0;

    /* Send to devices we connected to (as client) */
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t *tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected || !tracked->we_initiated || !tracked->device) continue;

        Characteristic *chr = binc_device_get_characteristic(tracked->device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
        if (chr) {
            GByteArray *data = g_byte_array_sized_new((guint)len);
            g_byte_array_append(data, buffer, (guint)len);
            binc_characteristic_write(chr, data, WITH_RESPONSE);
            g_byte_array_free(data, TRUE);
            sent_count++;
        }
    }

    /* Send to devices that connected to us (as server) via notification */
    gboolean has_incoming = FALSE;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t *tracked = &g_manager->discovered_devices[i];
        if (tracked->is_connected && !tracked->we_initiated) {
            has_incoming = TRUE;
            break;
        }
    }

    if (has_incoming && g_manager->app) {
        GByteArray *data = g_byte_array_sized_new((guint)len);
        g_byte_array_append(data, buffer, (guint)len);
        binc_application_set_char_value(g_manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, data);
        binc_application_notify(g_manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, data);
        g_byte_array_free(data, TRUE);
        sent_count++;
    }

    log_debug(BT_TAG, "Heartbeat sent to %u connections", sent_count);
    return TRUE;
}

/* ============================================================================
 * Adapter Callbacks
 * ========================================================================== */

static void on_discovery_state_changed(Adapter *adapter, DiscoveryState state, const GError *error) {
    (void)adapter;
    (void)error;

    const char *state_str = "UNKNOWN";
    switch (state) {
        case BINC_DISCOVERY_STARTING: state_str = "STARTING"; break;
        case BINC_DISCOVERY_STARTED:  state_str = "STARTED";  break;
        case BINC_DISCOVERY_STOPPING: state_str = "STOPPING"; break;
        case BINC_DISCOVERY_STOPPED:  state_str = "STOPPED";  break;
    }
    log_debug(BT_TAG, "Discovery state: %s", state_str);
}

static void on_scan_result(Adapter *adapter, Device *device) {
    (void)adapter;
    if (!g_manager || !device) return;

    const char *name = binc_device_get_name(device);
    const char *mac = binc_device_get_address(device);

    if (!is_localnet_device(name)) return;

    uint32_t device_id = extract_device_id_from_name(name);
    if (device_id == 0 || device_id == g_manager->device_id) return;

    int16_t rssi = binc_device_get_rssi(device);

    /* Check if already connected or connecting */
    tracked_device_t *tracked = find_device_by_id(device_id);
    if (tracked) {
        /* Always update the device pointer and RSSI */
        tracked->device = device;
        tracked->rssi = rssi;
        tracked->last_seen = get_current_timestamp();

        if (tracked->is_connected || tracked->is_connecting) {
            return;
        }
    } else {
        log_info(BT_TAG, "Discovered 0x%08X (RSSI: %d dBm)", device_id, rssi);

        /* Add new device */
        tracked = add_or_update_device(device_id, mac, device);
        if (!tracked) return;
        tracked->rssi = rssi;

        /* Notify discovery callback */
        if (g_manager->discovered_callback) {
            g_manager->discovered_callback(device_id, rssi);
        }
    }

    /*
     * Connection decision: lower device ID initiates connection.
     * This prevents both devices trying to connect simultaneously.
     */
    if (g_manager->device_id < device_id) {
        connect_to_device(tracked);
    }
}

static void on_remote_central_connected(Adapter *adapter, Device *device) {
    (void)adapter;
    if (!g_manager || !device) return;

    const char *name = binc_device_get_name(device);
    const char *mac = binc_device_get_address(device);

    uint32_t device_id = 0;
    if (is_localnet_device(name)) {
        device_id = extract_device_id_from_name(name);
    } else {
        device_id = mac_to_device_id(mac);
    }

    log_info(BT_TAG, "Remote central connected: %s (%s)", name ? name : "unknown", mac);

    /* Track device */
    tracked_device_t *tracked = add_or_update_device(device_id, mac, device);
    if (!tracked) return;

    tracked->is_connected = TRUE;
    tracked->we_initiated = FALSE;
    tracked->last_heartbeat = get_current_timestamp();

    binc_device_set_connection_state_change_cb(device, &on_connection_state_changed);

    if (device_id != 0) {
        log_info(BT_TAG, "Incoming connection from 0x%08X", device_id);
        if (g_manager->connected_callback) {
            g_manager->connected_callback(device_id);
        }
    }
}

/* ============================================================================
 * Device Callbacks
 * ========================================================================== */

static void on_connection_state_changed(Device *device, ConnectionState state, const GError *error) {
    if (!g_manager || !device) return;

    tracked_device_t *tracked = find_device_by_ptr(device);
    if (!tracked) {
        tracked = find_device_by_mac(binc_device_get_address(device));
    }

    uint32_t device_id = tracked ? tracked->device_id : 0;
    const char *state_name = binc_device_get_connection_state_name(device);

    if (error) {
        log_error(BT_TAG, "Connection error for 0x%08X: %s", device_id, error->message);
    }

    log_debug(BT_TAG, "Connection state 0x%08X: %s", device_id, state_name);

    switch (state) {
        case BINC_CONNECTED:
            log_debug(BT_TAG, "Device 0x%08X connected, waiting for services", device_id);
            /* Note: is_connected will be set in on_services_resolved for outgoing connections */
            break;

        case BINC_CONNECTING:
            if (tracked) {
                tracked->is_connecting = TRUE;
            }
            break;

        case BINC_DISCONNECTING:
            break;

        case BINC_DISCONNECTED: {
            log_info(BT_TAG, "Device 0x%08X disconnected", device_id);
            gboolean was_connected = FALSE;
            gboolean was_connecting = FALSE;

            if (tracked) {
                was_connected = tracked->is_connected;
                was_connecting = tracked->is_connecting;
                tracked->is_connected = FALSE;
                tracked->is_connecting = FALSE;

                if (was_connected && g_manager->disconnected_callback) {
                    g_manager->disconnected_callback(device_id);
                }
            }

            /*
             * Handle removal of device from BlueZ cache.
             * If we were connecting (not yet fully connected) and have failed
             * multiple times, consider removing the bonded device to clear
             * potentially stale bonding info.
             */
            BondingState bonding = binc_device_get_bonding_state(device);
            gboolean should_remove = FALSE;

            if (bonding != BINC_BONDED) {
                should_remove = TRUE;
            } else if (was_connecting && !was_connected && tracked &&
                       tracked->connection_attempts >= 3) {
                /* Bonded but failed to connect 3+ times - might be stale bond */
                log_info(BT_TAG, "Removing stale bond for 0x%08X after %u failed attempts",
                        device_id, tracked->connection_attempts);
                should_remove = TRUE;
            }

            if (should_remove) {
                log_debug(BT_TAG, "Removing device 0x%08X from cache", device_id);
                binc_adapter_remove_device(g_manager->adapter, device);
                if (tracked) {
                    tracked->device = NULL;
                }
            }
            break;
        }
    }
}

static void on_services_resolved(Device *device) {
    if (!g_manager || !device) return;

    tracked_device_t *tracked = find_device_by_ptr(device);
    if (!tracked) {
        tracked = find_device_by_mac(binc_device_get_address(device));
    }
    if (!tracked) {
        log_error(BT_TAG, "Services resolved for unknown device");
        return;
    }

    log_debug(BT_TAG, "Services resolved for 0x%08X", tracked->device_id);

    tracked->is_connected = TRUE;
    tracked->is_connecting = FALSE;
    tracked->connection_attempts = 0;  /* Reset on successful connection */
    tracked->last_heartbeat = get_current_timestamp();

    /* Subscribe to notifications on the data characteristic */
    Characteristic *chr = binc_device_get_characteristic(device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
    if (chr) {
        log_debug(BT_TAG, "Subscribing to notifications for 0x%08X", tracked->device_id);
        binc_characteristic_start_notify(chr);
    } else {
        log_error(BT_TAG, "Data characteristic not found for 0x%08X", tracked->device_id);
    }

    log_info(BT_TAG, "Connected to 0x%08X", tracked->device_id);

    if (g_manager->connected_callback) {
        g_manager->connected_callback(tracked->device_id);
    }
}

static void on_notify(Device *device, Characteristic *characteristic, const GByteArray *byteArray) {
    (void)characteristic;
    if (!g_manager || !byteArray || byteArray->len == 0) return;

    tracked_device_t *tracked = find_device_by_ptr(device);
    uint32_t sender_id = tracked ? tracked->device_id : 0;

    process_received_data(sender_id, byteArray->data, byteArray->len, tracked);
}

static void on_write_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error) {
    (void)characteristic;
    (void)byteArray;

    if (error) {
        tracked_device_t *tracked = find_device_by_ptr(device);
        log_error(BT_TAG, "Write error for 0x%08X: %s",
                 tracked ? tracked->device_id : 0, error->message);
    }
}

/* ============================================================================
 * Agent Callback (Just Works Pairing)
 * ========================================================================== */

static gboolean on_request_authorization(Device *device) {
    const char *name = binc_device_get_name(device);
    log_debug(BT_TAG, "Authorizing device: %s", name ? name : "unknown");
    return TRUE;  /* Always authorize for Just Works */
}

/* ============================================================================
 * Application Callbacks (GATT Server)
 * ========================================================================== */

static const char *on_local_char_read(const Application *app, const char *address,
                                       const char *service_uuid, const char *char_uuid,
                                       guint16 offset, guint16 mtu) {
    (void)address;
    (void)offset;
    (void)mtu;

    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID) &&
        g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
        /* Return empty data for reads */
        GByteArray *empty = g_byte_array_new();
        binc_application_set_char_value(app, service_uuid, char_uuid, empty);
        g_byte_array_free(empty, TRUE);
        return NULL;
    }

    return BLUEZ_ERROR_REJECTED;
}

static const char *on_local_char_write(const Application *app, const char *address,
                                        const char *service_uuid, const char *char_uuid,
                                        GByteArray *byteArray, guint16 offset, guint16 mtu) {
    (void)app;
    (void)offset;
    (void)mtu;

    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (!g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID) ||
        !g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
        return BLUEZ_ERROR_REJECTED;
    }

    if (!byteArray || byteArray->len == 0) return NULL;

    /* Find or create tracked device */
    tracked_device_t *tracked = find_device_by_mac(address);
    uint32_t device_id = tracked ? tracked->device_id : mac_to_device_id(address);

    if (!tracked) {
        tracked = add_or_update_device(device_id, address, NULL);
    }

    if (tracked) {
        tracked->is_connected = TRUE;
        tracked->last_heartbeat = get_current_timestamp();
    }

    log_debug(BT_TAG, "Received %u bytes from %s", byteArray->len, address);

    process_received_data(device_id, byteArray->data, byteArray->len, tracked);

    return NULL;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

ble_node_manager_t *ble_init(struct mesh_node *mesh_node, uint32_t device_id,
                              ble_discovered_callback discovered_cb,
                              ble_connected_callback connected_cb,
                              ble_disconnected_callback disconnected_cb,
                              ble_data_callback data_cb) {
    ble_node_manager_t *manager = g_new0(ble_node_manager_t, 1);

    manager->mesh_node = mesh_node;
    manager->device_id = device_id;
    manager->discovered_callback = discovered_cb;
    manager->connected_callback = connected_cb;
    manager->disconnected_callback = disconnected_cb;
    manager->data_callback = data_cb;

    snprintf(manager->local_name, sizeof(manager->local_name), LOCALNET_PREFIX "%08X", device_id);

    manager->discovered_devices = g_new0(tracked_device_t, MAX_DISCOVERED_DEVICES);
    manager->discovered_count = 0;

    g_manager = manager;
    log_debug(BT_TAG, "Initialized for device 0x%08X", device_id);

    return manager;
}

gboolean ble_start(ble_node_manager_t *manager) {
    if (!manager) return FALSE;

    log_debug(BT_TAG, "Starting BLE subsystem");

    /* Get D-Bus connection */
    GDBusConnection *dbus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (!dbus) {
        log_error(BT_TAG, "Failed to get D-Bus connection");
        return FALSE;
    }
    manager->dbus_connection = dbus;

    /* Get default adapter */
    manager->adapter = binc_adapter_get_default(dbus);
    if (!manager->adapter) {
        log_error(BT_TAG, "No Bluetooth adapter found");
        return FALSE;
    }
    log_info(BT_TAG, "Using adapter: %s", binc_adapter_get_name(manager->adapter));

    /* Create agent for Just Works pairing */
    manager->agent = binc_agent_create(manager->adapter, "/org/bluez/LocalNetAgent", NO_INPUT_NO_OUTPUT);
    binc_agent_set_request_authorization_cb(manager->agent, &on_request_authorization);

    /* Setup GATT application (server) */
    manager->app = binc_create_application(manager->adapter);
    binc_application_add_service(manager->app, LOCAL_NET_SERVICE_UUID);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID,
                                        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_NOTIFY);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_CTRL_CHAR_UUID,
                                        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE);
    binc_application_set_char_read_cb(manager->app, &on_local_char_read);
    binc_application_set_char_write_cb(manager->app, &on_local_char_write);
    binc_adapter_register_application(manager->adapter, manager->app);

    /* Setup adapter callbacks */
    binc_adapter_set_discovery_cb(manager->adapter, &on_scan_result);
    binc_adapter_set_discovery_state_cb(manager->adapter, &on_discovery_state_changed);
    binc_adapter_set_remote_central_cb(manager->adapter, &on_remote_central_connected);

    manager->running = TRUE;

    /* Start advertising and scanning */
    start_advertising();
    start_discovery();

    log_info(BT_TAG, "BLE subsystem started");
    return TRUE;
}

void ble_stop(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Stopping BLE subsystem");
    manager->running = FALSE;

    stop_discovery();
    stop_advertising();

    /* Disconnect all outgoing connections */
    for (guint i = 0; i < manager->discovered_count; i++) {
        tracked_device_t *tracked = &manager->discovered_devices[i];
        if (tracked->is_connected && tracked->device && tracked->we_initiated) {
            binc_device_disconnect(tracked->device);
        }
    }

    if (manager->advertisement) {
        binc_advertisement_free(manager->advertisement);
        manager->advertisement = NULL;
    }

    if (manager->app) {
        binc_application_free(manager->app);
        manager->app = NULL;
    }

    if (manager->agent) {
        binc_agent_free(manager->agent);
        manager->agent = NULL;
    }

    if (manager->adapter) {
        binc_adapter_free(manager->adapter);
        manager->adapter = NULL;
    }

    if (manager->dbus_connection) {
        g_dbus_connection_close_sync(manager->dbus_connection, NULL, NULL);
        g_object_unref(manager->dbus_connection);
        manager->dbus_connection = NULL;
    }
}

void ble_cleanup(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Cleaning up BLE subsystem");
    ble_stop(manager);

    g_free(manager->discovered_devices);
    g_free(manager);

    if (g_manager == manager) {
        g_manager = NULL;
    }
}

void ble_run_loop(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Starting main loop");

    manager->loop = g_main_loop_new(NULL, FALSE);

    /* Schedule heartbeat timer */
    manager->heartbeat_source = g_timeout_add_seconds(HEARTBEAT_INTERVAL_SECONDS, heartbeat_callback, NULL);

    g_main_loop_run(manager->loop);

    /* Cleanup timer */
    if (manager->heartbeat_source) {
        g_source_remove(manager->heartbeat_source);
        manager->heartbeat_source = 0;
    }

    g_main_loop_unref(manager->loop);
    manager->loop = NULL;
}

void ble_quit_loop(ble_node_manager_t *manager) {
    if (!manager || !manager->loop) return;

    log_debug(BT_TAG, "Stopping main loop");
    g_main_loop_quit(manager->loop);
}

gboolean ble_send_data(ble_node_manager_t *manager, uint32_t target_id, const uint8_t *data, size_t len) {
    if (!manager || !data || len == 0) return FALSE;

    tracked_device_t *tracked = find_device_by_id(target_id);
    if (!tracked || !tracked->is_connected) {
        return FALSE;
    }

    GByteArray *byte_array = g_byte_array_sized_new((guint)len);
    g_byte_array_append(byte_array, data, (guint)len);

    gboolean success = FALSE;

    if (tracked->we_initiated && tracked->device) {
        /* We connected to them - write to their characteristic */
        Characteristic *chr = binc_device_get_characteristic(tracked->device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
        if (chr) {
            binc_characteristic_write(chr, byte_array, WITH_RESPONSE);
            success = TRUE;
        }
    } else if (manager->app) {
        /* They connected to us - notify via our characteristic */
        binc_application_set_char_value(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, byte_array);
        binc_application_notify(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, byte_array);
        success = TRUE;
    }

    g_byte_array_free(byte_array, TRUE);
    return success;
}

gboolean ble_broadcast_data(ble_node_manager_t *manager, const uint8_t *data, size_t len) {
    if (!manager || !data || len == 0) return FALSE;

    gboolean sent_any = FALSE;
    for (guint i = 0; i < manager->discovered_count; i++) {
        tracked_device_t *tracked = &manager->discovered_devices[i];
        if (tracked->is_connected) {
            if (ble_send_data(manager, tracked->device_id, data, len)) {
                sent_any = TRUE;
            }
        }
    }
    return sent_any;
}

guint ble_get_connected_count(ble_node_manager_t *manager) {
    if (!manager) return 0;
    return count_connected();
}

void ble_get_connection_table(ble_node_manager_t *manager, uint32_t *devices, guint *count, guint max_count) {
    if (!manager || !devices || !count) return;

    *count = 0;
    for (guint i = 0; i < manager->discovered_count && *count < max_count; i++) {
        if (manager->discovered_devices[i].is_connected) {
            devices[(*count)++] = manager->discovered_devices[i].device_id;
        }
    }
}

void ble_print_connection_table(ble_node_manager_t *manager) {
    if (!manager) return;

    printf("\n");
    printf("--------------------------------------------------------------------\n");
    printf("CONNECTION TABLE\n");
    printf("--------------------------------------------------------------------\n");
    printf("\t Local Node: 0x%08X\n", manager->device_id);
    printf("--------------------------------------------------------------------\n");
    printf("\t %-12s %-12s %-10s %-10s %-18s\n", "Device ID", "Status", "RSSI", "Type", "MAC");
    printf("--------------------------------------------------------------------\n");

    guint known = 0, connected = 0, connecting = 0;
    for (guint i = 0; i < manager->discovered_count; i++) {
        tracked_device_t *tracked = &manager->discovered_devices[i];
        if (tracked->device_id == 0 && tracked->mac_address[0] == '\0') continue;

        known++;
        if (tracked->is_connected) connected++;
        if (tracked->is_connecting) connecting++;

        const char *status;
        if (tracked->is_connected) {
            status = "CONNECTED";
        } else if (tracked->is_connecting) {
            status = "CONNECTING";
        } else {
            status = "KNOWN";
        }
        const char *type = tracked->we_initiated ? "OUTGOING" : "INCOMING";

        printf("\t 0x%08X   %-12s %4d dBm   %-10s %-18s\n",
               tracked->device_id, status, tracked->rssi, type, tracked->mac_address);
    }

    if (known == 0) {
        printf("\t (no devices)\n");
    }

    printf("--------------------------------------------------------------------\n");
    printf("\t Total: %u known, %u connected, %u connecting\n", known, connected, connecting);
    printf("--------------------------------------------------------------------\n");
}
