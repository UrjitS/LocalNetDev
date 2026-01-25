/* bluetooth.c - Simplified LocalNet BLE mesh networking implementation */

#include "bluetooth.h"
#include <string.h>
#include <stdlib.h>

#define BT_TAG "LocalNet-BT"
#define LOCALNET_PREFIX "LocalNet-"
#define HEARTBEAT_INTERVAL_SECONDS 10
#define HEARTBEAT_TIMEOUT_SECONDS 30
#define RECONNECT_DELAY_MS 5000

/* Simple mesh packet for BLE communication */
#define MSG_TYPE_HEARTBEAT 0x01
#define MSG_TYPE_DATA      0x02
#define MSG_TYPE_DISCOVERY 0x03

struct mesh_packet {
    uint8_t type;
    uint8_t flags;
    uint32_t source_id;
    uint32_t timestamp;
};

static size_t serialize_mesh_packet(const struct mesh_packet *pkt, uint8_t *buffer, size_t buffer_size) {
    if (buffer_size < 8) return 0;
    buffer[0] = pkt->type;
    buffer[1] = pkt->flags;
    memcpy(&buffer[2], &pkt->source_id, sizeof(pkt->source_id));
    memcpy(&buffer[6], &pkt->timestamp, sizeof(pkt->timestamp));
    return 10;  // Actually 10 bytes if timestamp is 4 bytes
}

static gboolean deserialize_mesh_packet(const uint8_t *buffer, size_t len, struct mesh_packet *pkt) {
    if (len < 8) return FALSE;
    pkt->type = buffer[0];
    pkt->flags = buffer[1];
    memcpy(&pkt->source_id, &buffer[2], sizeof(pkt->source_id));
    if (len >= 10) {
        memcpy(&pkt->timestamp, &buffer[6], sizeof(pkt->timestamp));
    } else {
        pkt->timestamp = 0;
    }
    return TRUE;
}

static ble_node_manager_t *g_manager = NULL;

/* Forward declarations */
static void on_scan_result(Adapter *adapter, Device *device);
static void on_discovery_state_changed(Adapter *adapter, DiscoveryState state, const GError *error);
static void on_connection_state_changed(Device *device, ConnectionState state, const GError *error);
static void on_services_resolved(Device *device);
static void on_notify(Device *device, Characteristic *characteristic, const GByteArray *byteArray);
static void on_write_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error);
static void on_remote_central_connected(Adapter *adapter, Device *device);
static gboolean on_request_authorization(Device *device);
static const char* on_local_char_read(const Application *app, const char *address, const char* service_uuid,
                                       const char* char_uuid, const guint16 offset, const guint16 mtu);
static const char* on_local_char_write(const Application *app, const char *address, const char *service_uuid,
                                        const char *char_uuid, GByteArray *byteArray, const guint16 offset, const guint16 mtu);

/* Utility functions */
static uint32_t mac_to_device_id(const char *mac) {
    if (!mac) return 0;
    unsigned int b1, b2, b3, b4, b5, b6;
    if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &b1, &b2, &b3, &b4, &b5, &b6) == 6) {
        return (b4 << 16) | (b5 << 8) | b6;
    }
    return 0;
}

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

static uint64_t get_current_timestamp(void) {
    return (uint64_t)time(NULL);
}

static tracked_device_t* find_device_by_id(uint32_t device_id) {
    if (!g_manager) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].device_id == device_id) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t* find_device_by_mac(const char *mac) {
    if (!g_manager || !mac) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_str_equal(g_manager->discovered_devices[i].mac_address, mac)) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t* find_device_by_ptr(Device *device) {
    if (!g_manager || !device) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].device == device) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t* add_device(uint32_t device_id, const char *mac, Device *device) {
    if (!g_manager || g_manager->discovered_count >= MAX_DISCOVERED_DEVICES) return NULL;

    /* Check if already exists */
    tracked_device_t *existing = find_device_by_id(device_id);
    if (existing) {
        if (device) existing->device = device;
        if (mac) strncpy(existing->mac_address, mac, sizeof(existing->mac_address) - 1);
        existing->last_seen = get_current_timestamp();
        return existing;
    }

    tracked_device_t *tracked = &g_manager->discovered_devices[g_manager->discovered_count++];
    memset(tracked, 0, sizeof(*tracked));
    tracked->device_id = device_id;
    tracked->device = device;
    if (mac) strncpy(tracked->mac_address, mac, sizeof(tracked->mac_address) - 1);
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

/* Advertising control */
static void start_advertising(void) {
    if (!g_manager || !g_manager->adapter) return;

    if (g_manager->advertisement) {
        binc_adapter_stop_advertising(g_manager->adapter, g_manager->advertisement);
        binc_advertisement_free(g_manager->advertisement);
        g_manager->advertisement = NULL;
    }

    g_manager->advertisement = binc_advertisement_create();
    binc_advertisement_set_local_name(g_manager->advertisement, g_manager->local_name);

    GPtrArray *services = g_ptr_array_new();
    g_ptr_array_add(services, LOCAL_NET_SERVICE_UUID);
    binc_advertisement_set_services(g_manager->advertisement, services);
    g_ptr_array_free(services, TRUE);

    binc_adapter_start_advertising(g_manager->adapter, g_manager->advertisement);
    log_info(BT_TAG, "Advertising as %s", g_manager->local_name);
}

static void stop_advertising(void) {
    if (!g_manager || !g_manager->adapter || !g_manager->advertisement) return;
    binc_adapter_stop_advertising(g_manager->adapter, g_manager->advertisement);
}

/* Discovery control */
static void start_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    binc_adapter_set_discovery_filter(g_manager->adapter, -100, NULL, NULL);
    binc_adapter_start_discovery(g_manager->adapter);
}

static void stop_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    binc_adapter_stop_discovery(g_manager->adapter);
}

/* Connect to a device */
static void connect_to_device(tracked_device_t *tracked) {
    if (!g_manager || !tracked || !tracked->device) return;
    if (tracked->is_connected) return;

    log_debug(BT_TAG, "Connecting to device 0x%08X", tracked->device_id);

    /* Stop advertising and discovery before connecting to avoid conflicts */
    log_debug(BT_TAG, "Stopping advertising before connection attempt");
    stop_advertising();
    log_debug(BT_TAG, "Stopping discovery before connection attempt");
    stop_discovery();

    /* Set up callbacks before connecting */
    binc_device_set_connection_state_change_cb(tracked->device, &on_connection_state_changed);
    binc_device_set_services_resolved_cb(tracked->device, &on_services_resolved);
    binc_device_set_notify_char_cb(tracked->device, &on_notify);
    binc_device_set_write_char_cb(tracked->device, &on_write_characteristic);

    tracked->we_initiated = TRUE;
    binc_device_connect(tracked->device);
}

/* Heartbeat callback */
static gboolean heartbeat_callback(gpointer user_data) {
    if (!g_manager || !g_manager->running) return FALSE;

    uint64_t now = get_current_timestamp();
    guint connected = 0;
    guint timed_out = 0;

    /* Check all connected devices for heartbeat timeout */
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t *tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected) continue;

        connected++;

        /* Check for timeout */
        if (now - tracked->last_heartbeat > HEARTBEAT_TIMEOUT_SECONDS) {
            log_info(BT_TAG, "Heartbeat timeout: disconnecting 0x%08X", tracked->device_id);
            tracked->is_connected = FALSE;
            timed_out++;

            /* Disconnect the device */
            if (tracked->device && tracked->we_initiated) {
                binc_device_disconnect(tracked->device);
            }

            if (g_manager->disconnected_callback) {
                g_manager->disconnected_callback(tracked->device_id);
            }
        }
    }

    /* Create heartbeat message */
    struct mesh_packet packet = {
        .type = MSG_TYPE_HEARTBEAT,
        .flags = 0,
        .source_id = g_manager->device_id,
        .timestamp = (uint32_t)now
    };

    uint8_t buffer[32];
    size_t len = serialize_mesh_packet(&packet, buffer, sizeof(buffer));

    /* Send heartbeats to all connected devices we initiated connection to (as client) */
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t *tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected || !tracked->we_initiated || !tracked->device) continue;

        GByteArray *data = g_byte_array_sized_new(len);
        g_byte_array_append(data, buffer, len);

        Characteristic *ch = binc_device_get_characteristic(tracked->device,
                                                             LOCAL_NET_SERVICE_UUID,
                                                             LOCAL_NET_DATA_CHAR_UUID);
        if (ch) {
            binc_characteristic_write(ch, data, WITH_RESPONSE);
        }
        g_byte_array_free(data, TRUE);
    }

    /* Send heartbeats to connected clients via notification (as server) */
    gboolean has_incoming = FALSE;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t *tracked = &g_manager->discovered_devices[i];
        if (tracked->is_connected && !tracked->we_initiated) {
            has_incoming = TRUE;
            break;
        }
    }

    if (has_incoming && g_manager->app) {
        GByteArray *data = g_byte_array_sized_new(len);
        g_byte_array_append(data, buffer, len);
        binc_application_set_char_value(g_manager->app, LOCAL_NET_SERVICE_UUID,
                                        LOCAL_NET_DATA_CHAR_UUID, data);
        binc_application_notify(g_manager->app, LOCAL_NET_SERVICE_UUID,
                               LOCAL_NET_DATA_CHAR_UUID, data);
        g_byte_array_free(data, TRUE);
    }

    log_debug(BT_TAG, "Heartbeat sent to %u connected nodes", connected - timed_out);
    return TRUE;
}

/* Discovery state callback */
static void on_discovery_state_changed(Adapter *adapter, DiscoveryState state, const GError *error) {
    const char *state_name = "UNKNOWN";
    switch (state) {
        case BINC_DISCOVERY_STARTING: state_name = "STARTING"; break;
        case BINC_DISCOVERY_STARTED: state_name = "STARTED"; break;
        case BINC_DISCOVERY_STOPPED: state_name = "STOPPED"; break;
        case BINC_DISCOVERY_STOPPING: state_name = "STOPPING"; break;
    }
    log_info(BT_TAG, "Discovery state changed to %s", state_name);
}

/* Scan result callback */
static void on_scan_result(Adapter *adapter, Device *device) {
    if (!g_manager || !device) return;

    const char *name = binc_device_get_name(device);
    const char *mac = binc_device_get_address(device);

    if (!is_localnet_device(name)) return;

    uint32_t device_id = extract_device_id_from_name(name);
    if (device_id == 0 || device_id == g_manager->device_id) return;

    int16_t rssi = binc_device_get_rssi(device);

    /* Check if already connected */
    tracked_device_t *tracked = find_device_by_id(device_id);
    if (tracked && tracked->is_connected) {
        tracked->rssi = rssi;
        tracked->last_seen = get_current_timestamp();
        return;  /* Already connected, just update RSSI */
    }

    log_debug(BT_TAG, "Discovered LocalNet node: 0x%08X (RSSI: %d)", device_id, rssi);

    /* Add or update device */
    tracked = add_device(device_id, mac, device);
    if (!tracked) return;
    tracked->rssi = rssi;

    /* Notify discovery callback */
    if (g_manager->discovered_callback) {
        g_manager->discovered_callback(device_id, rssi);
    }

    /* Connection arbitration: lower ID initiates connection */
    if (g_manager->device_id < device_id) {
        log_debug(BT_TAG, "Connecting to 0x%08X (we have lower ID)", device_id);
        connect_to_device(tracked);
    } else {
        log_debug(BT_TAG, "Waiting for 0x%08X to connect to us (they have lower ID)", device_id);
    }
}

/* Connection state change callback */
static void on_connection_state_changed(Device *device, ConnectionState state, const GError *error) {
    if (!g_manager || !device) return;

    tracked_device_t *tracked = find_device_by_ptr(device);
    if (!tracked) {
        /* Try to find by MAC */
        const char *mac = binc_device_get_address(device);
        tracked = find_device_by_mac(mac);
    }

    const char *state_name = binc_device_get_connection_state_name(device);
    uint32_t device_id = tracked ? tracked->device_id : 0;

    if (error) {
        log_error(BT_TAG, "Connection error for 0x%08X: %s", device_id, error->message);
    }

    log_debug(BT_TAG, "Connection state changed for 0x%08X: %s", device_id, state_name);

    switch (state) {
        case BINC_CONNECTED:
            /* Wait for services to be resolved before marking as connected */
            break;

        case BINC_DISCONNECTED:
            if (tracked) {
                gboolean was_connected = tracked->is_connected;
                tracked->is_connected = FALSE;
                tracked->device = NULL;  /* Device may be freed by BlueZ */

                if (was_connected && g_manager->disconnected_callback) {
                    g_manager->disconnected_callback(device_id);
                }
            }

            /* Remove device from BlueZ cache to allow fresh discovery */
            if (device && binc_device_get_bonding_state(device) != BINC_BONDED) {
                binc_adapter_remove_device(g_manager->adapter, device);
            }

            /* Restart advertising and discovery after disconnection */
            log_debug(BT_TAG, "Restarting advertising and discovery after disconnection");
            start_advertising();
            start_discovery();
            break;

        case BINC_CONNECTING:
        case BINC_DISCONNECTING:
            /* Transitional states, just log */
            break;
    }
}

/* Services resolved callback */
static void on_services_resolved(Device *device) {
    if (!g_manager || !device) return;

    tracked_device_t *tracked = find_device_by_ptr(device);
    if (!tracked) return;

    log_debug(BT_TAG, "Services resolved for device 0x%08X", tracked->device_id);

    tracked->is_connected = TRUE;
    tracked->last_heartbeat = get_current_timestamp();

    /* Start notifications on the data characteristic */
    Characteristic *ch = binc_device_get_characteristic(device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
    if (ch) {
        binc_characteristic_start_notify(ch);
    }

    /* Restart advertising and discovery to allow other connections */
    log_debug(BT_TAG, "Restarting advertising and discovery after successful connection");
    start_advertising();
    start_discovery();

    /* Notify callback first - let connection stabilize before sending data */
    if (g_manager->connected_callback) {
        g_manager->connected_callback(tracked->device_id);
    }
}

/* Notification callback */
static void on_notify(Device *device, Characteristic *characteristic, const GByteArray *byteArray) {
    if (!g_manager || !byteArray || byteArray->len == 0) return;

    tracked_device_t *tracked = find_device_by_ptr(device);
    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
    }

    /* Parse and handle the message */
    struct mesh_packet packet;
    if (deserialize_mesh_packet(byteArray->data, byteArray->len, &packet)) {
        if (packet.type == MSG_TYPE_HEARTBEAT) {
            log_debug(BT_TAG, "Received heartbeat from 0x%08X", packet.source_id);
        } else if (g_manager->data_callback) {
            g_manager->data_callback(packet.source_id, byteArray->data, byteArray->len);
        }
    }
}

/* Write callback */
static void on_write_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error) {
    if (error) {
        tracked_device_t *tracked = find_device_by_ptr(device);
        log_error(BT_TAG, "Write characteristic error for 0x%08X: %s",
                  tracked ? tracked->device_id : 0, error->message);
    }
}

/* Remote central connected callback (they connected to us) */
static void on_remote_central_connected(Adapter *adapter, Device *device) {
    if (!g_manager || !device) return;

    const char *name = binc_device_get_name(device);
    const char *mac = binc_device_get_address(device);

    /* Try to identify the device */
    uint32_t device_id = 0;
    if (is_localnet_device(name)) {
        device_id = extract_device_id_from_name(name);
    } else {
        /* Try MAC-based ID */
        device_id = mac_to_device_id(mac);
    }

    if (device_id == 0) {
        log_debug(BT_TAG, "Non-LocalNet device connected as central: %s", mac);
        return;
    }

    log_info(BT_TAG, "Remote central connected: %s (%s)", name ? name : "unknown", mac);

    /* Track the device */
    tracked_device_t *tracked = add_device(device_id, mac, device);
    if (!tracked) return;

    tracked->is_connected = TRUE;
    tracked->we_initiated = FALSE;
    tracked->last_heartbeat = get_current_timestamp();

    /* Set up disconnect callback for incoming connections */
    binc_device_set_connection_state_change_cb(device, &on_connection_state_changed);

    log_info(BT_TAG, "LocalNet node connected as central: 0x%08X", device_id);

    if (g_manager->connected_callback) {
        g_manager->connected_callback(device_id);
    }
}

/* Authorization callback */
static gboolean on_request_authorization(Device *device) {
    const char *name = binc_device_get_name(device);
    log_debug(BT_TAG, "Authorizing device: %s", name ? name : "unknown");
    return TRUE;  /* Auto-accept (JustWorks) */
}

/* Local characteristic read callback */
static const char* on_local_char_read(const Application *app, const char *address, const char* service_uuid,
                                       const char* char_uuid, const guint16 offset, const guint16 mtu) {
    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID)) {
        if (g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
            /* Return empty for data reads */
            GByteArray *empty = g_byte_array_new();
            binc_application_set_char_value(app, service_uuid, char_uuid, empty);
            g_byte_array_free(empty, TRUE);
            return NULL;
        }
    }
    return BLUEZ_ERROR_REJECTED;
}

/* Local characteristic write callback */
static const char* on_local_char_write(const Application *app, const char *address, const char *service_uuid,
                                        const char *char_uuid, GByteArray *byteArray, const guint16 offset, const guint16 mtu) {
    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (!g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID)) {
        return BLUEZ_ERROR_REJECTED;
    }

    if (!g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
        return BLUEZ_ERROR_REJECTED;
    }

    if (!byteArray || byteArray->len == 0) return NULL;

    /* Find or create tracked device */
    uint32_t device_id = mac_to_device_id(address);
    tracked_device_t *tracked = find_device_by_mac(address);

    if (!tracked) {
        tracked = add_device(device_id, address, NULL);
    }

    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
        tracked->is_connected = TRUE;
        device_id = tracked->device_id;
    }

    log_debug(BT_TAG, "Received write from %s (ID: 0x%08X): %u bytes",
              address, device_id, byteArray->len);

    /* Parse message */
    struct mesh_packet packet;
    if (deserialize_mesh_packet(byteArray->data, byteArray->len, &packet)) {
        if (packet.type == MSG_TYPE_HEARTBEAT) {
            log_debug(BT_TAG, "Received heartbeat from 0x%08X", packet.source_id);
            /* Update device ID if we got it from the packet */
            if (tracked && tracked->device_id == 0 && packet.source_id != 0) {
                tracked->device_id = packet.source_id;
            }
        } else if (g_manager->data_callback) {
            g_manager->data_callback(packet.source_id, byteArray->data, byteArray->len);
        }
    }

    return NULL;
}

/* Public API */
ble_node_manager_t* ble_init(struct mesh_node *mesh_node, uint32_t device_id,
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

    snprintf(manager->local_name, sizeof(manager->local_name),
             LOCALNET_PREFIX "%08X", device_id);

    manager->discovered_devices = g_new0(tracked_device_t, MAX_DISCOVERED_DEVICES);
    manager->discovered_count = 0;

    g_manager = manager;
    log_debug(BT_TAG, "Initialized BLE node manager for device ID: 0x%08X", device_id);

    return manager;
}

gboolean ble_start(ble_node_manager_t *manager) {
    if (!manager) return FALSE;

    log_debug(BT_TAG, "Starting BLE node manager");

    /* Get DBus connection */
    GDBusConnection *dbus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (!dbus) {
        log_error(BT_TAG, "Failed to get DBus connection");
        return FALSE;
    }
    manager->dbus_connection = dbus;

    /* Get adapter */
    manager->adapter = binc_adapter_get_default(dbus);
    if (!manager->adapter) {
        log_error(BT_TAG, "No Bluetooth adapter found");
        return FALSE;
    }

    log_info(BT_TAG, "Using adapter: %s", binc_adapter_get_name(manager->adapter));

    /* Create agent for pairing */
    manager->agent = binc_agent_create(manager->adapter, "/org/bluez/LocalNetAgent", NO_INPUT_NO_OUTPUT);
    binc_agent_set_request_authorization_cb(manager->agent, &on_request_authorization);

    /* Setup GATT application (peripheral role) */
    manager->app = binc_create_application(manager->adapter);
    binc_application_add_service(manager->app, LOCAL_NET_SERVICE_UUID);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID,
                                        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_NOTIFY);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_CTRL_CHAR_UUID,
                                        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE);
    binc_application_set_char_read_cb(manager->app, &on_local_char_read);
    binc_application_set_char_write_cb(manager->app, &on_local_char_write);
    binc_adapter_register_application(manager->adapter, manager->app);

    /* Setup discovery callbacks */
    binc_adapter_set_discovery_cb(manager->adapter, &on_scan_result);
    binc_adapter_set_discovery_state_cb(manager->adapter, &on_discovery_state_changed);
    binc_adapter_set_remote_central_cb(manager->adapter, &on_remote_central_connected);

    manager->running = TRUE;

    /* Start advertising and discovery */
    start_advertising();
    start_discovery();

    log_debug(BT_TAG, "BLE node manager started successfully");
    return TRUE;
}

void ble_stop(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Stopping BLE node manager");
    manager->running = FALSE;

    /* Stop discovery and advertising */
    stop_discovery();
    stop_advertising();

    /* Disconnect all connections */
    for (guint i = 0; i < manager->discovered_count; i++) {
        tracked_device_t *tracked = &manager->discovered_devices[i];
        if (tracked->is_connected && tracked->device && tracked->we_initiated) {
            binc_device_disconnect(tracked->device);
        }
    }

    /* Free advertisement */
    if (manager->advertisement) {
        binc_advertisement_free(manager->advertisement);
        manager->advertisement = NULL;
    }

    /* Free application */
    if (manager->app) {
        binc_application_free(manager->app);
        manager->app = NULL;
    }

    /* Free agent */
    if (manager->agent) {
        binc_agent_free(manager->agent);
        manager->agent = NULL;
    }

    /* Free adapter */
    if (manager->adapter) {
        binc_adapter_free(manager->adapter);
        manager->adapter = NULL;
    }

    /* Close DBus connection */
    if (manager->dbus_connection) {
        g_dbus_connection_close_sync(manager->dbus_connection, NULL, NULL);
        g_object_unref(manager->dbus_connection);
        manager->dbus_connection = NULL;
    }
}

void ble_cleanup(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Cleaning up BLE node manager");
    ble_stop(manager);

    g_free(manager->discovered_devices);
    g_free(manager);

    if (g_manager == manager) {
        g_manager = NULL;
    }
}

void ble_run_loop(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Running main loop");

    manager->loop = g_main_loop_new(NULL, FALSE);

    /* Schedule heartbeat */
    manager->heartbeat_source = g_timeout_add_seconds(HEARTBEAT_INTERVAL_SECONDS, heartbeat_callback, NULL);

    g_main_loop_run(manager->loop);

    /* Cleanup */
    if (manager->heartbeat_source) {
        g_source_remove(manager->heartbeat_source);
        manager->heartbeat_source = 0;
    }

    g_main_loop_unref(manager->loop);
    manager->loop = NULL;
}

void ble_quit_loop(ble_node_manager_t *manager) {
    if (!manager || !manager->loop) return;

    log_debug(BT_TAG, "Quitting main loop");
    g_main_loop_quit(manager->loop);
}

gboolean ble_send_data(ble_node_manager_t *manager, uint32_t target_id, const uint8_t *data, size_t len) {
    if (!manager || !data || len == 0) return FALSE;

    tracked_device_t *tracked = find_device_by_id(target_id);
    if (!tracked || !tracked->is_connected) {
        return FALSE;
    }

    GByteArray *byte_array = g_byte_array_sized_new(len);
    g_byte_array_append(byte_array, data, len);

    if (tracked->we_initiated && tracked->device) {
        /* We're the central - write to peripheral */
        Characteristic *ch = binc_device_get_characteristic(tracked->device,
                                                             LOCAL_NET_SERVICE_UUID,
                                                             LOCAL_NET_DATA_CHAR_UUID);
        if (ch) {
            binc_characteristic_write(ch, byte_array, WITH_RESPONSE);
            g_byte_array_free(byte_array, TRUE);
            return TRUE;
        }
    } else if (manager->app) {
        /* We're the peripheral - use notification */
        binc_application_set_char_value(manager->app, LOCAL_NET_SERVICE_UUID,
                                        LOCAL_NET_DATA_CHAR_UUID, byte_array);
        binc_application_notify(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, byte_array);
        g_byte_array_free(byte_array, TRUE);
        return TRUE;
    }

    g_byte_array_free(byte_array, TRUE);
    return FALSE;
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
    printf("\t Device ID \t\t Status \t\t RSSI \t\t Type \t\t MAC\n");
    printf("--------------------------------------------------------------------\n");

    guint known = 0, connected = 0;
    for (guint i = 0; i < manager->discovered_count; i++) {
        tracked_device_t *tracked = &manager->discovered_devices[i];
        if (tracked->device_id == 0) continue;

        known++;
        if (tracked->is_connected) connected++;

        const char *status = tracked->is_connected ? "CONNECTED" : "KNOWN";
        const char *type = tracked->we_initiated ? "OUTGOING" : "INCOMING";
        if (tracked->we_initiated && !tracked->is_connected) {
            type = "OUTGOING";
        }

        printf("\t 0x%08X \t\t %-10s \t\t %4d dBm \t\t %-10s \t\t %-18s\n",
               tracked->device_id, status, tracked->rssi, type, tracked->mac_address);
    }

    if (known == 0) {
        printf("\t (no devices)\n");
    }

    printf("--------------------------------------------------------------------\n");
    printf("\t Total: %u known, %u connected\n", known, connected);
    printf("--------------------------------------------------------------------\n");
}
