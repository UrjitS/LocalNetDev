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


static ble_node_manager_t * g_manager = NULL;


static void on_scan_result(Adapter * adapter, Device * device);
static void on_discovery_state_changed(Adapter * adapter, DiscoveryState state, const GError * error);
static void on_connection_state_changed(Device * device, ConnectionState state, const GError * error);
static void on_services_resolved(Device * device);
static void on_notify(Device * device, Characteristic * characteristic, const GByteArray * byteArray);
static void on_write_characteristic(Device * device, Characteristic * characteristic, const GByteArray * byteArray, const GError * error);
static void on_remote_central_connected(Adapter * adapter, Device * device);
static gboolean on_request_authorization(Device * device);
static const char* on_local_char_read(const Application * app, const char * address, const char * service_uuid, const char * char_uuid, guint16 offset, guint16 mtu);
static const char* on_local_char_write(const Application * app, const char * address, const char * service_uuid, const char * char_uuid, GByteArray * byteArray, guint16 offset, guint16 mtu);

// Utility functions
static uint32_t extract_device_id_from_name(const char * name) {
    if (!name) return 0;
    if (g_str_has_prefix(name, LOCALNET_PREFIX)) {
        const char * hex = name + strlen(LOCALNET_PREFIX);
        return (uint32_t)strtoul(hex, NULL, 16);
    }
    return 0;
}

static gboolean is_localnet_device(const char * name) {
    return name && g_str_has_prefix(name, LOCALNET_PREFIX);
}


static tracked_device_t * find_device_by_id(const uint32_t device_id) {
    if (!g_manager) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].device_id == device_id) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t * find_device_by_mac(const char * mac) {
    if (!g_manager || !mac) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_str_equal(g_manager->discovered_devices[i].mac_address, mac)) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t * find_device_by_ptr(Device * device) {
    if (!g_manager || !device) return NULL;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].device == device) {
            return &g_manager->discovered_devices[i];
        }
    }
    return NULL;
}

static tracked_device_t * add_device(const uint32_t device_id, const char * mac, Device * device) {
    if (!g_manager || g_manager->discovered_count >= MAX_DISCOVERED_DEVICES) return NULL;

    // Check if already exists 
    tracked_device_t * existing = find_device_by_id(device_id);
    if (existing) {
        if (device) existing->device = device;
        if (mac) strncpy(existing->mac_address, mac, sizeof(existing->mac_address) - 1);
        existing->last_seen = get_current_timestamp();
        return existing;
    }

    tracked_device_t * tracked = &g_manager->discovered_devices[g_manager->discovered_count++];
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

// Advertising control 
static void start_advertising(void) {
    if (!g_manager || !g_manager->adapter) return;

    if (g_manager->advertisement) {
        binc_adapter_stop_advertising(g_manager->adapter, g_manager->advertisement);
        binc_advertisement_free(g_manager->advertisement);
        g_manager->advertisement = NULL;
    }

    g_manager->advertisement = binc_advertisement_create();
    binc_advertisement_set_local_name(g_manager->advertisement, g_manager->local_name);

    GPtrArray * services = g_ptr_array_new();
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

// Discovery control 
static void start_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    binc_adapter_set_discovery_filter(g_manager->adapter, -100, NULL, NULL);
    binc_adapter_start_discovery(g_manager->adapter);
}

static void stop_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    binc_adapter_stop_discovery(g_manager->adapter);
}

// Connect to a device 
static void connect_to_device(tracked_device_t * tracked) {
    if (!g_manager || !tracked || !tracked->device) return;
    if (tracked->is_connected || tracked->is_connecting) return;

    // Check if the device is in a stale bonded state - if so, we need to remove it and wait for rediscovery
    BondingState bond_state = binc_device_get_bonding_state(tracked->device);
    log_debug(BT_TAG, "Device 0x%08X bonding state: %d (BONDED=%d, NONE=%d)",
        tracked->device_id, bond_state, BINC_BONDED, BINC_BOND_NONE);

    if (bond_state == BINC_BONDED) {
        log_info(BT_TAG, "Device 0x%08X is in bonded state, removing to get fresh connection", tracked->device_id);
        binc_adapter_remove_device(g_manager->adapter, tracked->device);
        tracked->device = NULL;
        tracked->last_connect_attempt = get_current_timestamp();
        // Device will be rediscovered and we'll try again
        return;
    }

    log_info(BT_TAG, "Connecting to device 0x%08X", tracked->device_id);

    // Mark as connecting to prevent duplicate attempts
    tracked->is_connecting = TRUE;
    tracked->last_connect_attempt = get_current_timestamp();

    // Stop advertising and discovery before connecting to avoid conflicts
    log_debug(BT_TAG, "Stopping advertising before connection attempt");
    stop_advertising();
    log_debug(BT_TAG, "Stopping discovery before connection attempt");
    stop_discovery();

    // Set up callbacks before connecting 
    binc_device_set_connection_state_change_cb(tracked->device, &on_connection_state_changed);
    binc_device_set_services_resolved_cb(tracked->device, &on_services_resolved);
    binc_device_set_notify_char_cb(tracked->device, &on_notify);
    binc_device_set_write_char_cb(tracked->device, &on_write_characteristic);

    tracked->we_initiated = TRUE;
    binc_device_connect(tracked->device);
}

// Heartbeat callback
// NOLINTNEXTLINE
static gboolean heartbeat_callback(gpointer user_data) {
    if (!g_manager || !g_manager->running) return FALSE;

    const uint32_t now = get_current_timestamp();
    guint connected = 0;
    guint timed_out = 0;

    // Check all connected devices for heartbeat timeout 
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t * tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected) continue;

        connected++;

        // Check for timeout 
        if (now - tracked->last_heartbeat > HEARTBEAT_TIMEOUT_SECONDS) {
            log_info(BT_TAG, "Heartbeat timeout: disconnecting 0x%08X", tracked->device_id);
            tracked->is_connected = FALSE;
            timed_out++;

            // Disconnect the device 
            if (tracked->device && tracked->we_initiated) {
                binc_device_disconnect(tracked->device);
            }

            if (g_manager->disconnected_callback) {
                g_manager->disconnected_callback(tracked->device_id);
            }
        }
    }

    // Create proper heartbeat message using protocol structures 
    const struct heartbeat heartbeat = {
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
        .destination_id = 0  // Broadcast
    };

    // Serialize the heartbeat payload 
    uint8_t payload_buffer[16];
    const size_t payload_len = serialize_heartbeat(&heartbeat, payload_buffer, sizeof(payload_buffer));
    if (payload_len == 0) {
        log_error(BT_TAG, "Failed to serialize heartbeat");
        return TRUE;
    }

    // Create the full packet 
    const struct packet packet = {
        .header = &header,
        .network = &network,
        .payload = payload_buffer,
        .security = NULL
    };

    // Serialize the complete packet
    uint8_t buffer[64];
    const size_t len = serialize_packet(&packet, buffer, sizeof(buffer));
    if (len == 0) {
        log_error(BT_TAG, "Failed to serialize heartbeat packet");
        return TRUE;
    }

    // Send heartbeats to all connected devices we initiated connection to
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        const tracked_device_t * tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected || !tracked->we_initiated || !tracked->device) continue;

        GByteArray * data = g_byte_array_sized_new(len);
        g_byte_array_append(data, buffer, len);

        Characteristic * binc_characteristic = binc_device_get_characteristic(tracked->device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
        if (binc_characteristic) {
            binc_characteristic_write(binc_characteristic, data, WITH_RESPONSE);
        }
        g_byte_array_free(data, TRUE);
    }

    // Send heartbeats to connected clients via notification
    gboolean has_incoming = FALSE;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        const tracked_device_t * tracked = &g_manager->discovered_devices[i];
        if (tracked->is_connected && !tracked->we_initiated) {
            has_incoming = TRUE;
            break;
        }
    }

    if (has_incoming && g_manager->app) {
        GByteArray * data = g_byte_array_sized_new(len);
        g_byte_array_append(data, buffer, len);
        binc_application_set_char_value(g_manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, data);
        binc_application_notify(g_manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, data);
        g_byte_array_free(data, TRUE);
    }

    log_info(BT_TAG, "Heartbeat sent to %u connected nodes", connected - timed_out);
    return TRUE;
}

// Discovery state callback
// NOLINTNEXTLINE
static void on_discovery_state_changed(Adapter * adapter, DiscoveryState state, const GError * error) {
    const char * state_name = "UNKNOWN";
    switch (state) {
        case BINC_DISCOVERY_STARTING: state_name = "STARTING"; break;
        case BINC_DISCOVERY_STARTED: state_name = "STARTED"; break;
        case BINC_DISCOVERY_STOPPED: state_name = "STOPPED"; break;
        case BINC_DISCOVERY_STOPPING: state_name = "STOPPING"; break;
    }
    log_info(BT_TAG, "Discovery state changed to %s", state_name);
}

// Scan result callback
// NOLINTNEXTLINE
static void on_scan_result(Adapter * adapter, Device * device) {
    if (!g_manager || !device) return;

    const char * name = binc_device_get_name(device);
    const char * mac = binc_device_get_address(device);

    if (!is_localnet_device(name)) return;

    const uint32_t device_id = extract_device_id_from_name(name);
    if (device_id == 0 || device_id == g_manager->device_id) return;

    const int16_t rssi = binc_device_get_rssi(device);
    const uint64_t now = get_current_timestamp();

    // Check if already connected or connecting
    tracked_device_t * tracked = find_device_by_id(device_id);
    if (tracked) {
        tracked->rssi = rssi;
        tracked->last_seen = now;
        // Update device pointer in case it changed
        if (device) tracked->device = device;

        // If already connected or currently connecting, skip
        if (tracked->is_connected || tracked->is_connecting) {
            return;
        }

        // Rate limit reconnection attempts
        if (now - tracked->last_connect_attempt < RECONNECT_DELAY_SECONDS) {
            return;
        }
    }

    log_info(BT_TAG, "Discovered LocalNet node: 0x%08X (RSSI: %d)", device_id, rssi);

    // Add or update device
    tracked = add_device(device_id, mac, device);
    if (!tracked) return;
    tracked->rssi = rssi;

    // Call discovery callback
    if (g_manager->discovered_callback) {
        g_manager->discovered_callback(device_id, rssi);
    }

    if (g_manager->device_id < device_id) {
        // We should initiate the connection (we have lower ID)
        // But first, check if this device isn't already connected to us (race condition protection)
        if (tracked->is_connected) {
            log_debug(BT_TAG, "Device 0x%08X already connected to us, skipping connection attempt", device_id);
            return;
        }

        // Check if we're already in the process of connecting to another device
        gboolean already_connecting = FALSE;
        for (guint i = 0; i < g_manager->discovered_count; i++) {
            if (g_manager->discovered_devices[i].is_connecting) {
                already_connecting = TRUE;
                break;
            }
        }

        if (already_connecting) {
            // Queue this device for later - don't try to connect while another connection is in progress
            log_debug(BT_TAG, "Already connecting to another device, will connect to 0x%08X later", device_id);
            return;
        }

        log_debug(BT_TAG, "Initiating connection to 0x%08X (we have lower ID)", device_id);
        connect_to_device(tracked);
    } else {
        log_debug(BT_TAG, "Waiting for 0x%08X to connect to us (they have lower ID)", device_id);
    }
}

// Connection state change callback
// NOLINTNEXTLINE
static void on_connection_state_changed(Device * device, ConnectionState state, const GError * error) {
    if (!g_manager || !device) return;

    tracked_device_t * tracked = find_device_by_ptr(device);
    if (!tracked) {
        const char * mac = binc_device_get_address(device);
        tracked = find_device_by_mac(mac);
    }

    const char * state_name = binc_device_get_connection_state_name(device);
    const uint32_t device_id = tracked ? tracked->device_id : 0;

    if (error) {
        log_error(BT_TAG, "Connection error for 0x%08X: %s", device_id, error->message);
    }

    log_debug(BT_TAG, "Connection state changed for 0x%08X: %s", device_id, state_name);

    switch (state) {
        case BINC_CONNECTED:
            // Clear connecting flag - will be marked as connected in on_services_resolved
            if (tracked) {
                tracked->is_connecting = FALSE;
            }
            break;
        case BINC_DISCONNECTED:
            if (tracked) {
                const gboolean was_connected = tracked->is_connected;
                const gboolean was_connecting = tracked->is_connecting;
                tracked->is_connected = FALSE;
                tracked->is_connecting = FALSE;
                tracked->device = NULL;
                tracked->last_disconnect_time = get_current_timestamp();

                if (was_connected && g_manager->disconnected_callback) {
                    g_manager->disconnected_callback(device_id);
                }

                // If we disconnected during connection attempt (before services resolved),
                // this likely means bonding keys are mismatched. Force remove the device.
                if (was_connecting && !was_connected) {
                    log_error(BT_TAG, "Connection to 0x%08X failed during connection/service discovery - likely bonding mismatch", device_id);
                    // Force remove to clear any stale bonding info
                    log_debug(BT_TAG, "Force removing device to clear bonding info");
                    binc_adapter_remove_device(g_manager->adapter, device);
                    device = NULL;  // Device is now invalid
                }
            }

            // Always remove LocalNet devices from BlueZ cache to allow fresh discovery
            // This prevents stale bonding issues
            if (device) {  // Only if not already removed above
                const char * dev_name = binc_device_get_name(device);
                if (is_localnet_device(dev_name)) {
                    log_debug(BT_TAG, "Removing device from cache: %s (bonded: %d)",
                        dev_name, binc_device_get_bonding_state(device) == BINC_BONDED);
                    binc_adapter_remove_device(g_manager->adapter, device);
                } else if (binc_device_get_bonding_state(device) != BINC_BONDED) {
                    binc_adapter_remove_device(g_manager->adapter, device);
                }
            }

            // Restart advertising and discovery after disconnection
            log_debug(BT_TAG, "Restarting advertising and discovery after disconnection");
            start_advertising();
            start_discovery();
            break;
        case BINC_CONNECTING:
        case BINC_DISCONNECTING:
            break;
    }
}

// Forward declaration
static gboolean check_pending_connections_idle(gpointer user_data);

// Helper to restart advertising/discovery after a short delay
static gboolean restart_advertising_discovery_idle(gpointer user_data) {
    if (!g_manager || !g_manager->running) return FALSE;

    log_debug(BT_TAG, "Restarting advertising and discovery");
    start_advertising();
    start_discovery();

    // Also schedule a check for pending connections in case we have already-discovered devices
    g_timeout_add(1000, check_pending_connections_idle, NULL);

    return FALSE;  // Don't repeat
}

// Helper to check if there are pending connections we should initiate
static gboolean check_pending_connections_idle(gpointer user_data) {
    if (!g_manager || !g_manager->running) return FALSE;

    // Check if we're already connecting to something
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].is_connecting) {
            return FALSE;  // Already connecting, will check again later
        }
    }

    const uint64_t now = get_current_timestamp();

    // Find devices we should connect to but haven't yet
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t * tracked = &g_manager->discovered_devices[i];

        // Skip if no device ID, already connected, or we shouldn't initiate
        if (tracked->device_id == 0) continue;
        if (tracked->is_connected) continue;
        if (g_manager->device_id >= tracked->device_id) continue;  // They should connect to us

        // Check rate limiting
        if (now - tracked->last_connect_attempt < RECONNECT_DELAY_SECONDS) continue;

        // We need a valid device pointer to connect
        if (!tracked->device) {
            log_debug(BT_TAG, "Pending connection to 0x%08X but no device pointer, waiting for discovery", tracked->device_id);
            continue;
        }

        log_info(BT_TAG, "Initiating pending connection to 0x%08X", tracked->device_id);
        connect_to_device(tracked);
        return FALSE;  // Only start one connection at a time
    }

    return FALSE;  // Don't repeat
}

static void on_services_resolved(Device * device) {
    if (!g_manager || !device) return;

    tracked_device_t * tracked = find_device_by_ptr(device);
    if (!tracked) return;

    // Skip if already connected (prevent duplicate processing)
    if (tracked->is_connected) {
        log_debug(BT_TAG, "Services resolved but device 0x%08X already marked connected, skipping", tracked->device_id);
        return;
    }

    log_debug(BT_TAG, "Services resolved for device 0x%08X", tracked->device_id);

    tracked->is_connected = TRUE;
    tracked->is_connecting = FALSE;
    tracked->last_heartbeat = get_current_timestamp();

    Characteristic * characteristic = binc_device_get_characteristic(device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
    if (characteristic) {
        binc_characteristic_start_notify(characteristic);
        log_debug(BT_TAG, "Started notifications for device 0x%08X", tracked->device_id);
    } else {
        log_error(BT_TAG, "Failed to find data characteristic for device 0x%08X", tracked->device_id);
    }

    // Call connected callback before restarting advertising
    if (g_manager->connected_callback) {
        g_manager->connected_callback(tracked->device_id);
    }

    // Schedule restart of advertising and discovery after a delay to let connection stabilize
    g_timeout_add(1000, restart_advertising_discovery_idle, NULL);

    // Schedule a check for other pending connections after discovery restarts
    g_timeout_add(2000, check_pending_connections_idle, NULL);
}

// NOLINTNEXTLINE
static void on_notify(Device * device, Characteristic * characteristic, const GByteArray * byteArray) {
    if (!g_manager || !byteArray || byteArray->len == 0) return;

    tracked_device_t * tracked = find_device_by_ptr(device);
    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
    }

    // Parse the packet using protocol functions 
    struct header header;
    struct network network;
    if (parse_header(byteArray->data, byteArray->len, &header) != 0) {
        log_error(BT_TAG, "Failed to parse packet header");
        return;
    }

    if (byteArray->len < 16 || parse_network(byteArray->data + 8, byteArray->len - 8, &network) != 0) {
        log_error(BT_TAG, "Failed to parse network header");
        return;
    }

    if (header.message_type == MSG_HEARTBEAT) {
        struct heartbeat heartbeat;
        if (parse_heartbeat(byteArray->data + 16, byteArray->len - 16, &heartbeat) == 0) {
            log_info(BT_TAG, "Received heartbeat from 0x%08X (status: %u, connections: %u)", network.source_id, heartbeat.device_status, heartbeat.active_connection_number);

            // Update mesh node connection info if available
            if (g_manager->mesh_node && g_manager->mesh_node->connection_table) {
                reset_missed_heartbeats(g_manager->mesh_node->connection_table, network.source_id);
                update_last_seen(g_manager->mesh_node->connection_table, network.source_id, heartbeat.timestamp);
            }
        }
    } else if (g_manager->data_callback) {
        g_manager->data_callback(network.source_id, byteArray->data, byteArray->len);
    }
}

// NOLINTNEXTLINE
static void on_write_characteristic(Device * device, Characteristic * characteristic, const GByteArray * byteArray, const GError * error) {
    if (error) {
        const tracked_device_t * tracked = find_device_by_ptr(device);
        log_error(BT_TAG, "Write characteristic error for 0x%08X: %s", tracked ? tracked->device_id : 0, error->message);
    }
}

// NOLINTNEXTLINE
static void on_remote_central_connected(Adapter * adapter, Device * device) {
    if (!g_manager || !device) return;

    const char * name = binc_device_get_name(device);
    const char * mac = binc_device_get_address(device);

    // Identify the device
    uint32_t device_id = 0;
    if (is_localnet_device(name)) {
        device_id = extract_device_id_from_name(name);
    } else {
        // Try to find by MAC first in case we already discovered this device
        tracked_device_t * existing = find_device_by_mac(mac);
        if (existing && existing->device_id != 0) {
            device_id = existing->device_id;
        } else {
            device_id = mac_to_device_id(mac);
        }
    }

    if (device_id == 0) {
        log_info(BT_TAG, "Non-LocalNet device connected: %s", mac);
        return;
    }

    // Early debounce check - if we just disconnected from this device, ignore
    tracked_device_t * existing_tracked = find_device_by_id(device_id);
    if (existing_tracked) {
        const uint64_t now = get_current_timestamp();
        if (existing_tracked->last_disconnect_time > 0 &&
            (now - existing_tracked->last_disconnect_time < 3)) {
            log_debug(BT_TAG, "Ignoring spurious reconnection from 0x%08X (disconnected %lu seconds ago)",
                device_id, (unsigned long)(now - existing_tracked->last_disconnect_time));
            return;
        }
    }

    // Check for bidirectional connection scenario
    // If we should have initiated the connection (our ID < their ID), but they connected to us,
    // this might be a race condition. Accept the connection but note the unusual state.
    if (g_manager->device_id < device_id) {
        log_debug(BT_TAG, "Unexpected: device 0x%08X connected to us, but we should have initiated (our ID is lower)", device_id);
    }

    log_info(BT_TAG, "Remote connected: %s (%s)", name ? name : "unknown", mac);

    // Check if we already have this device tracked (e.g., from scan or we're connecting to them)
    tracked_device_t * tracked = find_device_by_id(device_id);
    if (tracked) {
        // If we're currently trying to connect to this device, don't override
        if (tracked->is_connecting) {
            log_debug(BT_TAG, "Device 0x%08X is connecting to us while we're connecting to them - accepting their connection", device_id);
            // Cancel our connection attempt conceptually - their connection wins
        }

        // Update existing tracking
        tracked->device = device;
        tracked->is_connected = TRUE;
        tracked->is_connecting = FALSE;
        tracked->we_initiated = FALSE;  // They connected to us
        tracked->last_heartbeat = get_current_timestamp();
        tracked->last_disconnect_time = 0;  // Clear disconnect time since we're now connected
        if (mac) strncpy(tracked->mac_address, mac, sizeof(tracked->mac_address) - 1);
    } else {
        // Add new device
        tracked = add_device(device_id, mac, device);
        if (!tracked) return;

        tracked->is_connected = TRUE;
        tracked->we_initiated = FALSE;
        tracked->last_heartbeat = get_current_timestamp();
    }

    binc_device_set_connection_state_change_cb(device, &on_connection_state_changed);

    log_info(BT_TAG, "LocalNet node connected: 0x%08X", device_id);

    if (g_manager->connected_callback) {
        g_manager->connected_callback(device_id);
    }
}

// Authorization callback
// NOLINTNEXTLINE
static gboolean on_request_authorization(Device * device) {
    const char * name = binc_device_get_name(device);
    const char * mac = binc_device_get_address(device);
    log_info(BT_TAG, "Authorizing device: %s (%s)", name ? name : "unknown", mac ? mac : "unknown");

    // Check if this is a LocalNet device we know about
    if (is_localnet_device(name)) {
        const uint32_t device_id = extract_device_id_from_name(name);
        tracked_device_t * tracked = find_device_by_id(device_id);
        if (tracked) {
            log_debug(BT_TAG, "Known LocalNet device 0x%08X requesting authorization", device_id);
        }
    }

    return TRUE;
}

// NOLINTNEXTLINE
static const char* on_local_char_read(const Application * app, const char * address, const char * service_uuid, const char * char_uuid, const guint16 offset, const guint16 mtu) {
    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID)) {
        if (g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
            // Track this connection if we don't already know about it
            tracked_device_t * tracked = find_device_by_mac(address);
            if (!tracked) {
                uint32_t device_id = mac_to_device_id(address);
                tracked = add_device(device_id, address, NULL);
                if (tracked) {
                    tracked->is_connected = TRUE;
                    tracked->we_initiated = FALSE;
                    tracked->last_heartbeat = get_current_timestamp();
                    log_info(BT_TAG, "Detected incoming connection from %s (ID: 0x%08X) via characteristic read", address, device_id);

                    if (g_manager->connected_callback) {
                        g_manager->connected_callback(device_id);
                    }
                }
            } else if (!tracked->is_connected) {
                tracked->is_connected = TRUE;
                tracked->we_initiated = FALSE;
                tracked->last_heartbeat = get_current_timestamp();
                log_info(BT_TAG, "Detected incoming connection from 0x%08X via characteristic read", tracked->device_id);

                if (g_manager->connected_callback) {
                    g_manager->connected_callback(tracked->device_id);
                }
            }

            GByteArray * empty = g_byte_array_new();
            binc_application_set_char_value(app, service_uuid, char_uuid, empty);
            g_byte_array_free(empty, TRUE);
            return NULL;
        }
    }
    return BLUEZ_ERROR_REJECTED;
}

// NOLINTNEXTLINE
static const char * on_local_char_write(const Application * app, const char * address, const char * service_uuid, const char * char_uuid, GByteArray * byteArray, const guint16 offset, const guint16 mtu) {
    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (!g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID)) {
        return BLUEZ_ERROR_REJECTED;
    }

    if (!g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
        return BLUEZ_ERROR_REJECTED;
    }

    if (!byteArray || byteArray->len == 0) return NULL;

    // Find/Create tracked device
    uint32_t device_id = mac_to_device_id(address);
    tracked_device_t * tracked = find_device_by_mac(address);
    gboolean is_new_connection = FALSE;

    if (!tracked) {
        tracked = add_device(device_id, address, NULL);
        is_new_connection = TRUE;
    } else if (!tracked->is_connected) {
        is_new_connection = TRUE;
    }

    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
        if (!tracked->is_connected) {
            tracked->is_connected = TRUE;
            tracked->we_initiated = FALSE;
        }
        device_id = tracked->device_id;
    }

    if (is_new_connection && g_manager->connected_callback) {
        log_info(BT_TAG, "Detected incoming connection from %s (ID: 0x%08X) via characteristic write", address, device_id);
        g_manager->connected_callback(device_id);
    }

    log_debug(BT_TAG, "Received write from %s (ID: 0x%08X): %u bytes", address, device_id, byteArray->len);

    struct header header;
    struct network network;
    if (parse_header(byteArray->data, byteArray->len, &header) != 0) {
        log_error(BT_TAG, "Failed to parse packet header from write");
        return NULL;
    }

    if (byteArray->len < 16 || parse_network(byteArray->data + 8, byteArray->len - 8, &network) != 0) {
        log_error(BT_TAG, "Failed to parse network header from write");
        return NULL;
    }

    if (header.message_type == MSG_HEARTBEAT) {
        struct heartbeat heartbeat;
        if (parse_heartbeat(byteArray->data + 16, byteArray->len - 16, &heartbeat) == 0) {
            log_info(BT_TAG, "Received heartbeat from 0x%08X", network.source_id);

            if (tracked && tracked->device_id == 0 && network.source_id != 0) {
                tracked->device_id = network.source_id;
            }

            if (g_manager->mesh_node && g_manager->mesh_node->connection_table) {
                reset_missed_heartbeats(g_manager->mesh_node->connection_table, network.source_id);
                update_last_seen(g_manager->mesh_node->connection_table, network.source_id, heartbeat.timestamp);
            }
        }
    } else if (g_manager->data_callback) {
        g_manager->data_callback(network.source_id, byteArray->data, byteArray->len);
    }

    return NULL;
}

// NOLINTNEXTLINE
ble_node_manager_t* ble_init(struct mesh_node * mesh_node, uint32_t device_id, ble_discovered_callback discovered_cb, ble_connected_callback connected_cb, ble_disconnected_callback disconnected_cb, ble_data_callback data_cb) {
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
    log_debug(BT_TAG, "Initialized BLE node manager for device ID: 0x%08X", device_id);

    return manager;
}

gboolean ble_start(ble_node_manager_t * manager) {
    if (!manager) return FALSE;

    log_debug(BT_TAG, "Starting BLE node manager");

    // Get DBus connection
    GDBusConnection * dbus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (!dbus) {
        log_error(BT_TAG, "Failed to get DBus connection");
        return FALSE;
    }
    manager->dbus_connection = dbus;

    // Get adapter
    manager->adapter = binc_adapter_get_default(dbus);
    if (!manager->adapter) {
        log_error(BT_TAG, "No Bluetooth adapter found");
        return FALSE;
    }

    log_info(BT_TAG, "Using adapter: %s", binc_adapter_get_name(manager->adapter));

    // Clean up any cached LocalNet devices from previous sessions
    // This includes removing bonding information to ensure fresh connections
    log_debug(BT_TAG, "Cleaning up stale LocalNet devices from previous session");
    GList * existing_devices = binc_adapter_get_devices(manager->adapter);
    for (const GList * it = existing_devices; it != NULL; it = it->next) {
        Device * device = it->data;
        const char * name = binc_device_get_name(device);
        if (is_localnet_device(name)) {
            log_debug(BT_TAG, "Removing stale cached device: %s (bonded: %d)", name,
                binc_device_get_bonding_state(device) == BINC_BONDED);
            // Disconnect if connected
            if (binc_device_get_connection_state(device) == BINC_CONNECTED) {
                binc_device_disconnect(device);
            }
            binc_adapter_remove_device(manager->adapter, device);
        }
    }
    g_list_free(existing_devices);

    // Create agent for pairing
    manager->agent = binc_agent_create(manager->adapter, "/org/bluez/LocalNetAgent", NO_INPUT_NO_OUTPUT);
    binc_agent_set_request_authorization_cb(manager->agent, &on_request_authorization);

    // Setup GATT application
    manager->app = binc_create_application(manager->adapter);
    binc_application_add_service(manager->app, LOCAL_NET_SERVICE_UUID);
    // Add WRITE_WITHOUT_RESP to avoid authorization delays
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID,
        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_WRITE_WITHOUT_RESP | GATT_CHR_PROP_NOTIFY);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_CTRL_CHAR_UUID,
        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_WRITE_WITHOUT_RESP);
    binc_application_set_char_read_cb(manager->app, &on_local_char_read);
    binc_application_set_char_write_cb(manager->app, &on_local_char_write);
    binc_adapter_register_application(manager->adapter, manager->app);

    // Setup discovery callbacks
    binc_adapter_set_discovery_cb(manager->adapter, &on_scan_result);
    binc_adapter_set_discovery_state_cb(manager->adapter, &on_discovery_state_changed);
    binc_adapter_set_remote_central_cb(manager->adapter, &on_remote_central_connected);

    manager->running = TRUE;

    // Start advertising and discovery 
    start_advertising();
    start_discovery();

    log_debug(BT_TAG, "BLE node manager started successfully");
    return TRUE;
}

void ble_stop(ble_node_manager_t * manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Stopping BLE node manager");
    manager->running = FALSE;

    // Stop discovery and advertising
    stop_discovery();
    stop_advertising();

    // Disconnect all connections
    for (guint i = 0; i < manager->discovered_count; i++) {
        const tracked_device_t * tracked = &manager->discovered_devices[i];
        if (tracked->is_connected && tracked->device && tracked->we_initiated) {
            binc_device_disconnect(tracked->device);
        }
    }

    // Remove all cached LocalNet devices from BlueZ to prevent ghost connections on restart
    if (manager->adapter) {
        log_debug(BT_TAG, "Removing cached LocalNet devices from BlueZ...");
        GList * devices = binc_adapter_get_devices(manager->adapter);
        for (const GList * it = devices; it != NULL; it = it->next) {
            Device * device = it->data;
            const char * name = binc_device_get_name(device);
            if (is_localnet_device(name)) {
                log_debug(BT_TAG, "Removing cached device: %s", name);
                binc_adapter_remove_device(manager->adapter, device);
            }
        }
        g_list_free(devices);
    }

    // Unregister GATT application before freeing
    if (manager->app && manager->adapter) {
        binc_adapter_unregister_application(manager->adapter, manager->app);
    }

    // Free advertisement
    if (manager->advertisement) {
        binc_advertisement_free(manager->advertisement);
        manager->advertisement = NULL;
    }

    // Free application
    if (manager->app) {
        binc_application_free(manager->app);
        manager->app = NULL;
    }

    // Free agent
    if (manager->agent) {
        binc_agent_free(manager->agent);
        manager->agent = NULL;
    }

    // Free adapter
    if (manager->adapter) {
        binc_adapter_free(manager->adapter);
        manager->adapter = NULL;
    }

    // Close DBus connection
    if (manager->dbus_connection) {
        g_dbus_connection_close_sync(manager->dbus_connection, NULL, NULL);
        g_object_unref(manager->dbus_connection);
        manager->dbus_connection = NULL;
    }
}

void ble_cleanup(ble_node_manager_t * manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Cleaning up BLE node manager");
    ble_stop(manager);

    g_free(manager->discovered_devices);
    g_free(manager);

    if (g_manager == manager) {
        g_manager = NULL;
    }
}

void ble_run_loop(ble_node_manager_t * manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Running main loop");

    manager->loop = g_main_loop_new(NULL, FALSE);

    // Schedule heartbeat
    manager->heartbeat_source = g_timeout_add_seconds(HEARTBEAT_INTERVAL_SECONDS, heartbeat_callback, NULL);

    g_main_loop_run(manager->loop);

    // Cleanup
    if (manager->heartbeat_source) {
        g_source_remove(manager->heartbeat_source);
        manager->heartbeat_source = 0;
    }

    g_main_loop_unref(manager->loop);
    manager->loop = NULL;
}

void ble_quit_loop(ble_node_manager_t * manager) {
    if (!manager || !manager->loop) return;

    log_debug(BT_TAG, "Quitting main loop");
    g_main_loop_quit(manager->loop);
}

// NOLINTNEXTLINE
gboolean ble_send_data(ble_node_manager_t * manager, uint32_t target_id, const uint8_t * data, size_t len) {
    if (!manager || !data || len == 0) return FALSE;

    tracked_device_t * tracked = find_device_by_id(target_id);
    if (!tracked || !tracked->is_connected) {
        return FALSE;
    }

    GByteArray * byte_array = g_byte_array_sized_new(len);
    g_byte_array_append(byte_array, data, len);

    if (tracked->we_initiated && tracked->device) {
        Characteristic * characteristic = binc_device_get_characteristic(tracked->device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
        if (characteristic) {
            binc_characteristic_write(characteristic, byte_array, WITH_RESPONSE);
            g_byte_array_free(byte_array, TRUE);
            return TRUE;
        }
    } else if (manager->app) {
        binc_application_set_char_value(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, byte_array);
        binc_application_notify(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, byte_array);
        g_byte_array_free(byte_array, TRUE);
        return TRUE;
    }

    g_byte_array_free(byte_array, TRUE);
    return FALSE;
}

// NOLINTNEXTLINE
gboolean ble_broadcast_data(ble_node_manager_t * manager, const uint8_t * data, size_t len) {
    if (!manager || !data || len == 0) return FALSE;

    gboolean sent_any = FALSE;

    for (guint i = 0; i < manager->discovered_count; i++) {
        const tracked_device_t * tracked = &manager->discovered_devices[i];
        if (tracked->is_connected) {
            if (ble_send_data(manager, tracked->device_id, data, len)) {
                sent_any = TRUE;
            }
        }
    }

    return sent_any;
}

guint ble_get_connected_count(ble_node_manager_t * manager) {
    if (!manager) return 0;
    return count_connected();
}

// NOLINTNEXTLINE
void ble_get_connection_table(ble_node_manager_t * manager, uint32_t * devices, guint * count, guint max_count) {
    if (!manager || !devices || !count) return;

    *count = 0;
    for (guint i = 0; i < manager->discovered_count && *count < max_count; i++) {
        if (manager->discovered_devices[i].is_connected) {
            devices[(*count)++] = manager->discovered_devices[i].device_id;
        }
    }
}

void ble_print_connection_table(ble_node_manager_t * manager) {
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
