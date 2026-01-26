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
static gboolean check_pending_connections_idle(gpointer user_data);

// Flag to prevent processing during cleanup/restart operations
static gboolean g_in_cleanup = FALSE;

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

// Validate that a Device pointer is still in the adapter's device list
// Returns TRUE if the device is still valid, FALSE if it's been removed
static gboolean is_device_valid(Device * device) {
    if (!device || !g_manager || !g_manager->adapter) return FALSE;

    GList * devices = binc_adapter_get_devices(g_manager->adapter);
    gboolean found = FALSE;
    for (const GList * it = devices; it != NULL; it = it->next) {
        if (it->data == device) {
            found = TRUE;
            break;
        }
    }
    g_list_free(devices);
    return found;
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

    // Check if already exists by device ID
    tracked_device_t * existing = find_device_by_id(device_id);
    if (existing) {
        if (device) existing->device = device;
        if (mac && mac[0] != '\0') strncpy(existing->mac_address, mac, sizeof(existing->mac_address) - 1);
        existing->last_seen = get_current_timestamp();
        return existing;
    }

    // Also check by MAC address to prevent duplicates when ID changes
    if (mac && mac[0] != '\0') {
        existing = find_device_by_mac(mac);
        if (existing) {
            // Update the device ID if we have a better one (non-zero)
            if (device_id != 0 && existing->device_id != device_id) {
                log_debug(BT_TAG, "Updating device ID for %s from 0x%08X to 0x%08X",
                    mac, existing->device_id, device_id);
                existing->device_id = device_id;
            }
            if (device) existing->device = device;
            existing->last_seen = get_current_timestamp();
            return existing;
        }
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

    // If already advertising, don't restart - this can interfere with active connections
    if (g_manager->advertisement) {
        log_debug(BT_TAG, "Already advertising, not restarting");
        return;
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
    if (!g_manager || !g_manager->adapter) return;
    if (!g_manager->advertisement) return;

    binc_adapter_stop_advertising(g_manager->adapter, g_manager->advertisement);
    binc_advertisement_free(g_manager->advertisement);
    g_manager->advertisement = NULL;
}

// Discovery control 
static gboolean g_discovery_running = FALSE;

static void start_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    if (g_discovery_running) {
        log_debug(BT_TAG, "Discovery already running, not restarting");
        return;
    }
    binc_adapter_set_discovery_filter(g_manager->adapter, -100, NULL, NULL);
    binc_adapter_start_discovery(g_manager->adapter);
}

static void stop_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    binc_adapter_stop_discovery(g_manager->adapter);
    g_discovery_running = FALSE;
}

// Force restart discovery - stops and starts to trigger fresh scan
static gboolean restart_discovery_delayed(gpointer user_data) {
    if (!g_manager || !g_manager->adapter || !g_manager->running) {
        g_in_cleanup = FALSE;
        return FALSE;
    }
    log_debug(BT_TAG, "Delayed discovery restart - starting discovery");
    g_in_cleanup = FALSE;  // Clear flag before starting discovery
    binc_adapter_set_discovery_filter(g_manager->adapter, -100, NULL, NULL);
    binc_adapter_start_discovery(g_manager->adapter);
    return FALSE;  // Don't repeat
}

static void restart_discovery(void) {
    if (!g_manager || !g_manager->adapter) return;
    if (g_in_cleanup) {
        log_debug(BT_TAG, "Already in cleanup, skipping restart_discovery");
        return;
    }
    log_debug(BT_TAG, "Force restarting discovery");
    g_in_cleanup = TRUE;  // Set flag to prevent race conditions during cleanup
    // Stop discovery first
    binc_adapter_stop_discovery(g_manager->adapter);
    g_discovery_running = FALSE;
    // Schedule restart after a short delay to allow BlueZ to clean up
    g_timeout_add(500, restart_discovery_delayed, NULL);
}

// Connect to a device
static void connect_to_device(tracked_device_t * tracked) {
    if (!g_manager || !tracked) return;
    if (!tracked->device) {
        log_debug(BT_TAG, "Cannot connect to 0x%08X - no device pointer", tracked->device_id);
        return;
    }
    if (tracked->is_connected || tracked->is_connecting) {
        log_debug(BT_TAG, "Cannot connect to 0x%08X - already connected/connecting", tracked->device_id);
        return;
    }

    // Validate device is still in adapter's list
    if (!is_device_valid(tracked->device)) {
        log_debug(BT_TAG, "Cannot connect to 0x%08X - device no longer valid", tracked->device_id);
        tracked->device = NULL;
        return;
    }

    // Check if the device is in a bonded state - this causes connection issues
    BondingState bond_state = binc_device_get_bonding_state(tracked->device);

    if (bond_state == BINC_BONDED) {
        log_info(BT_TAG, "Device 0x%08X is bonded, removing to prevent connection issues", tracked->device_id);

        // IMPORTANT: NULL out pointer BEFORE calling remove to prevent race conditions
        Device * device_to_remove = tracked->device;
        tracked->device = NULL;
        tracked->is_connecting = FALSE;
        tracked->is_connected = FALSE;

        // Remove the device entirely - this should clear bonding
        binc_adapter_remove_device(g_manager->adapter, device_to_remove);

        // Set last_connect_attempt further in the past to allow immediate retry after rediscovery
        // Set last_seen to now so we can track when to force discovery restart
        tracked->last_connect_attempt = get_current_timestamp() - RECONNECT_DELAY_SECONDS + 1;
        tracked->last_seen = get_current_timestamp();

        // Device will be rediscovered (hopefully without bond) and we can try connecting again
        // Force restart discovery to speed up rediscovery
        restart_discovery();
        return;
    }

    log_info(BT_TAG, "Connecting to device 0x%08X", tracked->device_id);

    // Mark as connecting to prevent duplicate attempts
    tracked->is_connecting = TRUE;
    tracked->last_connect_attempt = get_current_timestamp();

    // DON'T stop advertising or discovery - modern BLE can handle simultaneous operations
    // This keeps us discoverable and able to discover other nodes during connection

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
            tracked->is_connecting = FALSE;
            timed_out++;

            // Disconnect the device 
            if (tracked->device && tracked->we_initiated) {
                binc_device_disconnect(tracked->device);
            }

            // Clear the device pointer - it will be set again when rediscovered
            tracked->device = NULL;
            tracked->last_disconnect_time = now;

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
        tracked_device_t * tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected || !tracked->we_initiated || !tracked->device) continue;

        // Validate device is still valid before using it
        if (!is_device_valid(tracked->device)) {
            log_debug(BT_TAG, "Skipping heartbeat to 0x%08X - device no longer valid", tracked->device_id);
            tracked->device = NULL;  // Clear stale pointer
            continue;
        }

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

    // Periodically restart discovery to ensure we're actively scanning
    // This helps work around BLE stack issues where discovery might stall
    static guint heartbeat_count = 0;
    heartbeat_count++;
    if (heartbeat_count % 3 == 0) {  // Every 30 seconds (3 heartbeats)
        log_debug(BT_TAG, "Periodic discovery restart");
        start_discovery();
    }

    return TRUE;
}

// Discovery state callback
// NOLINTNEXTLINE
static void on_discovery_state_changed(Adapter * adapter, DiscoveryState state, const GError * error) {
    const char * state_name = "UNKNOWN";
    switch (state) {
        case BINC_DISCOVERY_STARTING: state_name = "STARTING"; break;
        case BINC_DISCOVERY_STARTED:
            state_name = "STARTED";
            g_discovery_running = TRUE;
            break;
        case BINC_DISCOVERY_STOPPED:
            state_name = "STOPPED";
            g_discovery_running = FALSE;
            break;
        case BINC_DISCOVERY_STOPPING: state_name = "STOPPING"; break;
    }
    if (error) {
        log_error(BT_TAG, "Discovery state changed to %s (error: %s)", state_name, error->message);
    } else {
        log_info(BT_TAG, "Discovery state changed to %s", state_name);
    }
}

// Scan result callback
// NOLINTNEXTLINE
static void on_scan_result(Adapter * adapter, Device * device) {
    if (!g_manager || !device) return;

    // Skip processing during cleanup to prevent race conditions
    if (g_in_cleanup) return;

    const char * name = binc_device_get_name(device);
    const char * mac = binc_device_get_address(device);

    if (!is_localnet_device(name)) return;

    const uint32_t device_id = extract_device_id_from_name(name);
    if (device_id == 0 || device_id == g_manager->device_id) return;

    const int16_t rssi = binc_device_get_rssi(device);
    const uint64_t now = get_current_timestamp();

    // Check if we already know this device
    tracked_device_t * tracked = find_device_by_id(device_id);
    if (tracked) {
        tracked->rssi = rssi;
        // Only update device pointer, don't reset last_seen for existing devices
        // last_seen tracks when we FIRST saw this device (for "they_are_slow" logic)
        tracked->device = device;

        // If already connected or currently connecting, just update and return
        if (tracked->is_connected || tracked->is_connecting) {
            return;
        }
    } else {
        // New device - log discovery and add to tracking
        log_info(BT_TAG, "Discovered LocalNet node: 0x%08X (RSSI: %d)", device_id, rssi);
        tracked = add_device(device_id, mac, device);
        if (!tracked) return;
        tracked->rssi = rssi;
        tracked->last_seen = now;  // Only set last_seen for NEW devices

        // Call discovery callback for new devices
        if (g_manager->discovered_callback) {
            g_manager->discovered_callback(device_id, rssi);
        }
    }

    // Rate limit connection attempts for this specific device
    // Handle case where last_connect_attempt might be in the future (after stuck connection cleanup)
    if (tracked->last_connect_attempt > now ||
        (now - tracked->last_connect_attempt < RECONNECT_DELAY_SECONDS)) {
        log_debug(BT_TAG, "Rate limiting connection to 0x%08X", device_id);
        return;
    }

    // Check if we're already in the process of connecting to another device
    // If so, still track this device but don't initiate a connection yet
    // The periodic check_pending_connections_idle will handle it later
    gboolean already_connecting = FALSE;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].is_connecting) {
            already_connecting = TRUE;
            break;
        }
    }

    // Decide if we should initiate connection
    gboolean we_have_priority = (g_manager->device_id < device_id);
    // Wait longer (20 seconds) before initiating connection if we don't have priority
    // This gives the higher priority device time to connect first
    gboolean they_are_slow = (now - tracked->last_seen > 20);

    if (already_connecting) {
        // Don't initiate new connection, but device is tracked for later
        log_debug(BT_TAG, "Already connecting to another device, 0x%08X tracked for later", device_id);
        return;
    }

    // Initiate connection based on priority
    if (we_have_priority) {
        // We have priority - connect immediately
        log_debug(BT_TAG, "Connecting to 0x%08X (we have lower ID, priority)", device_id);
        connect_to_device(tracked);
    } else if (they_are_slow) {
        // They have priority but haven't connected to us yet
        log_debug(BT_TAG, "Attempting connection to 0x%08X (they have priority but haven't connected)", device_id);
        connect_to_device(tracked);
    } else {
        log_debug(BT_TAG, "Waiting for 0x%08X to connect (they have lower ID)", device_id);
    }
}

// Connection state change callback
// NOLINTNEXTLINE
static void on_connection_state_changed(Device * device, ConnectionState state, const GError * error) {
    if (!g_manager || !device) return;

    // Validate device is still in adapter's list before using it
    if (!is_device_valid(device)) {
        log_debug(BT_TAG, "Connection state callback for removed device, ignoring");
        return;
    }

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

            // Only remove device from cache if it's bonded and we failed to connect
            // Don't remove on normal disconnects - this causes rediscovery delays
            // The device will be rediscovered naturally when it starts advertising again

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


// Helper to restart advertising/discovery after a short delay
static gboolean restart_advertising_discovery_idle(gpointer user_data) {
    if (!g_manager || !g_manager->running) return FALSE;

    log_info(BT_TAG, "Restarting advertising and discovery after connection");

    // Always ensure we're advertising so other nodes can find us
    start_advertising();

    // Restart discovery to find more nodes
    start_discovery();

    return FALSE;  // Don't repeat
}

// Helper to check if there are pending connections we should initiate
// Also checks for stuck connections and cleans them up
// Returns TRUE to keep running as a periodic timer
static gboolean check_pending_connections_idle(gpointer user_data) {
    if (!g_manager || !g_manager->running) return FALSE;

    const uint64_t now = get_current_timestamp();

    // Ensure discovery is running - if not, restart it
    if (!g_discovery_running) {
        log_warn(BT_TAG, "Discovery not running, restarting");
        start_discovery();
    }

    // Check if we're already connecting to something
    gboolean already_connecting = FALSE;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t * tracked = &g_manager->discovered_devices[i];
        if (tracked->is_connecting) {
            // Check for stuck connections (connecting for more than 15 seconds)
            if (now - tracked->last_connect_attempt > 15) {
                log_warn(BT_TAG, "Connection to 0x%08X stuck for 15+ seconds, canceling", tracked->device_id);
                tracked->is_connecting = FALSE;

                // Just remove the device from BlueZ cache - don't try to disconnect
                // a device that's stuck in connecting state as it may crash
                if (tracked->device) {
                    // IMPORTANT: NULL out pointer BEFORE calling remove to prevent
                    // race conditions with callbacks that might access this device
                    Device * device_to_remove = tracked->device;
                    tracked->device = NULL;
                    binc_adapter_remove_device(g_manager->adapter, device_to_remove);
                }

                // Mark last_seen as now so we can track when to force discovery restart
                // (Setting to 0 would break the timeout logic in the pending connection check)
                tracked->last_seen = now;
                // Add longer cooldown (10 seconds) after canceling stuck connection
                tracked->last_connect_attempt = now + 5;  // Will need to wait extra 5 + RECONNECT_DELAY seconds

                // Force restart discovery to find the device again after removal
                restart_discovery();
            } else {
                already_connecting = TRUE;
            }
        }
    }

    // If still connecting to something, wait for it to complete
    if (already_connecting) {
        return TRUE;
    }

    // Find devices we should connect to but haven't yet
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t * tracked = &g_manager->discovered_devices[i];

        // Skip if no device ID, already connected
        if (tracked->device_id == 0) continue;
        if (tracked->is_connected) continue;

        // Check rate limiting - handle case where last_connect_attempt might be in the future
        if (tracked->last_connect_attempt > now ||
            (now - tracked->last_connect_attempt < RECONNECT_DELAY_SECONDS)) {
            continue;
        }

        // We need a valid device pointer to connect
        if (!tracked->device) {
            // If we've been waiting too long for discovery, try to force restart discovery
            // This can happen if the remote device is advertising but we're not scanning
            // Only do this if last_seen is set (meaning we saw this device before)
            if (tracked->last_seen > 0 && (now - tracked->last_seen > 15)) {
                log_warn(BT_TAG, "Device 0x%08X not rediscovered for 15+ seconds, restarting discovery",
                    tracked->device_id);
                // Force restart discovery (stop + start)
                restart_discovery();
                // Reset last_seen to current time to avoid spamming this
                tracked->last_seen = now;
            } else {
                log_debug(BT_TAG, "Pending connection to 0x%08X but no device pointer, waiting for discovery",
                    tracked->device_id);
            }
            continue;
        }

        // Priority logic: connect to devices where we have lower ID first
        // Also connect to higher priority devices if they haven't connected to us after 20+ seconds
        gboolean we_have_priority = (g_manager->device_id < tracked->device_id);
        gboolean they_are_slow = (tracked->last_seen > 0 && (now - tracked->last_seen > 20));

        if (we_have_priority || they_are_slow) {
            // Double-check device is still valid right before connecting
            if (!is_device_valid(tracked->device)) {
                log_debug(BT_TAG, "Device 0x%08X no longer valid before connection, clearing", tracked->device_id);
                tracked->device = NULL;
                continue;
            }
            log_info(BT_TAG, "Initiating pending connection to 0x%08X (priority: %s, slow: %s)",
                tracked->device_id, we_have_priority ? "yes" : "no", they_are_slow ? "yes" : "no");
            connect_to_device(tracked);
            return TRUE;  // Keep the timer running
        }
    }

    return TRUE;  // Keep the timer running
}

static void on_services_resolved(Device * device) {
    if (!g_manager || !device) return;

    // Validate device is still valid
    if (!is_device_valid(device)) {
        log_debug(BT_TAG, "Services resolved callback for removed device, ignoring");
        return;
    }

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
}

// NOLINTNEXTLINE
static void on_notify(Device * device, Characteristic * characteristic, const GByteArray * byteArray) {
    if (!g_manager || !device || !byteArray || byteArray->len == 0) return;

    // Validate device is still valid
    if (!is_device_valid(device)) return;

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
    if (error && device && is_device_valid(device)) {
        const tracked_device_t * tracked = find_device_by_ptr(device);
        log_error(BT_TAG, "Write characteristic error for 0x%08X: %s", tracked ? tracked->device_id : 0, error->message);
    }
}

// NOLINTNEXTLINE
static void on_remote_central_connected(Adapter * adapter, Device * device) {
    if (!g_manager || !device) return;

    // Validate device and skip during cleanup
    if (g_in_cleanup || !is_device_valid(device)) {
        log_debug(BT_TAG, "Remote central connected callback during cleanup or for invalid device, ignoring");
        return;
    }

    const char * name = binc_device_get_name(device);
    const char * mac = binc_device_get_address(device);

    // Log all connection attempts for debugging
    log_debug(BT_TAG, "on_remote_central_connected called for %s (%s)",
        name ? name : "unknown", mac ? mac : "unknown");

    // Identify the device - only trust LOCALNET names or previously discovered devices
    uint32_t device_id = 0;
    if (is_localnet_device(name)) {
        device_id = extract_device_id_from_name(name);
    } else {
        // Try to find by MAC - we might have discovered this device via scanning
        tracked_device_t * existing = find_device_by_mac(mac);
        if (existing && existing->device_id != 0) {
            device_id = existing->device_id;
            log_debug(BT_TAG, "Found existing device 0x%08X by MAC %s", device_id, mac);
        } else {
            // Don't create a new entry - wait for proper identification via characteristic write
            log_debug(BT_TAG, "Unknown device connected - waiting for identification");
            binc_device_set_connection_state_change_cb(device, &on_connection_state_changed);
            return;
        }
    }

    if (device_id == 0) {
        log_debug(BT_TAG, "Non-LocalNet device connected: %s", mac);
        return;
    }

    // Debounce check - if we just disconnected from this device, ignore spurious reconnection
    // Use a short debounce (2 seconds) to filter ghost callbacks but allow real reconnections
    tracked_device_t * existing_tracked = find_device_by_id(device_id);
    if (existing_tracked) {
        const uint64_t now = get_current_timestamp();

        // Short debounce - ignore reconnections within 2 seconds of disconnect
        if (existing_tracked->last_disconnect_time > 0 &&
            (now - existing_tracked->last_disconnect_time < 2)) {
            log_debug(BT_TAG, "Ignoring spurious reconnection from 0x%08X (disconnected %lu seconds ago)",
                device_id, (unsigned long)(now - existing_tracked->last_disconnect_time));
            return;  // Just ignore, don't forcefully disconnect - it might be a ghost callback
        }

        // If we're currently trying to connect to this device, cancel our attempt
        if (existing_tracked->is_connecting) {
            log_info(BT_TAG, "Device 0x%08X connected to us while we were connecting - accepting theirs", device_id);
            existing_tracked->is_connecting = FALSE;

            // If we have an outgoing connection attempt, cancel it
            if (existing_tracked->device && existing_tracked->device != device) {
                // IMPORTANT: NULL out pointer BEFORE calling disconnect/remove
                Device * old_device = existing_tracked->device;
                existing_tracked->device = NULL;
                binc_device_disconnect(old_device);
                binc_adapter_remove_device(g_manager->adapter, old_device);
            }
        }

        // If already connected, this might be a duplicate - disconnect and ignore
        if (existing_tracked->is_connected) {
            log_warn(BT_TAG, "Device 0x%08X already connected, rejecting duplicate connection", device_id);
            binc_device_disconnect(device);
            return;
        }
    }

    log_info(BT_TAG, "Remote connected: %s (%s)", name ? name : "unknown", mac);

    // Track the connection
    tracked_device_t * tracked = find_device_by_id(device_id);
    if (tracked) {
        tracked->device = device;
        tracked->is_connected = TRUE;
        tracked->is_connecting = FALSE;
        tracked->we_initiated = FALSE;
        tracked->last_heartbeat = get_current_timestamp();
        tracked->last_disconnect_time = 0;
        if (mac) strncpy(tracked->mac_address, mac, sizeof(tracked->mac_address) - 1);
    } else {
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

    // IMPORTANT: When we're the peripheral (they connected to us), we need to ensure
    // we're still advertising and discovering so other nodes can find us
    // Schedule restart after a delay to let the connection stabilize
    g_timeout_add(1000, restart_advertising_discovery_idle, NULL);
}

// Authorization callback
// NOLINTNEXTLINE
static gboolean on_request_authorization(Device * device) {
    if (!device || !is_device_valid(device)) {
        return FALSE;  // Reject invalid device
    }

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
            // Only update tracking if we already know about this device (from scanning or prior writes)
            // Don't create new entries here since we don't know the real device ID from a read
            tracked_device_t * tracked = find_device_by_mac(address);
            if (tracked && !tracked->is_connected) {
                tracked->is_connected = TRUE;
                tracked->we_initiated = FALSE;
                tracked->last_heartbeat = get_current_timestamp();
                log_info(BT_TAG, "Detected incoming connection from 0x%08X via characteristic read", tracked->device_id);

                if (g_manager->connected_callback) {
                    g_manager->connected_callback(tracked->device_id);
                }
            } else if (!tracked) {
                // Unknown device reading our characteristic - they'll identify themselves when they write
                log_debug(BT_TAG, "Unknown device %s reading characteristic - waiting for write to identify", address);
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

    // Parse the packet first to get the real device ID from the source
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

    // Use the source_id from the packet as the authoritative device ID
    uint32_t device_id = network.source_id;
    if (device_id == 0) {
        // Fallback to MAC-derived ID if source_id is not set
        device_id = mac_to_device_id(address);
    }

    // Find tracked device - first by ID, then by MAC
    tracked_device_t * tracked = find_device_by_id(device_id);
    if (!tracked) {
        tracked = find_device_by_mac(address);
    }

    gboolean is_new_connection = FALSE;

    if (!tracked) {
        tracked = add_device(device_id, address, NULL);
        is_new_connection = TRUE;
    } else {
        // Update device ID if we had a placeholder/wrong ID from MAC
        if (tracked->device_id != device_id && device_id != 0) {
            log_debug(BT_TAG, "Updating device ID from 0x%08X to 0x%08X", tracked->device_id, device_id);
            tracked->device_id = device_id;
        }
        if (!tracked->is_connected) {
            is_new_connection = TRUE;
        }
    }

    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
        if (!tracked->is_connected) {
            tracked->is_connected = TRUE;
            tracked->we_initiated = FALSE;
        }
        // Update MAC if we didn't have it
        if (address && tracked->mac_address[0] == '\0') {
            strncpy(tracked->mac_address, address, sizeof(tracked->mac_address) - 1);
        }
    }

    if (is_new_connection && g_manager->connected_callback) {
        log_info(BT_TAG, "Detected incoming connection from %s (ID: 0x%08X) via characteristic write", address, device_id);
        g_manager->connected_callback(device_id);
    }

    log_debug(BT_TAG, "Received write from %s (ID: 0x%08X): %u bytes", address, device_id, byteArray->len);

    if (header.message_type == MSG_HEARTBEAT) {
        struct heartbeat heartbeat;
        if (parse_heartbeat(byteArray->data + 16, byteArray->len - 16, &heartbeat) == 0) {
            log_info(BT_TAG, "Received heartbeat from 0x%08X", network.source_id);


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

    log_info(BT_TAG, "Starting BLE node manager");

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

    // CRITICAL: Aggressively clean up any cached LocalNet devices BEFORE registering callbacks
    log_info(BT_TAG, "Performing aggressive cleanup of cached LocalNet devices...");

    // Pass 1: Force disconnect all LocalNet devices
    GList * existing_devices = binc_adapter_get_devices(manager->adapter);
    guint disconnect_count = 0;
    for (const GList * it = existing_devices; it != NULL; it = it->next) {
        Device * device = it->data;
        const char * name = binc_device_get_name(device);
        if (is_localnet_device(name)) {
            ConnectionState conn_state = binc_device_get_connection_state(device);
            log_debug(BT_TAG, "Found cached LocalNet device: %s (state: %d)", name, conn_state);

            // Always try to disconnect, regardless of reported state
            binc_device_disconnect(device);
            disconnect_count++;
        }
    }
    g_list_free(existing_devices);

    if (disconnect_count > 0) {
        log_debug(BT_TAG, "Waiting for %u disconnections to complete...", disconnect_count);
        g_usleep(500000);  // 500ms - longer delay for disconnections
    }

    // Pass 2: Remove all LocalNet devices from BlueZ cache
    existing_devices = binc_adapter_get_devices(manager->adapter);
    guint remove_count = 0;
    for (const GList * it = existing_devices; it != NULL; it = it->next) {
        Device * device = it->data;
        const char * name = binc_device_get_name(device);
        const char * mac = binc_device_get_address(device);

        if (is_localnet_device(name)) {
            log_debug(BT_TAG, "Removing cached device: %s (%s)", name, mac);
            binc_adapter_remove_device(manager->adapter, device);
            remove_count++;
        }
    }
    g_list_free(existing_devices);

    if (remove_count > 0) {
        log_debug(BT_TAG, "Waiting for %u device removals to complete...", remove_count);
        g_usleep(500000);  // 500ms - longer delay for removals
    }

    log_info(BT_TAG, "Cleanup complete - disconnected %u, removed %u devices", disconnect_count, remove_count);

    // Create agent for pairing (JustWorks - no bonding)
    manager->agent = binc_agent_create(manager->adapter, "/org/bluez/LocalNetAgent", NO_INPUT_NO_OUTPUT);
    binc_agent_set_request_authorization_cb(manager->agent, &on_request_authorization);

    // Setup GATT application
    manager->app = binc_create_application(manager->adapter);
    binc_application_add_service(manager->app, LOCAL_NET_SERVICE_UUID);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID,
        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_WRITE_WITHOUT_RESP | GATT_CHR_PROP_NOTIFY);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_CTRL_CHAR_UUID,
        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_WRITE_WITHOUT_RESP);
    binc_application_set_char_read_cb(manager->app, &on_local_char_read);
    binc_application_set_char_write_cb(manager->app, &on_local_char_write);
    binc_adapter_register_application(manager->adapter, manager->app);

    // Setup discovery callbacks AFTER cleanup
    binc_adapter_set_discovery_cb(manager->adapter, &on_scan_result);
    binc_adapter_set_discovery_state_cb(manager->adapter, &on_discovery_state_changed);
    binc_adapter_set_remote_central_cb(manager->adapter, &on_remote_central_connected);

    manager->running = TRUE;

    // Start advertising and discovery 
    start_advertising();
    start_discovery();

    log_info(BT_TAG, "BLE node manager started successfully");
    return TRUE;
}

void ble_stop(ble_node_manager_t * manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Stopping BLE node manager");
    manager->running = FALSE;

    // Stop discovery and advertising first
    stop_discovery();
    stop_advertising();

    // Disconnect all connections we initiated
    for (guint i = 0; i < manager->discovered_count; i++) {
        tracked_device_t * tracked = &manager->discovered_devices[i];
        if (tracked->is_connected && tracked->device && tracked->we_initiated) {
            log_debug(BT_TAG, "Disconnecting from 0x%08X", tracked->device_id);
            binc_device_disconnect(tracked->device);
            tracked->is_connected = FALSE;
            tracked->device = NULL;
        }
    }

    // Small delay to let disconnections complete
    g_usleep(100000);  // 100ms

    // Remove all cached LocalNet devices from BlueZ to prevent ghost connections on restart
    if (manager->adapter) {
        log_debug(BT_TAG, "Removing all cached LocalNet devices from BlueZ...");
        GList * devices = binc_adapter_get_devices(manager->adapter);
        for (const GList * it = devices; it != NULL; it = it->next) {
            Device * device = it->data;
            const char * name = binc_device_get_name(device);
            if (is_localnet_device(name)) {
                log_debug(BT_TAG, "Removing cached device: %s", name);
                // Disconnect if still connected
                if (binc_device_get_connection_state(device) == BINC_CONNECTED) {
                    binc_device_disconnect(device);
                }
                binc_adapter_remove_device(manager->adapter, device);
            }
        }
        g_list_free(devices);
    }

    // Small delay to let removals complete
    g_usleep(100000);  // 100ms

    // Unregister GATT application before freeing
    if (manager->app && manager->adapter) {
        log_debug(BT_TAG, "Unregistering GATT application");
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

    log_debug(BT_TAG, "BLE node manager stopped");
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

    // Schedule periodic connection check every 5 seconds to ensure we connect to all discovered devices
    manager->connection_check_source = g_timeout_add_seconds(5, check_pending_connections_idle, NULL);

    g_main_loop_run(manager->loop);

    // Cleanup
    if (manager->heartbeat_source) {
        g_source_remove(manager->heartbeat_source);
        manager->heartbeat_source = 0;
    }

    if (manager->connection_check_source) {
        g_source_remove(manager->connection_check_source);
        manager->connection_check_source = 0;
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
