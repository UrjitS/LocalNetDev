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
#include "handlers.h"
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

static void remove_tracked_device(const uint32_t device_id) {
    if (!g_manager) return;
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        if (g_manager->discovered_devices[i].device_id == device_id) {
            // Shift remaining elements down
            for (guint j = i; j < g_manager->discovered_count - 1; j++) {
                g_manager->discovered_devices[j] = g_manager->discovered_devices[j + 1];
            }
            g_manager->discovered_count--;
            memset(&g_manager->discovered_devices[g_manager->discovered_count], 0, sizeof(tracked_device_t));
            return;
        }
    }
}

static void clear_all_tracked_devices(void) {
    if (!g_manager || !g_manager->discovered_devices) return;
    memset(g_manager->discovered_devices, 0, sizeof(tracked_device_t) * MAX_DISCOVERED_DEVICES);
    g_manager->discovered_count = 0;
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
    if (tracked->is_connected) return;

    log_info(BT_TAG, "Connecting to device 0x%08X", tracked->device_id);

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

    // Collect timed out device IDs first (iterate backwards to safely remove)
    uint32_t timed_out_ids[MAX_DISCOVERED_DEVICES];
    guint timed_out_count = 0;

    // Check all connected devices for heartbeat timeout
    for (guint i = 0; i < g_manager->discovered_count; i++) {
        tracked_device_t * tracked = &g_manager->discovered_devices[i];
        if (!tracked->is_connected) continue;

        connected++;

        // Check for timeout 
        if (now - tracked->last_heartbeat > HEARTBEAT_TIMEOUT_SECONDS) {
            log_info(BT_TAG, "Heartbeat timeout: disconnecting 0x%08X", tracked->device_id);
            timed_out_ids[timed_out_count++] = tracked->device_id;
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

    // Now remove timed out devices from internal tracking
    for (guint i = 0; i < timed_out_count; i++) {
        remove_tracked_device(timed_out_ids[i]);
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

    /* Process retransmissions and route request timeouts */
    ble_process_retransmissions(g_manager);

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

    // Check if already connected, update rssi if we are
    tracked_device_t * tracked = find_device_by_id(device_id);
    if (tracked && tracked->is_connected) {
        tracked->rssi = rssi;
        tracked->last_seen = get_current_timestamp();
        return;
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

    if (g_manager->device_id > device_id) {
        log_debug(BT_TAG, "Connecting to 0x%08X", device_id);
        connect_to_device(tracked);
    } else {
        log_debug(BT_TAG, "Waiting for 0x%08X to connect to us", device_id);
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
            start_advertising();
            start_discovery();
            break;
        case BINC_DISCONNECTED:
            if (tracked) {
                const gboolean was_connected = tracked->is_connected;
                const uint32_t tracked_device_id = tracked->device_id;
                tracked->is_connected = FALSE;
                tracked->device = NULL;

                if (was_connected && g_manager->disconnected_callback) {
                    g_manager->disconnected_callback(tracked_device_id);
                }

                // Remove from internal tracking to prevent stale cache
                remove_tracked_device(tracked_device_id);
            }

            // Remove device from BlueZ cache to allow fresh discovery 
            if (binc_device_get_bonding_state(device) != BINC_BONDED) {
                binc_adapter_remove_device(g_manager->adapter, device);
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

static void on_services_resolved(Device * device) {
    if (!g_manager || !device) return;

    tracked_device_t * tracked = find_device_by_ptr(device);
    if (!tracked) return;

    log_debug(BT_TAG, "Services resolved for device 0x%08X", tracked->device_id);

    tracked->is_connected = TRUE;
    tracked->last_heartbeat = get_current_timestamp();

    Characteristic * characteristic = binc_device_get_characteristic(device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
    if (characteristic) {
        binc_characteristic_start_notify(characteristic);
    }

    log_debug(BT_TAG, "Restarting advertising and discovery after successful connection");
    // start_advertising();
    start_discovery();

    if (g_manager->connected_callback) {
        g_manager->connected_callback(tracked->device_id);
    }
}

// Helper function to process handler result and dispatch BLE actions
static void process_handler_result(struct handler_result *result, const uint8_t *data, size_t data_len) {
    if (!g_manager || !result) return;

    switch (result->action) {
        case HANDLER_ACTION_SEND_REPLY:
        case HANDLER_ACTION_FORWARD_REPLY:
            ble_send_route_reply(g_manager, result->target_node, result->request_id,
                                 result->route_cost, result->forward_path, result->forward_path_len);
            break;

        case HANDLER_ACTION_FORWARD_REQUEST:
            ble_broadcast_route_request(g_manager, result->request_id, result->destination_id,
                                        result->hop_count, result->reverse_path,
                                        result->reverse_path_len, result->exclude_neighbor);
            break;

        case HANDLER_ACTION_ROUTE_COMPLETE:
            /* Route discovery complete - check for queued packets to send */
            log_info(BT_TAG, "Route discovery complete for 0x%08X", result->destination_id);
            ble_send_queued_packets(g_manager, result->destination_id);
            break;

        case HANDLER_ACTION_CALL_DATA_CALLBACK:
            if (g_manager->data_callback) {
                g_manager->data_callback(result->source_id, data, data_len);
            }
            break;

        case HANDLER_ACTION_SEND_ACK: {
            /* Send acknowledgement back to source */
            uint8_t ack_buffer[64];
            const size_t ack_len = create_acknowledgement_packet(
                result->sequence_number,
                result->status_code,
                ack_buffer,
                sizeof(ack_buffer),
                g_manager->device_id,
                result->target_node
            );
            if (ack_len > 0) {
                ble_send_data(g_manager, result->target_node, ack_buffer, ack_len);
                log_debug(BT_TAG, "Sent ACK for seq %u to 0x%08X",
                         result->sequence_number, result->target_node);
            }
            /* Also deliver data locally if this was for us */
            if (g_manager->data_callback) {
                g_manager->data_callback(result->source_id, data, data_len);
            }
            break;
        }

        case HANDLER_ACTION_FORWARD_DATA:
            /* Forward data packet to next hop */
            if (result->packet_data && result->packet_len > 0) {
                if (ble_send_data(g_manager, result->next_hop, result->packet_data, result->packet_len)) {
                    log_debug(BT_TAG, "Forwarded packet to next hop 0x%08X", result->next_hop);
                } else {
                    log_error(BT_TAG, "Failed to forward packet to 0x%08X", result->next_hop);
                }
            }
            break;

        case HANDLER_ACTION_INITIATE_ROUTE_DISCOVERY: {
            /* Queue the packet and initiate route discovery if not already pending */
            if (result->packet_data && result->packet_len > 0 && g_manager->mesh_node->packet_queue) {
                const uint32_t current_time_ms = get_current_timestamp() * 1000;
                queue_packet_for_transmission(g_manager->mesh_node->packet_queue,
                                             result->destination_id,
                                             result->packet_data,
                                             result->packet_len,
                                             current_time_ms);
                /* Mark packet as awaiting route */
                struct pending_packet_queue *queue = g_manager->mesh_node->packet_queue;
                for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
                    if (queue->packets[i].destination_id == result->destination_id &&
                        queue->packets[i].state == PACKET_STATE_AWAITING_ACK) {
                        queue->packets[i].state = PACKET_STATE_AWAITING_ROUTE;
                    }
                }
            }

            /* Initiate route discovery if no request is pending */
            if (result->request_id == 0) {
                const uint32_t request_id = ble_initiate_route_discovery(g_manager, result->destination_id);
                if (request_id > 0) {
                    log_info(BT_TAG, "Initiated route discovery for 0x%08X (request: 0x%08X)",
                            result->destination_id, request_id);
                    /* Associate with queued packets */
                    if (g_manager->mesh_node->packet_queue) {
                        associate_route_request_with_packets(g_manager->mesh_node->packet_queue,
                                                            result->destination_id,
                                                            request_id);
                    }
                }
            } else {
                log_debug(BT_TAG, "Route discovery already pending for 0x%08X (request: 0x%08X)",
                         result->destination_id, result->request_id);
            }
            break;
        }

        case HANDLER_ACTION_TTL_EXPIRED:
        case HANDLER_ACTION_DEST_UNREACHABLE: {
            /* Send error acknowledgement back to source */
            uint8_t ack_buffer[64];
            const size_t ack_len = create_acknowledgement_packet(
                result->sequence_number,
                result->status_code,
                ack_buffer,
                sizeof(ack_buffer),
                g_manager->device_id,
                result->target_node
            );
            if (ack_len > 0) {
                ble_send_data(g_manager, result->target_node, ack_buffer, ack_len);
                log_debug(BT_TAG, "Sent error ACK (status: %u) for seq %u to 0x%08X",
                         result->status_code, result->sequence_number, result->target_node);
            }
            break;
        }

        case HANDLER_ACTION_NONE:
        case HANDLER_ACTION_ERROR:
        default:
            break;
    }

    free_handler_result(result);
}

// NOLINTNEXTLINE
static void on_notify(Device * device, Characteristic * characteristic, const GByteArray * byteArray) {
    if (!g_manager || !byteArray || byteArray->len == 0) return;

    tracked_device_t * tracked = find_device_by_ptr(device);
    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
    }

    const uint32_t sender_id = tracked ? tracked->device_id : 0;

    struct handler_result result;
    if (handle_incoming_packet(g_manager->mesh_node, byteArray->data, byteArray->len,
                                sender_id, &result) == 0) {
        process_handler_result(&result, byteArray->data, byteArray->len);
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
    // Reject connections if we're not actively advertising
    if (!g_manager->advertisement) {
        log_info(BT_TAG, "Rejecting ghost connection from %s", mac);
        binc_device_disconnect(device);
        binc_adapter_remove_device(adapter, device);
        return;
    }
    // Identify the device
    uint32_t device_id = 0;
    if (is_localnet_device(name)) {
        device_id = extract_device_id_from_name(name);
    } else {
        device_id = mac_to_device_id(mac);
    }

    if (device_id == 0) {
        log_info(BT_TAG, "Non-LocalNet device connected: %s", mac);
        return;
    }

    log_info(BT_TAG, "Remote connected: %s (%s)", name ? name : "unknown", mac);

    // Track device
    tracked_device_t * tracked = add_device(device_id, mac, device);
    if (!tracked) return;

    tracked->is_connected = TRUE;
    tracked->we_initiated = FALSE;
    tracked->last_heartbeat = get_current_timestamp();

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
    log_info(BT_TAG, "Authorizing device: %s", name ? name : "unknown");
    return TRUE;
}

// NOLINTNEXTLINE
static const char* on_local_char_read(const Application * app, const char * address, const char * service_uuid, const char * char_uuid, const guint16 offset, const guint16 mtu) {
    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID)) {
        if (g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
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

    if (!tracked) {
        tracked = add_device(device_id, address, NULL);
    }

    if (tracked) {
        tracked->last_heartbeat = get_current_timestamp();
        tracked->is_connected = TRUE;
        device_id = tracked->device_id;
    }

    log_info(BT_TAG, "Received write from %s (ID: 0x%08X): %u bytes", address, device_id, byteArray->len);

    struct handler_result result;
    if (handle_incoming_packet(g_manager->mesh_node, byteArray->data, byteArray->len,
                                device_id, &result) == 0) {
        // Update tracked device ID from packet if we didn't have one
        if (tracked && tracked->device_id == 0 && result.source_id != 0) {
            tracked->device_id = result.source_id;
        }

        process_handler_result(&result, byteArray->data, byteArray->len);
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

    // Power cycle the adapter to ensure clean state - this forces BlueZ to drop
    // any auto-reconnection attempts and cached connection state from previous sessions
    log_debug(BT_TAG, "Power cycling adapter to clear previous session state...");
    // Power on
    binc_adapter_power_on(manager->adapter);

    // Poll until ready (max 5 seconds)
    for (int i = 0; i < 50; i++) {
        g_usleep(100000);  // 100ms
        if (binc_adapter_is_discoverable(manager->adapter)) {
            g_usleep(500000);  // Extra 500ms for stability
            break;
        }
    }

    // Clean up any cached LocalNet devices from previous sessions
    log_debug(BT_TAG, "Cleaning up stale LocalNet devices from previous session");
    GList * existing_devices = binc_adapter_get_devices(manager->adapter);
    for (const GList * it = existing_devices; it != NULL; it = it->next) {
        Device * device = it->data;
        const char * name = binc_device_get_name(device);
        if (is_localnet_device(name)) {
            log_debug(BT_TAG, "Removing stale cached device: %s", name);
            binc_adapter_remove_device(manager->adapter, device);
        }
    }
    g_list_free(existing_devices);

    // Clear internal tracked device list to ensure fresh state
    clear_all_tracked_devices();

    binc_adapter_pairable_off(manager->adapter);
    log_debug(BT_TAG, "Disabled pairing to prevent ghost connections");

    // Create agent for pairing
    manager->agent = binc_agent_create(manager->adapter, "/org/bluez/LocalNetAgent", NO_INPUT_NO_OUTPUT);
    binc_agent_set_request_authorization_cb(manager->agent, &on_request_authorization);

    // Setup GATT application
    manager->app = binc_create_application(manager->adapter);
    binc_application_add_service(manager->app, LOCAL_NET_SERVICE_UUID);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID, GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_NOTIFY);
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_CTRL_CHAR_UUID, GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE);
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
    // Disconnect ALL devices aggressively
    log_debug(BT_TAG, "Disconnecting all devices...");
    for (guint i = 0; i < manager->discovered_count; i++) {
        const tracked_device_t * tracked = &manager->discovered_devices[i];
        if (tracked->device) {
            binc_device_disconnect(tracked->device);
            g_usleep(100000);  // 100ms per device
        }
    }

    // Wait for disconnections to complete
    g_usleep(500000);  // 500ms

    // Remove ALL cached LocalNet devices
    if (manager->adapter) {
        GList * devices = binc_adapter_get_devices(manager->adapter);
        for (const GList * it = devices; it != NULL; it = it->next) {
            Device * device = it->data;
            const char * name = binc_device_get_name(device);
            if (is_localnet_device(name)) {
                binc_adapter_remove_device(manager->adapter, device);
            }
        }
        g_list_free(devices);
    }

    // Clear internal tracked device list
    clear_all_tracked_devices();

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

    guint known = 0, connected = 0;
    for (guint i = 0; i < manager->discovered_count; i++) {
        tracked_device_t *tracked = &manager->discovered_devices[i];
        if (tracked->device_id == 0) continue;

        known++;
        if (tracked->is_connected) connected++;

        const char *status = tracked->is_connected ? "CONNECTED" : "KNOWN";
        const char *type = tracked->we_initiated ? "OUTGOING" : "INCOMING";

        printf("\t 0x%08X   %-12s %4d dBm   %-10s %-18s\n",
               tracked->device_id, status, tracked->rssi, type, tracked->mac_address);
    }

    if (known == 0) {
        printf("\t (no devices)\n");
    }

    printf("--------------------------------------------------------------------\n");
    printf("\t Total: %u known, %u connected\n", known, connected);
    printf("--------------------------------------------------------------------\n");
}

struct mesh_node *ble_get_mesh_node(ble_node_manager_t *manager) {
    if (!manager) return NULL;
    return manager->mesh_node;
}

/* ========================================================================== */
/* Route Discovery Implementation                                              */
/* ========================================================================== */

uint32_t ble_initiate_route_discovery(ble_node_manager_t *manager, const uint32_t destination_id) {
    if (!manager || !manager->mesh_node) return 0;

    struct route_request req = {0};

    const int result = create_route_request(manager->mesh_node, destination_id, &req);
    if (result <= 0) {
        if (req.reverse_path) free(req.reverse_path);
        return 0;
    }

    log_info(BT_TAG, "Initiating route discovery for 0x%08X (request_id: 0x%08X)",
            destination_id, req.request_id);

    // Broadcast route request to all connected neighbors
    const gboolean sent = ble_broadcast_route_request(manager, req.request_id, destination_id,
                                                       req.hop_count, req.reverse_path,
                                                       req.reverse_path_len, 0);

    if (req.reverse_path) free(req.reverse_path);

    return sent ? req.request_id : 0;
}

gboolean ble_broadcast_route_request(ble_node_manager_t *manager, const uint32_t request_id,
                                     const uint32_t destination_id, const uint8_t hop_count,
                                     const uint32_t *reverse_path, const uint8_t reverse_path_len,
                                     const uint32_t exclude_id) {
    if (!manager || !reverse_path || reverse_path_len == 0) return FALSE;

    // Build route request structure
    struct route_request req = {
        .request_id = request_id,
        .destination_id = destination_id,
        .hop_count = hop_count,
        .reverse_path_len = reverse_path_len,
        .reverse_path = (uint32_t *)reverse_path  // Cast away const for serialize
    };

    // Build packet header
    struct header header = {
        .protocol_version = PROTOCOL_VERSION,
        .message_type = MSG_ROUTE_REQUEST,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = MAX_HOP_COUNT,
        .payload_length = 0,  // Will be set after serialization
        .sequence_number = 0
    };

    struct network network = {
        .source_id = manager->device_id,
        .destination_id = destination_id
    };

    // Serialize route request payload
    uint8_t payload_buffer[256];
    const size_t payload_len = serialize_route_request(&req, payload_buffer, sizeof(payload_buffer));
    if (payload_len == 0) {
        log_error(BT_TAG, "Failed to serialize route request");
        return FALSE;
    }

    header.payload_length = (uint16_t)payload_len;

    // Create packet
    const struct packet packet = {
        .header = &header,
        .network = &network,
        .payload = payload_buffer,
        .security = NULL
    };

    // Serialize complete packet
    uint8_t buffer[MAX_BLE_PAYLOAD_SIZE];
    const size_t total_len = serialize_packet(&packet, buffer, sizeof(buffer));
    if (total_len == 0) {
        log_error(BT_TAG, "Failed to serialize route request packet");
        return FALSE;
    }

    // Send to all connected neighbors except exclude_id
    gboolean sent_any = FALSE;
    for (guint i = 0; i < manager->discovered_count; i++) {
        const tracked_device_t *tracked = &manager->discovered_devices[i];
        if (!tracked->is_connected) continue;
        if (tracked->device_id == exclude_id) continue;

        if (ble_send_data(manager, tracked->device_id, buffer, total_len)) {
            log_debug(BT_TAG, "Sent route request to 0x%08X", tracked->device_id);
            sent_any = TRUE;
        }
    }

    if (sent_any) {
        log_info(BT_TAG, "Broadcast route request for 0x%08X (hops: %u, path_len: %u)",
                destination_id, hop_count, reverse_path_len);
    }

    return sent_any;
}

gboolean ble_send_route_reply(ble_node_manager_t *manager, const uint32_t target_id,
                              const uint32_t request_id, const uint8_t route_cost,
                              const uint32_t *forward_path, const uint8_t forward_path_len) {
    if (!manager || !forward_path || forward_path_len == 0) return FALSE;

    // Build route reply structure
    struct route_reply reply = {
        .request_id = request_id,
        .route_cost = route_cost,
        .forward_path_len = forward_path_len,
        .forward_path = (uint32_t *)forward_path
    };

    // Build packet header
    struct header header = {
        .protocol_version = PROTOCOL_VERSION,
        .message_type = MSG_ROUTE_REPLY,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = MAX_HOP_COUNT,
        .payload_length = 0,
        .sequence_number = 0
    };

    struct network network = {
        .source_id = manager->device_id,
        .destination_id = target_id
    };

    // Serialize route reply payload
    uint8_t payload_buffer[256];
    const size_t payload_len = serialize_route_reply(&reply, payload_buffer, sizeof(payload_buffer));
    if (payload_len == 0) {
        log_error(BT_TAG, "Failed to serialize route reply");
        return FALSE;
    }

    header.payload_length = (uint16_t)payload_len;

    // Create packet
    const struct packet packet = {
        .header = &header,
        .network = &network,
        .payload = payload_buffer,
        .security = NULL
    };

    // Serialize complete packet
    uint8_t buffer[MAX_BLE_PAYLOAD_SIZE];
    const size_t total_len = serialize_packet(&packet, buffer, sizeof(buffer));
    if (total_len == 0) {
        log_error(BT_TAG, "Failed to serialize route reply packet");
        return FALSE;
    }

    log_info(BT_TAG, "Sending route reply to 0x%08X (cost: %u, path_len: %u)",
            target_id, route_cost, forward_path_len);

    return ble_send_data(manager, target_id, buffer, total_len);
}

uint16_t ble_send_message(ble_node_manager_t *manager, const uint32_t destination_id,
                          const uint8_t *payload, const size_t payload_len) {
    if (!manager || !manager->mesh_node || !payload || payload_len == 0) return 0;

    struct mesh_node *node = manager->mesh_node;

    /* Make forwarding decision to determine if we can send directly */
    struct forwarding_decision decision;
    uint8_t ttl = MAX_HOP_COUNT;
    make_forwarding_decision(node, destination_id, &ttl, &decision);

    /* Build the data packet */
    uint16_t seq_num = 0;
    if (node->packet_queue) {
        seq_num = node->packet_queue->next_sequence_number;
    }

    struct header header = {
        .protocol_version = PROTOCOL_VERSION,
        .message_type = MSG_DATA,
        .fragmentation_flag = 0,
        .fragmentation_number = 0,
        .total_fragments = 1,
        .time_to_live = MAX_HOP_COUNT,
        .payload_length = (uint16_t)payload_len,
        .sequence_number = seq_num
    };

    struct network network = {
        .source_id = manager->device_id,
        .destination_id = destination_id
    };

    const struct packet packet = {
        .header = &header,
        .network = &network,
        .payload = (uint8_t *)payload,
        .security = NULL
    };

    /* Serialize the packet */
    uint8_t buffer[MAX_BLE_PAYLOAD_SIZE];
    const size_t total_len = serialize_packet(&packet, buffer, sizeof(buffer));
    if (total_len == 0) {
        log_error(BT_TAG, "Failed to serialize data packet");
        return 0;
    }

    const uint32_t current_time_ms = get_current_timestamp() * 1000;

    if (decision.action == 0) {
        /* Have route - send directly and queue for retransmission */
        if (node->packet_queue) {
            seq_num = queue_packet_for_transmission(node->packet_queue, destination_id,
                                                    buffer, total_len, current_time_ms);
        }
        if (ble_send_data(manager, decision.next_hop, buffer, total_len)) {
            log_info(BT_TAG, "Sent message to 0x%08X via 0x%08X (seq: %u)",
                    destination_id, decision.next_hop, seq_num);
            return seq_num;
        }
    } else if (decision.action == -2) {
        /* No route - queue packet and initiate route discovery */
        if (node->packet_queue) {
            seq_num = queue_packet_for_transmission(node->packet_queue, destination_id,
                                                    buffer, total_len, current_time_ms);
            /* Mark as awaiting route */
            struct pending_packet *pkt = get_pending_packet(node->packet_queue, seq_num);
            if (pkt) {
                pkt->state = PACKET_STATE_AWAITING_ROUTE;
            }
        }

        /* Check if route discovery is already pending */
        if (!has_pending_route_discovery(node, destination_id)) {
            const uint32_t request_id = ble_initiate_route_discovery(manager, destination_id);
            if (request_id > 0) {
                log_info(BT_TAG, "Queued message for 0x%08X, initiated route discovery (request: 0x%08X)",
                        destination_id, request_id);
                /* Associate request with queued packets */
                if (node->packet_queue) {
                    associate_route_request_with_packets(node->packet_queue, destination_id, request_id);
                }
            }
        } else {
            log_info(BT_TAG, "Queued message for 0x%08X, route discovery already pending",
                    destination_id);
        }
        return seq_num;
    } else {
        /* Error - local delivery or TTL expired (shouldn't happen for new messages) */
        log_error(BT_TAG, "Cannot send message to 0x%08X: forwarding decision=%d",
                 destination_id, decision.action);
    }

    return 0;
}

void ble_send_queued_packets(ble_node_manager_t *manager, const uint32_t destination_id) {
    if (!manager || !manager->mesh_node || !manager->mesh_node->packet_queue) return;

    struct mesh_node *node = manager->mesh_node;
    struct pending_packet_queue *queue = node->packet_queue;

    /* Find route to destination */
    struct routing_entry *route = find_best_route(node->routing_table, destination_id);
    if (!route || !route->is_valid) {
        log_error(BT_TAG, "No route found for destination 0x%08X after route discovery", destination_id);
        handle_route_discovery_failed(queue, destination_id);
        return;
    }

    /* Send all queued packets for this destination
     * Note: handle_route_discovery_complete already changed state to AWAITING_ACK
     * and set next_retry_timestamp to current time, so we look for those packets */
    size_t sent_count = 0;
    const uint32_t current_time_ms = get_current_timestamp() * 1000;

    for (size_t i = 0; i < MAX_PENDING_PACKETS; i++) {
        struct pending_packet *pkt = &queue->packets[i];
        /* Look for packets that are AWAITING_ACK, have 0 retries (fresh from route discovery),
         * and are for this destination */
        if (pkt->destination_id == destination_id &&
            pkt->state == PACKET_STATE_AWAITING_ACK &&
            pkt->retry_count == 0 &&
            pkt->packet_data && pkt->packet_len > 0) {

            /* Send the packet */
            if (ble_send_data(manager, route->next_hop, pkt->packet_data, pkt->packet_len)) {
                log_info(BT_TAG, "Sent queued packet (seq: %u) to 0x%08X via 0x%08X",
                        pkt->sequence_number, destination_id, route->next_hop);
                /* Update timing so retransmit logic doesn't immediately resend */
                pkt->next_retry_timestamp = current_time_ms + INITIAL_RETRANSMIT_INTERVAL_MS;
                pkt->retry_interval_ms = INITIAL_RETRANSMIT_INTERVAL_MS;
                sent_count++;
            } else {
                log_error(BT_TAG, "Failed to send queued packet (seq: %u) to 0x%08X",
                         pkt->sequence_number, destination_id);
            }
        }
    }

    if (sent_count > 0) {
        log_info(BT_TAG, "Sent %zu queued packets for destination 0x%08X", sent_count, destination_id);
    }
}

void ble_process_retransmissions(ble_node_manager_t *manager) {
    if (!manager || !manager->mesh_node || !manager->mesh_node->packet_queue) return;

    struct mesh_node *node = manager->mesh_node;
    struct pending_packet_queue *queue = node->packet_queue;
    const uint32_t current_time_ms = get_current_timestamp() * 1000;

    /* Check for packets needing retransmission */
    uint16_t retry_seq_nums[MAX_PENDING_PACKETS];
    const size_t retry_count = check_retransmission_timeouts(queue, current_time_ms,
                                                             retry_seq_nums, MAX_PENDING_PACKETS);

    for (size_t i = 0; i < retry_count; i++) {
        struct pending_packet *pkt = get_pending_packet(queue, retry_seq_nums[i]);
        if (!pkt || !pkt->packet_data) continue;

        /* Find route to destination */
        struct routing_entry *route = find_best_route(node->routing_table, pkt->destination_id);
        if (!route || !route->is_valid) {
            log_warn(BT_TAG, "No route for retransmit of seq %u to 0x%08X - marking failed",
                    pkt->sequence_number, pkt->destination_id);
            pkt->state = PACKET_STATE_FAILED;

            /* Update link quality negatively */
            if (node->connection_table) {
                update_link_quality(node->connection_table, pkt->destination_id, 0);
            }
            continue;
        }

        /* Retransmit the packet */
        if (ble_send_data(manager, route->next_hop, pkt->packet_data, pkt->packet_len)) {
            log_info(BT_TAG, "Retransmit #%u of seq %u to 0x%08X via 0x%08X (interval: %ums)",
                    pkt->retry_count + 1, pkt->sequence_number,
                    pkt->destination_id, route->next_hop, pkt->retry_interval_ms);

            /* Update retry timing with exponential backoff */
            update_retry_timing(pkt, current_time_ms);
        } else {
            log_error(BT_TAG, "Failed retransmit of seq %u to 0x%08X",
                     pkt->sequence_number, pkt->destination_id);
            /* Still update timing to avoid immediate re-attempts */
            update_retry_timing(pkt, current_time_ms);
        }
    }

    /* Check for route request timeouts */
    uint32_t timed_out_dests[MAX_PENDING_REQUESTS];
    const size_t timeout_count = check_route_request_timeouts(node, get_current_timestamp(),
                                                              timed_out_dests, MAX_PENDING_REQUESTS);

    for (size_t i = 0; i < timeout_count; i++) {
        log_warn(BT_TAG, "Route request timeout for destination 0x%08X - retrying",
                timed_out_dests[i]);
        ble_initiate_route_discovery(manager, timed_out_dests[i]);
    }

    /* Cleanup delivered/failed packets periodically */
    const size_t cleaned = cleanup_pending_packets(queue);
    if (cleaned > 0) {
        log_debug(BT_TAG, "Cleaned up %zu delivered/failed packets", cleaned);
    }
}

