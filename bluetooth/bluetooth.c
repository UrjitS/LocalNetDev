#include "bluetooth.h"

/* Global reference for callbacks (needed since binc callbacks don't support user_data) */
static ble_node_manager_t *g_manager = NULL;

/* Forward declarations for internal callbacks */
static void on_scan_result(Adapter *adapter, Device *device);
static void on_connection_state_changed(Device *device, ConnectionState state, const GError *error);
static void on_services_resolved(Device *device);
static void on_read_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error);
static void on_write_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error);
static void on_notify_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray);
static gboolean on_request_authorization(Device *device);
static const char* on_local_char_read(const Application *app, const char *address, const char* service_uuid,
                                       const char* char_uuid, const guint16 offset, const guint16 mtu);
static const char* on_local_char_write(const Application *app, const char *address, const char *service_uuid,
                                        const char *char_uuid, GByteArray *byteArray, const guint16 offset, const guint16 mtu);
static gboolean periodic_discovery_callback(gpointer user_data);
static gboolean periodic_reconnect_callback(gpointer user_data);
static gboolean periodic_heartbeat_callback(gpointer user_data);

/* Utility function implementations */
uint32_t ble_extract_device_id(const char *device_name) {
    if (device_name == NULL) return 0;

    /* Check if the name starts with the expected prefix */
    if (!g_str_has_prefix(device_name, LOCAL_NET_DEVICE_PREFIX)) return 0;

    /* Extract the hex ID after the prefix */
    const char *id_str = device_name + strlen(LOCAL_NET_DEVICE_PREFIX);
    return (uint32_t)g_ascii_strtoull(id_str, NULL, 16);
}

char *ble_generate_device_name(uint32_t device_id) {
    return g_strdup_printf("%s%08X", LOCAL_NET_DEVICE_PREFIX, device_id);
}

discovered_device_t *ble_find_discovered_device(ble_node_manager_t *manager, uint32_t device_id) {
    if (!manager) return NULL;

    for (size_t i = 0; i < manager->discovered_count; i++) {
        if (manager->discovered_devices[i].device_id == device_id) {
            return &manager->discovered_devices[i];
        }
    }
    return NULL;
}

discovered_device_t *ble_find_device_by_ptr(ble_node_manager_t *manager, Device *device) {
    if (!manager || !device) return NULL;

    for (size_t i = 0; i < manager->discovered_count; i++) {
        if (manager->discovered_devices[i].device == device) {
            return &manager->discovered_devices[i];
        }
    }
    return NULL;
}

int ble_get_adapter_address(char *address, size_t len) {
    if (!address || len < 18) return -1;  /* Need at least 18 chars for "XX:XX:XX:XX:XX:XX\0" */

    /* Get DBus connection */
    GError *error = NULL;
    GDBusConnection *connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (!connection) {
        log_error(BT_TAG, "Failed to get DBus connection: %s", error ? error->message : "unknown");
        if (error) g_error_free(error);
        return -1;
    }

    /* Get the default adapter */
    Adapter *adapter = binc_adapter_get_default(connection);
    if (!adapter) {
        log_error(BT_TAG, "No Bluetooth adapter found");
        g_object_unref(connection);
        return -1;
    }

    /* Get the adapter's address */
    const char *addr = binc_adapter_get_address(adapter);
    if (!addr) {
        log_error(BT_TAG, "Failed to get adapter address");
        binc_adapter_free(adapter);
        g_object_unref(connection);
        return -1;
    }

    /* Copy the address */
    strncpy(address, addr, len - 1);
    address[len - 1] = '\0';

    /* Cleanup - don't close the system bus, just unref it */
    binc_adapter_free(adapter);
    g_object_unref(connection);

    return 0;
}

static discovered_device_t *add_discovered_device(ble_node_manager_t *manager, Device *device, uint32_t device_id, int8_t rssi) {
    if (!manager || manager->discovered_count >= MAX_DISCOVERED_DEVICES) return NULL;

    /* Check if already exists */
    discovered_device_t *existing = ble_find_discovered_device(manager, device_id);
    if (existing) {
        existing->rssi = rssi;
        existing->last_seen = get_current_timestamp();
        existing->device = device;
        return existing;
    }

    /* Add new device */
    discovered_device_t *entry = &manager->discovered_devices[manager->discovered_count];
    entry->device = device;
    entry->device_id = device_id;
    entry->rssi = rssi;
    entry->last_seen = get_current_timestamp();
    entry->is_connected = FALSE;
    entry->connection_pending = FALSE;
    manager->discovered_count++;

    return entry;
}

/* BLE Initialization */
ble_node_manager_t *ble_init(uint32_t device_id, enum NODE_TYPE node_type) {
    ble_node_manager_t *manager = g_new0(ble_node_manager_t, 1);
    if (!manager) return NULL;

    /* Create the mesh node */
    manager->mesh_node = create_mesh_node(device_id, node_type);
    if (!manager->mesh_node) {
        g_free(manager);
        return NULL;
    }

    /* Initialize state */
    manager->state = BLE_STATE_IDLE;
    manager->advertising = FALSE;
    manager->scanning = FALSE;
    manager->running = FALSE;
    manager->discovered_count = 0;

    /* Initialize timer IDs */
    manager->discovery_timer_id = 0;
    manager->reconnect_timer_id = 0;
    manager->heartbeat_timer_id = 0;

    /* Set global reference */
    g_manager = manager;

    log_debug(BT_TAG, "Initialized BLE node manager for device ID: 0x%08X", device_id);

    return manager;
}

void ble_cleanup(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Cleaning up BLE node manager");

    ble_stop(manager);

    /* Stop timers */
    if (manager->discovery_timer_id > 0) {
        g_source_remove(manager->discovery_timer_id);
        manager->discovery_timer_id = 0;
    }
    if (manager->reconnect_timer_id > 0) {
        g_source_remove(manager->reconnect_timer_id);
        manager->reconnect_timer_id = 0;
    }
    if (manager->heartbeat_timer_id > 0) {
        g_source_remove(manager->heartbeat_timer_id);
        manager->heartbeat_timer_id = 0;
    }

    /* Cleanup BLE resources */
    if (manager->advertisement) {
        if (manager->adapter) {
            binc_adapter_stop_advertising(manager->adapter, manager->advertisement);
        }
        binc_advertisement_free(manager->advertisement);
        manager->advertisement = NULL;
    }

    if (manager->app) {
        if (manager->adapter) {
            binc_adapter_unregister_application(manager->adapter, manager->app);
        }
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

    if (manager->main_loop) {
        g_main_loop_unref(manager->main_loop);
        manager->main_loop = NULL;
    }

    /* Free mesh node */
    if (manager->mesh_node) {
        free_mesh_node(manager->mesh_node);
        manager->mesh_node = NULL;
    }

    g_manager = NULL;
    g_free(manager);
}

int ble_start(ble_node_manager_t *manager) {
    if (!manager) return -1;

    log_debug(BT_TAG, "Starting BLE node manager");

    /* Get DBus connection */
    GError *error = NULL;
    manager->dbus_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (!manager->dbus_connection) {
        log_error(BT_TAG, "Failed to get DBus connection: %s", error ? error->message : "unknown error");
        if (error) g_error_free(error);
        return -1;
    }

    /* Create main loop */
    manager->main_loop = g_main_loop_new(NULL, FALSE);

    /* Get the default Bluetooth adapter */
    manager->adapter = binc_adapter_get_default(manager->dbus_connection);
    if (!manager->adapter) {
        log_error(BT_TAG, "No Bluetooth adapter found");
        return -1;
    }

    log_info(BT_TAG, "Using adapter: %s", binc_adapter_get_name(manager->adapter));

    /* Create agent for pairing (JustWorks mode) */
    manager->agent = binc_agent_create(manager->adapter, "/org/bluez/LocalNetAgent", NO_INPUT_NO_OUTPUT);
    binc_agent_set_request_authorization_cb(manager->agent, &on_request_authorization);

    /* Setup peripheral (GATT server) */
    manager->app = binc_create_application(manager->adapter);
    binc_application_add_service(manager->app, LOCAL_NET_SERVICE_UUID);

    /* Data characteristic - for mesh data transfer */
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID,
                                        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_NOTIFY);

    /* Control characteristic - for discovery/connection management */
    binc_application_add_characteristic(manager->app, LOCAL_NET_SERVICE_UUID, LOCAL_NET_CTRL_CHAR_UUID,
                                        GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE);

    binc_application_set_char_read_cb(manager->app, &on_local_char_read);
    binc_application_set_char_write_cb(manager->app, &on_local_char_write);
    binc_adapter_register_application(manager->adapter, manager->app);

    /* Setup central (scanner) */
    binc_adapter_set_discovery_cb(manager->adapter, &on_scan_result);
    binc_adapter_set_discovery_filter(manager->adapter, -100, NULL, NULL);  /* -100 dBm minimum RSSI */

    manager->running = TRUE;

    /* Start advertising immediately */
    ble_start_advertising(manager);

    /* Start periodic discovery */
    manager->discovery_timer_id = g_timeout_add(DISCOVERY_SCAN_INTERVAL_MS, periodic_discovery_callback, manager);

    /* Start periodic reconnect attempts */
    manager->reconnect_timer_id = g_timeout_add(RECONNECT_ATTEMPT_INTERVAL_MS, periodic_reconnect_callback, manager);

    /* Start heartbeat timer */
    manager->heartbeat_timer_id = g_timeout_add_seconds(HEARTBEAT_INTERVAL_SECONDS, periodic_heartbeat_callback, manager);

    /* Start initial discovery immediately */
    ble_start_discovery(manager);

    log_debug(BT_TAG, "BLE node manager started successfully");

    return 0;
}

void ble_stop(ble_node_manager_t *manager) {
    if (!manager) return;

    log_debug(BT_TAG, "Stopping BLE node manager");

    manager->running = FALSE;

    /* Stop discovery and advertising */
    ble_stop_discovery(manager);
    ble_stop_advertising(manager);

    /* Disconnect all connected devices */
    for (size_t i = 0; i < manager->discovered_count; i++) {
        if (manager->discovered_devices[i].is_connected && manager->discovered_devices[i].device) {
            binc_device_disconnect(manager->discovered_devices[i].device);
        }
    }

    /* Quit main loop if running */
    if (manager->main_loop && g_main_loop_is_running(manager->main_loop)) {
        g_main_loop_quit(manager->main_loop);
    }
}

/* Discovery functions */
int ble_start_discovery(ble_node_manager_t *manager) {
    if (!manager || !manager->adapter || manager->scanning) return -1;

    log_debug(BT_TAG, "Starting BLE discovery");

    binc_adapter_start_discovery(manager->adapter);
    manager->scanning = TRUE;
    manager->state = BLE_STATE_SCANNING;

    return 0;
}

void ble_stop_discovery(ble_node_manager_t *manager) {
    if (!manager || !manager->adapter || !manager->scanning) return;

    log_debug(BT_TAG, "Stopping BLE discovery");

    binc_adapter_stop_discovery(manager->adapter);
    manager->scanning = FALSE;

    if (manager->state == BLE_STATE_SCANNING) {
        manager->state = BLE_STATE_IDLE;
    }
}

int ble_is_discovering(ble_node_manager_t *manager) {
    return manager ? manager->scanning : 0;
}

/* Advertising functions */
int ble_start_advertising(ble_node_manager_t *manager) {
    if (!manager || !manager->adapter || manager->advertising) return -1;

    log_debug(BT_TAG, "Starting BLE advertising");

    /* Create advertisement */
    GPtrArray *adv_service_uuids = g_ptr_array_new();
    g_ptr_array_add(adv_service_uuids, (gpointer)LOCAL_NET_SERVICE_UUID);

    manager->advertisement = binc_advertisement_create();

    /* Set the device name with our ID */
    char *device_name = ble_generate_device_name(manager->mesh_node->device_id);
    binc_advertisement_set_local_name(manager->advertisement, device_name);
    g_free(device_name);

    binc_advertisement_set_services(manager->advertisement, adv_service_uuids);

    binc_adapter_start_advertising(manager->adapter, manager->advertisement);

    g_ptr_array_free(adv_service_uuids, TRUE);

    manager->advertising = TRUE;

    log_debug(BT_TAG, "Advertising as LocalNet-%08X", manager->mesh_node->device_id);

    return 0;
}

void ble_stop_advertising(ble_node_manager_t *manager) {
    if (!manager || !manager->adapter || !manager->advertising) return;

    log_debug(BT_TAG, "Stopping BLE advertising");

    if (manager->advertisement) {
        binc_adapter_stop_advertising(manager->adapter, manager->advertisement);
        binc_advertisement_free(manager->advertisement);
        manager->advertisement = NULL;
    }

    manager->advertising = FALSE;
}

int ble_is_advertising(ble_node_manager_t *manager) {
    return manager ? manager->advertising : 0;
}

/* Connection management */
int ble_connect_to_node(ble_node_manager_t *manager, uint32_t device_id) {
    if (!manager) return -1;

    discovered_device_t *discovered = ble_find_discovered_device(manager, device_id);
    if (!discovered || !discovered->device) {
        log_debug(BT_TAG, "Device 0x%08X not found in discovered list", device_id);
        return -1;
    }

    if (discovered->is_connected) {
        log_debug(BT_TAG, "Already connected to device 0x%08X", device_id);
        return 0;
    }

    if (discovered->connection_pending) {
        log_debug(BT_TAG, "Connection to device 0x%08X already pending", device_id);
        return 0;
    }

    /* Check if we have available connections */
    if (!has_available_connections(manager->mesh_node)) {
        log_debug(BT_TAG, "No available connections for device 0x%08X", device_id);
        return -1;
    }

    log_debug(BT_TAG, "Connecting to device 0x%08X", device_id);

    discovered->connection_pending = TRUE;

    /* Set up device callbacks */
    binc_device_set_connection_state_change_cb(discovered->device, &on_connection_state_changed);
    binc_device_set_services_resolved_cb(discovered->device, &on_services_resolved);
    binc_device_set_read_char_cb(discovered->device, &on_read_characteristic);
    binc_device_set_write_char_cb(discovered->device, &on_write_characteristic);
    binc_device_set_notify_char_cb(discovered->device, &on_notify_characteristic);

    /* Initiate connection */
    binc_device_connect(discovered->device);

    return 0;
}

int ble_disconnect_from_node(ble_node_manager_t *manager, uint32_t device_id) {
    if (!manager) return -1;

    discovered_device_t *discovered = ble_find_discovered_device(manager, device_id);
    if (!discovered || !discovered->device) {
        return -1;
    }

    if (!discovered->is_connected) {
        return 0;
    }

    log_debug(BT_TAG, "Disconnecting from device 0x%08X", device_id);

    binc_device_disconnect(discovered->device);

    return 0;
}

int ble_get_connected_count(ble_node_manager_t *manager) {
    if (!manager) return 0;

    int count = 0;
    for (size_t i = 0; i < manager->discovered_count; i++) {
        if (manager->discovered_devices[i].is_connected) {
            count++;
        }
    }
    return count;
}

/* Data transmission */
int ble_send_data(ble_node_manager_t *manager, uint32_t dest_id, const uint8_t *data, size_t len) {
    if (!manager || !data || len == 0) return -1;

    discovered_device_t *discovered = ble_find_discovered_device(manager, dest_id);
    if (!discovered || !discovered->device || !discovered->is_connected) {
        log_debug(BT_TAG, "Cannot send data to device 0x%08X - not connected", dest_id);
        return -1;
    }

    Characteristic *data_char = binc_device_get_characteristic(discovered->device,
                                                                LOCAL_NET_SERVICE_UUID,
                                                                LOCAL_NET_DATA_CHAR_UUID);
    if (!data_char) {
        log_debug(BT_TAG, "Data characteristic not found for device 0x%08X", dest_id);
        return -1;
    }

    GByteArray *byte_array = g_byte_array_sized_new(len);
    g_byte_array_append(byte_array, data, len);

    binc_characteristic_write(data_char, byte_array, WITH_RESPONSE);

    g_byte_array_free(byte_array, TRUE);

    /* Update link quality */
    update_link_quality(manager->mesh_node->connection_table, dest_id, 1);

    return 0;
}

int ble_broadcast_data(ble_node_manager_t *manager, const uint8_t *data, size_t len) {
    if (!manager || !data || len == 0) return -1;

    int sent_count = 0;
    for (size_t i = 0; i < manager->discovered_count; i++) {
        if (manager->discovered_devices[i].is_connected) {
            if (ble_send_data(manager, manager->discovered_devices[i].device_id, data, len) == 0) {
                sent_count++;
            }
        }
    }

    return sent_count;
}

/* Callback registration */
void ble_set_data_callback(ble_node_manager_t *manager, on_data_received_cb callback) {
    if (manager) manager->data_callback = callback;
}

void ble_set_connected_callback(ble_node_manager_t *manager, on_node_connected_cb callback) {
    if (manager) manager->connected_callback = callback;
}

void ble_set_disconnected_callback(ble_node_manager_t *manager, on_node_disconnected_cb callback) {
    if (manager) manager->disconnected_callback = callback;
}

void ble_set_discovered_callback(ble_node_manager_t *manager, on_node_discovered_cb callback) {
    if (manager) manager->discovered_callback = callback;
}

/* Main loop functions */
GMainLoop *ble_get_main_loop(ble_node_manager_t *manager) {
    return manager ? manager->main_loop : NULL;
}

void ble_run_main_loop(ble_node_manager_t *manager) {
    if (manager && manager->main_loop) {
        log_debug(BT_TAG, "Running main loop");
        g_main_loop_run(manager->main_loop);
    }
}

void ble_quit_main_loop(ble_node_manager_t *manager) {
    if (manager && manager->main_loop) {
        log_debug(BT_TAG, "Quitting main loop");
        g_main_loop_quit(manager->main_loop);
    }
}

/* Internal callbacks */
static void on_scan_result(Adapter *adapter, Device *device) {
    if (!g_manager || !device) return;

    const char *name = binc_device_get_name(device);
    if (!name || !g_str_has_prefix(name, LOCAL_NET_DEVICE_PREFIX)) {
        return;  /* Not a LocalNet device */
    }

    uint32_t device_id = ble_extract_device_id(name);
    if (device_id == 0 || device_id == g_manager->mesh_node->device_id) {
        return;  /* Invalid ID or self */
    }

    int16_t rssi = binc_device_get_rssi(device);

    log_debug(BT_TAG, "Discovered LocalNet node: 0x%08X (RSSI: %d)", device_id, rssi);

    /* Add to discovered list */
    discovered_device_t *discovered = add_discovered_device(g_manager, device, device_id, (int8_t)rssi);

    /* Notify callback */
    if (g_manager->discovered_callback) {
        g_manager->discovered_callback(device_id, (int8_t)rssi);
    }

    /* Auto-connect if we have available connections and not already connected */
    if (discovered && !discovered->is_connected && !discovered->connection_pending) {
        if (has_available_connections(g_manager->mesh_node)) {
            /* Add to connection table as discovering */
            struct connection_entry *conn = find_connection(g_manager->mesh_node->connection_table, device_id);
            if (!conn) {
                add_connection(g_manager->mesh_node->connection_table, device_id, (int8_t)rssi);
                update_connection_state(g_manager->mesh_node->connection_table, device_id, DISCOVERING);
            }

            /* Attempt to connect */
            ble_connect_to_node(g_manager, device_id);
        }
    }
}

static void on_connection_state_changed(Device *device, ConnectionState state, const GError *error) {
    if (!g_manager || !device) return;

    discovered_device_t *discovered = ble_find_device_by_ptr(g_manager, device);
    if (!discovered) return;

    if (error) {
        log_error(BT_TAG, "Connection error for 0x%08X: %s", discovered->device_id, error->message);
        discovered->connection_pending = FALSE;
        update_connection_state(g_manager->mesh_node->connection_table, discovered->device_id, DISCONNECTED);
        return;
    }

    log_debug(BT_TAG, "Connection state changed for 0x%08X: %s",
              discovered->device_id, binc_device_get_connection_state_name(device));

    if (state == BINC_CONNECTED) {
        /* Wait for services to be resolved before marking as fully connected */
        update_connection_state(g_manager->mesh_node->connection_table, discovered->device_id, CONNECTING);
    } else if (state == BINC_DISCONNECTED) {
        discovered->is_connected = FALSE;
        discovered->connection_pending = FALSE;

        /* Update connection table */
        update_connection_state(g_manager->mesh_node->connection_table, discovered->device_id, DISCONNECTED);

        /* Update available connections */
        g_manager->mesh_node->available_connections++;

        /* Notify callback */
        if (g_manager->disconnected_callback) {
            g_manager->disconnected_callback(discovered->device_id);
        }

        /* Clean up if not bonded */
        if (binc_device_get_bonding_state(device) != BINC_BONDED) {
            binc_adapter_remove_device(g_manager->adapter, device);
        }
    }
}

static void on_services_resolved(Device *device) {
    if (!g_manager || !device) return;

    discovered_device_t *discovered = ble_find_device_by_ptr(g_manager, device);
    if (!discovered) return;

    log_debug(BT_TAG, "Services resolved for device 0x%08X", discovered->device_id);

    /* Mark as connected */
    discovered->is_connected = TRUE;
    discovered->connection_pending = FALSE;

    /* Update connection table */
    update_connection_state(g_manager->mesh_node->connection_table, discovered->device_id, STABLE);
    update_last_seen(g_manager->mesh_node->connection_table, discovered->device_id, get_current_timestamp());

    /* Update available connections */
    if (g_manager->mesh_node->available_connections > 0) {
        g_manager->mesh_node->available_connections--;
    }

    /* Subscribe to notifications from data characteristic */
    Characteristic *data_char = binc_device_get_characteristic(device, LOCAL_NET_SERVICE_UUID, LOCAL_NET_DATA_CHAR_UUID);
    if (data_char) {
        binc_characteristic_start_notify(data_char);
    }

    /* Notify callback */
    if (g_manager->connected_callback) {
        g_manager->connected_callback(discovered->device_id);
    }

    /* Send discovery message to newly connected node */
    struct discovery_message disc_msg = {
        .available_connections = g_manager->mesh_node->available_connections,
        .timestamp = get_current_timestamp()
    };

    uint8_t buffer[32];
    size_t len = serialize_discovery(&disc_msg, buffer, sizeof(buffer));
    if (len > 0) {
        ble_send_data(g_manager, discovered->device_id, buffer, len);
    }
}

static void on_read_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error) {
    if (error) {
        log_error(BT_TAG, "Read characteristic error: %s", error->message);
        return;
    }
    /* Handle read response if needed */
}

static void on_write_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error) {
    if (!g_manager || !device) return;

    discovered_device_t *discovered = ble_find_device_by_ptr(g_manager, device);
    if (!discovered) return;

    if (error) {
        log_error(BT_TAG, "Write characteristic error for 0x%08X: %s", discovered->device_id, error->message);
        update_link_quality(g_manager->mesh_node->connection_table, discovered->device_id, 0);
        return;
    }

    /* Successful write - update link quality */
    update_link_quality(g_manager->mesh_node->connection_table, discovered->device_id, 1);
}

static void on_notify_characteristic(Device *device, Characteristic *characteristic, const GByteArray *byteArray) {
    if (!g_manager || !device || !byteArray || byteArray->len == 0) return;

    discovered_device_t *discovered = ble_find_device_by_ptr(g_manager, device);
    if (!discovered) return;

    log_debug(BT_TAG, "Received notification from 0x%08X: %u bytes", discovered->device_id, byteArray->len);

    /* Update last seen */
    update_last_seen(g_manager->mesh_node->connection_table, discovered->device_id, get_current_timestamp());

    /* Notify callback */
    if (g_manager->data_callback) {
        g_manager->data_callback(discovered->device_id, byteArray->data, byteArray->len);
    }
}

static gboolean on_request_authorization(Device *device) {
    const char *name = binc_device_get_name(device);
    log_debug(BT_TAG, "Authorizing device: %s", name ? name : "unknown");
    return TRUE;  /* Auto-accept (JustWorks) */
}

static const char* on_local_char_read(const Application *app, const char *address, const char* service_uuid,
                                       const char* char_uuid, const guint16 offset, const guint16 mtu) {
    if (!g_manager) return BLUEZ_ERROR_REJECTED;

    if (g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID)) {
        if (g_str_equal(char_uuid, LOCAL_NET_CTRL_CHAR_UUID)) {
            /* Return node info */
            struct discovery_message disc_msg = {
                .available_connections = g_manager->mesh_node->available_connections,
                .timestamp = get_current_timestamp()
            };

            uint8_t buffer[32];
            size_t len = serialize_discovery(&disc_msg, buffer, sizeof(buffer));

            GByteArray *value = g_byte_array_sized_new(len);
            g_byte_array_append(value, buffer, len);
            binc_application_set_char_value(app, service_uuid, char_uuid, value);
            g_byte_array_free(value, TRUE);

            return NULL;
        }
    }

    return BLUEZ_ERROR_REJECTED;
}

static const char* on_local_char_write(const Application *app, const char *address, const char *service_uuid,
                                        const char *char_uuid, GByteArray *byteArray, const guint16 offset, const guint16 mtu) {
    if (!g_manager || !byteArray) return BLUEZ_ERROR_REJECTED;

    if (g_str_equal(service_uuid, LOCAL_NET_SERVICE_UUID)) {
        if (g_str_equal(char_uuid, LOCAL_NET_DATA_CHAR_UUID)) {
            log_debug(BT_TAG, "Received write from %s: %u bytes", address, byteArray->len);

            /* Extract device ID from address (this is a placeholder - in real use you'd track by address) */
            /* For now, notify with a zero ID - the app layer should handle addressing */
            if (g_manager->data_callback) {
                g_manager->data_callback(0, byteArray->data, byteArray->len);
            }

            return NULL;
        }
    }

    return BLUEZ_ERROR_REJECTED;
}

/* Periodic callbacks */
static gboolean periodic_discovery_callback(gpointer user_data) {
    ble_node_manager_t *manager = (ble_node_manager_t *)user_data;

    if (!manager || !manager->running) return FALSE;

    /* Check if we should be discovering based on mesh node state */
    if (should_send_discovery(manager->mesh_node, get_current_timestamp())) {
        if (!manager->scanning) {
            log_debug(BT_TAG, "Periodic discovery: starting scan");
            ble_start_discovery(manager);
        }
    } else if (manager->scanning) {
        /* Stop scanning if we have enough connections */
        if (!has_available_connections(manager->mesh_node)) {
            log_debug(BT_TAG, "Periodic discovery: stopping scan (connections full)");
            ble_stop_discovery(manager);
        }
    }

    /* Check connection timeouts */
    check_connection_timeouts(manager->mesh_node->connection_table, get_current_timestamp());

    return TRUE;  /* Continue timer */
}

static gboolean periodic_reconnect_callback(gpointer user_data) {
    ble_node_manager_t *manager = (ble_node_manager_t *)user_data;

    if (!manager || !manager->running) return FALSE;

    /* Try to reconnect to disconnected known devices */
    for (size_t i = 0; i < manager->discovered_count; i++) {
        discovered_device_t *disc = &manager->discovered_devices[i];

        if (!disc->is_connected && !disc->connection_pending && disc->device) {
            struct connection_entry *conn = find_connection(manager->mesh_node->connection_table, disc->device_id);

            if (conn && conn->state == DISCONNECTED) {
                if (has_available_connections(manager->mesh_node)) {
                    log_debug(BT_TAG, "Attempting reconnection to 0x%08X", disc->device_id);
                    ble_connect_to_node(manager, disc->device_id);
                }
            }
        }
    }

    return TRUE;  /* Continue timer */
}

static gboolean periodic_heartbeat_callback(gpointer user_data) {
    ble_node_manager_t *manager = (ble_node_manager_t *)user_data;

    if (!manager || !manager->running) return FALSE;

    uint32_t current_time = get_current_timestamp();

    /* Send heartbeat to all connected nodes */
    struct heartbeat hb = {
        .device_status = 0x01,  /* Active */
        .active_connection_number = (uint8_t)ble_get_connected_count(manager),
        .timestamp = current_time
    };

    uint8_t buffer[32];
    size_t len = serialize_heartbeat(&hb, buffer, sizeof(buffer));

    if (len > 0) {
        ble_broadcast_data(manager, buffer, len);
    }

    /* Check for missed heartbeats */
    check_heartbeat_timeouts(manager->mesh_node, current_time);

    /* Expire old routes */
    expire_routes(manager->mesh_node->routing_table, current_time);

    log_debug(BT_TAG, "Heartbeat sent to %d connected nodes", ble_get_connected_count(manager));

    return TRUE;  /* Continue timer */
}

