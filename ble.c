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

#define TAG "TextTransfer"
#define TEXT_TRANSFER_SERVICE "00001234-0000-1000-8000-00805f9b34fb"
#define TEXT_DATA_CHAR "00001235-0000-1000-8000-00805f9b34fb"
#define MAX_CHUNK_SIZE 512

// Global variables
static Adapter *default_adapter = NULL;
static Device *connected_device = NULL;
static Application *app = NULL;
static Advertisement *advertisement = NULL;
static Agent *agent = NULL;
static GMainLoop *loop = NULL;
static char *text_to_send = NULL;
static size_t text_size = 0;
static size_t text_sent = 0;
static GString *received_text = NULL;

// Forward declarations
void on_scan_result(Adapter *adapter, Device *device);
void on_connection_state_changed(Device *device, ConnectionState state, const GError *error);
void on_services_resolved(Device *device);
void on_read(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error);
void on_write(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error);
void on_notify(Device *device, Characteristic *characteristic, const GByteArray *byteArray);
gboolean on_request_authorization(Device *device);
const char* on_local_char_read(const Application *app, const char *address, const char* service_uuid,
                                const char* char_uuid, const guint16 offset, const guint16 mtu);
const char* on_local_char_write(const Application *app, const char *address, const char *service_uuid,
                                 const char *char_uuid, GByteArray *byteArray, const guint16 offset, const guint16 mtu);

// Load text file
gboolean load_text_file(const char *filename) {
    GError *error = NULL;
    gchar *contents = NULL;
    gsize length = 0;

    if (!g_file_get_contents(filename, &contents, &length, &error)) {
        log_debug(TAG, "Failed to load file: %s", error->message);
        g_error_free(error);
        return FALSE;
    }

    text_to_send = contents;
    text_size = length;
    text_sent = 0;
    log_debug(TAG, "Loaded %zu bytes from %s", text_size, filename);
    return TRUE;
}

// Send next chunk of text
void send_next_chunk(Device *device) {
    if (text_sent >= text_size) {
        log_debug(TAG, "All text sent!");
        return;
    }

    size_t remaining = text_size - text_sent;
    size_t chunk_size = (remaining > MAX_CHUNK_SIZE) ? MAX_CHUNK_SIZE : remaining;

    GByteArray *chunk = g_byte_array_sized_new(chunk_size);
    g_byte_array_append(chunk, (const guint8*)(text_to_send + text_sent), chunk_size);

    Characteristic *text_char = binc_device_get_characteristic(device, TEXT_TRANSFER_SERVICE, TEXT_DATA_CHAR);
    if (text_char != NULL) {
        binc_characteristic_write(text_char, chunk, WITH_RESPONSE);
        text_sent += chunk_size;
        log_debug(TAG, "Sending chunk: %zu/%zu bytes", text_sent, text_size);
    }

    g_byte_array_free(chunk, TRUE);
}

// Callbacks for Central role
void on_scan_result(Adapter *adapter, Device *device) {
    const char* name = binc_device_get_name(device);
    if (name != NULL && g_str_has_prefix(name, "TextTransfer")) {
        log_debug(TAG, "Found device: %s", name);
        binc_adapter_stop_discovery(adapter);

        connected_device = device;
        binc_device_set_connection_state_change_cb(device, &on_connection_state_changed);
        binc_device_set_services_resolved_cb(device, &on_services_resolved);
        binc_device_set_read_char_cb(device, &on_read);
        binc_device_set_write_char_cb(device, &on_write);
        binc_device_set_notify_char_cb(device, &on_notify);
        binc_device_connect(device);
    }
}

void on_connection_state_changed(Device *device, ConnectionState state, const GError *error) {
    if (error != NULL) {
        log_debug(TAG, "Connection error: %s", error->message);
        return;
    }

    log_debug(TAG, "Connection state: %s", binc_device_get_connection_state_name(device));

    if (state == BINC_DISCONNECTED) {
        if (binc_device_get_bonding_state(device) != BINC_BONDED) {
            binc_adapter_remove_device(default_adapter, device);
        }
        connected_device = NULL;
    }
}

void on_services_resolved(Device *device) {
    log_debug(TAG, "Services resolved, setting up notifications...");

    Characteristic *text_char = binc_device_get_characteristic(device, TEXT_TRANSFER_SERVICE, TEXT_DATA_CHAR);
    if (text_char != NULL) {
        binc_characteristic_start_notify(text_char);

        // Start sending text after a short delay
        g_timeout_add(1000, (GSourceFunc)send_next_chunk, device);
    }
}

void on_read(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error) {
    if (error != NULL) {
        log_debug(TAG, "Read error: %s", error->message);
        return;
    }
}

void on_write(Device *device, Characteristic *characteristic, const GByteArray *byteArray, const GError *error) {
    if (error != NULL) {
        log_debug(TAG, "Write error: %s", error->message);
        return;
    }

    // Send next chunk after successful write
    send_next_chunk(device);
}

void on_notify(Device *device, Characteristic *characteristic, const GByteArray *byteArray) {
    if (byteArray != NULL && byteArray->len > 0) {
        g_string_append_len(received_text, (const gchar*)byteArray->data, byteArray->len);
        log_debug(TAG, "Received chunk: %u bytes (total: %zu)", byteArray->len, received_text->len);
    }
}

// Callbacks for Peripheral role
const char* on_local_char_read(const Application *app, const char *address, const char* service_uuid,
                                const char* char_uuid, const guint16 offset, const guint16 mtu) {
    if (g_str_equal(service_uuid, TEXT_TRANSFER_SERVICE) && g_str_equal(char_uuid, TEXT_DATA_CHAR)) {
        // Just return empty for reads - we use notifications/writes for data transfer
        GByteArray *empty = g_byte_array_new();
        binc_application_set_char_value(app, service_uuid, char_uuid, empty);
        g_byte_array_free(empty, TRUE);
        return NULL;
    }
    return BLUEZ_ERROR_REJECTED;
}

const char* on_local_char_write(const Application *app, const char *address, const char *service_uuid,
                                 const char *char_uuid, GByteArray *byteArray, const guint16 offset, const guint16 mtu) {
    if (g_str_equal(service_uuid, TEXT_TRANSFER_SERVICE) && g_str_equal(char_uuid, TEXT_DATA_CHAR)) {
        if (byteArray != NULL && byteArray->len > 0) {
            g_string_append_len(received_text, (const gchar*)byteArray->data, byteArray->len);
            log_debug(TAG, "Received write: %u bytes (total: %zu)", byteArray->len, received_text->len);
        }
        return NULL;
    }
    return BLUEZ_ERROR_REJECTED;
}

gboolean on_request_authorization(Device *device) {
    log_debug(TAG, "Authorizing device: %s", binc_device_get_name(device));
    return TRUE;  // JustWorks - auto accept
}

// Setup peripheral (server) role
void setup_peripheral() {
    log_debug(TAG, "Setting up peripheral...");

    // Create and register application
    app = binc_create_application(default_adapter);
    binc_application_add_service(app, TEXT_TRANSFER_SERVICE);
    binc_application_add_characteristic(app, TEXT_TRANSFER_SERVICE, TEXT_DATA_CHAR,
                                       GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE | GATT_CHR_PROP_NOTIFY);

    binc_application_set_char_read_cb(app, &on_local_char_read);
    binc_application_set_char_write_cb(app, &on_local_char_write);
    binc_adapter_register_application(default_adapter, app);

    // Create and start advertisement
    GPtrArray *adv_service_uuids = g_ptr_array_new();
    g_ptr_array_add(adv_service_uuids, TEXT_TRANSFER_SERVICE);

    advertisement = binc_advertisement_create();
    binc_advertisement_set_local_name(advertisement, "TextTransfer");
    binc_advertisement_set_services(advertisement, adv_service_uuids);
    binc_adapter_start_advertising(default_adapter, advertisement);

    g_ptr_array_free(adv_service_uuids, TRUE);
    log_debug(TAG, "Peripheral ready and advertising");
}

// Setup central (client) role
void setup_central() {
    log_debug(TAG, "Setting up central...");

    binc_adapter_set_discovery_cb(default_adapter, &on_scan_result);
    binc_adapter_set_discovery_filter(default_adapter, -100, NULL, NULL);

    // Start scanning after a delay to let peripheral advertise
    g_timeout_add(2000, (GSourceFunc)binc_adapter_start_discovery, default_adapter);
}

// Save received text to file
void save_received_text(const char *filename) {
    if (received_text->len > 0) {
        GError *error = NULL;
        if (g_file_set_contents(filename, received_text->str, received_text->len, &error)) {
            log_debug(TAG, "Saved %zu bytes to %s", received_text->len, filename);
        } else {
            log_debug(TAG, "Failed to save file: %s", error->message);
            g_error_free(error);
        }
    }
}

gboolean cleanup_callback(gpointer data) {
    log_debug(TAG, "Cleaning up...");

    save_received_text("received.txt");

    if (connected_device != NULL) {
        binc_device_disconnect(connected_device);
    }

    if (advertisement != NULL) {
        binc_adapter_stop_advertising(default_adapter, advertisement);
    }

    if (agent != NULL) {
        binc_agent_free(agent);
        agent = NULL;
    }

    if (default_adapter != NULL) {
        binc_adapter_free(default_adapter);
        default_adapter = NULL;
    }

    g_free(text_to_send);
    g_string_free(received_text, TRUE);
    g_main_loop_quit((GMainLoop *) data);
    return FALSE;
}

static void cleanup_handler(int signo) {
    if (signo == SIGINT) {
        log_debug(TAG, "Received SIGINT");
        cleanup_callback(loop);
    }
}

int main(int argc, char *argv[]) {
    log_enabled(TRUE);
    log_set_level(LOG_DEBUG);

    if (argc < 2) {
        printf("Usage: %s <text_file>\n", argv[0]);
        return 1;
    }

    if (!load_text_file(argv[1])) {
        return 1;
    }

    received_text = g_string_new(NULL);

    // Get a DBus connection
    GDBusConnection *dbusConnection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);

    // Setup signal handler
    if (signal(SIGINT, cleanup_handler) == SIG_ERR) {
        log_error(TAG, "Can't catch SIGINT");
    }

    // Setup mainloop
    loop = g_main_loop_new(NULL, FALSE);

    // Get the default adapter
    default_adapter = binc_adapter_get_default(dbusConnection);

    if (default_adapter == NULL) {
        log_error(TAG, "No Bluetooth adapter found");
        g_main_loop_unref(loop);
        return 1;
    }

    log_info(TAG, "Using adapter '%s'", binc_adapter_get_name(default_adapter));

    // Setup agent for bonding (JustWorks)
    agent = binc_agent_create(default_adapter, "/org/bluez/TextTransferAgent", NO_INPUT_NO_OUTPUT);
    binc_agent_set_request_authorization_cb(agent, &on_request_authorization);

    // Setup both peripheral and central roles
    setup_peripheral();
    setup_central();

    // Auto-cleanup after 5 minutes
    g_timeout_add_seconds(300, cleanup_callback, loop);

    // Run main loop
    log_debug(TAG, "Starting main loop...");
    g_main_loop_run(loop);

    // Disconnect from DBus
    g_dbus_connection_close_sync(dbusConnection, NULL, NULL);
    g_object_unref(dbusConnection);

    // Clean up mainloop
    g_main_loop_unref(loop);

    return 0;
}