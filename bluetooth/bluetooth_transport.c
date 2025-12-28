#include "bluetooth_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

/* Thread data for listener */
struct listener_thread_data {
    struct bt_transport *transport;
    pthread_t thread;
};

static struct listener_thread_data *listener_data = NULL;

/* Convert Bluetooth address to device ID (32-bit hash) */
uint32_t bt_addr_to_device_id(const uint8_t *bdaddr) {
    if (!bdaddr) return 0;

    // Use a simple hash combining the 6 bytes of the Bluetooth address
    // XOR and shift to create a 32-bit identifier
    uint32_t id = 0;
    id |= ((uint32_t)bdaddr[0] << 24);
    id |= ((uint32_t)bdaddr[1] << 16);
    id |= ((uint32_t)bdaddr[2] << 8);
    id |= ((uint32_t)bdaddr[3]);
    id ^= ((uint32_t)bdaddr[4] << 20);
    id ^= ((uint32_t)bdaddr[5] << 12);

    return id;
}

/* Convert Bluetooth address to string */
void bt_addr_to_str(const uint8_t *bdaddr, char *str) {
    if (!bdaddr || !str) return;

    snprintf(str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             bdaddr[5], bdaddr[4], bdaddr[3],
             bdaddr[2], bdaddr[1], bdaddr[0]);
}

/* Convert string to Bluetooth address */
int bt_str_to_addr(const char *str, uint8_t *bdaddr) {
    if (!str || !bdaddr) return -1;

    unsigned int addr[6];
    if (sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
               &addr[5], &addr[4], &addr[3],
               &addr[2], &addr[1], &addr[0]) != 6) {
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        bdaddr[i] = (uint8_t)addr[i];
    }

    return 0;
}

/* Initialize Bluetooth transport layer */
struct bt_transport *bt_transport_init(void) {
    struct bt_transport *transport = calloc(1, sizeof(struct bt_transport));
    if (!transport) {
        fprintf(stderr, "Failed to allocate transport\n");
        return NULL;
    }

    // Retrieve the resource number of the first available Bluetooth adapter
    transport->dev_id = hci_get_route(NULL);
    if (transport->dev_id < 0) {
        fprintf(stderr, "No Bluetooth adapter found\n");
        free(transport);
        return NULL;
    }

    // Opens a Bluetooth socket with the specified resource number
    transport->hci_socket = hci_open_dev(transport->dev_id);
    if (transport->hci_socket < 0) {
        fprintf(stderr, "Failed to open HCI device: %s\n", strerror(errno));
        free(transport);
        return NULL;
    }

    // Get local device info
    struct hci_dev_info di;
    if (hci_devinfo(transport->dev_id, &di) == 0) {
        memcpy(transport->local_bdaddr, &di.bdaddr, BT_ADDR_LEN);
        strncpy(transport->local_name, di.name, sizeof(transport->local_name) - 1);
        transport->local_device_id = bt_addr_to_device_id(transport->local_bdaddr);

        char addr_str[18];
        ba2str(&di.bdaddr, addr_str);
        printf("Local device: %s (%s) ID: 0x%08X\n",
               di.name, addr_str, transport->local_device_id);
    }

    transport->listen_socket = -1;
    transport->running = false;
    transport->listener_active = false;
    transport->device_count = 0;

    return transport;
}

/* Shutdown Bluetooth transport */
void bt_transport_shutdown(struct bt_transport *transport) {
    if (!transport) return;

    // Stop listener
    bt_stop_listener(transport);

    // Disconnect all devices
    for (size_t i = 0; i < transport->device_count; i++) {
        if (transport->devices[i].is_connected && transport->devices[i].socket_fd >= 0) {
            close(transport->devices[i].socket_fd);
        }
    }

    // Close sockets
    if (transport->listen_socket >= 0) {
        close(transport->listen_socket);
    }

    if (transport->hci_socket >= 0) {
        close(transport->hci_socket);
    }

    free(transport);
}

/* Set device discoverable mode */
int bt_set_discoverable(struct bt_transport *transport, bool discoverable) {
    if (!transport || transport->hci_socket < 0) return -1;

    uint8_t scan_mode = discoverable ? (SCAN_PAGE | SCAN_INQUIRY) : SCAN_PAGE;

    struct {
        uint8_t scan_enable;
    } cp;
    cp.scan_enable = scan_mode;

    struct hci_request request;
    memset(&request, 0, sizeof(request));
    request.ogf = OGF_HOST_CTL;
    request.ocf = 0x001A;
    request.cparam = &cp;
    request.clen = sizeof(cp);
    request.rparam = NULL;
    request.rlen = 0;

    if (hci_send_req(transport->hci_socket, &request, 1000) < 0) {
        fprintf(stderr, "Warning: Could not set discoverable mode: %s\n", strerror(errno));
        return -1;
    }

    printf("Bluetooth adapter set to %s mode\n", discoverable ? "DISCOVERABLE" : "NOT DISCOVERABLE");
    return 0;
}

/* Scan for nearby Bluetooth devices */
int bt_scan_devices(struct bt_transport *transport, struct bt_device_info *devices, size_t max_devices) {
    if (!transport || !devices || max_devices == 0) return -1;

    int sock = hci_open_dev(transport->dev_id);
    if (sock < 0) {
        fprintf(stderr, "Opening HCI socket\n");
        return -1;
    }

    inquiry_info *inquiry_results = malloc(max_devices * sizeof(inquiry_info));
    if (!inquiry_results) {
        close(sock);
        return -1;
    }

    printf("Scanning for devices (%d sec)...\n", BT_SCAN_TIME);

    int flags = IREQ_CACHE_FLUSH;
    // Performs a Bluetooth device discovery and returns a list of detected devices
    int num_found = hci_inquiry(transport->dev_id, BT_SCAN_TIME, max_devices,
                                 NULL, &inquiry_results, flags);

    if (num_found < 0) {
        perror("HCI inquiry failed");
        free(inquiry_results);
        close(sock);
        return -1;
    }

    printf("Found %d device(s)\n", num_found);

    for (int i = 0; i < num_found && (size_t)i < max_devices; i++) {
        memcpy(devices[i].bdaddr, &inquiry_results[i].bdaddr, BT_ADDR_LEN);
        devices[i].device_id = bt_addr_to_device_id(devices[i].bdaddr);
        devices[i].is_connected = false;
        devices[i].socket_fd = -1;

        char addr[19] = {0};
        char name[248] = {0};

        // Conversions between string and bdaddr_t structs
        ba2str(&(inquiry_results[i].bdaddr), addr);

        // Determines the user-friendly names associated with those addresses
        if (hci_read_remote_name(sock, &(inquiry_results[i].bdaddr), sizeof(name), name, 0) < 0) {
            strcpy(name, "[unknown]");
        }

        strncpy(devices[i].name, name, sizeof(devices[i].name) - 1);
        devices[i].rssi = 0;

        printf("[%d] %s - %s (ID: 0x%08X)\n", i, addr, name, devices[i].device_id);
    }

    free(inquiry_results);
    close(sock);

    return num_found;
}

/* Connect to a Bluetooth device */
int bt_connect(struct bt_transport *transport, struct bt_device_info *device) {
    if (!transport || !device) return -1;

    struct sockaddr_rc addr = {0};
    int sock;
    char addr_str[18];

    // Conversions between string and bdaddr_t structs
    ba2str((bdaddr_t *)device->bdaddr, addr_str);
    printf("Connecting to %s on channel %d...\n", addr_str, BT_RFCOMM_CHANNEL);

    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (sock < 0) {
        perror("Send socket creation failed");
        return -1;
    }

    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t)BT_RFCOMM_CHANNEL;
    memcpy(&addr.rc_bdaddr, device->bdaddr, BT_ADDR_LEN);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Could not connect to %s: %s\n", addr_str, strerror(errno));
        close(sock);
        return -1;
    }

    device->socket_fd = sock;
    device->is_connected = true;

    // Add to device list if not already present
    struct bt_device_info *existing = bt_find_device(transport, device->device_id);
    if (!existing && transport->device_count < BT_MAX_DEVICES) {
        transport->devices[transport->device_count] = *device;
        transport->device_count++;
    } else if (existing) {
        *existing = *device;
    }

    printf("Connected to %s\n", addr_str);

    // Notify callback
    if (transport->on_device_connected) {
        transport->on_device_connected(transport, device, transport->user_data);
    }

    return 0;
}

/* Disconnect from a Bluetooth device */
int bt_disconnect(struct bt_transport *transport, struct bt_device_info *device) {
    if (!transport || !device) return -1;

    if (device->socket_fd >= 0) {
        close(device->socket_fd);
        device->socket_fd = -1;
    }

    device->is_connected = false;

    // Notify callback
    if (transport->on_device_disconnected) {
        transport->on_device_disconnected(transport, device, transport->user_data);
    }

    return 0;
}

/* Send data to a connected device */
ssize_t bt_send(struct bt_transport *transport, struct bt_device_info *device,
                const uint8_t *data, size_t len) {
    if (!transport || !device || !data || len == 0) return -1;

    if (!device->is_connected || device->socket_fd < 0) {
        fprintf(stderr, "Device not connected\n");
        return -1;
    }

    ssize_t sent = write(device->socket_fd, data, len);
    if (sent < 0) {
        fprintf(stderr, "Failed to send data: %s\n", strerror(errno));
        // Mark device as disconnected
        device->is_connected = false;
        if (transport->on_device_disconnected) {
            transport->on_device_disconnected(transport, device, transport->user_data);
        }
        return -1;
    }

    return sent;
}

/* Broadcast data to all connected devices */
int bt_broadcast(struct bt_transport *transport, const uint8_t *data, size_t len,
                 struct bt_device_info *exclude_device) {
    if (!transport || !data || len == 0) return -1;

    int sent_count = 0;
    for (size_t i = 0; i < transport->device_count; i++) {
        struct bt_device_info *device = &transport->devices[i];

        // Skip excluded device
        if (exclude_device && device->device_id == exclude_device->device_id) {
            continue;
        }

        if (device->is_connected) {
            ssize_t result = bt_send(transport, device, data, len);
            if (result > 0) {
                sent_count++;
            }
        }
    }

    return sent_count;
}

/* Listener thread function */
static void *listener_thread_func(void *arg) {
    struct listener_thread_data *data = (struct listener_thread_data *)arg;
    struct bt_transport *transport = data->transport;

    uint8_t buffer[BT_RECV_BUFFER_SIZE];
    fd_set read_fds;
    struct timeval tv;

    while (transport->running) {
        FD_ZERO(&read_fds);
        int max_fd = transport->listen_socket;

        FD_SET(transport->listen_socket, &read_fds);

        // Add connected device sockets
        for (size_t i = 0; i < transport->device_count; i++) {
            if (transport->devices[i].is_connected && transport->devices[i].socket_fd >= 0) {
                FD_SET(transport->devices[i].socket_fd, &read_fds);
                if (transport->devices[i].socket_fd > max_fd) {
                    max_fd = transport->devices[i].socket_fd;
                }
            }
        }

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int result = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (result < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Select error: %s\n", strerror(errno));
            break;
        }

        if (result == 0) continue;  // Timeout

        // Check for incoming connections
        if (FD_ISSET(transport->listen_socket, &read_fds)) {
            struct sockaddr_rc rem_addr = {0};
            socklen_t opt = sizeof(rem_addr);

            int client = accept(transport->listen_socket, (struct sockaddr *)&rem_addr, &opt);
            if (client >= 0) {
                struct bt_device_info new_device = {0};
                memcpy(new_device.bdaddr, &rem_addr.rc_bdaddr, BT_ADDR_LEN);
                new_device.device_id = bt_addr_to_device_id(new_device.bdaddr);
                new_device.is_connected = true;
                new_device.socket_fd = client;
                strcpy(new_device.name, "[incoming]");

                char addr_str[18];
                ba2str(&rem_addr.rc_bdaddr, addr_str);
                printf("\nConnection from %s (ID: 0x%08X)\n", addr_str, new_device.device_id);

                // Add to device list
                if (transport->device_count < BT_MAX_DEVICES) {
                    transport->devices[transport->device_count] = new_device;
                    transport->device_count++;

                    if (transport->on_device_connected) {
                        transport->on_device_connected(transport,
                            &transport->devices[transport->device_count - 1],
                            transport->user_data);
                    }
                } else {
                    fprintf(stderr, "Max devices reached, rejecting connection\n");
                    close(client);
                }
            }
        }

        // Check for data from connected devices
        for (size_t i = 0; i < transport->device_count; i++) {
            struct bt_device_info *device = &transport->devices[i];

            if (device->is_connected && device->socket_fd >= 0 &&
                FD_ISSET(device->socket_fd, &read_fds)) {

                memset(buffer, 0, sizeof(buffer));
                ssize_t bytes_read = read(device->socket_fd, buffer, sizeof(buffer) - 1);

                if (bytes_read > 0) {
                    char addr_str[18];
                    ba2str((bdaddr_t *)device->bdaddr, addr_str);
                    printf("\n\nRECEIVED MESSAGE FROM %s:\n", addr_str);
                    printf("%s\n\n", (char *)buffer);

                    if (transport->on_data_received) {
                        transport->on_data_received(transport, device, buffer,
                                                    bytes_read, transport->user_data);
                    }
                } else if (bytes_read == 0) {
                    // Connection closed
                    char addr_str[18];
                    ba2str((bdaddr_t *)device->bdaddr, addr_str);
                    printf("Device %s disconnected\n", addr_str);

                    close(device->socket_fd);
                    device->socket_fd = -1;
                    device->is_connected = false;

                    if (transport->on_device_disconnected) {
                        transport->on_device_disconnected(transport, device, transport->user_data);
                    }
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    // Error
                    fprintf(stderr, "Read error from device: %s\n", strerror(errno));
                    close(device->socket_fd);
                    device->socket_fd = -1;
                    device->is_connected = false;

                    if (transport->on_device_disconnected) {
                        transport->on_device_disconnected(transport, device, transport->user_data);
                    }
                }
            }
        }
    }

    transport->listener_active = false;
    return NULL;
}

/* Start the listener for incoming connections */
int bt_start_listener(struct bt_transport *transport) {
    if (!transport) return -1;

    if (transport->listener_active) {
        printf("Listener already running\n");
        return 0;
    }

    // Set discoverable mode before listening
    bt_set_discoverable(transport, true);

    // Create listening socket
    transport->listen_socket = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (transport->listen_socket < 0) {
        perror("Listener socket creation failed");
        return -1;
    }

    // Bind to local address
    struct sockaddr_rc loc_addr = {0};
    loc_addr.rc_family = AF_BLUETOOTH;
    loc_addr.rc_bdaddr = *BDADDR_ANY;
    loc_addr.rc_channel = (uint8_t)BT_RFCOMM_CHANNEL;

    if (bind(transport->listen_socket, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
        perror("Listener bind failed");
        close(transport->listen_socket);
        transport->listen_socket = -1;
        return -1;
    }

    if (listen(transport->listen_socket, 1) < 0) {
        perror("Listener failed");
        close(transport->listen_socket);
        transport->listen_socket = -1;
        return -1;
    }

    printf("Listening on RFCOMM channel %d\n", BT_RFCOMM_CHANNEL);

    // Start listener thread
    listener_data = malloc(sizeof(struct listener_thread_data));
    if (!listener_data) {
        close(transport->listen_socket);
        transport->listen_socket = -1;
        return -1;
    }

    listener_data->transport = transport;
    transport->running = true;
    transport->listener_active = true;

    if (pthread_create(&listener_data->thread, NULL, listener_thread_func, listener_data) != 0) {
        perror("Failed to create listener thread");
        free(listener_data);
        listener_data = NULL;
        close(transport->listen_socket);
        transport->listen_socket = -1;
        transport->running = false;
        transport->listener_active = false;
        return -1;
    }

    return 0;
}

/* Stop the listener */
void bt_stop_listener(struct bt_transport *transport) {
    if (!transport) return;

    transport->running = false;

    if (listener_data) {
        pthread_join(listener_data->thread, NULL);
        free(listener_data);
        listener_data = NULL;
    }

    if (transport->listen_socket >= 0) {
        close(transport->listen_socket);
        transport->listen_socket = -1;
    }

    transport->listener_active = false;
}

/* Find device by device ID */
struct bt_device_info *bt_find_device(struct bt_transport *transport, uint32_t device_id) {
    if (!transport) return NULL;

    for (size_t i = 0; i < transport->device_count; i++) {
        if (transport->devices[i].device_id == device_id) {
            return &transport->devices[i];
        }
    }

    return NULL;
}

/* Find device by Bluetooth address */
struct bt_device_info *bt_find_device_by_addr(struct bt_transport *transport, const uint8_t *bdaddr) {
    if (!transport || !bdaddr) return NULL;

    for (size_t i = 0; i < transport->device_count; i++) {
        if (memcmp(transport->devices[i].bdaddr, bdaddr, BT_ADDR_LEN) == 0) {
            return &transport->devices[i];
        }
    }

    return NULL;
}

/* Set transport callbacks */
void bt_set_callbacks(struct bt_transport *transport,
                      void (*on_discovered)(struct bt_transport*, struct bt_device_info*, void*),
                      void (*on_connected)(struct bt_transport*, struct bt_device_info*, void*),
                      void (*on_disconnected)(struct bt_transport*, struct bt_device_info*, void*),
                      void (*on_data)(struct bt_transport*, struct bt_device_info*, const uint8_t*, size_t, void*),
                      void *user_data) {
    if (!transport) return;

    transport->on_device_discovered = on_discovered;
    transport->on_device_connected = on_connected;
    transport->on_device_disconnected = on_disconnected;
    transport->on_data_received = on_data;
    transport->user_data = user_data;
}

