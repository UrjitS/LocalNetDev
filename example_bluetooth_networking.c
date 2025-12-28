#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#define MAX_CONNECTIONS 10
#define RFCOMM_CHANNEL 1
#define MAX_NAME 248
#define SCAN_INTERVAL 10
#define SERVICE_UUID "00001101-0000-1000-8000-00805F9B34FB"

typedef struct {
    int sock;
    bdaddr_t addr;
    char name[MAX_NAME];
    int active;
    pthread_t thread;
} connection_t;

typedef struct {
    connection_t connections[MAX_CONNECTIONS];
    int conn_count;
    pthread_mutex_t mutex;
    int server_sock;
    int running;
    sdp_session_t* sdp_session;
} node_state_t;

node_state_t g_state = {0};

// Function prototypes
void* connection_handler(void* arg);
void* server_thread(void* arg);
void* scanner_thread(void* arg);
void cleanup_connection(connection_t* conn);
int is_already_connected(bdaddr_t* addr);
void send_message(int sock, const char* msg);
sdp_session_t* register_service(uint8_t rfcomm_channel);
int set_discoverable(int enable);

void signal_handler(int sig) {
    printf("\nShutting down gracefully...\n");
    g_state.running = 0;
}

int set_discoverable(int enable) {
    // Use system command as a simple fallback
    // This requires hciconfig to be installed
    int result;
    if (enable) {
        result = system("hciconfig hci0 piscan 2>/dev/null");
    } else {
        result = system("hciconfig hci0 noscan 2>/dev/null");
    }

    if (result == 0) {
        printf("Bluetooth adapter set to %s mode\n", enable ? "discoverable" : "non-discoverable");
        return 0;
    } else {
        fprintf(stderr, "Warning: Failed to set scan mode via hciconfig\n");
        return -1;
    }
}

sdp_session_t* register_service(uint8_t rfcomm_channel) {
    uuid_t root_uuid, l2cap_uuid, rfcomm_uuid, svc_uuid;
    sdp_list_t *l2cap_list = 0, *rfcomm_list = 0, *root_list = 0, *proto_list = 0, *access_proto_list = 0;
    sdp_data_t *channel = 0;
    sdp_record_t *record = sdp_record_alloc();

    // Set service class
    sdp_uuid128_create(&svc_uuid, &(const uint128_t){{0}});
    sdp_set_service_id(record, svc_uuid);

    // Set service name
    sdp_list_t service_class = {0};
    sdp_uuid16_create(&root_uuid, SERIAL_PORT_SVCLASS_ID);
    service_class.data = &root_uuid;
    sdp_set_service_classes(record, &service_class);

    // Set Bluetooth profile
    sdp_profile_desc_t profile;
    sdp_uuid16_create(&profile.uuid, SERIAL_PORT_PROFILE_ID);
    profile.version = 0x0100;
    sdp_list_t profile_list = {0};
    profile_list.data = &profile;
    sdp_set_profile_descs(record, &profile_list);

    // Make service browseable
    sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
    root_list = sdp_list_append(0, &root_uuid);
    sdp_set_browse_groups(record, root_list);

    // Set L2CAP protocol
    sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
    l2cap_list = sdp_list_append(0, &l2cap_uuid);
    proto_list = sdp_list_append(0, l2cap_list);

    // Set RFCOMM protocol
    sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
    channel = sdp_data_alloc(SDP_UINT8, &rfcomm_channel);
    rfcomm_list = sdp_list_append(0, &rfcomm_uuid);
    sdp_list_append(rfcomm_list, channel);
    sdp_list_append(proto_list, rfcomm_list);

    access_proto_list = sdp_list_append(0, proto_list);
    sdp_set_access_protos(record, access_proto_list);

    // Set service name and description
    sdp_set_info_attr(record, "BT Mesh Node", "Mesh Node", "Mesh networking node");

    // Register service
    sdp_session_t *session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
    if (!session) {
        perror("Failed to connect to SDP server");
        sdp_record_free(record);
        return NULL;
    }

    if (sdp_record_register(session, record, 0) < 0) {
        perror("Service registration failed");
        sdp_close(session);
        sdp_record_free(record);
        return NULL;
    }

    printf("Service registered on RFCOMM channel %d\n", rfcomm_channel);

    // Cleanup
    sdp_data_free(channel);
    sdp_list_free(l2cap_list, 0);
    sdp_list_free(rfcomm_list, 0);
    sdp_list_free(root_list, 0);
    sdp_list_free(access_proto_list, 0);

    return session;
}

void cleanup_connection(connection_t* conn) {
    if (conn->active) {
        conn->active = 0;
        if (conn->sock >= 0) {
            close(conn->sock);
            conn->sock = -1;
        }
    }
}

int is_already_connected(bdaddr_t* addr) {
    pthread_mutex_lock(&g_state.mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_state.connections[i].active &&
            bacmp(&g_state.connections[i].addr, addr) == 0) {
            pthread_mutex_unlock(&g_state.mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_state.mutex);
    return 0;
}

void send_message(int sock, const char* msg) {
    if (sock >= 0) {
        int len = strlen(msg);
        if (write(sock, msg, len) < 0) {
            perror("Failed to send message");
        }
    }
}

void* connection_handler(void* arg) {
    connection_t* conn = (connection_t*)arg;
    char buffer[1024];
    int bytes;

    printf("Connection handler started for %s\n", conn->name);

    // Send initial greeting
    char greeting[256];
    snprintf(greeting, sizeof(greeting), "HELLO from node\n");
    send_message(conn->sock, greeting);

    // Keep connection alive and handle incoming messages
    while (g_state.running && conn->active) {
        memset(buffer, 0, sizeof(buffer));
        bytes = read(conn->sock, buffer, sizeof(buffer) - 1);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received from %s: %s\n", conn->name, buffer);

            // Echo back or send acknowledgment
            char response[1024];
            int response_len = snprintf(response, sizeof(response), "ACK: ");
            int remaining = sizeof(response) - response_len - 1;
            strncat(response, buffer, remaining);
            send_message(conn->sock, response);
        } else if (bytes == 0) {
            printf("Connection closed by %s\n", conn->name);
            break;
        } else if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000); // 100ms
                continue;
            }
            perror("Read error");
            break;
        }
    }

    printf("Connection handler ending for %s\n", conn->name);
    cleanup_connection(conn);
    return NULL;
}

void* server_thread(void* arg) {
    struct sockaddr_rc loc_addr = {0}, rem_addr = {0};
    socklen_t opt = sizeof(rem_addr);

    // Create server socket
    g_state.server_sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (g_state.server_sock < 0) {
        perror("Failed to create server socket");
        return NULL;
    }

    // Set socket options for reuse
    int reuse = 1;
    if (setsockopt(g_state.server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("Failed to set SO_REUSEADDR");
    }

    // Bind to local adapter
    loc_addr.rc_family = AF_BLUETOOTH;
    loc_addr.rc_bdaddr = *BDADDR_ANY;
    loc_addr.rc_channel = (uint8_t)RFCOMM_CHANNEL;

    if (bind(g_state.server_sock, (struct sockaddr*)&loc_addr, sizeof(loc_addr)) < 0) {
        perror("Failed to bind server socket");
        close(g_state.server_sock);
        return NULL;
    }

    // Listen for connections
    if (listen(g_state.server_sock, 5) < 0) {
        perror("Failed to listen");
        close(g_state.server_sock);
        return NULL;
    }

    printf("Server listening on RFCOMM channel %d\n", RFCOMM_CHANNEL);

    // Register SDP service
    g_state.sdp_session = register_service(RFCOMM_CHANNEL);
    if (!g_state.sdp_session) {
        fprintf(stderr, "Warning: SDP registration failed, connections may not work\n");
    }

    while (g_state.running) {
        int client = accept(g_state.server_sock, (struct sockaddr*)&rem_addr, &opt);
        if (client < 0) {
            if (!g_state.running) break;
            perror("Accept failed");
            continue;
        }

        char addr_str[18];
        ba2str(&rem_addr.rc_bdaddr, addr_str);
        printf("Incoming connection from %s\n", addr_str);

        // Check if already connected
        if (is_already_connected(&rem_addr.rc_bdaddr)) {
            printf("Already connected to this device\n");
            close(client);
            continue;
        }

        // Find free slot
        pthread_mutex_lock(&g_state.mutex);
        int slot = -1;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (!g_state.connections[i].active) {
                slot = i;
                break;
            }
        }

        if (slot >= 0) {
            connection_t* conn = &g_state.connections[slot];
            conn->sock = client;
            conn->addr = rem_addr.rc_bdaddr;
            conn->active = 1;
            ba2str(&rem_addr.rc_bdaddr, conn->name);

            printf("Accepted connection from %s\n", conn->name);

            pthread_create(&conn->thread, NULL, connection_handler, conn);
            pthread_detach(conn->thread);
        } else {
            printf("No free connection slots\n");
            close(client);
        }
        pthread_mutex_unlock(&g_state.mutex);
    }

    if (g_state.sdp_session) {
        sdp_close(g_state.sdp_session);
    }
    close(g_state.server_sock);
    return NULL;
}

void* scanner_thread(void* arg) {
    inquiry_info* devices = NULL;
    int dev_id, sock, num_devices;
    char addr[19] = {0};
    char name[MAX_NAME] = {0};

    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("No Bluetooth adapter found");
        return NULL;
    }

    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Failed to open HCI socket");
        return NULL;
    }

    printf("Scanner started\n");

    while (g_state.running) {
        printf("Scanning for devices...\n");

        devices = (inquiry_info*)malloc(255 * sizeof(inquiry_info));
        if (!devices) {
            perror("Failed to allocate memory");
            sleep(SCAN_INTERVAL);
            continue;
        }

        num_devices = hci_inquiry(dev_id, 8, 255, NULL, &devices, IREQ_CACHE_FLUSH);
        if (num_devices < 0) {
            perror("Inquiry failed");
            free(devices);
            sleep(SCAN_INTERVAL);
            continue;
        }

        printf("Found %d device(s)\n", num_devices);

        for (int i = 0; i < num_devices; i++) {
            ba2str(&devices[i].bdaddr, addr);
            memset(name, 0, sizeof(name));

            if (hci_read_remote_name(sock, &devices[i].bdaddr, sizeof(name), name, 0) < 0)
                strcpy(name, "Unknown");

            printf("  %s - %s\n", addr, name);

            // Check if already connected
            if (is_already_connected(&devices[i].bdaddr)) {
                continue;
            }

            // Try to connect
            struct sockaddr_rc addr_rc = {0};
            int client_sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
            if (client_sock < 0) continue;

            addr_rc.rc_family = AF_BLUETOOTH;
            addr_rc.rc_channel = (uint8_t)RFCOMM_CHANNEL;
            addr_rc.rc_bdaddr = devices[i].bdaddr;

            printf("  Attempting to connect to %s...\n", addr);

            int connect_result = connect(client_sock, (struct sockaddr*)&addr_rc, sizeof(addr_rc));
            if (connect_result == 0) {
                printf("  Successfully connected to %s\n", name);

                pthread_mutex_lock(&g_state.mutex);
                int slot = -1;
                for (int j = 0; j < MAX_CONNECTIONS; j++) {
                    if (!g_state.connections[j].active) {
                        slot = j;
                        break;
                    }
                }

                if (slot >= 0) {
                    connection_t* conn = &g_state.connections[slot];
                    conn->sock = client_sock;
                    conn->addr = devices[i].bdaddr;
                    conn->active = 1;
                    strncpy(conn->name, name, MAX_NAME - 1);

                    pthread_create(&conn->thread, NULL, connection_handler, conn);
                    pthread_detach(conn->thread);
                } else {
                    close(client_sock);
                }
                pthread_mutex_unlock(&g_state.mutex);
            } else {
                int err = errno;
                printf("  Connection failed: %s (errno: %d)\n", strerror(err), err);
                if (err == ECONNREFUSED) {
                    printf("  -> Device may not be running the service or not in discoverable mode\n");
                } else if (err == EHOSTDOWN) {
                    printf("  -> Device is not reachable\n");
                } else if (err == EOPNOTSUPP) {
                    printf("  -> Authentication/pairing may be required\n");
                }
                close(client_sock);
            }
        }

        free(devices);

        // Wait before next scan
        for (int i = 0; i < SCAN_INTERVAL && g_state.running; i++) {
            sleep(1);
        }
    }

    close(sock);
    return NULL;
}

int main(int argc, char** argv) {
    pthread_t server_tid, scanner_tid;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Bluetooth Mesh Node Starting...\n");
    printf("This node will scan for and connect to other nodes\n");
    printf("Press Ctrl+C to exit\n\n");

    // Make adapter discoverable
    if (set_discoverable(1) < 0) {
        fprintf(stderr, "Warning: Failed to set discoverable mode\n");
        fprintf(stderr, "Try manually: sudo hciconfig hci0 piscan\n");
    }

    // Initialize state
    pthread_mutex_init(&g_state.mutex, NULL);
    g_state.running = 1;
    g_state.server_sock = -1;
    g_state.sdp_session = NULL;

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        g_state.connections[i].sock = -1;
        g_state.connections[i].active = 0;
    }

    // Start server thread
    if (pthread_create(&server_tid, NULL, server_thread, NULL) != 0) {
        perror("Failed to create server thread");
        return 1;
    }

    // Start scanner thread
    if (pthread_create(&scanner_tid, NULL, scanner_thread, NULL) != 0) {
        perror("Failed to create scanner thread");
        g_state.running = 0;
        pthread_join(server_tid, NULL);
        return 1;
    }

    // Main loop - could add interactive commands here
    while (g_state.running) {
        sleep(1);

        // Optional: Send periodic keepalive or status messages
        pthread_mutex_lock(&g_state.mutex);
        int active_count = 0;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (g_state.connections[i].active) {
                active_count++;
            }
        }
        pthread_mutex_unlock(&g_state.mutex);

        // Print status every 30 seconds
        static int counter = 0;
        if (++counter >= 30) {
            printf("Active connections: %d\n", active_count);
            counter = 0;
        }
    }

    // Cleanup
    printf("Cleaning up...\n");
    pthread_join(scanner_tid, NULL);
    pthread_join(server_tid, NULL);

    pthread_mutex_lock(&g_state.mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        cleanup_connection(&g_state.connections[i]);
    }
    pthread_mutex_unlock(&g_state.mutex);

    pthread_mutex_destroy(&g_state.mutex);

    // Restore discoverable mode
    set_discoverable(0);

    printf("Shutdown complete\n");
    return 0;
}