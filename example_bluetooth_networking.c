#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define MAX_CONNECTIONS 10
#define RFCOMM_CHANNEL 1
#define MAX_NAME 248
#define SCAN_INTERVAL 10
#define SERVICE_UUID "00001101-0000-1000-8000-00805F9B34FB" // Serial Port Profile

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
} node_state_t;

node_state_t g_state = {0};

// Function prototypes
void* connection_handler(void* arg);
void* server_thread(void* arg);
void* scanner_thread(void* arg);
void cleanup_connection(connection_t* conn);
int is_already_connected(bdaddr_t* addr);
void send_message(int sock, const char* msg);

void signal_handler(int sig) {
    printf("\nShutting down gracefully...\n");
    g_state.running = 0;
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
            snprintf(response, sizeof(response), "ACK: %s", buffer);
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

    while (g_state.running) {
        int client = accept(g_state.server_sock, (struct sockaddr*)&rem_addr, &opt);
        if (client < 0) {
            if (!g_state.running) break;
            perror("Accept failed");
            continue;
        }

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

            if (connect(client_sock, (struct sockaddr*)&addr_rc, sizeof(addr_rc)) == 0) {
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

    // Initialize state
    pthread_mutex_init(&g_state.mutex, NULL);
    g_state.running = 1;
    g_state.server_sock = -1;

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

    printf("Shutdown complete\n");
    return 0;
}