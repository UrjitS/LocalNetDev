#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define MAX_DEVICES 10
#define SCAN_TIME 5
#define RFCOMM_CHANNEL 1

volatile bool listener_ready = false;
volatile bool stop_scanning = false;

// Set adapter to use Just Works (no pairing required)
int set_simple_pairing_mode(int hci_sock) {
    struct hci_request rq;
    uint8_t mode = 0x01; // Enable Simple Pairing
    uint8_t status;

    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_HOST_CTL;
    rq.ocf = 0x0056; // OCF_WRITE_SIMPLE_PAIRING_MODE
    rq.cparam = &mode;
    rq.clen = sizeof(mode);
    rq.rparam = &status;
    rq.rlen = 1;

    if (hci_send_req(hci_sock, &rq, 1000) < 0) {
        return -1;
    }

    return status;
}

// Disable authentication requirement
int set_no_security(int sock) {
    struct bt_security bt_sec;
    socklen_t len = sizeof(bt_sec);

    memset(&bt_sec, 0, sizeof(bt_sec));
    bt_sec.level = BT_SECURITY_LOW; // No authentication/encryption required

    if (setsockopt(sock, SOL_BLUETOOTH, BT_SECURITY, &bt_sec, sizeof(bt_sec)) < 0) {
        perror("Warning: Could not set security level");
        return -1;
    }

    return 0;
}

// Make adapter discoverable and connectable
int make_discoverable(int dev_id) {
    int hci_sock = hci_open_dev(dev_id);
    if (hci_sock < 0) {
        return -1;
    }

    // Enable Simple Pairing (Just Works)
    if (set_simple_pairing_mode(hci_sock) < 0) {
        fprintf(stderr, "Note: Could not enable Simple Pairing mode\n");
    } else {
        printf("Simple Pairing (Just Works) enabled\n");
    }

    // Set to discoverable and connectable
    uint8_t scan_mode = SCAN_PAGE | SCAN_INQUIRY;
    struct hci_request rq;
    uint8_t scan_enable = scan_mode;

    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_HOST_CTL;
    rq.ocf = OCF_WRITE_SCAN_ENABLE;
    rq.cparam = &scan_enable;
    rq.clen = sizeof(scan_enable);
    rq.rparam = NULL;
    rq.rlen = 0;

    if (hci_send_req(hci_sock, &rq, 1000) < 0) {
        fprintf(stderr, "Warning: Could not set discoverable mode: %s\n", strerror(errno));
        close(hci_sock);
        return -1;
    }

    printf("Bluetooth adapter set to DISCOVERABLE and CONNECTABLE mode\n");
    close(hci_sock);
    return 0;
}

void* listener_thread(void* arg) {
    struct sockaddr_rc loc_addr = {0}, rem_addr = {0};
    char buf[1024] = {0};
    int s, client, bytes_read;
    socklen_t opt = sizeof(rem_addr);
    int dev_id;

    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("Failed to get device ID");
        return NULL;
    }

    int hci_sock = hci_open_dev(dev_id);
    if (hci_sock >= 0) {
        struct hci_dev_info di;
        if (hci_devinfo(dev_id, &di) == 0) {
            printf("Local device: %s (%s)\n", di.name, batostr(&di.bdaddr));
        }
        close(hci_sock);
    }

    // Make discoverable
    make_discoverable(dev_id);

    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (s < 0) {
        perror("Listener socket creation failed");
        return NULL;
    }

    // Set to low security - no pairing required
    set_no_security(s);

    // Allow socket reuse
    int reuse = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
    }

    // Set non-blocking accept with timeout
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    loc_addr.rc_family = AF_BLUETOOTH;
    loc_addr.rc_bdaddr = *BDADDR_ANY;
    loc_addr.rc_channel = RFCOMM_CHANNEL;

    if (bind(s, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
        perror("Listener bind failed");
        close(s);
        return NULL;
    }

    if (listen(s, 5) < 0) {
        perror("Listener failed");
        close(s);
        return NULL;
    }

    printf("Listening on RFCOMM channel %d (NO PAIRING REQUIRED)\n", RFCOMM_CHANNEL);
    printf("Ready to accept connections!\n\n");

    listener_ready = true;

    while (true) {
        client = accept(s, (struct sockaddr *)&rem_addr, &opt);
        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout - this is normal, continue
                continue;
            }
            perror("Accept failed");
            continue;
        }

        // Got a connection!
        stop_scanning = true; // Signal to stop scanning when we get a connection

        // Set security on accepted connection too
        set_no_security(client);

        char addr_str[18];
        ba2str(&rem_addr.rc_bdaddr, addr_str);
        printf("\n*** INCOMING CONNECTION from %s ***\n", addr_str);

        memset(buf, 0, sizeof(buf));
        bytes_read = read(client, buf, sizeof(buf) - 1);
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
            printf("RECEIVED: %s\n", buf);

            // Send acknowledgment
            const char *ack = "Message received!";
            write(client, ack, strlen(ack));
            printf("Sent acknowledgment\n");
        } else if (bytes_read == 0) {
            printf("Connection closed by %s\n", addr_str);
        } else {
            perror("Read failed");
        }

        close(client);
        printf("*** Connection closed ***\n\n");

        stop_scanning = false;
    }

    close(s);
    return NULL;
}

int scan_devices(inquiry_info **devices, int dev_id) {
    int sock, num_rsp;
    int max_rsp = MAX_DEVICES;
    int flags = IREQ_CACHE_FLUSH;

    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Opening HCI socket for scan");
        return -1;
    }

    *devices = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));
    printf("Scanning for devices (%d sec)...\n", SCAN_TIME);

    // Temporarily disable discoverable mode during scan
    uint8_t scan_mode = SCAN_PAGE; // Only page scan (connectable but not discoverable)
    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_HOST_CTL;
    rq.ocf = OCF_WRITE_SCAN_ENABLE;
    rq.cparam = &scan_mode;
    rq.clen = sizeof(scan_mode);
    hci_send_req(sock, &rq, 1000);

    num_rsp = hci_inquiry(dev_id, SCAN_TIME, max_rsp, NULL, devices, flags);

    // Re-enable discoverable mode after scan
    make_discoverable(dev_id);

    if (num_rsp < 0) {
        perror("HCI inquiry failed");
        close(sock);
        free(*devices);
        return -1;
    }

    printf("Found %d device(s)\n", num_rsp);

    for (int i = 0; i < num_rsp; i++) {
        char addr[19] = {0};
        char name[248] = {0};

        ba2str(&((*devices)[i].bdaddr), addr);

        if (hci_read_remote_name(sock, &((*devices)[i].bdaddr), sizeof(name), name, 0) < 0) {
            strcpy(name, "[unknown]");
        }

        printf("  [%d] %s - %s\n", i, addr, name);
    }

    close(sock);
    return num_rsp;
}

int send_message(bdaddr_t *dest_addr, const char *message) {
    struct sockaddr_rc addr = {0};
    int sock;
    char addr_str[18];
    char buf[1024] = {0};

    ba2str(dest_addr, addr_str);
    printf("\n>>> Connecting to %s on channel %d...\n", addr_str, RFCOMM_CHANNEL);

    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (sock < 0) {
        perror("Send socket creation failed");
        return -1;
    }

    // Set to low security - no pairing required
    set_no_security(sock);

    // Set connection timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = RFCOMM_CHANNEL;
    addr.rc_bdaddr = *dest_addr;

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Could not connect to %s: %s\n", addr_str, strerror(errno));
        close(sock);
        return -1;
    }

    printf(">>> Connected! Sending message...\n");

    if (write(sock, message, strlen(message)) < 0) {
        perror("Send failed");
        close(sock);
        return -1;
    }

    printf(">>> Message sent: \"%s\"\n", message);

    // Wait for response
    int bytes_read = read(sock, buf, sizeof(buf) - 1);
    if (bytes_read > 0) {
        buf[bytes_read] = '\0';
        printf(">>> Response: %s\n", buf);
    } else if (bytes_read == 0) {
        printf(">>> Connection closed by remote device\n");
    }

    close(sock);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s \"message\" [bluetooth_address]\n", argv[0]);
        printf("  If bluetooth_address is provided, will only send to that device\n");
        printf("  Otherwise, will scan and send to all discovered devices\n");
        return EXIT_FAILURE;
    }

    const char *message = argv[1];
    const char *target_addr = (argc >= 3) ? argv[2] : NULL;
    pthread_t listener;
    int dev_id;

    printf("===========================================\n");
    printf("Bluetooth RFCOMM Messaging (Just Works)\n");
    printf("===========================================\n");
    printf("Message: \"%s\"\n", message);
    if (target_addr) {
        printf("Target: %s\n", target_addr);
    } else {
        printf("Mode: Scan and broadcast\n");
    }
    printf("===========================================\n\n");

    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("No Bluetooth adapter found");
        return EXIT_FAILURE;
    }

    printf("Starting listener thread...\n");
    if (pthread_create(&listener, NULL, listener_thread, NULL) != 0) {
        perror("Failed to create listener thread");
        return EXIT_FAILURE;
    }

    // Wait for listener to be ready
    while (!listener_ready) {
        usleep(100000);
    }
    printf("Listener ready!\n\n");

    // Wait a bit more to ensure other device can discover us
    sleep(2);

    // If specific address provided, send only to that device
    if (target_addr) {
        bdaddr_t dest_addr;
        if (str2ba(target_addr, &dest_addr) < 0) {
            fprintf(stderr, "Invalid Bluetooth address: %s\n", target_addr);
            return EXIT_FAILURE;
        }

        while (true) {
            if (!stop_scanning) {
                send_message(&dest_addr, message);
            }
            sleep(5);
        }
    } else {
        // Scan and send to all devices
        while (true) {
            if (!stop_scanning) {
                inquiry_info *devices = NULL;
                int num_devices = scan_devices(&devices, dev_id);

                if (num_devices > 0) {
                    printf("\nSending to %d device(s)...\n", num_devices);
                    for (int i = 0; i < num_devices && !stop_scanning; i++) {
                        send_message(&(devices[i].bdaddr), message);
                        sleep(1);
                    }
                } else {
                    printf("No devices found.\n");
                }

                if (devices) {
                    free(devices);
                }
            }

            printf("\nWaiting 10 seconds...\n\n");
            sleep(10);
        }
    }

    pthread_join(listener, NULL);
    return EXIT_SUCCESS;
}