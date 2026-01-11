#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define MAX_DEVICES 10
#define SCAN_TIME 5

void* listener_thread(void* arg) {
    struct sockaddr_rc loc_addr = {0}, rem_addr = {0};
    char buf[1024] = {0};
    int s, client, bytes_read;
    socklen_t opt = sizeof(rem_addr);
    int dev_id, hci_sock;

    // Retrieve the resource number of the first available Bluetooth adapter https://people.csail.mit.edu/albert/bluez-intro/c404.html
    dev_id = hci_get_route(NULL);
    // opens a Bluetooth socket with the specified resource number https://people.csail.mit.edu/albert/bluez-intro/c404.html
    hci_sock = hci_open_dev(dev_id);

    if (hci_sock >= 0) {
        struct hci_dev_info di;
        if (hci_devinfo(dev_id, &di) == 0) {
            printf("Local device: %s (%s)\n", di.name, batostr(&di.bdaddr));
        }

        // Just need scan mode  https://people.csail.mit.edu/albert/bluez-intro/x559.html
        uint8_t scan_mode = SCAN_PAGE | SCAN_INQUIRY;
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

        if (hci_send_req(hci_sock, &request, 1000) < 0) {
            fprintf(stderr, "Warning: Could not set discoverable mode: %s\n", strerror(errno));
        } else {
            printf("Bluetooth adapter set to DISCOVERABLE mode\n");
        }

        close(hci_sock);
    }

    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (s < 0) {
        perror("Listener socket creation failed");
        return NULL;
    }

    loc_addr.rc_family = AF_BLUETOOTH;
    loc_addr.rc_bdaddr = *BDADDR_ANY;
    loc_addr.rc_channel = (uint8_t)BTPROTO_RFCOMM;

    if (bind(s, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
        perror("Listener bind failed");
        close(s);
        return NULL;
    }

    if (listen(s, 1) < 0) {
        perror("Listener failed");
        close(s);
        return NULL;
    }

    printf("Listening on RFCOMM channel %d\n", BTPROTO_RFCOMM);

    while (true) {
        client = accept(s, (struct sockaddr *)&rem_addr, &opt);
        if (client < 0) {
            perror("Accept failed");
            continue;
        }

        char addr_str[18];
        ba2str(&rem_addr.rc_bdaddr, addr_str);
        printf("\nConnection from %s\n", addr_str);

        memset(buf, 0, sizeof(buf));
        bytes_read = read(client, buf, sizeof(buf) - 1);
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
            printf("\n\nRECEIVED MESSAGE FROM %s:\n", addr_str);
            printf("%s\n\n", buf);
        }

        close(client);
    }

    close(s);
    return NULL;
}

int scan_devices(inquiry_info **devices) {
    int dev_id, sock, num_rsp;
    int max_rsp = MAX_DEVICES;
    int flags = IREQ_CACHE_FLUSH;

    dev_id = hci_get_route(NULL); // get device id https://people.csail.mit.edu/albert/bluez-intro/c404.html
    sock = hci_open_dev(dev_id); // opens a Bluetooth socket with the specified resource number https://people.csail.mit.edu/albert/bluez-intro/c404.html

    if (dev_id < 0 || sock < 0) {
        perror("Opening HCI socket");
        return -1;
    }

    *devices = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));
    printf("Scanning for devices (%d sec)...\n", SCAN_TIME);
    // performs a Bluetooth device discovery and returns a list of detected devices and some basic information about them
    num_rsp = hci_inquiry(dev_id, SCAN_TIME, max_rsp, NULL, devices, flags);

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

        // Conversions between string and bdaddr_t structs https://people.csail.mit.edu/albert/bluez-intro/c404.html
        ba2str(&((*devices)[i].bdaddr), addr);

        // Determines the user-friendly names associated with those addresses https://people.csail.mit.edu/albert/bluez-intro/c404.html
        if (hci_read_remote_name(sock, &((*devices)[i].bdaddr), sizeof(name), name, 0) < 0) {
            strcpy(name, "[unknown]");
        }

        printf("[%d] %s - %s\n", i, addr, name);
    }

    close(sock);
    return num_rsp;
}

int send_message(bdaddr_t *dest_addr, const char *message) {
    struct sockaddr_rc addr = {0};
    int sock;
    char addr_str[18];
    char buf[1024] = {0};

    // Conversions between string and bdaddr_t structs https://people.csail.mit.edu/albert/bluez-intro/c404.html
    ba2str(dest_addr, addr_str);
    printf("Connecting to %s on channel %d...\n", addr_str, BTPROTO_RFCOMM);

    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (sock < 0) {
        perror("Send socket creation failed");
        return -1;
    }

    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t)BTPROTO_RFCOMM;
    addr.rc_bdaddr = *dest_addr;

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Could not connect to %s: %s\n", addr_str, strerror(errno));
        close(sock);
        return -1;
    }

    printf("Connected, sending message...\n");

    if (write(sock, message, strlen(message)) < 0) {
        perror("Send failed");
        close(sock);
        return -1;
    }

    printf("Message sent to %s\n", addr_str);

    // Wait for response
    printf("Waiting for response...\n");
    int bytes_read = read(sock, buf, sizeof(buf) - 1);
    if (bytes_read > 0) {
        buf[bytes_read] = '\0';
        printf("\n\nRECEIVED RESPONSE FROM %s:\n", addr_str);
        printf("%s\n\n", buf);
    } else if (bytes_read == 0) {
        printf("Connection closed by remote device\n");
    } else {
        perror("Read failed");
    }

    close(sock);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s \"message to send\"\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *message = argv[1];
    pthread_t listener;

    printf("Bluetooth Prototype\n");
    printf("Sending Message: \"%s\"\n\n", message);

    if (pthread_create(&listener, NULL, listener_thread, NULL) != 0) {
        perror("Failed to create listener thread");
        return EXIT_FAILURE;
    }

    sleep(5);

    while (true) {
        inquiry_info *devices = NULL;
        int num_devices = scan_devices(&devices);

        if (num_devices > 0) {
            printf("\nSending to discovered devices\n\n");
            for (int i = 0; i < num_devices; i++) {
                send_message(&(devices[i].bdaddr), message);
                sleep(1);
            }
        } else {
            printf("No devices found.\n");
        }

        if (devices) {
            free(devices);
        }

        printf("\nWaiting 5 seconds before rescanning...\n\n");
        sleep(5);
    }

    pthread_join(listener, NULL);
    return EXIT_SUCCESS;
}