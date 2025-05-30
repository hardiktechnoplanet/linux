#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

/* Create and configure a socket to monitor network traffic */
static int setup_socket(const char *ifname) {
    struct sockaddr_ll addr;
    int sock;

    /* Create raw socket */
    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        return -1;
    }

    /* Bind socket to network interface */
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = if_nametoindex(ifname);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Error binding to %s: %s\n", ifname, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd, map_fd, sock;
    char *interface = "lo";    // Default to loopback interface
    int key;
    unsigned long long packets;

    /* Step 1: Load the BPF program */
    printf("Loading BPF program...\n");
    obj = bpf_object__open_file("my_bpf_prog.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error loading BPF program\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Step 2: Get file descriptors for the program and map */
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "count_packets"));
    map_fd = bpf_object__find_map_fd_by_name(obj, "protocol_map");

    if (prog_fd < 0 || map_fd < 0) {
        fprintf(stderr, "Error getting BPF program or map\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Step 3: Set up network monitoring */
    sock = setup_socket(interface);
    if (sock < 0) {
        bpf_object__close(obj);
        return 1;
    }

    /* Step 4: Attach BPF program to socket */
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        fprintf(stderr, "Error attaching BPF program\n");
        close(sock);
        bpf_object__close(obj);
        return 1;
    }

    /* Step 5: Monitor packet counts */
    printf("\nMonitoring packets on %s interface...\n", interface);
    printf("Protocol numbers: 1=ICMP, 6=TCP, 17=UDP\n");
    printf("Try 'ping localhost' in another terminal\n\n");

    while (1) {
        printf("\033[2J\033[H");  // Clear screen
        printf("Protocol counts:\n");
        
        /* Check each protocol */
        for (key = 0; key < 256; key++) {
            if (bpf_map_lookup_elem(map_fd, &key, &packets) == 0 && packets > 0) {
                printf("Protocol %3d: %llu packets\n", key, packets);
            }
        }
        sleep(1);
    }

    return 0;
}
