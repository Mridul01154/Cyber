#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include "logger.h"
#include "detection.h"
#include "proc_monitor.h"

typedef struct ethhdr {
    u_char dest[6];
    u_char src[6];
    u_short type;
} ethhdr;

typedef struct iphdr {
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_int src_addr;
    u_int dst_addr;
} iphdr;

typedef struct udphdr {
    u_short src_port;
    u_short dst_port;
    u_short len;
    u_short crc;
} udphdr;

 struct ipv6hdr {
        unsigned char ver_tc_flow[4];
        unsigned short payload_len;
        unsigned char next_header;
        unsigned char hop_limit;
        unsigned char src[16];
        unsigned char dst[16];
    };

typedef struct tcphdr {
    u_short src_port;
    u_short dst_port;
    u_int seq_num;
    u_int ack_num;
    u_char offset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
} tcphdr;

struct arphdr {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

// === Helper functions ===
void print_mac(const uint8_t *mac, char *buf) {
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

void print_ip(const uint8_t *ip, char *buf) {
    sprintf(buf, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void get_tcp_flags_str(u_char flags, char *buf, size_t buflen) {
    buf[0] = '\0';  // clear buffer

    if (flags & 0x01) strncat(buf, "FIN ", buflen - strlen(buf) - 1);
    if (flags & 0x02) strncat(buf, "SYN ", buflen - strlen(buf) - 1);
    if (flags & 0x04) strncat(buf, "RST ", buflen - strlen(buf) - 1);
    if (flags & 0x08) strncat(buf, "PSH ", buflen - strlen(buf) - 1);
    if (flags & 0x10) strncat(buf, "ACK ", buflen - strlen(buf) - 1);
    if (flags & 0x20) strncat(buf, "URG ", buflen - strlen(buf) - 1);
}

void print_ip_IN(u_int ip) {
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    printf("%s", inet_ntoa(addr));
}

void ip_to_str(u_int ip, char *buf) {
    struct in_addr addr;
    addr.s_addr = ip;
    strcpy(buf, inet_ntoa(addr));
}

// === Process monitor thread ===
DWORD WINAPI proc_monitor_thread(LPVOID param) {
    while (1) {
        monitor_processes();
        Sleep(10000);
    }
    return 0;
}

// === Packet handler ===
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    ethhdr *eth = (ethhdr *)pkt_data;
    u_short eth_type = ntohs(eth->type);

    if (eth_type == 0x0800) { // IPv4 packet
        iphdr *ip = (iphdr *)(pkt_data + 14);
        printf("IP Packet: ");
        print_ip_IN(ip->src_addr);
        printf(" -> ");
        print_ip_IN(ip->dst_addr);

        char logbuf[256] = "IP Packet: ";
        char src_ip[16], dst_ip[16];
        ip_to_str(ip->src_addr, src_ip);
        ip_to_str(ip->dst_addr, dst_ip);
        detect_blacklist_ip(src_ip);
        strcat(logbuf, src_ip);
        strcat(logbuf, " -> ");
        strcat(logbuf, dst_ip);

if (ip->proto == 6) { // TCP
    tcphdr *tcp = (tcphdr *)(pkt_data + 14 + (ip->ver_ihl & 0x0F) * 4);

    char flags_str[64];
    get_tcp_flags_str(tcp->flags, flags_str, sizeof(flags_str));

    printf(" [TCP %d -> %d] [Flags: %s]", ntohs(tcp->src_port), ntohs(tcp->dst_port), flags_str);

    if (tcp->flags & 0x02) { // SYN
        detect_syn_flood(src_ip);
        log_message("INFO", "[SYN_PACKET] TCP SYN detected: %s -> %s", src_ip, dst_ip);
    }

    detect_blacklist_port(ntohs(tcp->dst_port));
    detect_port_scan(src_ip, ntohs(tcp->dst_port));

    char portinfo[128];
    sprintf(portinfo, " [TCP %d -> %d] [Flags: %s]", ntohs(tcp->src_port), ntohs(tcp->dst_port), flags_str);
    strcat(logbuf, portinfo);

    log_message("INFO", "[TCP_PACKET] %s", logbuf);
}

        else if (ip->proto == 17) { // UDP
            udphdr *udp = (udphdr *)(pkt_data + 14 + (ip->ver_ihl & 0x0F) * 4);
            printf(" [UDP %d -> %d]", ntohs(udp->src_port), ntohs(udp->dst_port));

            detect_udp_flood(src_ip);
            detect_port_scan(src_ip, ntohs(udp->dst_port));

            char portinfo[64];
            sprintf(portinfo, " [UDP %d -> %d]", ntohs(udp->src_port), ntohs(udp->dst_port));
            strcat(logbuf, portinfo);

            log_message("INFO", "[UDP_PACKET] %s", logbuf);
        }
        else {
            printf(" [Protocol: %d]", ip->proto);
            char protoinfo[32];
            sprintf(protoinfo, " [Protocol: %d]", ip->proto);
            strcat(logbuf, protoinfo);

            log_message("INFO", "[IP_PACKET] %s", logbuf);
        }

        printf("\n");
    }
    else if (eth_type == 0x0806) { // ARP
        struct arphdr *arp = (struct arphdr *)(pkt_data + sizeof(ethhdr));

        char sender_ip[16], target_ip[16];
        char sender_mac[18], target_mac[18];
        print_ip(arp->sender_ip, sender_ip);
        print_ip(arp->target_ip, target_ip);
        print_mac(arp->sender_mac, sender_mac);
        print_mac(arp->target_mac, target_mac);

        printf(" [ARP %s (%s) -> %s (%s)]\n", sender_ip, sender_mac, target_ip, target_mac);

        char logbuf[256];
        sprintf(logbuf, "ARP %s (%s) -> %s (%s)", sender_ip, sender_mac, target_ip, target_mac);
        log_message("INFO", "[ARP_PACKET] %s", logbuf);
    }
    else { // IPv6 or other
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(pkt_data + 14);

        char src_ip[40], dst_ip[40];
        sprintf(src_ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ip6->src[0], ip6->src[1], ip6->src[2], ip6->src[3],
            ip6->src[4], ip6->src[5], ip6->src[6], ip6->src[7],
            ip6->src[8], ip6->src[9], ip6->src[10], ip6->src[11],
            ip6->src[12], ip6->src[13], ip6->src[14], ip6->src[15]);

        sprintf(dst_ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ip6->dst[0], ip6->dst[1], ip6->dst[2], ip6->dst[3],
            ip6->dst[4], ip6->dst[5], ip6->dst[6], ip6->dst[7],
            ip6->dst[8], ip6->dst[9], ip6->dst[10], ip6->dst[11],
            ip6->dst[12], ip6->dst[13], ip6->dst[14], ip6->dst[15]);

        printf(" [IPv6 %s -> %s]\n", src_ip, dst_ip);
        log_message("INFO", "[IPV6_PACKET] IPv6 packet: %s -> %s", src_ip, dst_ip);
    }
}

// === Main ===
int main() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    if (init_logger("sniffer") != 0) {
        fprintf(stderr, "Logger init failed. Exiting.\n");
        return -1;
    }

    load_rules("config/rules.config");
    load_proc_rules("config/proc_rules.config");
    load_bad_hashes("config/bad_hashes.txt");

    HANDLE hProcThread = CreateThread(NULL, 0, proc_monitor_thread, NULL, 0, NULL);
    if (!hProcThread) {
        log_message("ERROR", "Failed to start process monitor thread");
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    for (device = alldevs; device; device = device->next) {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("No interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter interface number: ");
    int inum;
    scanf("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("Invalid interface number.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (device = alldevs, i = 1; i < inum; device = device->next, i++);

    pcap_t *adhandle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (!adhandle) {
        fprintf(stderr, "Unable to open adapter. %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("Listening on %s...\n", device->description);
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    pcap_freealldevs(alldevs);
if (hProcThread) {
        TerminateThread(hProcThread, 0);
        CloseHandle(hProcThread);
    }
    free_proc_blacklist();
    free_all_detection_memory();
    close_logger();
    return 0;
}
