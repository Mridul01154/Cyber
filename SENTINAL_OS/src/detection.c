#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "logger.h"

#define MAX_BLACKLIST_BUCKETS 101
#define MAX_PORT_SCAN_BUCKETS 101
#define MAX_PORTS_TRACKED 100
#define MAX_FLOOD_BUCKETS 101

typedef struct ip_node {
    char ip[16];
    struct ip_node *next;
} ip_node_t;

typedef struct port_node {
    int port;
    struct port_node *next;
} port_node_t;

typedef struct scan_entry {
    char ip[16];
    int ports_seen[MAX_PORTS_TRACKED];
    int port_count;
    time_t first_seen;
    struct scan_entry *next;
} scan_entry_t;

typedef struct flood_entry {
    char ip[16];
    int count;
    time_t first_seen;
    struct flood_entry *next;
} flood_entry_t;

// Tables
ip_node_t *ip_blacklist_table[MAX_BLACKLIST_BUCKETS] = {0};
port_node_t *port_blacklist_table[MAX_BLACKLIST_BUCKETS] = {0};
scan_entry_t *scan_table[MAX_PORT_SCAN_BUCKETS] = {0};
flood_entry_t *syn_table[MAX_FLOOD_BUCKETS] = {0};
flood_entry_t *udp_table[MAX_FLOOD_BUCKETS] = {0};

// Config
int port_scan_threshold = 10;
int port_scan_window = 60;
int syn_flood_threshold = 500;
int syn_flood_window = 10;
int udp_flood_threshold = 500;
int udp_flood_window = 10;
int alert_on_arp = 1;

// Hash helpers
unsigned int hash_ip(const char *ip) {
    unsigned int h = 0;
    while (*ip) h = (h << 5) + h + (unsigned char)(*ip++);
    return h % MAX_BLACKLIST_BUCKETS;
}

unsigned int hash_port(int port) {
    return port % MAX_BLACKLIST_BUCKETS;
}

unsigned int hash_flood_ip(const char *ip) {
    unsigned int h = 0;
    while (*ip) h = (h << 5) + h + (unsigned char)(*ip++);
    return h % MAX_FLOOD_BUCKETS;
}

// Persistence helpers
int ip_already_blacklisted(const char *ip) {
    unsigned int idx = hash_ip(ip);
    for (ip_node_t *node = ip_blacklist_table[idx]; node; node = node->next) {
        if (strcmp(node->ip, ip) == 0) return 1;
    }
    return 0;
}

int port_already_blacklisted(int port) {
    unsigned int idx = hash_port(port);
    for (port_node_t *node = port_blacklist_table[idx]; node; node = node->next) {
        if (node->port == port) return 1;
    }
    return 0;
}

void persist_blacklist_ip(const char *ip) {
    FILE *fp = fopen("config/rules.config", "a");
    if (fp) {
        fprintf(fp, "BLACKLIST_IP=%s\n", ip);
        fclose(fp);
        log_message("INFO", "Persisted IP %s to rules.conf", ip);
    } else {
        perror("fopen");
        log_message("ERROR", "Failed to write IP to rules.conf");
    }
}

void free_ip_blacklist() {
    for (int i = 0; i < MAX_BLACKLIST_BUCKETS; i++) {
        ip_node_t *node = ip_blacklist_table[i];
        while (node) {
            ip_node_t *tmp = node;
            node = node->next;
            free(tmp);
        }
        ip_blacklist_table[i] = NULL;
    }
}

void free_port_blacklist() {
    for (int i = 0; i < MAX_BLACKLIST_BUCKETS; i++) {
        port_node_t *node = port_blacklist_table[i];
        while (node) {
            port_node_t *tmp = node;
            node = node->next;
            free(tmp);
        }
        port_blacklist_table[i] = NULL;
    }
}

void free_scan_table() {
    for (int i = 0; i < MAX_PORT_SCAN_BUCKETS; i++) {
        scan_entry_t *entry = scan_table[i];
        while (entry) {
            scan_entry_t *tmp = entry;
            entry = entry->next;
            free(tmp);
        }
        scan_table[i] = NULL;
    }
}

void free_flood_table(flood_entry_t **table) {
    for (int i = 0; i < MAX_FLOOD_BUCKETS; i++) {
        flood_entry_t *entry = table[i];
        while (entry) {
            flood_entry_t *tmp = entry;
            entry = entry->next;
            free(tmp);
        }
        table[i] = NULL;
    }
}

void free_all_detection_memory() {
    free_ip_blacklist();
    free_port_blacklist();
    free_scan_table();
    free_flood_table(syn_table);
    free_flood_table(udp_table);
    log_message("INFO", "Freed all detection memory");
}


void persist_blacklist_port(int port) {
    FILE *fp = fopen("config/rules.config", "a");
    if (fp) {
        fprintf(fp, "BLACKLIST_PORT=%d\n", port);
        fclose(fp);
        log_message("INFO", "Persisted port %d to rules.conf", port);
    } else {
        log_message("ERROR", "Failed to write port to rules.conf");
    }
}

// Config loader
void load_rules(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_message("ERROR", "Could not open rules config: %s", filename);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || strlen(line) < 3) continue;

        if (strncmp(line, "BLACKLIST_IP=", 13) == 0) {
            char ip[16];
            sscanf(line + 13, "%15s", ip);
            unsigned int idx = hash_ip(ip);
            ip_node_t *node = malloc(sizeof(ip_node_t));
            if (node) {
                strcpy(node->ip, ip);
                node->next = ip_blacklist_table[idx];
                ip_blacklist_table[idx] = node;
            }
        } else if (strncmp(line, "BLACKLIST_PORT=", 15) == 0) {
            int port;
            sscanf(line + 15, "%d", &port);
            unsigned int idx = hash_port(port);
            port_node_t *node = malloc(sizeof(port_node_t));
            if (node) {
                node->port = port;
                node->next = port_blacklist_table[idx];
                port_blacklist_table[idx] = node;
            }
        } else if (strncmp(line, "UDP_FLOOD_THRESHOLD=", 20) == 0) {
            sscanf(line + 20, "%d", &udp_flood_threshold);
        } else if (strncmp(line, "UDP_FLOOD_WINDOW=", 17) == 0) {
            sscanf(line + 17, "%d", &udp_flood_window);
        } else if (strncmp(line, "PORT_SCAN_THRESHOLD=", 20) == 0) {
            sscanf(line + 20, "%d", &port_scan_threshold);
        } else if (strncmp(line, "PORT_SCAN_WINDOW=", 17) == 0) {
            sscanf(line + 17, "%d", &port_scan_window);
        } else if (strncmp(line, "SYN_FLOOD_THRESHOLD=", 20) == 0) {
            sscanf(line + 20, "%d", &syn_flood_threshold);
        } else if (strncmp(line, "SYN_FLOOD_WINDOW=", 17) == 0) {
            sscanf(line + 17, "%d", &syn_flood_window);
        } else if (strncmp(line, "ALERT_ON_ARP=", 13) == 0) {
            sscanf(line + 13, "%d", &alert_on_arp);
        }
    }

    fclose(fp);
    log_message("INFO", "Rules loaded successfully");
}

// Detection
void detect_blacklist_ip(const char *ip) {
    if (!ip_already_blacklisted(ip)) return;
    log_message("ALERT", "Blacklisted IP detected: %s", ip);
}

void detect_blacklist_port(int port) {
    if (!port_already_blacklisted(port)) return;
    log_message("ALERT", "Blacklisted port accessed: %d", port);
}

void detect_port_scan(const char *ip, int port) {
    time_t now = time(NULL);
    unsigned int ip_idx = hash_ip(ip) % MAX_PORT_SCAN_BUCKETS;
    scan_entry_t *entry = scan_table[ip_idx];

    while (entry && strcmp(entry->ip, ip) != 0) entry = entry->next;

    if (!entry) {
        entry = calloc(1, sizeof(scan_entry_t));
        if (!entry) return;
        strncpy(entry->ip, ip, sizeof(entry->ip)-1);
        entry->first_seen = now;
        entry->next = scan_table[ip_idx];
        scan_table[ip_idx] = entry;
    }

    for (int i = 0; i < entry->port_count; i++) {
        if (entry->ports_seen[i] == port) return;
    }

    if (entry->port_count < MAX_PORTS_TRACKED) {
        entry->ports_seen[entry->port_count++] = port;
    }

    if (entry->port_count >= port_scan_threshold && (now - entry->first_seen) <= port_scan_window) {
        log_message("ALERT", "Port scan detected from %s", ip);
        // Possibly block IP or take action here
        entry->port_count = 0;
        entry->first_seen = now;
    } else if ((now - entry->first_seen) > port_scan_window) {
        entry->port_count = 1;
        entry->ports_seen[0] = port;
        entry->first_seen = now;
    }
}

void detect_flood(flood_entry_t **table, const char *ip, int threshold, int window, const char *flood_type) {
    unsigned int idx = hash_flood_ip(ip);
    flood_entry_t *entry = table[idx];

    while (entry && strcmp(entry->ip, ip) != 0) entry = entry->next;

    if (!entry) {
        entry = calloc(1, sizeof(flood_entry_t));
        if (!entry) return;
        strcpy(entry->ip, ip);
        entry->first_seen = time(NULL);
        entry->next = table[idx];
        table[idx] = entry;
    }

    entry->count++;
    time_t now = time(NULL);

    if (entry->count >= threshold && (now - entry->first_seen) <= window) {
        log_message("ALERT", "%s flood detected from %s", flood_type, ip);

        if (!ip_already_blacklisted(ip)) {
            unsigned int blk_idx = hash_ip(ip);
            ip_node_t *node = malloc(sizeof(ip_node_t));
            if (node) {
                strcpy(node->ip, ip);
                node->next = ip_blacklist_table[blk_idx];
                ip_blacklist_table[blk_idx] = node;
                log_message("INFO", "%s added to IP blacklist", ip);
                persist_blacklist_ip(ip);
            }
        }

        entry->count = 0;
        entry->first_seen = now;
    } else if ((now - entry->first_seen) > window) {
        entry->count = 1;
        entry->first_seen = now;
    }
}

void detect_syn_flood(const char *ip) {
    detect_flood(syn_table, ip, syn_flood_threshold, syn_flood_window, "SYN");
}

void detect_udp_flood(const char *ip) {
    detect_flood(udp_table, ip, udp_flood_threshold, udp_flood_window, "UDP");
}
