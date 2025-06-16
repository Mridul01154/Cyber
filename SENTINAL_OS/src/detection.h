#ifndef DETECTION_H
#define DETECTION_H

void load_rules(const char *filename);
void detect_blacklist_ip(const char *ip);
void detect_blacklist_port(int port);
void detect_port_scan(const char *ip, int port);
void detect_syn_flood(const char *ip);
void detect_udp_flood(const char *ip);
void free_all_detection_memory();
#endif
