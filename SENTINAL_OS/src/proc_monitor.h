// proc_monitor.h
#ifndef PROC_MONITOR_H
#define PROC_MONITOR_H

// Load process blacklist from a config file
void load_proc_rules(const char *filename);

// Scan running processes and log alerts for blacklisted ones
void monitor_processes(void);

// Free memory used by process blacklist
void free_proc_blacklist(void);

void load_bad_hashes(const char *filename);

#endif // PROC_MONITOR_H
