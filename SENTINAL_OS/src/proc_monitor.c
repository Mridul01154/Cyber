#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include "logger.h"

#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | 12)
#endif

#define MAX_PROC_BLACKLIST 50
#define MAX_HASH_BLACKLIST 1000
#define SHA256LEN 32

static char *proc_blacklist[MAX_PROC_BLACKLIST] = {0};
static int proc_blacklist_count = 0;

static char bad_hashes[MAX_HASH_BLACKLIST][65];  // 64 hex chars + null
static int bad_hash_count = 0;

void free_proc_blacklist(void) {
    for (int i = 0; i < proc_blacklist_count; i++) {
        free(proc_blacklist[i]);
    }
    proc_blacklist_count = 0;
}

void free_bad_hashes(void) {
    bad_hash_count = 0;
}

void load_proc_rules(const char *filename) {
    free_proc_blacklist();  // prevent leaks on reload

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_message("ERROR", "Could not open process rules: %s", filename);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || strlen(line) < 3) continue;

        if (strncmp(line, "BLACKLIST_PROC=", 15) == 0 && proc_blacklist_count < MAX_PROC_BLACKLIST) {
            char *proc = _strdup(line + 15);
            if (proc) {
                proc[strcspn(proc, "\r\n")] = 0;  // Remove newline
                proc_blacklist[proc_blacklist_count++] = proc;
            } else {
                log_message("ERROR", "Failed to allocate memory for blacklist entry");
            }
        }
    }

    fclose(fp);
    log_message("INFO", "Process rules loaded successfully");
}

void load_bad_hashes(const char *filename) {
    free_bad_hashes();  // reset before load

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_message("ERROR", "Could not open hash list: %s", filename);
        return;
    }

    char line[128];
    while (fgets(line, sizeof(line), fp) && bad_hash_count < MAX_HASH_BLACKLIST) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 64) {
            strcpy(bad_hashes[bad_hash_count++], line);
        }
    }

    fclose(fp);
    log_message("INFO", "Bad hashes loaded successfully");
}

int is_blacklisted_proc(const char *proc_name) {
    for (int i = 0; i < proc_blacklist_count; i++) {
        if (_stricmp(proc_blacklist[i], proc_name) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_bad_hash(const char *sha256_hex) {
    for (int i = 0; i < bad_hash_count; i++) {
        if (_stricmp(bad_hashes[i], sha256_hex) == 0) return 1;
    }
    return 0;
}

int compute_sha256(const char *filepath, char *output_hex) {
    int result = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[4096];
    DWORD bytesRead;
    BYTE hash[SHA256LEN];
    DWORD hashLen = SHA256LEN;

    FILE *f = fopen(filepath, "rb");
    if (!f) return 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto cleanup;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;

    while ((bytesRead = (DWORD)fread(buffer, 1, sizeof(buffer), f)) != 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) goto cleanup;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) goto cleanup;

    for (DWORD i = 0; i < hashLen; i++) {
        sprintf(output_hex + i * 2, "%02x", hash[i]);
    }
    output_hex[64] = '\0';
    result = 1;

cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    fclose(f);
    return result;
}

void monitor_processes(void) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        log_message("ERROR", "Failed to create process snapshot");
        return;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe)) {
        do {
            if (is_blacklisted_proc(pe.szExeFile)) {
                log_message("ALERT", "Blacklisted process detected: %s (PID: %u)", pe.szExeFile, pe.th32ProcessID);
            }

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                char path[MAX_PATH] = {0};
                if (GetModuleFileNameEx(hProc, NULL, path, MAX_PATH)) {
                    char sha256[65];
                    if (compute_sha256(path, sha256)) {
                        if (is_bad_hash(sha256)) {
                            log_message("ALERT", "Bad hash process: %s (PID: %u) Hash: %s", path, pe.th32ProcessID, sha256);
                        }
                    }
                }
                CloseHandle(hProc);
            }

        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
}
