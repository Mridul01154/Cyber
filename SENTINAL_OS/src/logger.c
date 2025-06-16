#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <direct.h>
#include <windows.h>

static FILE *log_file = NULL;
static CRITICAL_SECTION log_lock;

int init_logger(const char *filename) {
    _mkdir("logs");

    char fullpath[256];
    snprintf(fullpath, sizeof(fullpath), "logs/%s.log", filename);

    log_file = fopen(fullpath, "a");
    if (!log_file) {
        perror("fopen");
        return -1;
    }
    InitializeCriticalSection(&log_lock);
    return 0;
}

void log_message(const char *level, const char *fmt, ...) {
    EnterCriticalSection(&log_lock);
    if (!log_file) return;

    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", lt);

    fprintf(log_file, "[%s] [%s] ", timebuf, level);

    va_list args;
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file);
    LeaveCriticalSection(&log_lock);

}

void close_logger(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    LeaveCriticalSection(&log_lock);
    DeleteCriticalSection(&log_lock);
}
