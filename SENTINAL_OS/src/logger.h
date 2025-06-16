#ifndef LOGGER_H
#define LOGGER_H

int init_logger(const char *filename);
void log_message(const char *level, const char *fmt, ...);
void close_logger();

#endif
