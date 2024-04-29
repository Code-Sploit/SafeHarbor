#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "rule.h"
#include "log.h"

extern int CONFIG_DEFAULT_FILTER;
extern int CONFIG_DEFAULT_LOG;
extern int CONFIG_DEFAULT_MISMATCH;

extern int TIME_BUF_SIZE;

extern int BRIDGE_MAJOR;
extern int BRIDGE_MINOR;

extern int FILTER_MATCH;
extern int FILTER_NOMATCH;

extern struct tm current_time_value;
extern char log_buf[LOG_BUF_SIZE];
extern struct mutex file_mutex;
extern struct mutex rule_mutex;
extern struct timespec64 tv;

extern struct Configuration *configuration;

extern struct SPIConnectionManager *spi_connection_manager;

extern spinlock_t log_lock;

extern int num_rules;

#endif