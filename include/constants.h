#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "rule.h"
#include "log.h"

extern int TIME_BUF_SIZE;

extern int BRIDGE_MAJOR;
extern int BRIDGE_MINOR;

extern int FILTER_MATCH;
extern int FILTER_NOMATCH;

extern struct tm current_time_value;
extern struct Rule rules[MAX_RULES];
extern char log_buf[LOG_BUF_SIZE];
extern struct mutex file_mutex;
extern struct mutex rule_mutex;
extern struct timespec64 tv;

extern spinlock_t log_lock;

extern int num_rules;

extern int DO_SHOW_RULE_MISMATCHES;
extern int DO_FILTERING;
extern int DO_LOGGING;

#endif