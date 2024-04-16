#ifndef SAFEHARBOR_H
#define SAFEHARBOR_H

#include <linux/ioctl.h>

#define MAX_STR_LEN 512

#define BRIDGE_ADD_RULE _IOWR('c', '1', char[MAX_STR_LEN])
#define BRIDGE_DEL_RULE _IOWR('c', '2', char[MAX_STR_LEN])
#define BRIDGE_LST_RULE _IOWR('c', '3', char[MAX_STR_LEN])

#define BRIDGE_FILTER_SET  _IOWR('c', '4', char[MAX_STR_LEN])
#define BRIDGE_LOGGING_SET _IOWR('c', '5', char[MAX_STR_LEN])
#define BRIDGE_MISMATCH_SET _IOWR('c', '6', char[MAX_STR_LEN])

#endif