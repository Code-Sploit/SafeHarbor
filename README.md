# SafeHarbor
SafeHarbor is a barebones firewall for linux written in C

# Firewall Source Code Documentation

## Introduction
The SafeHarbor firewall is a Linux kernel module designed to provide network packet filtering and logging capabilities. It intercepts network packets at various hook points in the networking stack, allowing it to inspect and potentially block or allow traffic based on predefined rules.

## Structure
The firewall source code is organized into several files:

1. **main.c**: Initializes and exits the firewall module. Registers NetFilter hooks and loads configuration.
2. **filter.c**: Implements packet filtering logic based on defined rules.
3. **helper.c**: Provides helper functions for time conversion, IP address manipulation, and string operations.
4. **log.c**: Handles logging of packet events to a log file.
5. **rule.c**: Manages loading and parsing of firewall rules from a configuration file.
6. **bridge.c**: Implements IOCTL bridge functionality for configuration changes at runtime.

## Core Functionality
- **Packet Filtering**: The `filter.c` file contains functions for matching packets against defined rules and deciding whether to drop or accept them.
- **Logging**: Packet events are logged to a file using functions in the `log.c` file, providing visibility into firewall activity.
- **Rule Management**: The `rule.c` file handles the loading and parsing of firewall rules from a configuration file, enabling dynamic rule updates.
- **Configuration Bridge**: The `bridge.c` file implements an IOCTL bridge for runtime configuration changes, allowing settings like filtering behavior and logging to be adjusted without module reloads.

## Dependencies
The firewall module depends on kernel headers and NetFilter infrastructure for packet interception and manipulation.

## API Documentation

### `filter.c`

#### `filter_match_protocol(int protocol, char *rule_protocol)`
- **Description**: Matches packet protocol against rule protocol.
- **Parameters**: `protocol` (int) - Packet protocol, `rule_protocol` (char*) - Rule protocol.
- **Returns**: `FILTER_MATCH` if matched, `FILTER_NOMATCH` otherwise.

#### `filter_match_direction(int direction, char *rule_direction)`
- **Description**: Matches packet direction against rule direction.
- **Parameters**: `direction` (int) - Packet direction, `rule_direction` (char*) - Rule direction.
- **Returns**: `FILTER_MATCH` if matched, `FILTER_NOMATCH` otherwise.

#### `filter_match_ip(unsigned int ip, char *rule_ip)`
- **Description**: Matches packet IP address against rule IP.
- **Parameters**: `ip` (unsigned int) - Packet IP address, `rule_ip` (char*) - Rule IP address.
- **Returns**: `FILTER_MATCH` if matched, `FILTER_NOMATCH` otherwise.

#### `filter_match_port(unsigned int port, char *rule_port)`
- **Description**: Matches packet port against rule port.
- **Parameters**: `port` (unsigned int) - Packet port, `rule_port` (char*) - Rule port.
- **Returns**: `FILTER_MATCH` if matched, `FILTER_NOMATCH` otherwise.

### `helper.c`

#### `get_current_time_string()`
- **Description**: Returns the current time as a formatted string.
- **Returns**: Formatted string representing the current time.

#### `ip_ntoa(unsigned int ip)`
- **Description**: Converts an IP address from integer to string format.
- **Parameters**: `ip` (unsigned int) - IP address in integer format.
- **Returns**: String representation of the IP address.

#### `remove_whitespaces(char *str)`
- **Description**: Removes leading whitespaces from a string.
- **Parameters**: `str` (char*) - Input string to remove whitespaces from.

#### `atoi(const char *str)`
- **Description**: Converts a string to an integer.
- **Parameters**: `str` (const char*) - Input string to convert.
- **Returns**: Converted integer value.

### `log.c`

#### `log_message(const char *format, ...)`
- **Description**: Logs a message to the firewall log file.
- **Parameters**: `format` (const char*) - Format string for the log message, `...` - Additional arguments for formatting.

### `rule.c`

#### `config_load()`
- **Description**: Loads firewall rules from a configuration file.
- **Returns**: 0 on success, negative error code on failure.

#### `parse_rule(char *rule)`
- **Description**: Parses a rule string and adds it to the list of firewall rules.
- **Parameters**: `rule` (char*) - Rule string to parse.
- **Returns**: 0 on success, negative error code on failure.

### `bridge.c`

#### `safeharbor_ioctl_handler(unsigned int cmd, unsigned long arg)`
- **Description**: IOCTL handler function for handling runtime configuration changes.
- **Parameters**: `cmd` (unsigned int) - IOCTL command, `arg` (unsigned long) - IOCTL argument.
- **Returns**: 0 on success, negative error code on failure.

# safeharborctl Source Code Documentation

## Introduction
The `safeharborctl` utility is a command-line interface for managing the SafeHarbor firewall module. It provides actions for enabling/disabling the module, restarting it, and configuring firewall settings.

## Structure
The `safeharborctl` source code consists of a single C file, divided into sections for different actions and functionalities.

## Core Functionality
- **Kernel Module Management**: Enables/disables the firewall module by loading/unloading the kernel module using system commands (`insmod` and `rmmod`).
- **Configuration**: Interacts with the firewall module through IOCTL calls to set filtering, logging, and rule mismatch behaviors.
- **Error Handling**: Proper error handling is implemented for system calls and file operations.

## Dependencies
The `safeharborctl` utility depends on standard C library functions and system calls for file operations, process management, and system command execution.
