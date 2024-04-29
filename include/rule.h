#ifndef RULE_H
#define RULE_H

#define MAX_BUF_SIZE 1024
#define MAX_RULES 50
#define MAX_GROUPS 25

struct Rule
{
    int action;
    
    char *direction;
    char *protocol;
    char *src;
    char *sport;
    char *dst;
    char *dport;

    char *name;
};

struct Group
{
    char *name;

    int logging;
    int filtering;

    struct Rule **rules;

    int rule_count;
};

struct BannedProtocol
{
    char *name;
    char *target;
};

struct Configuration
{
    int filtering;
    int logging;
    int mismatches;
    int spi;
    int dpi;

    struct Rule **rules;
    struct Group **groups;

    int rule_count;
    int group_count;

    int banned_protocol_count;

    struct BannedProtocol **banned_protocols;
};

struct Configuration *configuration_initialize(int filtering, int logging, int mismatches);
struct Rule *rule_initialize(int action, char *direction, char *protocol, char *src, char *sport, char *dst, char *dport, char *name);
struct Group *group_initialize(char *name, int logging, int filtering);

void configuration_add_rule(struct Configuration *configuration, struct Rule *rule);
void configuration_add_group(struct Configuration *configuration, struct Group *group);
void configuration_add_rule_to_group(struct Group *group, struct Rule *rule);

void group_set_rules(struct Group *group, struct Rule **rules, int rule_count);

int configuration_reset(struct Configuration *configuration);
int configuration_load(struct Configuration *configuration);

#endif