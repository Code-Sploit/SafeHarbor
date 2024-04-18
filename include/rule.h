#ifndef RULE_H
#define RULE_H

#define MAX_BUF_SIZE 1024
#define MAX_RULES 50

struct Rule {
    char action[10];
    char protocol[5];
    char direction[10];
    char src_ip[16];
    char src_port[6];
    char dest_ip[16];
    char dest_port[6];
};

int config_load(void);

int parse_line(char *line);
int parse_rule(char *rule);

#endif