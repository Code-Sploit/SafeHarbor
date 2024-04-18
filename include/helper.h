#ifndef HELPER_H
#define HELPER_H

void get_until_delim(char *buffer, char *str, char delim);
void remove_whitespaces(char *str);

char *get_current_time_string(void);
char *ip_ntoa(unsigned int ip);

int atoi(const char *str);

#endif