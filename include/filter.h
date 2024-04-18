#ifndef FILTER_H
#define FILTER_H

#include <linux/netfilter_ipv4.h>
#include <linux/buffer_head.h>
#include <linux/netfilter.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/path.h>
#include <linux/file.h>
#include <linux/time.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/fs.h>
#include <linux/in.h>

int filter_match_protocol(int protocol, char *rule_protocol);
int filter_match_direction(int direction, char *rule_direction);
int filter_match_ip(unsigned int ip, char *rule_ip);
int filter_match_port(unsigned int port, char *rule_port);

unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif