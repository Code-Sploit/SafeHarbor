#ifndef BRIDGE_H
#define BRIDGE_H

#define BRIDGE_MAJOR 64
#define BRIDGE_MINOR 0

int bridge_init(void);
int bridge_deinit(void);

int bridge_open(struct inode *device, struct file *instance);
int bridge_close(struct inode *device, struct file *instance);

long int bridge_ctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif