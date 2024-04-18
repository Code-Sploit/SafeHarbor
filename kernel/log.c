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

#include "../include/constants.h"
#include "../include/helper.h"
#include "../include/log.h"

#define LOG_FILE_PATH "/var/log/safeharbor.log"

void log_message(const char *format, ...)
{
    if (DO_LOGGING == 0)
    {
        return;
    }

    va_list args;

    struct file *file;
    loff_t pos;
    int ret;

    va_start(args, format);
    vsnprintf(log_buf, LOG_BUF_SIZE, format, args);
    va_end(args);

    mutex_lock(&file_mutex);

    file = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0777);
    
    if (IS_ERR(file))
    {
        printk(KERN_ERR "SafeHarbor: Failed to open log file: %ld\n", PTR_ERR(file));
        mutex_unlock(&file_mutex);
        return;
    }

    pos = file->f_pos;

    static char datetime[256];
    
    sprintf(datetime, "[%s] ", get_current_time_string());
    
    ret = kernel_write(file, datetime, strlen(datetime), &pos);
    
    if (ret < 0)
    {
        printk(KERN_ERR "SafeHarbor: Failed to write datetime to log file: `%d`\n", ret);
        filp_close(file, NULL);
        mutex_unlock(&file_mutex);
        return;
    }
    
    pos = file->f_pos;

    ret = kernel_write(file, log_buf, strlen(log_buf), &pos);
    
    if (ret < 0)
    {
        printk(KERN_ERR "SafeHarbor: Failed to write log message to log file: `%d`\n", ret);
    }
    else
    {

    }

    filp_close(file, NULL);

    mutex_unlock(&file_mutex);
}

MODULE_LICENSE("GPL");