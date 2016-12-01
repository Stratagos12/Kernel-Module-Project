//'Hello World' kernel module, logs call to init_module
// and cleanup_module to /var/log/messages

// In Ubuntu 8.04 we use make and appropriate Makefile to compile kernel module

#define __KERNEL__
#define MODULE

#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
 printk(KERN_INFO "init_module() called\n");
 return 0;
}

void cleanup_module(void)
{
 printk(KERN_INFO "cleanup_module() called\n");
}