#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

static struct nf_hook_ops nfho, nfho_out;         //struct holding set of hook function options
struct sk_buff *sock_buff;
struct iphdr *ip_header;
unsigned int source;

int len, temp, flag;

static char *msg = 0;
static char *token = 0;

static ssize_t
read_proc (struct file *filp, char __user * buf, size_t count, loff_t * offp)
{
  if (count > temp)
    {
      count = temp;
    }
  temp = temp - count;
  copy_to_user (buf, msg, count);
  if (count == 0)
    temp = len;

  return count;
}

static ssize_t
write_proc (struct file *filp, const char __user * buf, size_t count,
	    loff_t * offp)
{

  if (msg == 0 || count >= 100)
    {
      printk (KERN_INFO " either msg is 0 or count >100\n");
    }
  
  // you have to move data from user space to kernel buffer
  copy_from_user (msg, buf, count);
  msg[count] = '\0';
  printk (KERN_INFO "Message Recieved %s\n", msg);
  strsep(msg, ' ');
  token = strsep(msg, ' ')
  if ((strcmp(token, "All\0") == 0)
    {
      if (strcmp(strsep(msg, ' '), "Input\0") == 0)
        {
          flag = 0;
        }
      else
        {
          flag = 1;
        }
    }
  else
    {
       
    }
  len = count;
  temp = len;
  return count;
}

static const struct file_operations proc_fops = {
  .owner = THIS_MODULE,
  .read = read_proc,
  .write = write_proc,
};

void
create_new_proc_entry (void)
{
  proc_create ("hello", 0666, NULL, &proc_fops);
  msg = kmalloc (100 * sizeof (char), GFP_KERNEL);
  if (msg == 0)
    {
      printk (KERN_EMERG "why is msg 0 \n");
    }
}

//function to be called by hook
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{                                             //log to var/log/messages
  sock_buff = skb;
  ip_header = (struct iphdr *)skb_network_header(sock_buff);
  source = ip_header->saddr; 
  printk(KERN_INFO "Address of Source: %d", source);
  return NF_DROP;                                                                   //drops the packet
}

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{                                             //log to var/log/messages
  sock_buff = skb;
  ip_header = (struct iphdr *)skb_network_header(sock_buff);
  source = ip_header->daddr; 
  printk(KERN_INFO "Address of Source: %d", source);
  return NF_DROP;                                                                   //drops the packet
}

//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;                       //function to call when conditions below met
  nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook
  create_new_proc_entry ();
  
  nfho_out.hook = hook_func_out;
  nfho_out.hooknum = NF_INET_LOCAL_OUT;
  nfho_out.pf = PF_INET;
  nfho_out.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nfho_out);

  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho_out);                     //cleanup – unregister hook
  nf_unregister_hook(&nfho);
  remove_proc_entry ("hello", NULL);
}