#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include "datatype.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LINUX FIREWALL");
MODULE_AUTHOR("SIYUAN LIU");

#define PROCFILE "firewall_sy"
#define MAXLEN sizeof(struct PolicyCache)

static struct PolicyCache* head;

static struct proc_dir_entry *procEntry;
//static unsigned int bufferIndex = 0;
static char* bufferSpace;

static struct nf_hook_ops hookIn;
static struct nf_hook_ops hookOut;


unsigned int GetMaskedIP(IP ip, IP mask)
{
    unsigned int ipAddr = (ip.seg4 << 24) | (ip.seg3 << 16) | (ip.seg2 << 8) | (ip.seg1);
    unsigned int maskAddr = (mask.seg4 << 24) | (mask.seg3 << 16) | (mask.seg2 << 8) | (mask.seg1);
    return (ipAddr & maskAddr);
}

void DeletePolicy(int index)
{   
    struct PolicyCache* curItem = head;
    struct PolicyCache* preItem = NULL;
    int i = 1;
    printk(KERN_INFO "in DeletePolicy.\n");
    if(index <= 0)
    {
        printk(KERN_INFO "DeletePolicy: index <= 0.\n");
        return;
    }
    
    while(curItem != NULL && i < index)
    {
        preItem = curItem;
        curItem = curItem->next;
        i++;
    }
    
    if(i == index && curItem != NULL)
    {
        // item is head
        if(index == 1)
        {
            head = head->next;
        }
        // item is not head
        else
        {
            preItem->next = curItem->next;
        }
        kfree(curItem);
    }
}

void AddPolicy(struct PolicyCache* newItem)
{
    struct PolicyCache* curItem = head;
    if(head == NULL)
    {
        printk(KERN_INFO "AddPolicy(): head is null\n");
        head = newItem;
    }
    else
    {
        printk(KERN_INFO "AddPolicy(): head is not null\n");
        while(curItem->next != NULL)
        {
            curItem = curItem->next;
        }
        curItem->next = newItem;
    }
}

int proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int counter = 0;
    struct PolicyCache *curItem = head;
    
    printk(KERN_INFO "in proc_read.\n");
    if (off > 0)
    {
        printk(KERN_INFO "proc_read(): off > 0.\n");
        *eof = 1;
        return 0;
    }
    
    if (head == NULL)
    {
        printk(KERN_INFO "proc_read(): the linked list is empty.\n");
        return 0;
    }
    
    do
    {  
        memcpy(page + sizeof(struct PolicyCache) * counter, curItem, sizeof(struct PolicyCache));
        counter++;
        curItem = curItem->next;
    } while(curItem != NULL);
   
    return sizeof(struct PolicyCache) * counter;
}
 
 

int proc_write(struct file *filp, const char *buffer, unsigned long len, void *data)
{
    int ret = 0;
    struct PolicyCache* curItem = kmalloc(sizeof(struct PolicyCache), GFP_KERNEL);
    printk(KERN_INFO "in proc_write.\n");
    
    if (curItem == NULL)
    {
        printk(KERN_INFO "proc_write: allocate memory for curItem failed.\n");
        return -ENOMEM;
    }
    
    if (len > MAXLEN + 1)
    {
        printk(KERN_INFO "proc_write: bufferSpace is full.\n");
        return -EFAULT;
    } 
 
    if (copy_from_user(curItem, buffer, sizeof(struct PolicyCache)))
    {
        printk(KERN_INFO "proc_write: copy_from_user failed.\n");
        return -EFAULT;
    }
    
    //add operation
    if (curItem->operation == IN || curItem->operation == OUT)
    {
        printk(KERN_INFO "proc_write: add operation.\n");
        AddPolicy(curItem);
        ret = len;
    } 
    //delete operation
    else if (curItem->operation == DEL)
    {
        printk(KERN_INFO "proc_write: delete operation.\n");
        DeletePolicy(curItem->index);
        kfree(curItem);
        ret = len;
    }
    else
    {
        printk(KERN_INFO "proc_write: neither ADD nor DELETE operation. skip it.\n");
    }
    return ret;
}


unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, 
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{         
    struct iphdr *ipHeader = (struct iphdr *)skb_network_header(skb);
    unsigned int srcip = ipHeader->saddr;
    unsigned int destip = ipHeader->daddr;
    unsigned int protocol = ipHeader->protocol;
    unsigned int srcport = 0;
    unsigned int destport = 0;
    struct udphdr *udpHeader;
    struct tcphdr *tcpHeader;
    struct icmphdr *icmpHeader;
    struct PolicyCache *curItem;
    unsigned int policySrcMaskedIp = 0;
    unsigned int policyDestMaskedIp = 0;
    printk(KERN_INFO "in hook_func_out.\n");
    if (protocol == IPPROTO_UDP)
    {
        udpHeader = (struct udphdr *)(skb_transport_header(skb));
        srcport = (unsigned int)ntohs(udpHeader->source);
        destport = (unsigned int)ntohs(udpHeader->dest);
    }
    else if (protocol == IPPROTO_TCP)
    {
        tcpHeader = (struct tcphdr *)(skb_transport_header(skb));
        srcport = (unsigned int)ntohs(tcpHeader->source);
        destport = (unsigned int)ntohs(tcpHeader->dest);
    }
    else if (protocol == IPPROTO_ICMP)
    {
        icmpHeader = (struct icmphdr *)(skb_transport_header(skb));
    }
    
    //traverse linked list to find a match
    for(curItem = head;curItem != NULL; curItem = curItem->next)
    {
        if(curItem->operation != OUT)
        {
            continue;
        }
        
        if(curItem->proto == UDP && protocol != IPPROTO_UDP)
        {
            continue;
        }
        else if(curItem->proto == TCP && protocol != IPPROTO_TCP)
        {
            continue;
        }
        else if(curItem->proto == ICMP && protocol != IPPROTO_ICMP)
        {
            continue;
        }
        
        if(curItem->srcport != 0 &&curItem->srcport != srcport)
        {
            continue;
        }
        
        if(curItem->destport != 0 && curItem->destport != destport)
        {
            continue;
        }
        
        policySrcMaskedIp = GetMaskedIP(curItem->srcip, curItem->srcnetmask);
        if(policySrcMaskedIp != 0 && policySrcMaskedIp != srcip)
        {
            continue;
        }
        
        policyDestMaskedIp = GetMaskedIP(curItem->destip, curItem->destnetmask);
        if(policyDestMaskedIp != 0 && policyDestMaskedIp != destip)
        {
            continue;
        }
        
        if(curItem->action == UNBLOCK)
        {
            return NF_ACCEPT;
        }
        else if(curItem->action == BLOCK)
        {
            return NF_DROP;
        }
        
    }
    return NF_ACCEPT; 
}
 

unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, 
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct iphdr *ipHeader = (struct iphdr *)skb_network_header(skb);
    unsigned int srcip = ipHeader->saddr;
    unsigned int destip = ipHeader->daddr;
    unsigned int protocol = ipHeader->protocol;
    unsigned int srcport = 0;
    unsigned int destport = 0;
    struct udphdr *udpHeader;
    struct tcphdr *tcpHeader;
    struct icmphdr *icmpHeader;
    struct PolicyCache *curItem;
    unsigned int policySrcMaskedIp = 0;
    unsigned int policyDestMaskedIp = 0;
    printk(KERN_INFO "in hook_func_in.\n");
    if (protocol == IPPROTO_UDP)
    {
        udpHeader = (struct udphdr *)(skb_transport_header(skb));
        srcport = (unsigned int)ntohs(udpHeader->source);
        destport = (unsigned int)ntohs(udpHeader->dest);
    }
    else if (protocol == IPPROTO_TCP)
    {
        tcpHeader = (struct tcphdr *)(skb_transport_header(skb));
        srcport = (unsigned int)ntohs(tcpHeader->source);
        destport = (unsigned int)ntohs(tcpHeader->dest);
    }
    else if (protocol == IPPROTO_ICMP)
    {
        icmpHeader = (struct icmphdr *)(skb_transport_header(skb));
    }
    
    //traverse linked list to find a match
    for(curItem = head;curItem != NULL; curItem = curItem->next)
    {
        if(curItem->operation != IN)
        {
            continue;
        }
        
        if(curItem->proto == UDP && protocol != IPPROTO_UDP)
        {
            continue;
        }
        else if(curItem->proto == TCP && protocol != IPPROTO_TCP)
        {
            continue;
        }
        else if(curItem->proto == ICMP && protocol != IPPROTO_ICMP)
        {
            continue;
        }
        
        if(curItem->srcport != 0 && curItem->srcport != srcport)
        {
            continue;
        }
        
        if(curItem->destport != 0 && curItem->destport != destport)
        {
            continue;
        }
        
        policySrcMaskedIp = GetMaskedIP(curItem->srcip, curItem->srcnetmask);
        if(policySrcMaskedIp != 0 && policySrcMaskedIp != srcip)
        {
            continue;
        }
        
        policyDestMaskedIp = GetMaskedIP(curItem->destip, curItem->destnetmask);
        if(policyDestMaskedIp != 0 && policyDestMaskedIp != destip)
        {
            continue;
        }
        
        if(curItem->action == UNBLOCK)
        {
            return NF_ACCEPT;
        }
        else if(curItem->action == BLOCK)
        {
            return NF_DROP;
        }
        
    }
    
    return NF_ACCEPT;                
}
 

int init_module(void)
{
    printk(KERN_INFO "in init_module.\n");
    bufferSpace = (char *) vmalloc(MAXLEN);
    if(bufferSpace)
    {
        memset(bufferSpace, 0, MAXLEN);
        procEntry = create_proc_entry(PROCFILE, 0666, NULL);

        if (procEntry!=NULL)
        {
            // initialize linked list
            head = NULL;
            
            // define read_proc and write_proc
            procEntry->read_proc = proc_read;
            procEntry->write_proc = proc_write;
           
            // register hook in / out
            hookIn.hook = hook_func_in; 
            hookIn.hooknum = NF_INET_LOCAL_IN;
            hookIn.pf = PF_INET;
            hookIn.priority = NF_IP_PRI_FIRST;
            nf_register_hook(&hookIn);
 
            hookOut.hook = hook_func_out;
            hookOut.hooknum = NF_INET_LOCAL_OUT;
            hookOut.pf = PF_INET; 
            hookOut.priority = NF_IP_PRI_FIRST;
            nf_register_hook(&hookOut);
            printk(KERN_INFO "init_module: kernel module created\n");
            return 0;
        }
        else
        {   
            vfree(bufferSpace);
            printk(KERN_INFO "init_module: create proc entry failed.\n");
            return -ENOMEM; 
        }
    }
    else
    {
        printk(KERN_INFO "init_module: allocate bufferSpace failed.\n");
        return -ENOMEM;
    }
    
}
 

void cleanup_module(void) 
{
    struct PolicyCache *curItem;
    struct PolicyCache *space;
    printk(KERN_INFO "in cleanup_module.\n");
    
    nf_unregister_hook(&hookIn);
    nf_unregister_hook(&hookOut);
    
    curItem = head;
    while(curItem != NULL)
    {
        space = curItem;
        curItem = curItem->next;
        kfree(space);
    }
    vfree(bufferSpace);
    remove_proc_entry(PROCFILE, NULL);
    printk(KERN_INFO "kernel module unloaded.\n");
}