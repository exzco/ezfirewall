#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>

#define MAX_RULES 100
#define MAX_RULE_LENGTH 128

typedef enum {
    ACTION_ALLOW = 0,
    ACTION_DENY = 1
} rule_action_t;

typedef struct {
    __be32 ip;          
    __u8 protocol;       
    rule_action_t action; 
    struct list_head list; 
} firewall_rule_t;

/* Initialize rule management system */
int init_rule_manager(void);

/* Cleanup rule management system */
void cleanup_rule_manager(void);

/* Add a rule to the firewall */
int add_rule(__be32 ip, __u8 protocol, rule_action_t action);

/* Delete a rule from the firewall */
int delete_rule(__be32 ip, __u8 protocol);

/* Check if a packet matches any rule */
unsigned int check_rules(struct sk_buff *skb, 
                          const struct nf_hook_state *state);

#endif 