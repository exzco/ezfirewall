#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/skbuff.h>
#include "func/func.h"
#include "rule_proc_interface/rules.h"

MODULE_LICENSE("GPL");

static struct nf_hook_ops my_ops_1;

static int __init firewall_init(void){

    printk(KERN_INFO "Firewall module loaded\n");

    init_rule_manager();

    my_ops_1.hook = func_filter_Protocol;
    my_ops_1.pf = PF_INET;
    my_ops_1.hooknum = NF_INET_PRE_ROUTING;
    my_ops_1.priority = NF_IP_PRI_FIRST;

    // Register the hook
    nf_register_net_hook(&init_net, &my_ops_1);
    return 0;
}

static void __exit firewall_exit(void){

    printk(KERN_INFO "Firewall module unloaded\n");
    
    cleanup_rule_manager();

    nf_unregister_net_hook(&init_net, &my_ops_1);
}

module_init(firewall_init);
module_exit(firewall_exit);