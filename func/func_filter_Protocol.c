#include "func.h"
#include "../rule_proc_interface/rules.h" 

unsigned int func_filter_Protocol(void *priv,struct sk_buff *skb,const struct nf_hook_state *state){
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    if(!skb){
        printk(KERN_INFO "skb is NULL\n");
        return NF_ACCEPT; 
    }

    ip_header = ip_hdr(skb);
    if(ip_header) {
        printk(KERN_INFO "IP packet: src %pI4, dst %pI4, protocol %u\n", &ip_header->saddr, &ip_header->daddr, ip_header->protocol);

        if (ip_header->protocol == IPPROTO_TCP) {
            tcp_header = tcp_hdr(skb);
            if (tcp_header) {
                printk(KERN_INFO "TCP packet: src port %u, dst port %u\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
                // return NF_ACCEPT;
            }
        }

        if (ip_header->protocol == IPPROTO_UDP) {
            udp_header = udp_hdr(skb);
            if (udp_header) {
                printk(KERN_INFO "UDP packet: src port %u, dst port %u\n", ntohs(udp_header->source), ntohs(udp_header->dest));
                // return NF_ACCEPT;
            }
        
        }

        if (ip_header->protocol == IPPROTO_ICMP) {
            printk(KERN_INFO "ICMP packet,src %pI4, dst %pI4\n", &ip_header->saddr, &ip_header->daddr);
            // return NF_DROP;
        }

        unsigned int rule_verdict = check_rules(skb, state);
    
        /* If a rule matches, return its verdict */
        if (rule_verdict != NF_ACCEPT)
            return rule_verdict;
        }

    return NF_ACCEPT;

}
