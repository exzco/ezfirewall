#ifndef FUNC_H
#define FUNC_H

#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/skbuff.h>
#include<linux/kernel.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/ip.h>
#include<linux/in.h>

#define NF_ACCEPT 1
#define NF_DROP 0

// 基于协议过滤的函数声明
unsigned int func_filter_Protocol(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);


#endif