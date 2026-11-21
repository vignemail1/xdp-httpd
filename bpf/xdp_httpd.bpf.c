// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks SEC(".maps");

/* Injectés par l'espace utilisateur (ordre réseau) */
volatile const __u32 CFG_IP = 0;
volatile const __u16 CFG_PORT = 0;
volatile const __u16 CFG_PORT_TLS = 0;   /* 0 = désactivé */

struct arp_eth {
    __be16 htype, ptype; __u8 hlen, plen; __be16 op;
    __u8 sha[6]; __be32 spa; __u8 tha[6]; __be32 tpa;
} __attribute__((packed));

SEC("xdp")
int xdp_httpd(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        struct arp_eth *a = (void *)(eth + 1);
        if ((void *)(a + 1) > end) return XDP_PASS;
        return a->tpa == CFG_IP ? bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_PASS) : XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;
    if (ip->daddr != CFG_IP) return XDP_PASS;          /* pas pour nous : noyau */

    if (ip->protocol == IPPROTO_ICMP)                  /* ping géré par smoltcp */
        return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_DROP);
    if (ip->protocol != IPPROTO_TCP || ip->ihl < 5) return XDP_DROP;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > end) return XDP_DROP;
    if (tcp->dest == CFG_PORT || (CFG_PORT_TLS && tcp->dest == CFG_PORT_TLS))
        return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_DROP);
    return XDP_DROP;                                   /* autre port sur notre IP */
}

char LICENSE[] SEC("license") = "GPL";
