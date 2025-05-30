// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800

/* Define a BPF map to count packets by protocol */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} protocol_map SEC(".maps");

/* BPF program that counts packets by IP protocol */
SEC("socket")
int count_packets(struct __sk_buff *skb)
{
    __u32 proto_key;
    __u64 *value;
    __u16 eth_proto;
    
    /* Read ethernet protocol (ip/arp/etc) */
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2))
        return 0;
    
    /* We only care about IP packets */
    if (bpf_ntohs(eth_proto) != ETH_P_IP)
        return 0;

    /* Read IP protocol */
    if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &proto_key, 1))
        return 0;

    /* Lookup protocol counter */
    value = bpf_map_lookup_elem(&protocol_map, &proto_key);
    if (value)
        __sync_fetch_and_add(value, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";
