#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>
#include "sockops.h"

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *ops){
    // skip if the packet is not ipv4
    if(ops->family!= AF_INET){
        return BPF_OK;
    }

    // skip if it is not established op
    if(ops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB && ops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    struct sock_key key = {
        .sip = ops->local_ip4,
        .dip = ops->remote_ip4,
        .sport = bpf_htonl(ops->local_port),
        .dport = ops->remote_port,
        .family = ops->family,
    };
    
    bpf_sock_hash_update(ops, &sock_ops_map, &key, BPF_NOEXIST);
    return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";