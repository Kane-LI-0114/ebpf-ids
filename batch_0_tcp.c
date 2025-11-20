#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bcc/proto.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/sock.h>

#define HOME_NET 0x0201010A
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Helper macro to safely access packet data
#define BOUNDS_CHECK(ptr, end, size) ((void *)(ptr) + (size) <= (void *)(end))

// Generated eBPF batch program - Batch 0, Rules 0-4
// This program processes the following rules:
// 1. SID_105_MALWARE-BACKDOOR_-_Dagger_1.4.
// 2. SID_108_MALWARE-BACKDOOR_QAZ_Worm_Clie
// 3. SID_110_MALWARE-BACKDOOR_netbus_getinf
// 4. SID_115_MALWARE-BACKDOOR_NetBus_Pro_2.
// 5. SID_117_MALWARE-BACKDOOR_Infector.1.x



SEC("xdp")
int ids_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (!BOUNDS_CHECK(eth, data_end, sizeof(*eth)))
        return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)eth + 1;
    if (!BOUNDS_CHECK(ip, data_end, sizeof(*ip)))
        return XDP_PASS;

    // Process rule checks here
    // Rules included: SID_105_MALWARE-BACKDOOR_-_Dagger_1.4., SID_108_MALWARE-BACKDOOR_QAZ_Worm_Clie, SID_110_MALWARE-BACKDOOR_netbus_getinf, SID_115_MALWARE-BACKDOOR_NetBus_Pro_2., SID_117_MALWARE-BACKDOOR_Infector.1.x

    // Default: pass packet
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
