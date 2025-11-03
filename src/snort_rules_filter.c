#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map to store blocked packets statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // Rule SID
    __type(value, __u64);  // Packet count
    __uint(max_entries, 10000);
} rule_stats SEC(".maps");

/* Map for IP blacklist/whitelist */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // IP address
    __type(value, __u8);   // 1 = blocked
    __uint(max_entries, 256000);
} ip_blacklist SEC(".maps");

/* Helper function to check packet bounds */
static __always_inline int check_bound(void *ptr, void *data_end, __u64 size) {
    if ((void *)ptr + size > data_end)
        return 0;
    return 1;
}

/* Helper to match byte pattern in payload */
static __always_inline int match_pattern(void *start, void *data_end, 
                                         unsigned char *pattern, int len) {
    if ((void *)start + len > data_end)
        return 0;
    
    for (int i = 0; i < len && i < 64; i++) {  // eBPF loop limit
        if (((unsigned char *)start)[i] != pattern[i])
            return 0;
    }
    return 1;
}

/* ========================================
 * Rule 0: SID 105
 * Action: alert
 * Message: MALWARE-BACKDOOR - Dagger_1.4.0
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_105(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check source port: 2589
    if (bpf_ntohs(tcph->source) != 2589) {
        return 0;
    }
    
    // Flow direction: to_client,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Match pattern: "2|00 00 00 06 00 00 00|Drives|24 00|",de..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {
        return 0;
    }
    
    // Rule matched - update statistics
    __u32 key = 105;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 1: SID 108
 * Action: alert
 * Message: MALWARE-BACKDOOR QAZ Worm Client Login access
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_108(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check destination port: 7597
    if (bpf_ntohs(tcph->dest) != 7597) {
        return 0;
    }
    
    // Flow direction: to_server,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Match pattern: "qazwsx.hsq..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {
        return 0;
    }
    
    // Rule matched - update statistics
    __u32 key = 108;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 2: SID 110
 * Action: alert
 * Message: MALWARE-BACKDOOR netbus getinfo
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_110(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check destination port range: 12345-12346
    __u16 dport = bpf_ntohs(tcph->dest);
    if (dport < 12345 || dport > 12346) {
        return 0;
    }
    
    // Flow direction: to_server,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Match pattern: "GetInfo|0D|..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {
        return 0;
    }
    
    // Rule matched - update statistics
    __u32 key = 110;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 3: SID 115
 * Action: alert
 * Message: MALWARE-BACKDOOR NetBus Pro 2.0 connection established
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_115(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check source port: 20034
    if (bpf_ntohs(tcph->source) != 20034) {
        return 0;
    }
    
    // Flow direction: to_client,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Multiple content patterns (2 total)
    // Pattern 1: "BN|10 00 02 00|",depth 6..."
    // Pattern 2: "|05 00|",depth 2,offset 8..."

    // Rule matched - update statistics
    __u32 key = 115;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 4: SID 117
 * Action: alert
 * Message: MALWARE-BACKDOOR Infector.1.x
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_117(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Flow direction: to_client,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Match pattern: "WHATISIT",depth 9..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {
        return 0;
    }
    
    // Rule matched - update statistics
    __u32 key = 117;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 5: SID 118
 * Action: alert
 * Message: MALWARE-BACKDOOR SatansBackdoor.2.0.Beta
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_118(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check source port: 666
    if (bpf_ntohs(tcph->source) != 666) {
        return 0;
    }
    
    // Flow direction: to_client,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Multiple content patterns (2 total)
    // Pattern 1: "Remote|3A| ",depth 11,nocase..."
    // Pattern 2: "You are connected to me.|0D 0A|Remote|3A..."

    // Rule matched - update statistics
    __u32 key = 118;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 6: SID 119
 * Action: alert
 * Message: MALWARE-BACKDOOR Doly 2.0 access
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_119(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check source port: 6789
    if (bpf_ntohs(tcph->source) != 6789) {
        return 0;
    }
    
    // Flow direction: to_client,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Match pattern: "Wtzup Use",depth 32..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {
        return 0;
    }
    
    // Rule matched - update statistics
    __u32 key = 119;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 7: SID 121
 * Action: alert
 * Message: MALWARE-BACKDOOR Infector 1.6 Client to Server Connection Request
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_121(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check source port range: 1000-1300
    __u16 sport = bpf_ntohs(tcph->source);
    if (sport < 1000 || sport > 1300) {
        return 0;
    }
    
    // Check destination port: 146
    if (bpf_ntohs(tcph->dest) != 146) {
        return 0;
    }
    
    // Flow direction: to_server,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Match pattern: "FC ..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {
        return 0;
    }
    
    // Rule matched - update statistics
    __u32 key = 121;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 8: SID 141
 * Action: alert
 * Message: MALWARE-BACKDOOR HackAttack 1.20 Connect
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_141(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check source port: 31785
    if (bpf_ntohs(tcph->source) != 31785) {
        return 0;
    }
    
    // Flow direction: to_client,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Match pattern: "host..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {
        return 0;
    }
    
    // Rule matched - update statistics
    __u32 key = 141;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

/* ========================================
 * Rule 9: SID 144
 * Action: alert
 * Message: PROTOCOL-FTP ADMw0rm ftp login attempt
 * Protocol: IPPROTO_TCP
 * ========================================*/
static __always_inline int check_rule_144(struct iphdr *iph, void *data_end, void *data) {
    
    // Check protocol: IPPROTO_TCP
    if (iph->protocol != IPPROTO_TCP) {
        return 0;  // Protocol mismatch
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
    // Check destination port: 21
    if (bpf_ntohs(tcph->dest) != 21) {
        return 0;
    }
    
    // Flow direction: to_server,established
    // TODO: Implement connection tracking for flow state

    // Payload content matching
    void *payload = (void *)tcph + (tcph->doff * 4);
    // Multiple content patterns (2 total)
    // Pattern 1: "USER",nocase..."
    // Pattern 2: "w0rm",distance 1,nocase..."

    // Rule matched - update statistics
    __u32 key = 144;
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }
    
    return 1;  // Rule matched
}

SEC("xdp")
int xdp_snort_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    
    // Bounds check for Ethernet header
    if (!check_bound(eth, data_end, sizeof(*eth))) {
        return XDP_PASS;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *iph = (void *)eth + sizeof(*eth);
    
    // Bounds check for IP header
    if (!check_bound(iph, data_end, sizeof(*iph))) {
        return XDP_PASS;
    }
    
    // Check against all rules
    if (check_rule_105(iph, data_end, data)) {
        // Action: DROP packet matching rule 105
        return XDP_DROP;
    }
    
    if (check_rule_108(iph, data_end, data)) {
        // Action: DROP packet matching rule 108
        return XDP_DROP;
    }
    
    if (check_rule_110(iph, data_end, data)) {
        // Action: DROP packet matching rule 110
        return XDP_DROP;
    }
    
    if (check_rule_115(iph, data_end, data)) {
        // Action: DROP packet matching rule 115
        return XDP_DROP;
    }
    
    if (check_rule_117(iph, data_end, data)) {
        // Action: DROP packet matching rule 117
        return XDP_DROP;
    }
    
    if (check_rule_118(iph, data_end, data)) {
        // Action: DROP packet matching rule 118
        return XDP_DROP;
    }
    
    if (check_rule_119(iph, data_end, data)) {
        // Action: DROP packet matching rule 119
        return XDP_DROP;
    }
    
    if (check_rule_121(iph, data_end, data)) {
        // Action: DROP packet matching rule 121
        return XDP_DROP;
    }
    
    if (check_rule_141(iph, data_end, data)) {
        // Action: DROP packet matching rule 141
        return XDP_DROP;
    }
    
    if (check_rule_144(iph, data_end, data)) {
        // Action: DROP packet matching rule 144
        return XDP_DROP;
    }
    
    // No rules matched - pass packet
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
