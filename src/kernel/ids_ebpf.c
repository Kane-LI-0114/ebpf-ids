// eBPF IDS kernel program
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/in.h>
#include <uapi/linux/pkt_cls.h>

// Control whether to only accept packets from 10.10.1.3
#define ALLOW_ONLY_10_10_1_3 1  // Set to 1 to enable whitelist, 0 to disable

// Event data structure
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 anomaly_type;
    __u8 app_proto;     // Application layer protocol identifier
    __u8 _pad;          // Padding for alignment
    __u32 payload_len;
    __u8 payload[256];
};

// eBPF Maps definition
BPF_PERF_OUTPUT(events);
// Use LRU Hash to avoid memory leaks
BPF_TABLE("lru_hash", __u64, __u32, connection_state, 10240);
// Monitored ports map, dynamically updated from userspace
BPF_HASH(monitored_ports, __u16, __u8);
// Per-CPU Array for temporary event data storage to avoid stack overflow
BPF_PERCPU_ARRAY(packet_event_heap, struct packet_event, 1);

// Debug counters
BPF_ARRAY(debug_counters, __u64, 10);

// Debug counter indices
#define DEBUG_TOTAL_PACKETS 0
#define DEBUG_IP_PACKETS 1
#define DEBUG_TCP_PACKETS 2
#define DEBUG_UDP_PACKETS 3
#define DEBUG_ICMP_PACKETS 4
#define DEBUG_MATCHED_PACKETS 5
#define DEBUG_PARSE_ERRORS 6
#define DEBUG_EVENTS_SUBMITTED 7

// Debug counter increment function
static inline void inc_counter(int idx) {
    int key = idx;
    __u64 *counter = debug_counters.lookup(&key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

// Packet parsing function
static inline int parse_packet(struct __sk_buff *skb, struct packet_event *evt) {
    inc_counter(DEBUG_TOTAL_PACKETS);
    // Load data from skb
    __u32 proto;
    __u32 nhoff = ETH_HLEN;
    
    // Read Ethernet protocol type
    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = bpf_ntohs(proto);
    
    // Check if it's IP protocol
    if (proto != ETH_P_IP) {
        inc_counter(DEBUG_PARSE_ERRORS);
        return -1;
    }
    
    inc_counter(DEBUG_IP_PACKETS);
    
    // Read IP header information
    struct iphdr ip;
    bpf_skb_load_bytes(skb, nhoff, &ip, sizeof(ip));
    
#if ALLOW_ONLY_10_10_1_3
    // Only accept packets from 10.10.1.3
    __u32 src_ip_host = bpf_ntohl(ip.saddr);
    __u8 octet1 = (src_ip_host >> 24) & 0xFF;
    __u8 octet2 = (src_ip_host >> 16) & 0xFF;
    __u8 octet3 = (src_ip_host >> 8) & 0xFF;
    __u8 octet4 = src_ip_host & 0xFF;
    
    if (octet1 != 10 || octet2 != 10 || octet3 != 1 || octet4 != 3) {
        return -1;  // Drop packets not from 10.10.1.3
    }
#endif
    
    // Fill basic IP information
    evt->src_ip = ip.saddr;
    evt->dst_ip = ip.daddr;
    evt->protocol = ip.protocol;
    
    __u32 l4_offset = nhoff + (ip.ihl * 4);
    
    // Parse transport layer based on protocol type
    if (ip.protocol == IPPROTO_TCP) {
        inc_counter(DEBUG_TCP_PACKETS);
        struct tcphdr tcp;
        bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp));
        
        evt->src_port = bpf_ntohs(tcp.source);
        evt->dst_port = bpf_ntohs(tcp.dest);
        
        // Extract TCP payload
        __u32 payload_offset = l4_offset + (tcp.doff * 4);
        
        // Ensure payload_len is non-negative with explicit boundary check
        if (skb->len > payload_offset) {
            __u32 payload_len = skb->len - payload_offset;
            
            // Limit maximum payload_len
            if (payload_len > 256)
                payload_len = 256;
            
            // Use bit operation to ensure positive value (eBPF verifier requirement)
            payload_len &= 0xFF;
            
            if (payload_len > 0) {
                evt->payload_len = payload_len;
                bpf_skb_load_bytes(skb, payload_offset, evt->payload, payload_len);
            }
        } else {
            evt->payload_len = 0;
        }
        
    } else if (ip.protocol == IPPROTO_UDP) {
        inc_counter(DEBUG_UDP_PACKETS);
        struct udphdr udp;
        bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp));
        
        evt->src_port = bpf_ntohs(udp.source);
        evt->dst_port = bpf_ntohs(udp.dest);
        
        // Extract UDP payload
        __u32 payload_offset = l4_offset + sizeof(struct udphdr);
        
        // Ensure payload_len is non-negative with explicit boundary check
        if (skb->len > payload_offset) {
            __u32 payload_len = skb->len - payload_offset;
            
            // Limit maximum payload_len
            if (payload_len > 256)
                payload_len = 256;
            
            // Use bit operation to ensure positive value (eBPF verifier requirement)
            payload_len &= 0xFF;
            
            if (payload_len > 0) {
                evt->payload_len = payload_len;
                bpf_skb_load_bytes(skb, payload_offset, evt->payload, payload_len);
            }
        } else {
            evt->payload_len = 0;
        }
    } else {
        evt->src_port = 0;
        evt->dst_port = 0;
        evt->payload_len = 0;
    }
    
    return 0;
}

// Rule matching function
static inline int match_rules(struct packet_event *evt) {
    // Capture all ICMP traffic (ping)
    if (evt->protocol == IPPROTO_ICMP) {
        inc_counter(DEBUG_ICMP_PACKETS);
        inc_counter(DEBUG_MATCHED_PACKETS);
        return 1;
    }
    
    // Dynamic port check: verify if destination port is in monitored list
    if (evt->protocol == IPPROTO_TCP || evt->protocol == IPPROTO_UDP) {
        __u16 port = evt->dst_port;
        __u8 *exists = monitored_ports.lookup(&port);
        if (exists) {
            inc_counter(DEBUG_MATCHED_PACKETS);
            return 1;
        }
    }
    
    // Check common attack ports (kept as fallback or specific logic)
    if (evt->protocol == IPPROTO_TCP) {
        // SSH brute force detection (port 22)
        if (evt->dst_port == 22) {
            return 1;
        }
        // HTTP/HTTPS anomalous traffic
        if (evt->dst_port == 80 || evt->dst_port == 443) {
            // Check for suspicious patterns in payload
            if (evt->payload_len > 0) {
                return 1;
            }
        }
    }
    
    // Check scanning behavior
    __u64 conn_key = ((__u64)evt->src_ip << 32) | evt->dst_ip;
    __u32 *conn_count = connection_state.lookup(&conn_key);
    if (conn_count) {
        // Use atomic operation to increment count
        __sync_fetch_and_add(conn_count, 1);
        if (*conn_count > 100) {  // Port scan threshold
            return 1;
        }
    } else {
        __u32 initial_count = 1;
        connection_state.update(&conn_key, &initial_count);
    }
    
    return 0;
}

// Protocol analysis function
static inline int analyze_protocol(struct packet_event *evt) {
    // Analyze TCP protocol
    if (evt->protocol == IPPROTO_TCP) {
        // Check common service ports
        if (evt->dst_port == 80 || evt->dst_port == 8080) {
            // HTTP protocol analysis
            if (evt->payload_len >= 4) {
                // Simple check for HTTP request
                if (evt->payload[0] == 'G' && evt->payload[1] == 'E' && 
                    evt->payload[2] == 'T' && evt->payload[3] == ' ') {
                    evt->app_proto = 1; // HTTP
                    return 1;  // HTTP GET request
                }
                if (evt->payload[0] == 'P' && evt->payload[1] == 'O' && 
                    evt->payload[2] == 'S' && evt->payload[3] == 'T') {
                    evt->app_proto = 1; // HTTP
                    return 1;  // HTTP POST request
                }
            }
        }
        // FTP protocol detection
        else if (evt->dst_port == 21) {
            evt->app_proto = 2; // FTP
            return 1;
        }
        // SSH protocol detection
        else if (evt->dst_port == 22) {
            evt->app_proto = 3; // SSH
            return 1;
        }
    }
    // Analyze UDP protocol
    else if (evt->protocol == IPPROTO_UDP) {
        // DNS protocol detection (port 53)
        if (evt->dst_port == 53 || evt->src_port == 53) {
            evt->app_proto = 4; // DNS
            return 1;
        }
        // DHCP protocol detection
        else if (evt->dst_port == 67 || evt->dst_port == 68) {
            evt->app_proto = 5; // DHCP
            return 1;
        }
    }
    
    return 0;
}

// Anomaly detection function
static inline void detect_anomaly(struct packet_event *evt) {
    // Detect massive connections (possible DDoS)
    __u64 dst_key = evt->dst_ip;
    __u32 *dst_count = connection_state.lookup(&dst_key);
    
    if (dst_count) {
        // Use atomic operation to increment count
        __sync_fetch_and_add(dst_count, 1);
        // DDoS detection threshold
        if (*dst_count > 1000) {
            evt->anomaly_type = 1;  // Anomalous traffic detected
            return;
        }
    } else {
        __u32 initial_count = 1;
        connection_state.update(&dst_key, &initial_count);
    }
    
    // Detect anomalous ports (high port numbers)
    if (evt->dst_port > 50000) {
        evt->anomaly_type = 2;
        return;
    }
    
    // Detect suspicious payload size
    if (evt->payload_len > 0) {
        // Detect abnormally large packets
        if (evt->payload_len >= 200) {
            evt->anomaly_type = 3;
            return;
        }
        
        // Detect suspicious patterns in payload
        // Simple check for shell command characteristics
        #pragma unroll
        for (int i = 0; i < 255; i++) {
            if (i >= evt->payload_len - 1) break;
            
            if (evt->payload[i] == '/' && evt->payload[i+1] == 'b') {
                evt->anomaly_type = 4;  // May contain /bin/sh etc.
                return;
            }
            if (evt->payload[i] == '<' && evt->payload[i+1] == 's') {
                evt->anomaly_type = 5;  // May contain <script> XSS attack
                return;
            }
        }
    }
    
    // Detect suspicious source IP
    __u32 src_ip = evt->src_ip;
    __u8 first_octet = src_ip & 0xFF;
    
    // Detect traffic from 0.0.0.0
    if (src_ip == 0) {
        evt->anomaly_type = 6;
        return;
    }
}

// Main hook function - network filter
int ids_filter(struct __sk_buff *skb) {
    // Use Per-CPU Array to avoid stack overflow
    int zero = 0;
    struct packet_event *evt = packet_event_heap.lookup(&zero);
    if (!evt) {
        return 0;
    }
    
    // Reset key fields (because Map memory is reused)
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    evt->protocol = 0;
    evt->anomaly_type = 0;
    evt->app_proto = 0;
    evt->payload_len = 0;
    
    // Parse packet
    if (parse_packet(skb, evt) < 0) {
        return 0;
    }
    
    // Rule matching
    int matched = match_rules(evt);
    
    // Protocol analysis
    analyze_protocol(evt);
    
    // Anomaly detection
    detect_anomaly(evt);
    
    if (matched > 0 || evt->anomaly_type > 0) {
        inc_counter(DEBUG_EVENTS_SUBMITTED);
        events.perf_submit(skb, evt, sizeof(*evt));
    }
    
    return 0;
}
