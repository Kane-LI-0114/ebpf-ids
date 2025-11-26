// eBPF IDS 内核程序
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/in.h>
#include <uapi/linux/pkt_cls.h>

// 控制是否只接收来自 10.10.1.3 的数据包
#define ALLOW_ONLY_10_10_1_3 1  // 设置为 1 启用白名单，0 禁用

// 定义事件数据结构
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 anomaly_type;
    __u8 app_proto;     // 新增：应用层协议标识
    __u8 _pad;          // 填充对齐
    __u32 payload_len;
    __u8 payload[256];
};

// eBPF Maps 定义
BPF_PERF_OUTPUT(events);
BPF_HASH(rule_cache, __u32, __u32);
// 使用 LRU Hash 避免内存泄漏
BPF_TABLE("lru_hash", __u64, __u32, connection_state, 10240);
// 新增：监控端口 Map，由用户空间动态更新
BPF_HASH(monitored_ports, __u16, __u8);
// 新增：Per-CPU Array 用于临时存储事件数据，避免栈溢出
BPF_PERCPU_ARRAY(packet_event_heap, struct packet_event, 1);

// 调试计数器
BPF_ARRAY(debug_counters, __u64, 10);

// 调试计数器索引
#define DEBUG_TOTAL_PACKETS 0
#define DEBUG_IP_PACKETS 1
#define DEBUG_TCP_PACKETS 2
#define DEBUG_UDP_PACKETS 3
#define DEBUG_ICMP_PACKETS 4
#define DEBUG_MATCHED_PACKETS 5
#define DEBUG_PARSE_ERRORS 6
#define DEBUG_EVENTS_SUBMITTED 7

// 调试计数器递增函数
static inline void inc_counter(int idx) {
    int key = idx;
    __u64 *counter = debug_counters.lookup(&key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

// 包解析函数
static inline int parse_packet(struct __sk_buff *skb, struct packet_event *evt) {
    inc_counter(DEBUG_TOTAL_PACKETS);
    // 从 skb 中加载数据
    __u32 proto;
    __u32 nhoff = ETH_HLEN;
    
    // 读取以太网协议类型
    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = bpf_ntohs(proto);
    
    // 检查是否为 IP 协议
    if (proto != ETH_P_IP) {
        inc_counter(DEBUG_PARSE_ERRORS);
        return -1;
    }
    
    inc_counter(DEBUG_IP_PACKETS);
    
    // 读取 IP 头部信息
    struct iphdr ip;
    bpf_skb_load_bytes(skb, nhoff, &ip, sizeof(ip));
    
#if ALLOW_ONLY_10_10_1_3
    // 只接收来自 10.10.1.3 的数据包
    __u32 src_ip_host = bpf_ntohl(ip.saddr);
    __u8 octet1 = (src_ip_host >> 24) & 0xFF;
    __u8 octet2 = (src_ip_host >> 16) & 0xFF;
    __u8 octet3 = (src_ip_host >> 8) & 0xFF;
    __u8 octet4 = src_ip_host & 0xFF;
    
    if (octet1 != 10 || octet2 != 10 || octet3 != 1 || octet4 != 3) {
        return -1;  // 丢弃非 10.10.1.3 的数据包
    }
#endif
    
    // 填充基本 IP 信息
    evt->src_ip = ip.saddr;
    evt->dst_ip = ip.daddr;
    evt->protocol = ip.protocol;
    
    __u32 l4_offset = nhoff + (ip.ihl * 4);
    
    // 根据协议类型解析传输层
    if (ip.protocol == IPPROTO_TCP) {
        inc_counter(DEBUG_TCP_PACKETS);
        struct tcphdr tcp;
        bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp));
        
        evt->src_port = bpf_ntohs(tcp.source);
        evt->dst_port = bpf_ntohs(tcp.dest);
        
        // 提取 TCP payload
        __u32 payload_offset = l4_offset + (tcp.doff * 4);
        
        // 确保 payload_len 非负 - 使用显式的边界检查
        if (skb->len > payload_offset) {
            __u32 payload_len = skb->len - payload_offset;
            
            // 限制 payload_len 的最大值
            if (payload_len > 256)
                payload_len = 256;
            
            // 使用位操作确保值为正数（eBPF 验证器要求）
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
        
        // 提取 UDP payload
        __u32 payload_offset = l4_offset + sizeof(struct udphdr);
        
        // 确保 payload_len 非负 - 使用显式的边界检查
        if (skb->len > payload_offset) {
            __u32 payload_len = skb->len - payload_offset;
            
            // 限制 payload_len 的最大值
            if (payload_len > 256)
                payload_len = 256;
            
            // 使用位操作确保值为正数（eBPF 验证器要求）
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

// 规则匹配函数
static inline int match_rules(struct packet_event *evt) {
    __u32 key = 0;
    __u32 *rule_count = rule_cache.lookup(&key);
    
    // 捕获所有 ICMP 流量（ping）
    if (evt->protocol == IPPROTO_ICMP) {
        inc_counter(DEBUG_ICMP_PACKETS);
        inc_counter(DEBUG_MATCHED_PACKETS);
        return 1;
    }
    
    if (!rule_count)
        return 0;
    
    // 动态端口检查：检查目的端口是否在监控列表中
    if (evt->protocol == IPPROTO_TCP || evt->protocol == IPPROTO_UDP) {
        __u16 port = evt->dst_port;
        __u8 *exists = monitored_ports.lookup(&port);
        if (exists) {
            inc_counter(DEBUG_MATCHED_PACKETS);
            return 1;
        }
    }
    
    // 检查常见攻击端口 (保留作为后备或特定逻辑)
    if (evt->protocol == IPPROTO_TCP) {
        // SSH 暴力破解检测 (端口 22)
        if (evt->dst_port == 22) {
            return 1;
        }
        // HTTP/HTTPS 异常流量
        if (evt->dst_port == 80 || evt->dst_port == 443) {
            // 检查 payload 中是否包含可疑模式
            if (evt->payload_len > 0) {
                return 1;
            }
        }
    }
    
    // 检查扫描行为
    __u64 conn_key = ((__u64)evt->src_ip << 32) | evt->dst_ip;
    __u32 *conn_count = connection_state.lookup(&conn_key);
    if (conn_count) {
        // 使用原子操作增加计数
        __sync_fetch_and_add(conn_count, 1);
        if (*conn_count > 100) {  // 端口扫描阈值
            return 1;
        }
    } else {
        __u32 initial_count = 1;
        connection_state.update(&conn_key, &initial_count);
    }
    
    return 0;
}

// 协议分析函数
static inline int analyze_protocol(struct packet_event *evt) {
    // 分析 TCP 协议
    if (evt->protocol == IPPROTO_TCP) {
        // 检查常见服务端口
        if (evt->dst_port == 80 || evt->dst_port == 8080) {
            // HTTP 协议分析
            if (evt->payload_len >= 4) {
                // 简单检查是否为 HTTP 请求
                if (evt->payload[0] == 'G' && evt->payload[1] == 'E' && 
                    evt->payload[2] == 'T' && evt->payload[3] == ' ') {
                    evt->app_proto = 1; // HTTP
                    return 1;  // HTTP GET 请求
                }
                if (evt->payload[0] == 'P' && evt->payload[1] == 'O' && 
                    evt->payload[2] == 'S' && evt->payload[3] == 'T') {
                    evt->app_proto = 1; // HTTP
                    return 1;  // HTTP POST 请求
                }
            }
        }
        // FTP 协议检测
        else if (evt->dst_port == 21) {
            evt->app_proto = 2; // FTP
            return 1;
        }
        // SSH 协议检测
        else if (evt->dst_port == 22) {
            evt->app_proto = 3; // SSH
            return 1;
        }
    }
    // 分析 UDP 协议
    else if (evt->protocol == IPPROTO_UDP) {
        // DNS 协议检测 (端口 53)
        if (evt->dst_port == 53 || evt->src_port == 53) {
            evt->app_proto = 4; // DNS
            return 1;
        }
        // DHCP 协议检测
        else if (evt->dst_port == 67 || evt->dst_port == 68) {
            evt->app_proto = 5; // DHCP
            return 1;
        }
    }
    
    return 0;
}

// 异常检测函数
static inline void detect_anomaly(struct packet_event *evt) {
    // 检测大量连接（可能的 DDoS）
    __u64 dst_key = evt->dst_ip;
    __u32 *dst_count = connection_state.lookup(&dst_key);
    
    if (dst_count) {
        // 使用原子操作增加计数
        __sync_fetch_and_add(dst_count, 1);
        // DDoS 检测阈值
        if (*dst_count > 1000) {
            evt->anomaly_type = 1;  // 检测到异常流量
            return;
        }
    } else {
        __u32 initial_count = 1;
        connection_state.update(&dst_key, &initial_count);
    }
    
    // 检测异常端口（高端口号）
    if (evt->dst_port > 50000) {
        evt->anomaly_type = 2;
        return;
    }
    
    // 检测可疑的 payload 大小
    if (evt->payload_len > 0) {
        // 检测异常大的数据包
        if (evt->payload_len >= 200) {
            evt->anomaly_type = 3;
            return;
        }
        
        // 检测 payload 中的可疑模式
        // 简单检查是否包含 shell 命令特征
        #pragma unroll
        for (int i = 0; i < 255; i++) {
            if (i >= evt->payload_len - 1) break;
            
            if (evt->payload[i] == '/' && evt->payload[i+1] == 'b') {
                evt->anomaly_type = 4;  // 可能包含 /bin/sh 等
                return;
            }
            if (evt->payload[i] == '<' && evt->payload[i+1] == 's') {
                evt->anomaly_type = 5;  // 可能包含 <script> XSS 攻击
                return;
            }
        }
    }
    
    // 检测可疑的源 IP（私有地址作为源地址的外部通信）
    __u32 src_ip = evt->src_ip;
    __u8 first_octet = src_ip & 0xFF;
    
    // 检测来自 0.0.0.0 的流量
    if (src_ip == 0) {
        evt->anomaly_type = 6;
        return;
    }
}

// 主钩子函数 - 网络过滤器
int ids_filter(struct __sk_buff *skb) {
    // 使用 Per-CPU Array 避免栈溢出
    int zero = 0;
    struct packet_event *evt = packet_event_heap.lookup(&zero);
    if (!evt) {
        return 0;
    }
    
    // 重置关键字段 (因为 Map 内存是复用的)
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    evt->protocol = 0;
    evt->anomaly_type = 0;
    evt->app_proto = 0;
    evt->payload_len = 0;
    
    // 解析数据包
    if (parse_packet(skb, evt) < 0) {
        return 0;
    }
    
    // 规则匹配
    int matched = match_rules(evt);
    
    // 协议分析
    analyze_protocol(evt);
    
    // 异常检测
    detect_anomaly(evt);
    
    if (matched > 0 || evt->anomaly_type > 0) {
        inc_counter(DEBUG_EVENTS_SUBMITTED);
        events.perf_submit(skb, evt, sizeof(*evt));
    }
    
    return 0;
}
