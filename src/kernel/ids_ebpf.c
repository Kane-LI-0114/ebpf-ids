// eBPF IDS 内核程序
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>
#include <uapi/linux/pkt_cls.h>

// 定义事件数据结构
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 payload_len;
    __u8 payload[256];
};

// 定义规则匹配结果结构
struct match_result {
    __u32 rule_id;
    __u32 severity;
    __u64 timestamp;
};

// eBPF Maps 定义
BPF_PERF_OUTPUT(events);
BPF_HASH(rule_cache, __u32, __u32);
BPF_HASH(connection_state, __u64, __u32);

// 包解析函数
static inline int parse_packet(struct __sk_buff *skb, struct packet_event *evt) {
    // 从 skb 中加载数据
    __u32 proto;
    __u32 nhoff = ETH_HLEN;
    
    // 读取以太网协议类型
    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = bpf_ntohs(proto);
    
    // 检查是否为 IP 协议
    if (proto != ETH_P_IP)
        return -1;
    
    // 读取 IP 头部信息
    struct iphdr ip;
    bpf_skb_load_bytes(skb, nhoff, &ip, sizeof(ip));
    
    // 填充基本 IP 信息
    evt->src_ip = ip.saddr;
    evt->dst_ip = ip.daddr;
    evt->protocol = ip.protocol;
    
    __u32 l4_offset = nhoff + (ip.ihl * 4);
    
    // 根据协议类型解析传输层
    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp));
        
        evt->src_port = bpf_ntohs(tcp.source);
        evt->dst_port = bpf_ntohs(tcp.dest);
        
        // 提取 TCP payload
        __u32 payload_offset = l4_offset + (tcp.doff * 4);
        
        // 确保 payload_len 非负
        if (skb->len > payload_offset) {
            __u32 payload_len = skb->len - payload_offset;
            
            if (payload_len > 256)
                payload_len = 256;
            
            evt->payload_len = payload_len;
            bpf_skb_load_bytes(skb, payload_offset, evt->payload, payload_len & 0xff);
        } else {
            evt->payload_len = 0;
        }
        
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp));
        
        evt->src_port = bpf_ntohs(udp.source);
        evt->dst_port = bpf_ntohs(udp.dest);
        
        // 提取 UDP payload
        __u32 payload_offset = l4_offset + sizeof(struct udphdr);
        
        // 确保 payload_len 非负
        if (skb->len > payload_offset) {
            __u32 payload_len = skb->len - payload_offset;
            
            if (payload_len > 256)
                payload_len = 256;
            
            evt->payload_len = payload_len;
            bpf_skb_load_bytes(skb, payload_offset, evt->payload, payload_len & 0xff);
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
    
    if (!rule_count)
        return 0;
    
    // 检查常见攻击端口
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
        (*conn_count)++;
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
                    return 1;  // HTTP GET 请求
                }
                if (evt->payload[0] == 'P' && evt->payload[1] == 'O' && 
                    evt->payload[2] == 'S' && evt->payload[3] == 'T') {
                    return 1;  // HTTP POST 请求
                }
            }
        }
        // FTP 协议检测
        else if (evt->dst_port == 21) {
            return 1;
        }
        // SSH 协议检测
        else if (evt->dst_port == 22) {
            return 1;
        }
    }
    // 分析 UDP 协议
    else if (evt->protocol == IPPROTO_UDP) {
        // DNS 协议检测 (端口 53)
        if (evt->dst_port == 53 || evt->src_port == 53) {
            return 1;
        }
        // DHCP 协议检测
        else if (evt->dst_port == 67 || evt->dst_port == 68) {
            return 1;
        }
    }
    
    return 0;
}

// 异常检测函数
static inline int detect_anomaly(struct packet_event *evt) {
    // 检测大量连接（可能的 DDoS）
    __u64 dst_key = evt->dst_ip;
    __u32 *dst_count = connection_state.lookup(&dst_key);
    
    if (dst_count) {
        (*dst_count)++;
        // DDoS 检测阈值
        if (*dst_count > 1000) {
            return 1;  // 检测到异常流量
        }
    } else {
        __u32 initial_count = 1;
        connection_state.update(&dst_key, &initial_count);
    }
    
    // 检测异常端口（高端口号）
    if (evt->dst_port > 50000) {
        return 1;
    }
    
    // 检测可疑的 payload 大小
    if (evt->payload_len > 0) {
        // 检测异常大的数据包
        if (evt->payload_len >= 200) {
            return 1;
        }
        
        // 检测 payload 中的可疑模式
        // 简单检查是否包含 shell 命令特征
        for (int i = 0; i < evt->payload_len - 1 && i < 255; i++) {
            if (evt->payload[i] == '/' && evt->payload[i+1] == 'b') {
                return 1;  // 可能包含 /bin/sh 等
            }
            if (evt->payload[i] == '<' && evt->payload[i+1] == 's') {
                return 1;  // 可能包含 <script> XSS 攻击
            }
        }
    }
    
    // 检测可疑的源 IP（私有地址作为源地址的外部通信）
    __u32 src_ip = evt->src_ip;
    __u8 first_octet = src_ip & 0xFF;
    
    // 检测来自 0.0.0.0 的流量
    if (src_ip == 0) {
        return 1;
    }
    
    return 0;
}

// 主钩子函数 - 网络过滤器
int ids_filter(struct __sk_buff *skb) {
    struct packet_event evt = {};
    
    // 解析数据包
    if (parse_packet(skb, &evt) < 0) {
        return 0;
    }
    
    // 规则匹配
    if (match_rules(&evt) > 0) {
        events.perf_submit(skb, &evt, sizeof(evt));
    }
    
    // 协议分析
    analyze_protocol(&evt);
    
    // 异常检测
    detect_anomaly(&evt);
    
    return 0;
}
