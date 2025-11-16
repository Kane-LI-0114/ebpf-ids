#!/usr/bin/env python3
from bcc import BPF
from datetime import datetime
import socket
import struct

# eBPF program using Socket Filter (compatible with virtio_net)
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct scan_event_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_HASH(syn_tracker, u32, u64);
BPF_PERF_OUTPUT(scan_alerts);

int detect_port_scan(struct __sk_buff *skb) {
    u8 *cursor = 0;
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (ethernet->type != ETH_P_IP)
        return 0;
    
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->nextp != IPPROTO_TCP)
        return 0;
    
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
    
    // Detect SYN scans (SYN flag set, ACK flag not set)
    if (tcp->flag_syn == 1 && tcp->flag_ack == 0) {
        u32 src_ip = ip->src;
        u64 *scan_count = syn_tracker.lookup(&src_ip);
        u64 count = 1;
        
        if (scan_count) {
            count = *scan_count + 1;
        }
        syn_tracker.update(&src_ip, &count);
        
        // Alert after 15 SYN packets from same source
        if (count > 15) {
            struct scan_event_t alert = {};
            alert.saddr = ip->src;
            alert.daddr = ip->dst;
            alert.sport = tcp->src_port;
            alert.dport = tcp->dst_port;
            
            scan_alerts.perf_submit(skb, &alert, sizeof(alert));
        }
    }
    
    return 0;
}
"""

def handle_alert(cpu, data, size):
    event = b["scan_alerts"].event(data)
    src = socket.inet_ntoa(struct.pack("I", event.saddr))
    dst = socket.inet_ntoa(struct.pack("I", event.daddr))
    
    print(f"\n{'*'*70}")
    print(f"[INTRUSION ALERT] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'*'*70}")
    print(f"⚠️  Suspicious Port Scan Detected!")
    print(f"Attacker IP:  {src}:{event.sport}")
    print(f"Target IP:    {dst}:{event.dport}")
    print(f"Scan Type:    SYN Scan (Stealth)")
    print(f"{'*'*70}\n")

print("[*] Initializing eBPF Port Scan Detection System...")
print("[*] Mode: Socket Filter (compatible with Google Cloud VMs)")

# Suppress compiler warnings
cflags = ["-Wno-macro-redefined"]
b = BPF(text=bpf_text, cflags=cflags)

# Google Cloud VM interface
interface = "ens4"

print(f"[*] Attaching eBPF program to interface: {interface}")
function_name = b.load_func("detect_port_scan", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_name, interface)

print("[✓] eBPF Program Successfully Deployed!")
print("[✓] Detection System Active and Monitoring")
print(f"[*] Monitoring interface {interface} for port scans...")
print("[*] Threshold: Alert after 15+ SYN packets from same source")
print("[*] Press Ctrl+C to terminate\n")

b["scan_alerts"].open_perf_buffer(handle_alert)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[*] Shutting down detection system...")
    print("[✓] eBPF program detached successfully")
    print("[✓] Monitoring terminated")
