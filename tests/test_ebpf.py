#!/usr/bin/env python3
from bcc import BPF
from datetime import datetime
import socket
import struct

# eBPF program code
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Structure to store scan events
struct scan_event_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 flags;
};

// Hash map to count SYN packets per source IP
BPF_HASH(syn_count, u32, u64);

// Perf event array to send alerts to userspace
BPF_PERF_OUTPUT(events);

// XDP program to detect port scans
int detect_scan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check if IP packet
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Check if TCP packet
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    // Detect SYN scan (SYN flag set, ACK flag not set)
    if (tcp->syn && !tcp->ack) {
        u32 saddr = ip->saddr;
        u64 *count = syn_count.lookup(&saddr);
        u64 new_count = 1;
        
        if (count) {
            new_count = *count + 1;
        }
        
        syn_count.update(&saddr, &new_count);
        
        // Alert if more than 10 SYN packets from same source
        if (new_count > 10) {
            struct scan_event_t evt = {};
            evt.saddr = ip->saddr;
            evt.daddr = ip->daddr;
            evt.sport = ntohs(tcp->source);
            evt.dport = ntohs(tcp->dest);
            evt.flags = ((u8 *)tcp)[13];
            
            events.perf_submit(ctx, &evt, sizeof(evt));
        }
    }
    
    return XDP_PASS;
}
"""

# Callback function to handle events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    # Convert IP addresses to readable format
    src_ip = socket.inet_ntoa(struct.pack("I", event.saddr))
    dst_ip = socket.inet_ntoa(struct.pack("I", event.daddr))
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    print(f"\n{'='*70}")
    print(f"[ALERT] Port Scan Detected at {timestamp}")
    print(f"{'='*70}")
    print(f"Source IP:      {src_ip}")
    print(f"Source Port:    {event.sport}")
    print(f"Target IP:      {dst_ip}")
    print(f"Target Port:    {event.dport}")
    print(f"TCP Flags:      0x{event.flags:02x}")
    print(f"{'='*70}\n")

# Load BPF program
print("[*] Loading eBPF program...")
b = BPF(text=bpf_text)

# Get network interface (modify as needed)
interface = "eth0"  # Change to your interface name (use 'ip link show' to find it)

print(f"[*] Attaching eBPF program to interface: {interface}")
fn = b.load_func("detect_scan", BPF.XDP)
b.attach_xdp(interface, fn, 0)

print("[✓] eBPF program successfully deployed!")
print(f"[*] Monitoring interface {interface} for port scans...")
print("[*] Press Ctrl+C to stop\n")

# Open perf buffer
b["events"].open_perf_buffer(print_event)

# Poll for events
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[*] Detaching eBPF program...")

# Cleanup
b.remove_xdp(interface, 0)
print("[✓] eBPF program detached successfully")
