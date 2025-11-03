import json
import os
from pathlib import Path

class SnortToEBPFGenerator:
    """
    Converts parsed Snort rules into eBPF C code fragments for packet matching.
    Handles protocol matching, IP filtering, port checks, TCP flags, and content patterns.
    """
    
    def __init__(self):
        self.protocol_map = {
            1: "IPPROTO_ICMP",
            6: "IPPROTO_TCP",
            17: "IPPROTO_UDP",
            0: "IPPROTO_IP"
        }
    
    def generate_ebpf_header(self):
        """Generate eBPF program header with includes and structures"""
        return '''#include <linux/bpf.h>
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

'''
    
    def generate_protocol_check(self, rule):
        """Generate protocol matching code"""
        protocol_num = rule.get('protocol_num', 0)
        protocol_name = self.protocol_map.get(protocol_num, f"{protocol_num}")
        
        if protocol_num == 0:
            return "    // Match all protocols\n"
        
        return f'''    // Check protocol: {protocol_name}
    if (iph->protocol != {protocol_name}) {{
        return 0;  // Protocol mismatch
    }}
    
'''
    
    def generate_ip_check(self, rule):
        """Generate IP address matching code"""
        code = ""
        src_ip = rule.get('src_ip')
        dst_ip = rule.get('dst_ip')
        
        # Source IP check
        if src_ip and src_ip not in ['any', '$HOME_NET', '$EXTERNAL_NET', None]:
            if '/' in src_ip:
                ip, mask = src_ip.split('/')
                code += f'''    // Check source IP CIDR: {src_ip}
    __u32 src_ip = bpf_ntohl(iph->saddr);
    __u32 network = /* Convert {ip} to __u32 */;
    __u32 netmask = (~0U) << (32 - {mask});
    if ((src_ip & netmask) != (network & netmask)) {{
        return 0;
    }}
    
'''
            else:
                code += f'''    // Check source IP: {src_ip}
    __u32 src_addr = bpf_ntohl(iph->saddr);
    __u32 expected_src = /* Convert {src_ip} to __u32 */;
    if (src_addr != expected_src) {{
        return 0;
    }}
    
'''
        
        # Destination IP check
        if dst_ip and dst_ip not in ['any', '$HOME_NET', '$EXTERNAL_NET', None]:
            if '/' in dst_ip:
                ip, mask = dst_ip.split('/')
                code += f'''    // Check destination IP CIDR: {dst_ip}
    __u32 dst_ip = bpf_ntohl(iph->daddr);
    __u32 dst_network = /* Convert {ip} to __u32 */;
    __u32 dst_netmask = (~0U) << (32 - {mask});
    if ((dst_ip & dst_netmask) != (dst_network & dst_netmask)) {{
        return 0;
    }}
    
'''
            else:
                code += f'''    // Check destination IP: {dst_ip}
    __u32 dst_addr = bpf_ntohl(iph->daddr);
    __u32 expected_dst = /* Convert {dst_ip} to __u32 */;
    if (dst_addr != expected_dst) {{
        return 0;
    }}
    
'''
        
        return code
    
    def generate_port_check(self, rule):
        """Generate port matching code for TCP/UDP"""
        code = ""
        protocol_num = rule.get('protocol_num', 0)
        
        if protocol_num not in [6, 17]:  # TCP or UDP
            return code
        
        src_port = rule.get('src_port')
        dst_port = rule.get('dst_port')
        
        port_var = "tcph" if protocol_num == 6 else "udph"
        
        # Source port check
        if src_port:
            port_type = src_port.get('type')
            if port_type == 'single':
                port = src_port.get('port')
                code += f'''    // Check source port: {port}
    if (bpf_ntohs({port_var}->source) != {port}) {{
        return 0;
    }}
    
'''
            elif port_type == 'range':
                start = src_port.get('start')
                end = src_port.get('end')
                code += f'''    // Check source port range: {start}-{end}
    __u16 sport = bpf_ntohs({port_var}->source);
    if (sport < {start} || sport > {end}) {{
        return 0;
    }}
    
'''
            elif port_type == 'list':
                ports = src_port.get('ports', [])
                if ports:
                    ports_str = ' || '.join([f"sport == {p}" for p in ports[:10]])
                    code += f'''    // Check source port in list
    __u16 sport = bpf_ntohs({port_var}->source);
    if (!({ports_str})) {{
        return 0;
    }}
    
'''
        
        # Destination port check
        if dst_port:
            port_type = dst_port.get('type')
            if port_type == 'single':
                port = dst_port.get('port')
                code += f'''    // Check destination port: {port}
    if (bpf_ntohs({port_var}->dest) != {port}) {{
        return 0;
    }}
    
'''
            elif port_type == 'range':
                start = dst_port.get('start')
                end = dst_port.get('end')
                code += f'''    // Check destination port range: {start}-{end}
    __u16 dport = bpf_ntohs({port_var}->dest);
    if (dport < {start} || dport > {end}) {{
        return 0;
    }}
    
'''
            elif port_type == 'list':
                ports = dst_port.get('ports', [])
                if ports:
                    ports_str = ' || '.join([f"dport == {p}" for p in ports[:10]])
                    code += f'''    // Check destination port in list
    __u16 dport = bpf_ntohs({port_var}->dest);
    if (!({ports_str})) {{
        return 0;
    }}
    
'''
        
        return code
    
    def generate_tcp_flags_check(self, rule):
        """Generate TCP flags matching code"""
        tcp_flags = rule.get('tcp_flags', {})
        if not tcp_flags or rule.get('protocol_num') != 6:
            return ""
        
        code = "    // Check TCP flags\n"
        
        flags_to_check = []
        for flag_name, flag_value in tcp_flags.items():
            if flag_value:
                flag_lower = flag_name.lower()
                flags_to_check.append((flag_name, flag_lower))
        
        if flags_to_check:
            for flag_name, flag_lower in flags_to_check:
                code += f"    if (!tcph->{flag_lower}) {{  // {flag_name} must be set\n"
                code += "        return 0;\n"
                code += "    }\n"
            code += "\n"
        
        return code
    
    def generate_content_check(self, rule):
        """Generate payload content matching code"""
        content = rule.get('content')
        if not content:
            return ""
        
        protocol_num = rule.get('protocol_num', 0)
        
        code = "    // Payload content matching\n"
        
        if protocol_num == 6:
            code += "    void *payload = (void *)tcph + (tcph->doff * 4);\n"
        elif protocol_num == 17:
            code += "    void *payload = (void *)udph + sizeof(*udph);\n"
        else:
            code += "    void *payload = (void *)iph + (iph->ihl * 4);\n"
        
        if isinstance(content, str):
            # Single content pattern
            pattern_preview = content[:40].replace('\n', ' ')
            code += f'''    // Match pattern: "{pattern_preview}..."
    // TODO: Implement pattern matching for this content
    if (!check_bound(payload, data_end, 64)) {{
        return 0;
    }}
    
'''
        elif isinstance(content, list):
            # Multiple content patterns
            code += f"    // Multiple content patterns ({len(content)} total)\n"
            for idx, pattern in enumerate(content[:3]):  # Show first 3
                pattern_preview = str(pattern)[:40].replace('\n', ' ')
                code += f"    // Pattern {idx+1}: \"{pattern_preview}...\"\n"
            code += "\n"
        
        return code
    
    def generate_flow_check(self, rule):
        """Generate flow direction check"""
        flow = rule.get('flow')
        if not flow:
            return ""
        
        code = f"    // Flow direction: {flow}\n"
        code += "    // TODO: Implement connection tracking for flow state\n\n"
        return code
    
    def generate_rule_function(self, rule, index):
        """Generate a complete eBPF function for a single rule"""
        sid = rule.get('sid', index)
        msg = rule.get('msg', 'Unknown rule')
        protocol_num = rule.get('protocol_num', 0)
        action = rule.get('action', 'alert')
        
        code = f'''/* ========================================
 * Rule {index}: SID {sid}
 * Action: {action}
 * Message: {msg}
 * Protocol: {self.protocol_map.get(protocol_num, str(protocol_num))}
 * ========================================*/
static __always_inline int check_rule_{sid}(struct iphdr *iph, void *data_end, void *data) {{
    
'''
        
        # Generate protocol check
        code += self.generate_protocol_check(rule)
        
        # Generate IP checks
        code += self.generate_ip_check(rule)
        
        # Generate transport layer parsing and checks
        if protocol_num == 6:  # TCP
            code += '''    // Parse TCP header
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(tcph, data_end, sizeof(*tcph))) {
        return 0;
    }
    
'''
            code += self.generate_port_check(rule)
            code += self.generate_tcp_flags_check(rule)
            
        elif protocol_num == 17:  # UDP
            code += '''    // Parse UDP header
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(udph, data_end, sizeof(*udph))) {
        return 0;
    }
    
'''
            code += self.generate_port_check(rule)
        
        elif protocol_num == 1:  # ICMP
            code += '''    // Parse ICMP header
    struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
    if (!check_bound(icmph, data_end, sizeof(*icmph))) {
        return 0;
    }
    
'''
        
        # Generate flow check
        code += self.generate_flow_check(rule)
        
        # Generate content check
        code += self.generate_content_check(rule)
        
        code += f'''    // Rule matched - update statistics
    __u32 key = {sid};
    __u64 *count = bpf_map_lookup_elem(&rule_stats, &key);
    if (count) {{
        __sync_fetch_and_add(count, 1);
    }} else {{
        __u64 init_val = 1;
        bpf_map_update_elem(&rule_stats, &key, &init_val, BPF_ANY);
    }}
    
    return 1;  // Rule matched
}}

'''
        
        return code
    
    def generate_main_xdp_program(self, rule_sids):
        """Generate the main XDP program that calls rule functions"""
        code = '''SEC("xdp")
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
'''
        
        # Add rule checks (limit to first 50 for practical purposes)
        for sid in rule_sids[:50]:
            code += f'''    if (check_rule_{sid}(iph, data_end, data)) {{
        // Action: DROP packet matching rule {sid}
        return XDP_DROP;
    }}
    
'''
        
        code += '''    // No rules matched - pass packet
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
'''
        
        return code
    
    def generate_complete_program(self, rules, max_rules=50):
        """Generate complete eBPF program with all rules"""
        output = []
        
        # Add header
        output.append(self.generate_ebpf_header())
        
        # Generate individual rule functions
        rule_sids = []
        for idx, rule in enumerate(rules[:max_rules]):
            sid = rule.get('sid', idx)
            rule_sids.append(sid)
            output.append(self.generate_rule_function(rule, idx))
        
        # Generate main XDP program
        output.append(self.generate_main_xdp_program(rule_sids))
        
        return ''.join(output)


def main():
    # Get the directory where this script is located
    script_dir = Path(__file__).parent.resolve()
    
    # Construct path to JSON file (assuming it's in the same directory)
    json_file = script_dir / 'snort_rules_ebpf.json'
    
    # Verify the file exists
    if not json_file.exists():
        print(f"❌ Error: File not found at: {json_file}")
        print(f"Script directory: {script_dir}")
        print(f"Current working directory: {os.getcwd()}")
        return
    
    print(f"✓ Loading rules from: {json_file}")
    
    # Load parsed Snort rules
    with open(json_file, 'r') as f:
        rules = json.load(f)
    
    print(f"✓ Loaded {len(rules):,} parsed Snort rules\n")
    
    # Initialize generator
    generator = SnortToEBPFGenerator()
    
    # Generate complete eBPF program
    ebpf_code = generator.generate_complete_program(rules, max_rules=10)
    
    # Save output to the same directory
    output_file = script_dir / 'snort_rules_filter.c'
    with open(output_file, 'w') as f:
        f.write(ebpf_code)
    
    print(f"✓ Generated eBPF C code with {min(10, len(rules))} rules")
    print(f"✓ Output saved to: {output_file}")
    
    # Print compilation instructions
    print(f"\n{'='*70}")
    print("COMPILATION AND DEPLOYMENT:")
    print(f"{'='*70}")
    print(f"\n# Navigate to output directory:")
    print(f"cd {script_dir}")
    print(f"\n# Compile to eBPF bytecode:")
    print("clang -O2 -target bpf -c snort_rules_filter.c -o snort_rules_filter.o")
    print(f"\n# Load into kernel (replace eth0 with your interface):")
    print("sudo ip link set dev eth0 xdp obj snort_rules_filter.o sec xdp_snort_filter")
    print(f"\n# View statistics:")
    print("sudo bpftool map dump name rule_stats")
    print(f"\n# Unload:")
    print("sudo ip link set dev eth0 xdp off")

if __name__ == "__main__":
    main()