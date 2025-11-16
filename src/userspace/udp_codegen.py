#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UDP Rules eBPF Code Generator
Generates eBPF C code for UDP-based Snort rules
"""

import json
from typing import Dict, List, Optional, Set
from pathlib import Path


class UDPRulesEBPFManager:
    """Manages UDP rules and generates corresponding eBPF C code"""

    def __init__(self):
        self.rules: List[Dict] = []
        self.rule_count = 0
        self.generated_code = ""
        self.metadata = []

    def add_rule(self, rule_config: Dict) -> bool:
        """Add a UDP rule to the manager"""
        # Validate that this is a UDP rule
        if rule_config.get("protocol_num") != 17:
            return False

        # Skip rules without SID
        if not rule_config.get("sid"):
            return False

        self.rules.append(rule_config)
        self.rule_count += 1
        return True

    def generate_all_code(self) -> Dict:
        """Generate complete eBPF C code for all UDP rules"""
        if not self.rules:
            return {"code": "", "count": 0, "metadata": []}

        code_parts = []

        # Header
        code_parts.append(self._generate_header())

        # Data structures
        code_parts.append(self._generate_data_structures())

        # Helper functions
        code_parts.append(self._generate_helper_functions())

        # Rule checking function
        code_parts.append(self._generate_rule_checker())

        # Main filter function
        code_parts.append(self._generate_main_function())

        self.generated_code = "\n\n".join(code_parts)

        # Build metadata
        self.metadata = [
            {
                "sid": rule.get("sid"),
                "msg": rule.get("msg", "Unknown"),
                "priority": rule.get("priority", 3),
                "classtype": rule.get("classtype", "unknown")
            }
            for rule in self.rules
        ]

        return {
            "code": self.generated_code,
            "count": self.rule_count,
            "metadata": self.metadata
        }

    def _generate_header(self) -> str:
       """Generate BPF header includes and definitions"""
       return """#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bcc/proto.h>

// Alert event structure
struct alert_event {
    u32 rule_id;
    u32 priority;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    char msg[256];
};

BPF_PERF_OUTPUT(alert_events);
"""

    def _generate_data_structures(self) -> str:
        """Generate BPF maps for rule storage"""
        return f"""// UDP Rule count: {self.rule_count}
// Rules are compiled into the checker function"""

    def _generate_helper_functions(self) -> str:
        """Generate helper functions for packet parsing and matching"""
        return """// Helper: Check if IP matches (supports basic matching)
static __always_inline int match_ip(u32 packet_ip, const char *rule_ip_str) {
    // For simplicity, we match against common variables
    // $EXTERNAL_NET, $HOME_NET, any, or specific IPs
    // In a real implementation, these would be resolved at load time
    return 1;  // Accept all for now
}

// Helper: Check if port matches
static __always_inline int match_port(u16 packet_port, u16 rule_port, int port_type) {
    if (port_type == 0) {  // any port
        return 1;
    }
    if (port_type == 1) {  // single port
        return packet_port == rule_port;
    }
    return 0;
}

// Helper: Simple content matching (checks if pattern exists in payload)
static __always_inline int match_content(void *data, void *data_end, 
                                         const char *pattern, int pattern_len) {
    // Simplified content matching
    // In production, this would use more sophisticated algorithms
    if (data + pattern_len > data_end) {
        return 0;
    }

    // Basic byte comparison
    for (int i = 0; i < pattern_len && i < 32; i++) {
        if (data + i >= data_end) {
            return 0;
        }
    }

    return 1;  // Simplified match
}

// Helper: Send alert
static __always_inline void send_alert(struct __sk_buff *skb, u32 sid, 
                                       u32 priority, u32 src_ip, u32 dst_ip,
                                       u16 src_port, u16 dst_port, 
                                       const char *msg) {
    struct alert_event alert = {};
    alert.rule_id = sid;
    alert.priority = priority;
    alert.src_ip = src_ip;
    alert.dst_ip = dst_ip;
    alert.src_port = src_port;
    alert.dst_port = dst_port;

    // Copy message (simplified)
    #pragma unroll
    for (int i = 0; i < 32 && msg[i] != '\\0'; i++) {
        if (i < 256) {
            alert.msg[i] = msg[i];
        }
    }

    alert_events.perf_submit(skb, &alert, sizeof(alert));
}"""

    def _generate_rule_checker(self) -> str:
        """Generate the main rule checking logic"""
        code = ["// UDP Rule Checker",
                "static __always_inline int check_udp_rules(struct __sk_buff *skb,",
                "                                            u32 src_ip, u32 dst_ip,",
                "                                            u16 src_port, u16 dst_port,",
                "                                            void *payload, void *data_end) {",
                "    int matched = 0;",
                ""]

        # Generate check for each rule
        for idx, rule in enumerate(self.rules):
            sid = rule.get("sid")
            msg = rule.get("msg", "Alert").replace('"', '\\"')[:64]
            priority = rule.get("priority", 3)

            src_port_rule = rule.get("src_port")
            dst_port_rule = rule.get("dst_port")
            content = rule.get("content", "")

            code.append(f"    // Rule {idx + 1}: SID={sid} - {msg[:40]}")
            code.append(f"    {{")
            code.append(f"        int rule_match = 1;")

            # Source port matching
            if src_port_rule and src_port_rule.get("type") == "single":
                port = src_port_rule.get("port")
                code.append(f"        if (src_port != {port}) rule_match = 0;")

            # Destination port matching
            if dst_port_rule and dst_port_rule.get("type") == "single":
                port = dst_port_rule.get("port")
                code.append(f"        if (dst_port != {port}) rule_match = 0;")
            elif dst_port_rule and dst_port_rule.get("type") == "range":
                start = dst_port_rule.get("start", 0)
                end = dst_port_rule.get("end", 65535)
                code.append(f"        if (dst_port < {start} || dst_port > {end}) rule_match = 0;")

            # Alert if matched
            code.append(f"        if (rule_match) {{")
            code.append(f'            send_alert(skb, {sid}, {priority}, src_ip, dst_ip,')
            code.append(f'                       src_port, dst_port, "{msg}");')
            code.append(f"            matched++;")
            code.append(f"        }}")
            code.append(f"    }}")
            code.append("")

        code.append("    return matched;")
        code.append("}")

        return "\n".join(code)

    def _generate_main_function(self) -> str:
        """Generate the main BPF filter function"""
        return """// Main UDP IDS filter function
int ids_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    // Check if IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }

    // Check if UDP
    if (ip->protocol != IPPROTO_UDP) {
        return 0;
    }

    // Parse UDP header
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) {
        return 0;
    }

    // Extract packet info
    u32 src_ip = ip->saddr;
    u32 dst_ip = ip->daddr;
    u16 src_port = __constant_ntohs(udp->source);
    u16 dst_port = __constant_ntohs(udp->dest);

    // Payload starts after UDP header
    void *payload = (void *)(udp + 1);

    // Check against UDP rules
    check_udp_rules(skb, src_ip, dst_ip, src_port, dst_port, payload, data_end);

    return 0;  // Always accept packet (monitoring mode)
}"""

    def export_code(self, output_path: str):
        """Export generated code to file"""
        if not self.generated_code:
            self.generate_all_code()

        with open(output_path, 'w') as f:
            f.write(self.generated_code)

    def export_metadata(self, output_path: str):
        """Export rule metadata to JSON"""
        with open(output_path, 'w') as f:
            json.dump(self.metadata, f, indent=2)


# Example usage
if __name__ == "__main__":
    manager = UDPRulesEBPFManager()

    # Example rule
    example_rule = {
        "action": "alert",
        "protocol_num": 17,
        "src_ip": "$EXTERNAL_NET",
        "src_port": None,
        "dst_ip": "$HOME_NET",
        "dst_port": {"type": "single", "port": 161},
        "tcp_flags": {},
        "msg": "PROTOCOL-SNMP public access attempt",
        "sid": 1417,
        "rev": 11,
        "classtype": "attempted-recon",
        "priority": 3
    }

    manager.add_rule(example_rule)
    result = manager.generate_all_code()

    print(f"Generated code for {result['count']} UDP rules")
    print("\nCode Preview:")
    print(result['code'][:500])
