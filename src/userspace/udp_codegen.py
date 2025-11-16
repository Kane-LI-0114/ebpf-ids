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

BPF_PERF_OUTPUT(alerts);  // Changed from alert_events to alerts
"""
    def _generate_data_structures(self) -> str:
        """Generate BPF maps for rule storage"""
        return f"""// UDP Rule count: {self.rule_count}
// Rules are compiled into the checker function"""

    
    def _generate_helper_functions(self) -> str:
     """Generate helper functions for packet parsing and matching"""
     return """// Helper: Send alert  
static __always_inline void send_alert(void *ctx, u32 sid,
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
    
    alerts.perf_submit(ctx, &alert, sizeof(alert));  // Changed from alert_events
}"""

    def _generate_rule_checker(self) -> str:
       """Generate the main rule checking logic"""
       code = ["// UDP Rule Checker",
            "static __always_inline int check_udp_rules(void *ctx,",
            "                                            u32 src_ip, u32 dst_ip,",
            "                                            u16 src_port, u16 dst_port,",
            "                                            void *payload, void *data_end) {",
            "    int matched = 0;",
            ""]
    
    # Generate rule checks for each UDP rule
       for i, rule in enumerate(self.rules):
         sid = rule.get("sid", 0)
         msg = rule.get("msg", "Unknown").replace('"', '\\"')  # Escape quotes
         priority = rule.get("priority", 3)
        
        # Parse destination port
         dst_port = rule.get("dst_port")
         if dst_port and isinstance(dst_port, dict):
             port_num = dst_port.get("port", 0)
             port_type = dst_port.get("type", "any")
            
             if port_type == "single" and port_num:
                 code.append(f"    // Rule {sid}: {msg}")
                 code.append(f"    if (dst_port == {port_num}) {{")
                 code.append(f"        send_alert(ctx, {sid}, {priority}, src_ip, dst_ip, src_port, dst_port, \"{msg}\");")
                 code.append(f"        matched++;")
                 code.append(f"    }}")
                 code.append("")
        
        # Parse source port
         src_port_rule = rule.get("src_port")
         if src_port_rule and isinstance(src_port_rule, dict):
             port_num = src_port_rule.get("port", 0)
             port_type = src_port_rule.get("type", "any")
            
             if port_type == "single" and port_num:
                 code.append(f"    // Rule {sid}: {msg}")
                 code.append(f"    if (src_port == {port_num}) {{")
                 code.append(f"        send_alert(ctx, {sid}, {priority}, src_ip, dst_ip, src_port, dst_port, \"{msg}\");")
                 code.append(f"        matched++;")
                 code.append(f"    }}")
                 code.append("")
    
    # Close the function
       code.append("    return matched;")
       code.append("}")
    
       return "\n".join(code)


    def _generate_main_function(self) -> str:
      """Generate the main BPF filter function"""
      return """// Main UDP IDS filter function (Socket Filter mode)
int ids_filter(struct __sk_buff *skb) {
    // Socket filters cannot directly access skb->data/data_end
    // We need to use BPF helper functions instead
    
    // Get protocol from IP header at offset 14 + 9
    u8 protocol = load_byte(skb, 14 + 9);
    if (protocol != IPPROTO_UDP) {
        return 0;
    }
    
    // Extract source and destination IPs (offset 14 + 12 and 14 + 16)
    u32 src_ip = load_word(skb, 14 + 12);
    u32 dst_ip = load_word(skb, 14 + 16);
    
    // Get IP header length to calculate UDP header position
    u8 ihl = (load_byte(skb, 14) & 0x0F) * 4;
    
    // Extract UDP ports (after IP header)
    u16 src_port = load_half(skb, 14 + ihl);
    u16 dst_port = load_half(skb, 14 + ihl + 2);
    
    src_port = bpf_ntohs(src_port);
    dst_port = bpf_ntohs(dst_port);
    
    // Check against UDP rules (no direct payload access)
    check_udp_rules(skb, src_ip, dst_ip, src_port, dst_port, 0, 0);
    
    return 0;
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
