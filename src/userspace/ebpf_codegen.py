#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF Code Generator for Snort TCP Rules
Converts parsed Snort rules to eBPF C code segments
"""

import json
import ipaddress
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class PortSpec:
    """Represents a port specification"""
    port_type: str  # 'single', 'range', 'list', 'any', 'variable'
    port: Optional[int] = None
    start: Optional[int] = None
    end: Optional[int] = None
    ports: Optional[List[int]] = None
    variable_name: Optional[str] = None


class TCPRuleEBPFCodegen:
    """
    Generates eBPF C code segments from parsed TCP Snort rules
    
    Generates optimized packet filtering code that can be loaded into the kernel
    via BCC (BPF Compiler Collection)
    """
    
    def __init__(self, rule_config: Dict[str, Any]):
        """
        Initialize the code generator with a parsed rule configuration
        
        Args:
            rule_config: Dict containing parsed rule from parser.py output
                        Must have protocol_num == 6 (TCP)
        """
        if rule_config.get("protocol_num") != 6:
            raise ValueError(f"Only TCP rules supported (protocol_num=6), got {rule_config.get('protocol_num')}")
        
        self.rule = rule_config
        self.sid = rule_config.get("sid", 0)
        self.msg = rule_config.get("msg", "Unknown rule")
        self.action = rule_config.get("action", "alert")
        self.priority = rule_config.get("priority", 3)
        self.classtype = rule_config.get("classtype", "unknown")
        
    def generate_ebpf_code(self) -> str:
        """
        Generate complete eBPF C code segment for this rule
        
        Returns:
            String containing eBPF C code ready for compilation
        """
        code_parts = []
        
        # Header comments
        code_parts.append(self._generate_header_comment())
        
        # Define check function
        code_parts.append(self._generate_check_function())
        
        # Alert function
        code_parts.append(self._generate_alert_function())
        
        return "\n".join(code_parts)
    
    def _generate_header_comment(self) -> str:
        """Generate comment header with rule information"""
        comment = f"""
// eBPF Rule Implementation: SID {self.sid}
// Rule Name: {self.msg}
// Protocol: TCP (6)
// Action: {self.action.upper()}
// Priority: {self.priority}
// Classification: {self.classtype}
// Generated from Snort rule parser output
"""
        return comment
    
    def _generate_check_function(self) -> str:
        """Generate the main packet checking function"""
        func_name = f"check_rule_{self.sid}"
        
        code_parts = [
            f"// Check function for rule {self.sid}",
            f"static inline int {func_name}(struct __sk_buff *skb, void *data, void *data_end) {{",
            "    // Parse Ethernet header",
            "    struct ethhdr *eth = data;",
            "    if ((void *)(eth + 1) > data_end)",
            "        return 0;",
            "",
            "    // Parse IP header",
            "    struct iphdr *iph = (struct iphdr *)(eth + 1);",
            "    if ((void *)(iph + 1) > data_end)",
            "        return 0;",
            "",
            "    // Verify TCP protocol",
            "    if (iph->protocol != IPPROTO_TCP)",
            "        return 0;",
            "",
            "    // Parse TCP header",
            "    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);",
            "    if ((void *)(tcph + 1) > data_end)",
            "        return 0;",
            ""
        ]
        
        # Generate protocol-specific checks
        code_parts.append(self._generate_protocol_checks(func_name))
        
        # Generate port checks
        code_parts.append(self._generate_port_checks())
        
        # Generate TCP flags checks if present
        if self.rule.get("tcp_flags"):
            code_parts.append(self._generate_flags_checks())
        
        # Generate content matching if present
        if self.rule.get("content"):
            code_parts.append(self._generate_content_checks())
        
        # Return success if all checks pass
        code_parts.append("    return 1;  // All checks passed")
        code_parts.append("}")
        
        return "\n".join(code_parts)
    
    def _generate_protocol_checks(self, func_name: str) -> str:
        """Generate IP/port validation checks"""
        checks = []
        
        # Check source IP if specified
        src_ip = self.rule.get("src_ip")
        if src_ip and src_ip != "any":
            checks.append(self._generate_ip_check("source", "iph->saddr", src_ip))
        
        # Check destination IP if specified
        dst_ip = self.rule.get("dst_ip")
        if dst_ip and dst_ip != "any":
            checks.append(self._generate_ip_check("destination", "iph->daddr", dst_ip))
        
        return "\n".join(checks)
    
    def _generate_ip_check(self, direction: str, ip_var: str, ip_spec: str) -> str:
        """Generate IP address checking code"""
        if ip_spec.startswith("$"):
            # Variable reference - would need to be resolved at runtime
            return f"    // Variable IP check: {ip_spec} ({direction})"
        
        try:
            network = ipaddress.ip_network(ip_spec, strict=False)
            ip_int = int(network.network_address)
            mask_int = int(network.netmask)
            
            code = f"""    // Check {direction} IP: {ip_spec}
    __u32 {direction}_net = htonl(0x{ip_int:08x});
    __u32 {direction}_mask = htonl(0x{mask_int:08x});
    if (({ip_var} & {direction}_mask) != ({direction}_net & {direction}_mask))
        return 0;"""
            return code
        except:
            return f"    // Unable to parse IP: {ip_spec}"
    
    def _generate_port_checks(self) -> str:
        """Generate port matching checks"""
        checks = []
        
        # Check source port
        src_port = self.rule.get("src_port")
        if src_port:
            checks.append(self._generate_port_check("src", "tcph->source", src_port))
        
        # Check destination port
        dst_port = self.rule.get("dst_port")
        if dst_port:
            checks.append(self._generate_port_check("dst", "tcph->dest", dst_port))
        
        return "\n".join(checks)
    
    def _generate_port_check(self, direction: str, port_var: str, port_spec: Dict[str, Any]) -> str:
        """Generate port matching code"""
        port_type = port_spec.get("type")
        
        if port_type == "single":
            port = port_spec.get("port")
            return f"""    // Check {direction} port: {port}
    if ({port_var} != htons({port}))
        return 0;"""
        
        elif port_type == "range":
            start = port_spec.get("start", 0)
            end = port_spec.get("end", 65535)
            return f"""    // Check {direction} port range: {start}-{end}
    __u16 {direction}_port = ntohs({port_var});
    if ({direction}_port < {start} || {direction}_port > {end})
        return 0;"""
        
        elif port_type == "list":
            ports = port_spec.get("ports", [])
            port_checks = [f"ntohs({port_var}) != {p}" for p in ports]
            condition = " && ".join(port_checks)
            return f"""    // Check {direction} port list: {ports}
    if ({condition})
        return 0;"""
        
        elif port_type == "variable":
            var_name = port_spec.get("name", "UNKNOWN")
            return f"""    // Variable port check: {var_name} ({direction})
    // Port variables need runtime resolution"""
        
        return f"    // Unknown port type: {port_type}"
    
    def _generate_flags_checks(self) -> str:
        """Generate TCP flags matching code"""
        flags = self.rule.get("tcp_flags", {})
        if not flags:
            return ""
        
        checks = ["    // Check TCP flags"]
        
        flag_byte_checks = []
        if flags.get("SYN"):
            flag_byte_checks.append("(tcph->syn == 1)")
        if flags.get("ACK"):
            flag_byte_checks.append("(tcph->ack == 1)")
        if flags.get("FIN"):
            flag_byte_checks.append("(tcph->fin == 1)")
        if flags.get("RST"):
            flag_byte_checks.append("(tcph->rst == 1)")
        if flags.get("PSH"):
            flag_byte_checks.append("(tcph->psh == 1)")
        if flags.get("URG"):
            flag_byte_checks.append("(tcph->urg == 1)")
        
        if flag_byte_checks:
            flag_condition = " && ".join(flag_byte_checks)
            checks.append(f"    if (!({flag_condition}))")
            checks.append("        return 0;")
        
        return "\n".join(checks)
    
    def _generate_content_checks(self) -> str:
        """Generate content/payload matching code"""
        content = self.rule.get("content")
        if not content:
            return ""
        
        # Note: This is a simplified version. Full content matching would require
        # more complex pattern matching logic
        checks = [
            "    // Content matching (simplified)",
            f"    // Full pattern: {content}",
            "    // Note: Complex content matching requires BPF string matching library"
        ]
        
        return "\n".join(checks)
    
    def _generate_alert_function(self) -> str:
        """Generate the alert reporting function"""
        code = f"""
// Alert function for rule {self.sid}
static inline void alert_rule_{self.sid}(struct __sk_buff *skb, 
                                          __u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port) {{
    // Create alert event
    struct alert_event {{
        __u32 rule_id;
        __u32 priority;
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
        char msg[256];
    }} alert = {{}};
    
    alert.rule_id = {self.sid};
    alert.priority = {self.priority};
    alert.src_ip = src_ip;
    alert.dst_ip = dst_ip;
    alert.src_port = src_port;
    alert.dst_port = dst_port;
    
    // Copy alert message (limited to 255 chars in eBPF)
    __builtin_memcpy(&alert.msg, "{self.msg[:255]}", 
                     sizeof("{self.msg[:255]}"));
    
    // Submit alert to userspace via perf buffer
    // events.perf_submit(ctx, &alert, sizeof(alert));
}}
"""
        return code
    
    def get_rule_metadata(self) -> Dict[str, Any]:
        """Get rule metadata for management and logging"""
        return {
            "sid": self.sid,
            "msg": self.msg,
            "action": self.action,
            "priority": self.priority,
            "classtype": self.classtype,
            "protocol_num": 6,
            "src_ip": self.rule.get("src_ip"),
            "src_port": self.rule.get("src_port"),
            "dst_ip": self.rule.get("dst_ip"),
            "dst_port": self.rule.get("dst_port"),
            "tcp_flags": self.rule.get("tcp_flags", {}),
            "content": self.rule.get("content"),
            "flow": self.rule.get("flow")
        }


class TCPRulesEBPFManager:
    """
    Manager class for handling multiple TCP rules
    Aggregates code generation and provides integration with ids_manager
    """
    
    def __init__(self):
        """Initialize the manager"""
        self.generators = []
        self.generated_code = []
        self.rule_metadata = []
    
    def add_rule(self, rule_config: Dict[str, Any]) -> bool:
        """
        Add a TCP rule for code generation
        
        Args:
            rule_config: Parsed rule configuration (protocol_num must be 6)
            
        Returns:
            True if rule was added successfully, False otherwise
        """
        try:
            if rule_config.get("protocol_num") != 6:
                return False
            
            generator = TCPRuleEBPFCodegen(rule_config)
            self.generators.append(generator)
            return True
        except Exception as e:
            print(f"Error adding rule: {e}")
            return False
    
    def generate_all_code(self) -> Dict[str, Any]:
        """
        Generate eBPF C code for all added rules
        
        Returns:
            Dict containing:
                - "code": Complete eBPF C code segments
                - "metadata": List of rule metadata
                - "count": Number of rules processed
        """
        self.generated_code = []
        self.rule_metadata = []
        
        for generator in self.generators:
            try:
                code = generator.generate_ebpf_code()
                self.generated_code.append(code)
                self.rule_metadata.append(generator.get_rule_metadata())
            except Exception as e:
                print(f"Error generating code for rule {generator.sid}: {e}")
        
        return {
            "code": "\n".join(self.generated_code),
            "metadata": self.rule_metadata,
            "count": len(self.generated_code)
        }
    
    def export_code(self, output_file: str):
        """
        Export generated code to a file
        
        Args:
            output_file: Path to output C source file
        """
        if not self.generated_code:
            self.generate_all_code()
        
        with open(output_file, 'w') as f:
            f.write("// Auto-generated eBPF code for TCP rule detection\n")
            f.write("// Generated from Snort rules\n\n")
            f.write("#include <uapi/linux/ptrace.h>\n")
            f.write("#include <net/sock.h>\n")
            f.write("#include <bcc/proto.h>\n\n")
            f.write("".join(self.generated_code))
    
    def export_metadata(self, output_file: str):
        """
        Export rule metadata to JSON
        
        Args:
            output_file: Path to output JSON file
        """
        if not self.rule_metadata:
            self.generate_all_code()
        
        with open(output_file, 'w') as f:
            json.dump(self.rule_metadata, f, indent=2)


# Example usage and integration with ids_manager
if __name__ == "__main__":
    # Load sample rules from the parsed JSON
    with open("snort_rules_ebpf.json", "r") as f:
        all_rules = json.load(f)
    
    # Filter TCP rules only
    tcp_rules = [r for r in all_rules if r.get("protocol_num") == 6]
    
    print(f"Total rules: {len(all_rules)}")
    print(f"TCP rules: {len(tcp_rules)}")
    
    # Create manager and add first 5 TCP rules as example
    manager = TCPRulesEBPFManager()
    
    for rule in tcp_rules[:5]:
        if manager.add_rule(rule):
            print(f"Added rule SID {rule.get('sid')}")
    
    # Generate code
    result = manager.generate_all_code()
    
    print(f"\nGenerated code for {result['count']} rules")
    
    # Export results
    manager.export_code("generated_tcp_rules.c")
    manager.export_metadata("generated_tcp_rules_metadata.json")
    
    print("Generated files:")
    print("  - generated_tcp_rules.c")
    print("  - generated_tcp_rules_metadata.json")
