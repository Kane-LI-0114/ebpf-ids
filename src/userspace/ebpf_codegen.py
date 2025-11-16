#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF Code Generator for Snort TCP Rules

Converts parsed Snort rules to eBPF C code segments.
"""

import json
import os
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
    """

    def __init__(self, rule_config: Dict[str, Any]):
        if rule_config.get("protocol_num") != 6:
            raise ValueError(
                f"Only TCP rules supported (protocol_num=6), "
                f"got {rule_config.get('protocol_num')}"
            )

        self.rule = rule_config
        self.sid = rule_config.get("sid", 0)
        self.msg = rule_config.get("msg", "Unknown rule")
        self.action = rule_config.get("action", "alert")
        self.priority = rule_config.get("priority", 3)
        self.classtype = rule_config.get("classtype", "unknown")

    def generate_ebpf_code(self) -> str:
        """Generate complete eBPF C code segment for this rule"""
        code_parts: List[str] = []

        # Comment header
        code_parts.append(self.generate_header_comment())

        # Define alert function BEFORE the check function so calls are not implicit
        code_parts.append(self.generate_alert_function())

        # Now emit the check function that calls alert_rule_<sid>
        code_parts.append(self.generate_check_function())

        return "\n".join(code_parts)

    def generate_header_comment(self) -> str:
        """Generate comment header with rule information"""
        # Sanitize msg for block comments: avoid '/*' and '*/' (which trigger -Wcomment)
        header_msg = (
            self.msg.replace("/*", "/ *")
            .replace("*/", "* /")
            .replace("\n", " ")
        )

        comment = f"""\
/*
 * eBPF Rule Implementation
 * SID: {self.sid}
 * Rule Name: {header_msg}
 * Protocol: TCP (6)
 * Action: {self.action.upper()}
 * Priority: {self.priority}
 * Classification: {self.classtype}
 * Generated from Snort rule parser output
 */
"""
        return comment

    def generate_check_function(self) -> str:
        """Generate the main packet checking function"""
        func_name = f"check_rule_{self.sid}"

        code_parts: List[str] = [
            f"/* Check function for rule {self.sid} */",
            f"static __always_inline int {func_name}(struct __sk_buff *skb, void *data, void *data_end) {{",
            "    /* Parse Ethernet header */",
            "    struct ethhdr *eth = data;",
            "    if ((void *)(eth + 1) > data_end) {",
            "        return 0;",
            "    }",
            "",
            "    /* Parse IP header */",
            "    struct iphdr *iph = (struct iphdr *)(eth + 1);",
            "    if ((void *)(iph + 1) > data_end) {",
            "        return 0;",
            "    }",
            "",
            "    /* Verify TCP protocol */",
            "    if (iph->protocol != IPPROTO_TCP) {",
            "        return 0;",
            "    }",
            "",
            "    /* Parse TCP header */",
            "    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);",
            "    if ((void *)(tcph + 1) > data_end) {",
            "        return 0;",
            "    }",
            "",
        ]

        # Protocol and IP checks
        code_parts.append(self.generate_protocol_checks(func_name))

        # Port checks
        code_parts.append(self.generate_port_checks())

        # TCP flag checks
        if self.rule.get("tcp_flags"):
            code_parts.append(self.generate_flags_checks())

        # Content / payload checks
        if self.rule.get("content"):
            code_parts.append(self.generate_content_checks())

        # Final alert trigger
        code_parts.append("    /* All checks passed - trigger alert */")
        code_parts.append(
            f"    alert_rule_{self.sid}(skb, iph->saddr, iph->daddr, tcph->source, tcph->dest);"
        )
        code_parts.append("    return 1;")
        code_parts.append("}")

        return "\n".join(code_parts)

    def generate_protocol_checks(self, func_name: str) -> str:
        """Generate IP/port validation checks"""
        checks: List[str] = []

        src_ip = self.rule.get("src_ip")
        if src_ip and src_ip != "any":
            checks.append(self.generate_ip_check("source", "iph->saddr", src_ip))

        dst_ip = self.rule.get("dst_ip")
        if dst_ip and dst_ip != "any":
            checks.append(self.generate_ip_check("destination", "iph->daddr", dst_ip))

        return "\n".join(checks)

    def generate_ip_check(self, direction: str, ip_var: str, ip_spec: str) -> str:
        """Generate IP address checking code"""
        if ip_spec.startswith("$"):
            return f"    /* Variable IP check: {ip_spec} ({direction}) */\n"

        try:
            network = ipaddress.ip_network(ip_spec, strict=False)
            ip_int = int(network.network_address)
            mask_int = int(network.netmask)

            code = f"    /* Check {direction} IP: {ip_spec} */\n"
            code += f"    u32 {direction}_net = htonl(0x{ip_int:08x});\n"
            code += f"    u32 {direction}_mask = htonl(0x{mask_int:08x});\n"
            code += (
                f"    if (({ip_var} & {direction}_mask) != "
                f"({direction}_net & {direction}_mask)) {{\n"
            )
            code += "        return 0;\n"
            code += "    }\n"
            return code
        except Exception:
            return f"    /* Unable to parse IP: {ip_spec} */\n"

    def generate_port_checks(self) -> str:
        """Generate port matching checks"""
        checks: List[str] = []

        src_port = self.rule.get("src_port")
        if src_port:
            checks.append(self.generate_port_check("src", "tcph->source", src_port))

        dst_port = self.rule.get("dst_port")
        if dst_port:
            checks.append(self.generate_port_check("dst", "tcph->dest", dst_port))

        return "\n".join(checks)

    def generate_port_check(
        self, direction: str, port_var: str, port_spec: Dict[str, Any]
    ) -> str:
        """Generate port matching code"""
        port_type = port_spec.get("type")

        if port_type == "single":
            port = port_spec.get("port")
            return (
                f"    /* Check {direction} port: {port} */\n"
                f"    if ({port_var} != htons({port})) {{\n"
                f"        return 0;\n"
                f"    }}\n"
            )

        elif port_type == "range":
            start = port_spec.get("start", 0)
            end = port_spec.get("end", 65535)
            return (
                f"    /* Check {direction} port range: {start}-{end} */\n"
                f"    u16 {direction}_port = ntohs({port_var});\n"
                f"    if ({direction}_port < {start} || {direction}_port > {end}) {{\n"
                f"        return 0;\n"
                f"    }}\n"
            )

        elif port_type == "list":
            ports = port_spec.get("ports", [])
            valid_ports: List[int] = []

            for p in ports:
                try:
                    p_int = int(p)
                except (TypeError, ValueError):
                    continue
                # Restrict to common range to keep code size manageable
                if 1 <= p_int <= 1000:
                    valid_ports.append(p_int)

            if not valid_ports:
                return (
                    f"    /* No valid {direction} ports in list (1-1000), "
                    f"skipping port check */\n"
                )

            port_checks = [f"ntohs({port_var}) != {p}" for p in valid_ports]
            condition = " && ".join(port_checks)
            return (
                f"    /* Check {direction} port list: {valid_ports} */\n"
                f"    if ({condition}) {{\n"
                f"        return 0;\n"
                f"    }}\n"
            )

        elif port_type == "variable":
            var_name = port_spec.get("name", "UNKNOWN")
            return (
                f"    /* Variable port check: {var_name} ({direction}) - "
                f"Port variables need runtime resolution */\n"
            )

        return f"    /* Unknown port type: {port_type} */\n"

    def generate_flags_checks(self) -> str:
        """Generate TCP flags matching code"""
        flags = self.rule.get("tcp_flags", {})
        if not flags:
            return ""

        checks: List[str] = ["    /* Check TCP flags */"]

        flag_byte_checks: List[str] = []

        if flags.get("SYN"):
            flag_byte_checks.append("tcph->syn == 1")
        if flags.get("ACK"):
            flag_byte_checks.append("tcph->ack == 1")
        if flags.get("FIN"):
            flag_byte_checks.append("tcph->fin == 1")
        if flags.get("RST"):
            flag_byte_checks.append("tcph->rst == 1")
        if flags.get("PSH"):
            flag_byte_checks.append("tcph->psh == 1")
        if flags.get("URG"):
            flag_byte_checks.append("tcph->urg == 1")

        if flag_byte_checks:
            flag_condition = " && ".join(flag_byte_checks)
            checks.append(f"    if (!({flag_condition})) {{")
            checks.append("        return 0;")
            checks.append("    }")

        return "\n".join(checks)

    def generate_content_checks(self) -> str:
        """Generate content/payload matching code"""
        content = self.rule.get("content")
        if not content:
            return ""

        # Convert content (list/str/etc.) to a safe, readable string
        try:
            content_str = json.dumps(content, ensure_ascii=False)
        except TypeError:
            content_str = str(content)

        # Avoid extremely long lines
        if len(content_str) > 200:
            content_str = content_str[:197] + "..."

        # Make it safe for a single-line comment
        content_str = content_str.replace("\n", "\\n")

        checks: List[str] = [
            "    /* Content matching (simplified) */",
            f"    // Full pattern: {content_str}",
            "    // Note: Complex content matching requires BPF string matching library",
        ]

        return "\n".join(checks)

    def generate_alert_function(self) -> str:
        """Generate the alert reporting function"""
        # Escape message for C string
        safe_msg = self.msg.replace('"', '\\"').replace("\n", "\\n")[:255]

        code = f"""
/* Alert function for rule {self.sid} */
static __always_inline void alert_rule_{self.sid}(struct __sk_buff *skb,
                                                 u32 src_ip,
                                                 u32 dst_ip,
                                                 u16 src_port,
                                                 u16 dst_port) {{
    struct alert_event {{
        u32 rule_id;
        u32 priority;
        u32 src_ip;
        u32 dst_ip;
        u16 src_port;
        u16 dst_port;
        char msg[256];
    }} alert = {{0}};

    alert.rule_id  = {self.sid};
    alert.priority = {self.priority};
    alert.src_ip   = src_ip;
    alert.dst_ip   = dst_ip;
    alert.src_port = src_port;
    alert.dst_port = dst_port;

    /* Copy alert message (limited to 255 chars in eBPF) */
    __builtin_memcpy(alert.msg, "{safe_msg}",
                     sizeof("{safe_msg}") < 255 ? sizeof("{safe_msg}") : 255);

    /* Submit alert to userspace via perf buffer */
    alerts.perf_submit(skb, &alert, sizeof(alert));
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
        }


class TCPRulesEBPFManager:
    """Manager class for handling multiple TCP rules"""

    def __init__(self, max_rules: int = 50):
        # Hard limit on how many TCP rules we will generate code for
        self.max_rules = max_rules
        self.generators: List[TCPRuleEBPFCodegen] = []
        self.generated_code: List[str] = []
        self.rule_metadata: List[Dict[str, Any]] = []

    def add_rule(self, rule_config: Dict[str, Any]) -> bool:
        """Add a TCP rule for code generation (up to max_rules)"""
        try:
            # Only TCP rules
            if rule_config.get("protocol_num") != 6:
                return False

            # Enforce maximum number of rules
            if len(self.generators) >= self.max_rules:
                # Optional: log or silently skip extra rules
                # print(f"Skipping rule SID {rule_config.get('sid')}, max_rules={self.max_rules} reached")
                return False

            generator = TCPRuleEBPFCodegen(rule_config)
            self.generators.append(generator)
            return True
        except Exception as e:
            print(f"Error adding rule: {e}")
            return False

    def generate_all_code(self) -> Dict[str, Any]:
        """Generate eBPF C code for all added rules"""
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
            "count": len(self.generated_code),
        }

    def export_code(self, output_file: str):
        """Export generated code to C file with proper headers"""
        if not self.generated_code:
            self.generate_all_code()

        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # Build complete eBPF C program with perf buffer declaration
        header = """/*
 * Auto-generated eBPF code for TCP rule detection
 * Generated from Snort rules
 * This code requires Linux kernel 4.1+ with eBPF support
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/string.h>

/* Alert event structure */
struct alert_event {
    u32 rule_id;
    u32 priority;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    char msg[256];
};

/* Define perf buffer for alerts */
BPF_PERF_OUTPUT(alerts);

"""

        # Main filter function that calls all rule checks
        main_function = """
/* Main packet filter function */
int ids_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Check all rules */
"""

        # Add calls to each rule check function
        for generator in self.generators:
            main_function += f"    check_rule_{generator.sid}(skb, data, data_end);\n"

        main_function += """
    return 0; /* Pass packet to network stack */
}
"""

        all_code = header + "\n".join(self.generated_code) + "\n" + main_function

        try:
            with open(output_file, "w") as f:
                f.write(all_code)
            print(f"✓ Successfully exported eBPF code to {output_file}")
        except Exception as e:
            print(f"✗ Failed to export code: {e}")
            raise

    def export_metadata(self, output_file: str):
        """Export rule metadata to JSON"""
        if not self.rule_metadata:
            self.generate_all_code()

        with open(output_file, "w") as f:
            json.dump(self.rule_metadata, f, indent=2)


if __name__ == "__main__":
    # Example usage
    with open("snort_rules_ebpf.json", "r") as f:
        all_rules = json.load(f)

    tcp_rules = [r for r in all_rules if r.get("protocol_num") == 6]

    print(f"Total rules: {len(all_rules)}")
    print(f"TCP rules: {len(tcp_rules)}")

    # Limit to 50 rules here as well
    manager = TCPRulesEBPFManager(max_rules=50)

    for rule in tcp_rules[:50]:
        if manager.add_rule(rule):
            print(f"Added rule SID: {rule.get('sid')}")

    result = manager.generate_all_code()
    print(f"\nGenerated code for {result['count']} rules")

    manager.export_code("generated/tcp_rules.c")
    manager.export_metadata("generated/tcp_rules_metadata.json")

    print("\nGenerated files:")
    print(" - generated/tcp_rules.c")
    print(" - generated/tcp_rules_metadata.json")
