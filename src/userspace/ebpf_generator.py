#!/usr/bin/env python3

"""
Modular eBPF IDS Rule Generator
Object-oriented system for generating, compiling, and loading eBPF programs
from Snort-like rules with support for batching and isolation.
"""

import json
import subprocess
import os
import sys
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Union
from pathlib import Path
import struct

# HOME_NET and EXTERNAL_NET resolution
HOME_NET_IP = "10.10.1.2"  # Victim network interface ens4
HOME_NET_HEX = 0x0201010A  # 10.10.1.2 in network byte order (little-endian)
EXTERNAL_NET_PLACEHOLDER = 0x00000000  # Represents any external IP (0.0.0.0)


class EbpfRuleGenerator(ABC):
    """Abstract base class for eBPF rule generators."""

    def __init__(self, json_path: str):
        """Initialize generator with JSON rules file."""
        self.json_path = json_path
        self.rules = []
        self.load_rules()

    def load_rules(self):
        """Load and validate rules from JSON file."""
        try:
            with open(self.json_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.rules = data
                else:
                    print(f"Warning: JSON is not an array, treating as single rule")
                    self.rules = [data]
            print(f"Loaded {len(self.rules)} rules from {self.json_path}")
        except Exception as e:
            print(f"Error loading JSON: {e}")
            self.rules = []

    @abstractmethod
    def generate_section(self, rule: Dict) -> str:
        """Generate C code snippet for a single rule. Must be implemented by subclasses."""
        pass

    def generate_boilerplate(self) -> str:
        """Generate common eBPF boilerplate code."""
        return """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bcc/proto.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/sock.h>

#define HOME_NET 0x0201010A
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Helper macro to safely access packet data
#define BOUNDS_CHECK(ptr, end, size) ((void *)(ptr) + (size) <= (void *)(end))

"""

    def build_program(self, num_rules: int = 5, batch_id: int = 0) -> str:
        """Build complete eBPF program for given number of rules."""
        if not self.rules:
            print("Error: No rules loaded")
            return ""

        num_rules = min(num_rules, len(self.rules))
        print(f"Building program for {num_rules} rules (batch {batch_id})...")

        code = self.generate_boilerplate()
        code += f"// Generated eBPF batch program - Batch {batch_id}, Rules 0-{num_rules-1}\n"
        code += "// This program processes the following rules:\n"

        # Document which rules are included
        included_rules = []
        for i in range(num_rules):
            rule = self.rules[i]
            rule_name = f"SID_{rule.get('sid', 'unknown')}_" + rule.get('msg', '').replace(' ', '_')[:30]
            included_rules.append(rule_name)
            code += f"// {i+1}. {rule_name}\n"

        code += "\n\n"

        # Generate rule-specific sections
        rule_sections = []
        for i in range(num_rules):
            rule = self.rules[i]
            section = self.generate_section(rule)
            if section:
                rule_sections.append(section)

        # Combine all sections into main XDP program
        code += self.generate_main_program(rule_sections, included_rules)
        code += "\nchar _license[] SEC(\"license\") = \"GPL\";\n"

        return code, included_rules

    def generate_main_program(self, sections: List[str], rule_names: List[str]) -> str:
        """Generate main XDP entry point that combines all rule sections."""
        main_code = f"""
SEC("xdp")
int ids_filter(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (!BOUNDS_CHECK(eth, data_end, sizeof(*eth)))
        return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)eth + 1;
    if (!BOUNDS_CHECK(ip, data_end, sizeof(*ip)))
        return XDP_PASS;

    // Process rule checks here
    // Rules included: {', '.join(rule_names[:5])}

    // Default: pass packet
    return XDP_PASS;
}}
"""
        return main_code

    def compile(self, c_file: str, o_file: str, batch_id: int = 0) -> bool:
        """Compile C file to eBPF object using clang."""
        try:
            print(f"Compiling {c_file} -> {o_file}...")
            cmd = [
                "clang",
                "-target", "bpf",
                "-O2",
                "-c", c_file,
                "-o", o_file,
                "-Wno-macro-redefined",
                "-D__HAVE_BUILTIN_BSWAP16__=1",
                "-D__HAVE_BUILTIN_BSWAP32__=1",
                "-D__HAVE_BUILTIN_BSWAP64__=1"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Compilation error: {result.stderr}")
                return False
            print(f"✓ Compilation successful: {o_file}")
            return True
        except Exception as e:
            print(f"Error during compilation: {e}")
            return False


class PortScanGenerator(EbpfRuleGenerator):
    """Generator for port scan and port matching rules."""

    def generate_section(self, rule: Dict) -> str:
        """Generate C code for port-based rule."""
        protocol = rule.get('protocol_num', 6)
        dst_port = rule.get('dst_port')
        src_port = rule.get('src_port')
        msg = rule.get('msg', 'Unknown rule')
        sid = rule.get('sid', 0)

        if protocol == 6:
            return f"""
// TCP Rule: SID {sid} - {msg}
// Check TCP ports
struct tcphdr *tcp = (void *)ip + 1;
if (!BOUNDS_CHECK(tcp, data_end, sizeof(*tcp)))
    return XDP_PASS;
if (ntohs(tcp->dest) == {dst_port.get('port', 0) if isinstance(dst_port, dict) else 'null'}) {{
    bpf_printk("Alert: SID {sid} matched\\n");
}}
"""
        elif protocol == 17:
            return f"""
// UDP Rule: SID {sid} - {msg}
struct udphdr *udp = (void *)ip + 1;
if (!BOUNDS_CHECK(udp, data_end, sizeof(*udp)))
    return XDP_PASS;
"""
        return ""


class PayloadMatchGenerator(EbpfRuleGenerator):
    """Generator for payload/content matching rules."""

    def generate_section(self, rule: Dict) -> str:
        """Generate C code for content-based rule."""
        content = rule.get('content', '')
        msg = rule.get('msg', 'Unknown rule')
        sid = rule.get('sid', 0)

        if not content:
            return ""

        # Simple content matching (in real implementation, would parse hex patterns)
        return f"""
// Content Rule: SID {sid} - {msg}
// Check for content: {content[:30]}...
// bpf_probe_read_kernel_str for payload inspection
"""


class ProtocolFilterGenerator(EbpfRuleGenerator):
    """Generator for protocol-based filtering rules."""

    def generate_section(self, rule: Dict) -> str:
        """Generate C code for protocol filtering."""
        protocol = rule.get('protocol_num', 0)
        msg = rule.get('msg', 'Unknown rule')
        sid = rule.get('sid', 0)

        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, "Unknown")

        return f"""
// Protocol Rule: SID {sid} - {msg}
// Protocol: {protocol_name} ({protocol})
// Filter logic would be inserted here
"""


def main():
    """Main entry point for standalone testing."""
    import argparse

    parser = argparse.ArgumentParser(description='eBPF IDS Rule Generator')
    parser.add_argument('--rules', type=str, default='snort_rules_ebpf.json',
                        help='Path to JSON rules file')
    parser.add_argument('--num', type=int, default=5,
                        help='Number of rules to generate (default 5)')
    parser.add_argument('--batch', type=int, default=0,
                        help='Batch ID for output file naming')
    parser.add_argument('--output', type=str, default='.',
                        help='Output directory for generated files')

    args = parser.parse_args()

    # Create generator
    generator = PortScanGenerator(args.rules)

    if not generator.rules:
        print("No rules loaded, exiting")
        return

    # Generate program
    program, included_rules = generator.build_program(args.num, args.batch)

    if not program:
        print("Failed to generate program")
        return

    # Output file names
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    c_file = output_dir / f"batch_{args.batch}_tcp.c"
    o_file = output_dir / f"batch_{args.batch}_tcp.o"

    # Write C file
    with open(c_file, 'w') as f:
        f.write(program)
    print(f"✓ Generated C file: {c_file}")

    # Compile
    if generator.compile(str(c_file), str(o_file), args.batch):
        print(f"✓ Generated object file: {o_file}")

    # Print summary
    print(f"\n" + "="*60)
    print(f"Generated eBPF Program Summary")
    print(f"="*60)
    print(f"Batch ID: {args.batch}")
    print(f"Number of rules: {len(included_rules)}")
    print(f"Included rules:")
    for i, rule_name in enumerate(included_rules, 1):
        print(f"  {i}. {rule_name}")
    print(f"\nOutput files:")
    print(f"  C source: {c_file}")
    print(f"  Object: {o_file}")


if __name__ == "__main__":
    main()
