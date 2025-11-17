#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OOP-Based eBPF Code Generator for Snort Rules
Breaks rules into small, manageable pieces for kernel deployment

Architecture:
1. RulePattern classes - Analyze and classify rules
2. CodeGenerator classes - Generate focused eBPF C code
3. RuleBatcher - Group rules into deployable batches (5, 10, 20...)
4. DeploymentManager - Handle progressive kernel loading

Design Principles:
- Keep each eBPF function small (<1KB)
- Group related rules together
- Support $EXTERNAL_NET and $HOME_NET variable substitution
- Progressive testing (start with 1-5 rules)
"""

import json
import os
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum


# ============================================================================
# 1. DATA MODELS & ENUMS
# ============================================================================

class ProtocolType(Enum):
    TCP = 6
    UDP = 17
    ICMP = 1
    OTHER = 0


class FlowDirection(Enum):
    TO_SERVER = "to_server"
    TO_CLIENT = "to_client"
    STATELESS = "stateless"
    UNKNOWN = "unknown"


@dataclass
class IPConfig:
    """Configuration for IP address handling"""
    home_net: str = "10.0.0.0/8"  # Default private network
    external_net: str = "0.0.0.0/0"  # Any external
    telnet_servers: str = "10.0.0.0/8"
    http_servers: str = "10.0.0.0/8"
    http_ports: str = "80,443,8080"
    smtp_servers: str = "10.0.0.0/8"

    def resolve_variable(self, var: str) -> str:
        """Resolve Snort rule variables"""
        mapping = {
            "$HOME_NET": self.home_net,
            "$EXTERNAL_NET": self.external_net,
            "$TELNET_SERVERS": self.telnet_servers,
            "$HTTP_SERVERS": self.http_servers,
            "$HTTP_PORTS": self.http_ports,
            "$SMTP_SERVERS": self.smtp_servers,
        }
        return mapping.get(var, var)


@dataclass
class PortSpec:
    """Represents port specification"""
    port_type: str  # "single", "range", "list", "variable", None
    value: Union[int, Tuple[int, int], List[int], str, None] = None

    @classmethod
    def from_rule(cls, port_obj) -> Optional['PortSpec']:
        if port_obj is None:
            return None
        if isinstance(port_obj, dict):
            return cls(
                port_type=port_obj.get("type", "single"),
                value=port_obj.get("port") or port_obj.get("start") or port_obj.get("ports")
            )
        return None


@dataclass
class RulePattern:
    """Complete rule pattern representation"""
    sid: int
    msg: str
    protocol_num: int
    src_ip: str
    src_port: Optional[PortSpec]
    dst_ip: str
    dst_port: Optional[PortSpec]
    tcp_flags: Dict = field(default_factory=dict)
    content: Union[str, List[str], None] = None
    flow: Optional[str] = None
    priority: int = 3
    classtype: str = "unknown"


# ============================================================================
# 2. RULE PATTERN ANALYZERS (OOP)
# ============================================================================

class BaseRuleAnalyzer(ABC):
    """Base analyzer for different rule types"""

    def __init__(self, ip_config: IPConfig = None):
        self.ip_config = ip_config or IPConfig()

    @abstractmethod
    def analyze(self, rule: Dict) -> RulePattern:
        """Convert rule dict to RulePattern"""
        pass

    @abstractmethod
    def can_handle(self, rule: Dict) -> bool:
        """Check if this analyzer handles the rule type"""
        pass

    def _parse_port(self, port_obj) -> Optional[PortSpec]:
        """Parse port specification"""
        return PortSpec.from_rule(port_obj)

    def _resolve_ip(self, ip_str: str) -> str:
        """Resolve IP variables"""
        return self.ip_config.resolve_variable(ip_str)


class TCPRuleAnalyzer(BaseRuleAnalyzer):
    """Analyzes TCP-specific rules"""

    def can_handle(self, rule: Dict) -> bool:
        return rule.get("protocol_num") == 6

    def analyze(self, rule: Dict) -> RulePattern:
        return RulePattern(
            sid=rule.get("sid", 0),
            msg=rule.get("msg", ""),
            protocol_num=6,
            src_ip=self._resolve_ip(rule.get("src_ip", "any")),
            src_port=self._parse_port(rule.get("src_port")),
            dst_ip=self._resolve_ip(rule.get("dst_ip", "any")),
            dst_port=self._parse_port(rule.get("dst_port")),
            tcp_flags=rule.get("tcp_flags", {}),
            content=rule.get("content"),
            flow=rule.get("flow", ""),
            priority=rule.get("priority", 3),
            classtype=rule.get("classtype", "unknown")
        )


class UDPRuleAnalyzer(BaseRuleAnalyzer):
    """Analyzes UDP-specific rules"""

    def can_handle(self, rule: Dict) -> bool:
        return rule.get("protocol_num") == 17

    def analyze(self, rule: Dict) -> RulePattern:
        return RulePattern(
            sid=rule.get("sid", 0),
            msg=rule.get("msg", ""),
            protocol_num=17,
            src_ip=self._resolve_ip(rule.get("src_ip", "any")),
            src_port=self._parse_port(rule.get("src_port")),
            dst_ip=self._resolve_ip(rule.get("dst_ip", "any")),
            dst_port=self._parse_port(rule.get("dst_port")),
            content=rule.get("content"),
            flow=rule.get("flow", ""),
            priority=rule.get("priority", 3),
            classtype=rule.get("classtype", "unknown")
        )


class ICMPRuleAnalyzer(BaseRuleAnalyzer):
    """Analyzes ICMP-specific rules"""

    def can_handle(self, rule: Dict) -> bool:
        return rule.get("protocol_num") == 1

    def analyze(self, rule: Dict) -> RulePattern:
        return RulePattern(
            sid=rule.get("sid", 0),
            msg=rule.get("msg", ""),
            protocol_num=1,
            src_ip=self._resolve_ip(rule.get("src_ip", "any")),
            src_port=None,
            dst_ip=self._resolve_ip(rule.get("dst_ip", "any")),
            dst_port=None,
            content=rule.get("content"),
            flow=rule.get("flow", ""),
            priority=rule.get("priority", 3),
            classtype=rule.get("classtype", "unknown")
        )


class RulePatternFactory:
    """Factory for creating appropriate analyzers"""

    def __init__(self, ip_config: IPConfig = None):
        self.ip_config = ip_config or IPConfig()
        self.analyzers = [
            TCPRuleAnalyzer(ip_config),
            UDPRuleAnalyzer(ip_config),
            ICMPRuleAnalyzer(ip_config),
        ]

    def analyze_rule(self, rule: Dict) -> Optional[RulePattern]:
        """Find appropriate analyzer and parse rule"""
        for analyzer in self.analyzers:
            if analyzer.can_handle(rule):
                return analyzer.analyze(rule)
        return None


# ============================================================================
# 3. EBPF CODE GENERATORS (OOP)
# ============================================================================

class BaseEBPFGenerator(ABC):
    """Base class for eBPF code generation"""

    def __init__(self, batch_id: int = 0):
        self.batch_id = batch_id
        self.rules: List[RulePattern] = []

    @abstractmethod
    def generate_function(self) -> str:
        """Generate a single eBPF function for this batch"""
        pass

    @abstractmethod
    def add_rule(self, pattern: RulePattern) -> bool:
        """Add rule to this generator (return False if full)"""
        pass

    def get_rule_count(self) -> int:
        return len(self.rules)

    def is_full(self) -> int:
        """Check if generator is full (implementation-specific)"""
        return False


class TCPRuleEBPFGenerator(BaseEBPFGenerator):
    """Generates eBPF code for TCP rules"""

    MAX_RULES_PER_FUNCTION = 10

    def add_rule(self, pattern: RulePattern) -> bool:
        if pattern.protocol_num != 6:
            return False
        if len(self.rules) >= self.MAX_RULES_PER_FUNCTION:
            return False
        self.rules.append(pattern)
        return True

    def generate_function(self) -> str:
        """Generate eBPF function for TCP rules"""
        if not self.rules:
            return ""

        func_name = f"tcp_rules_batch_{self.batch_id}"
        rules_code = self._generate_rule_checks()

        code = f'''
// eBPF Function: TCP Rules Batch {self.batch_id}
// Contains {len(self.rules)} rules
static __always_inline int {func_name}(struct __sk_buff *skb) {{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    if (ip->protocol != IPPROTO_TCP)
        return 0;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return 0;

    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);
    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;

{rules_code}

    return 0;
}}
'''
        return code

    def _generate_rule_checks(self) -> str:
        """Generate port and content checking logic"""
        checks = []
        for rule in self.rules:
            check = self._generate_single_rule_check(rule)
            checks.append(check)
        return "\n".join(checks)

    def _generate_single_rule_check(self, rule: RulePattern) -> str:
        """Generate check for single TCP rule"""
        code = f"    // Rule SID {rule.sid}: {rule.msg}\n"
        code += f"    if (1) {{ // Rule check\n"

        # Port checking
        if rule.src_port:
            code += self._generate_port_check(
                rule.src_port, "src_port", "source"
            )
        if rule.dst_port:
            code += self._generate_port_check(
                rule.dst_port, "dst_port", "destination"
            )

        # Content matching (simplified)
        if rule.content:
            code += f"        // TODO: Implement content matching for SID {rule.sid}\n"

        code += f'''        struct alert_event_t event = {{}};
        event.rule_id = {rule.sid};
        event.priority = {rule.priority};
        event.src_ip = src_ip;
        event.dst_ip = dst_ip;
        event.src_port = src_port;
        event.dst_port = dst_port;
        __builtin_memcpy(&event.msg, "{rule.msg[:250]}", {min(len(rule.msg), 250)});
        alerts.perf_submit(skb, &event, sizeof(event));
    }}
'''
        return code

    def _generate_port_check(self, port_spec: PortSpec, port_var_name: str, direction_str: str) -> str:
        """
        Generates a C code snippet for checking a port condition.
        It now correctly accepts the port specification, the C variable name for the port,
        and a string indicating the direction for comments.
        """
        if not port_spec or port_spec.value is None:
            return ""

        condition = ""
        port_type = port_spec.port_type
        port_value = port_spec.value

        if port_type == "single":
            condition = f"{port_var_name} != {port_value}"
        elif port_type == "range":
            start, end = port_value
            condition = f"({port_var_name} < {start} || {port_var_name} > {end})"
        elif port_type == "list":
            conditions = [f"{port_var_name} != {p}" for p in port_value]
            condition = " && ".join(conditions)
            if condition:
                condition = f"({condition})"

        if condition:
            return f"    if ({condition}) return 0; /* Rule does not match {direction_str} port */\n"
        return ""


class UDPRuleEBPFGenerator(BaseEBPFGenerator):
    """Generates eBPF code for UDP rules"""

    MAX_RULES_PER_FUNCTION = 10

    def add_rule(self, pattern: RulePattern) -> bool:
        if pattern.protocol_num != 17:
            return False
        if len(self.rules) >= self.MAX_RULES_PER_FUNCTION:
            return False
        self.rules.append(pattern)
        return True

    def generate_function(self) -> str:
        """Generate eBPF function for UDP rules"""
        if not self.rules:
            return ""

        func_name = f"udp_rules_batch_{self.batch_id}"

        code = f'''
// eBPF Function: UDP Rules Batch {self.batch_id}
// Contains {len(self.rules)} rules
static __always_inline int {func_name}(struct __sk_buff *skb) {{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    if (ip->protocol != IPPROTO_UDP)
        return 0;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return 0;

    uint16_t src_port = ntohs(udp->source);
    uint16_t dst_port = ntohs(udp->dest);
    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;

    // UDP rule checks here
    // TODO: Implement UDP rule matching

    return 0;
}}
'''
        return code


# ============================================================================
# 4. RULE BATCHER (OOP)
# ============================================================================

class RuleBatcher:
    """Groups rules into manageable batches for kernel deployment"""

    def __init__(self, batch_size: int = 5, ip_config: IPConfig = None):
        self.batch_size = batch_size
        self.ip_config = ip_config or IPConfig()
        self.batches: List[List[RulePattern]] = []
        self.factory = RulePatternFactory(ip_config)

    def load_rules_from_json(self, json_path: str) -> int:
        """Load rules from JSON file and create batches"""
        with open(json_path, 'r') as f:
            rules_data = json.load(f)

        parsed_rules = []
        for rule_dict in rules_data:
            pattern = self.factory.analyze_rule(rule_dict)
            if pattern:
                parsed_rules.append(pattern)

        # Group into batches
        for i in range(0, len(parsed_rules), self.batch_size):
            batch = parsed_rules[i:i + self.batch_size]
            self.batches.append(batch)

        return len(parsed_rules)

    def get_batch(self, batch_num: int) -> Optional[List[RulePattern]]:
        """Get specific batch"""
        if 0 <= batch_num < len(self.batches):
            return self.batches[batch_num]
        return None

    def get_batch_count(self) -> int:
        """Total number of batches"""
        return len(self.batches)

    def generate_batch_code(self, batch_num: int) -> Dict[str, str]:
        """Generate eBPF code for specific batch"""
        batch = self.get_batch(batch_num)
        if not batch:
            return {}

        tcp_gen = TCPRuleEBPFGenerator(batch_num)
        udp_gen = UDPRuleEBPFGenerator(batch_num)

        for rule in batch:
            if rule.protocol_num == 6:
                tcp_gen.add_rule(rule)
            elif rule.protocol_num == 17:
                udp_gen.add_rule(rule)

        result = {}
        if tcp_gen.get_rule_count() > 0:
            result['tcp'] = tcp_gen.generate_function()
        if udp_gen.get_rule_count() > 0:
            result['udp'] = udp_gen.generate_function()

        return result


# ============================================================================
# 5. DEPLOYMENT MANAGER
# ============================================================================

class DeploymentManager:
    """Manages progressive eBPF program deployment to kernel"""

    def __init__(self, json_path: str, batch_size: int = 5, ip_config: IPConfig = None):
        self.json_path = json_path
        self.batch_size = batch_size
        self.ip_config = ip_config or IPConfig()
        self.batcher = RuleBatcher(batch_size, ip_config)
        self.loaded_batches: List[int] = []
        self.kernel_functions: Dict[int, Dict[str, str]] = {}

    def load_and_batch_rules(self) -> int:
        """Load rules and create batches"""
        total_rules = self.batcher.load_rules_from_json(self.json_path)
        print(f"✓ Loaded {total_rules} rules")
        print(f"✓ Created {self.batcher.get_batch_count()} batches (size: {self.batch_size})")
        return total_rules

    def generate_batch_code(self, batch_num: int) -> bool:
        """Generate code for specific batch"""
        code_dict = self.batcher.generate_batch_code(batch_num)
        if code_dict:
            self.kernel_functions[batch_num] = code_dict
            tcp_count = 1 if 'tcp' in code_dict else 0
            udp_count = 1 if 'udp' in code_dict else 0
            print(f"✓ Generated code for batch {batch_num} ({tcp_count} TCP, {udp_count} UDP functions)")
            return True
        return False

    def get_batch_info(self, batch_num: int) -> Dict:
        """Get information about specific batch"""
        batch = self.batcher.get_batch(batch_num)
        if not batch:
            return {}

        tcp_count = sum(1 for r in batch if r.protocol_num == 6)
        udp_count = sum(1 for r in batch if r.protocol_num == 17)
        icmp_count = sum(1 for r in batch if r.protocol_num == 1)

        return {
            'batch_num': batch_num,
            'total_rules': len(batch),
            'tcp_rules': tcp_count,
            'udp_rules': udp_count,
            'icmp_rules': icmp_count,
            'rules': [(r.sid, r.msg) for r in batch]
        }

    def export_batch_code(self, batch_num: int, output_dir: str) -> bool:
        """Export batch code to file"""
        code_dict = self.kernel_functions.get(batch_num, {})
        if not code_dict:
            return False

        os.makedirs(output_dir, exist_ok=True)

        for proto, code in code_dict.items():
            filename = os.path.join(output_dir, f"batch_{batch_num}_{proto}_rules.c")
            with open(filename, 'w') as f:
                f.write(code)
            print(f"✓ Exported {filename}")

        return True

    def generate_test_command(self, batch_num: int) -> str:
        """Generate nmap command to test rule detection"""
        batch = self.batcher.get_batch(batch_num)
        if not batch:
            return ""

        # Find TCP rules with specific ports
        tcp_rules = [r for r in batch if r.protocol_num == 6 and r.dst_port]

        if tcp_rules:
            ports = set()
            for rule in tcp_rules:
                if rule.dst_port.port_type == "single":
                    ports.add(str(rule.dst_port.value))
                elif rule.dst_port.port_type == "range":
                    start, end = rule.dst_port.value
                    ports.add(f"{start}-{end}")

            port_str = ",".join(sorted(ports))
            cmd = f"nmap -p {port_str} -sV --script banner localhost"
            return cmd

        return ""


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_batch_summary(manager: DeploymentManager):
    """Print summary of all batches"""
    print("\n" + "=" * 80)
    print("BATCH SUMMARY")
    print("=" * 80)
    
    for i in range(manager.batcher.get_batch_count()):
        info = manager.get_batch_info(i)
        if info:
            print(f"\nBatch {i}:")
            print(f"  Total Rules: {info['total_rules']}")
            print(f"  TCP: {info['tcp_rules']}, UDP: {info['udp_rules']}, ICMP: {info['icmp_rules']}")
            print(f"  Sample Rules:")
            for sid, msg in info['rules'][:3]:
                print(f"    - SID {sid}: {msg[:60]}")


if __name__ == "__main__":
    # Example usage
    print("eBPF OOP Code Generator Module Loaded")
    print("This module provides:")
    print("  - RulePattern analyzers (TCP, UDP, ICMP)")
    print("  - eBPF code generators with OOP design")
    print("  - RuleBatcher for grouping rules")
    print("  - DeploymentManager for progressive kernel loading")
