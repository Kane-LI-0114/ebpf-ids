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
    home_net: str = "10.0.0.0/8"       # Default private network
    external_net: str = "0.0.0.0/0"    # Any external
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
    def from_rule(cls, port_obj: dict) -> Optional["PortSpec"]:
        if not port_obj:
            return None

        if isinstance(port_obj, (int, str)):
            return cls(port_type="single", value=port_obj)

        if isinstance(port_obj, dict):
            port_type = port_obj.get("type", "single")
            value = None

            if port_type == "range":
                if "start" in port_obj and "end" in port_obj:
                    value = (port_obj["start"], port_obj["end"])
            elif port_type == "list":
                value = port_obj.get("ports")
            else:  # 'single' or default
                value = port_obj.get("port")

            return cls(port_type=port_type, value=value)

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
            classtype=rule.get("classtype", "unknown"),
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
            classtype=rule.get("classtype", "unknown"),
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
            classtype=rule.get("classtype", "unknown"),
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

C_HEADER_DEFINITIONS = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bcc/proto.h>

// Data structure to send alerts from kernel to user space
struct alert_event_t {
    u32 rule_id;
    u32 priority;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    char msg[250];
};

// BPF map to push alerts to user space
BPF_PERF_OUTPUT(alerts);
"""


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
        if pattern.protocol_num != 6 or len(self.rules) >= self.MAX_RULES_PER_FUNCTION:
            return False
        self.rules.append(pattern)
        return True

    def generate_function(self) -> str:
        """
        Generate eBPF function for TCP rules.

        This function does not access packet data directly; it only receives
        already-parsed 5‑tuple fields from the top-level ids_filter.
        """
        if not self.rules:
            return ""

        func_name = f"tcp_rules_batch_{self.batch_id}"
        rules_code = self._generate_rule_checks()

        func_logic = f"""
// eBPF Function: TCP Rules Batch {self.batch_id} | Rules: {len(self.rules)}
static __always_inline int {func_name}(
    struct __sk_buff *skb,
    u32 src_ip,
    u32 dst_ip,
    u16 src_port,
    u16 dst_port
) {{
{rules_code}
    return 0;
}}
"""
        return C_HEADER_DEFINITIONS + func_logic

    def _generate_rule_checks(self) -> str:
        """Generate port and content checking logic"""
        checks = [self._generate_single_rule_check(rule) for rule in self.rules]
        return "\n".join(checks)

    def _generate_single_rule_check(self, rule: RulePattern) -> str:
        """Generate check for single TCP rule"""
        conditions: List[str] = []

        if rule.src_port and rule.src_port.value is not None:
            conditions.append(self._generate_port_check(rule.src_port, "src_port"))
        if rule.dst_port and rule.dst_port.value is not None:
            conditions.append(self._generate_port_check(rule.dst_port, "dst_port"))

        # Combine all conditions with &&
        full_condition = " && ".join(filter(None, conditions))
        if not full_condition:
            full_condition = "1"

        alert_block = f"""
        struct alert_event_t event = {{0}};
        event.rule_id = {rule.sid};
        event.priority = {rule.priority};
        event.src_ip = src_ip;
        event.dst_ip = dst_ip;
        event.src_port = src_port;
        event.dst_port = dst_port;
        __builtin_memcpy(&event.msg, "{rule.msg[:249]}", {min(len(rule.msg), 249)});
        alerts.perf_submit(skb, &event, sizeof(event));
"""

        return f"""
    // Rule SID {rule.sid}: {rule.msg}
    if ({full_condition}) {{
{alert_block}
    }}
"""

    def _generate_port_check(self, port_spec: PortSpec, port_var_name: str) -> str:
        if port_spec.port_type == "single":
            return f"{port_var_name} == {port_spec.value}"
        elif port_spec.port_type == "range":
            start, end = port_spec.value
            return f"({port_var_name} >= {start} && {port_var_name} <= {end})"
        elif port_spec.port_type == "list":
            return " || ".join([f"{port_var_name} == {p}" for p in port_spec.value])
        return ""


class UDPRuleEBPFGenerator(BaseEBPFGenerator):
    """Generates eBPF code for UDP rules"""

    MAX_RULES_PER_FUNCTION = 10

    def add_rule(self, pattern: RulePattern) -> bool:
        if pattern.protocol_num != 17 or len(self.rules) >= self.MAX_RULES_PER_FUNCTION:
            return False
        self.rules.append(pattern)
        return True

    def generate_function(self) -> str:
        """
        Generate eBPF function for UDP rules.

        Like the TCP generator, this does not access packet data directly.
        """
        if not self.rules:
            return ""

        func_name = f"udp_rules_batch_{self.batch_id}"
        # You can later add UDP-specific conditions using src_port/dst_port/src_ip/dst_ip.
        rules_code = "// TODO: Add UDP rule checks here"

        func_logic = f"""
// eBPF Function: UDP Rules Batch {self.batch_id} | Rules: {len(self.rules)}
static __always_inline int {func_name}(
    struct __sk_buff *skb,
    u32 src_ip,
    u32 dst_ip,
    u16 src_port,
    u16 dst_port
) {{
    {rules_code}
    return 0;
}}
"""
        return C_HEADER_DEFINITIONS + func_logic


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
        with open(json_path, "r") as f:
            rules_data = json.load(f)

        parsed_rules: List[RulePattern] = []
        for rule_dict in rules_data:
            pattern = self.factory.analyze_rule(rule_dict)
            if pattern:
                parsed_rules.append(pattern)

        for i in range(0, len(parsed_rules), self.batch_size):
            self.batches.append(parsed_rules[i : i + self.batch_size])

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

        result: Dict[str, str] = {}
        if tcp_gen.get_rule_count() > 0:
            result["tcp"] = tcp_gen.generate_function()
        if udp_gen.get_rule_count() > 0:
            result["udp"] = udp_gen.generate_function()

        return result


# ============================================================================
# 5. DEPLOYMENT MANAGER & UTILS
# ============================================================================

class DeploymentManager:
    """Manages progressive eBPF program deployment to kernel"""

    def __init__(self, json_path: str, batch_size: int = 5, ip_config: IPConfig = None):
        self.json_path = json_path
        self.batch_size = batch_size
        self.ip_config = ip_config or IPConfig()
        self.batcher = RuleBatcher(batch_size, ip_config)
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
            tcp_count = 1 if "tcp" in code_dict else 0
            udp_count = 1 if "udp" in code_dict else 0
            print(f"✓ Generated code for batch {batch_num} ({tcp_count} TCP, {udp_count} UDP functions)")
            return True
        return False

    def get_batch_info(self, batch_num: int) -> Dict:
        """Get information about specific batch"""
        batch = self.batcher.get_batch(batch_num)
        if not batch:
            return {}
        return {
            "batch_num": batch_num,
            "total_rules": len(batch),
            "tcp_rules": sum(1 for r in batch if r.protocol_num == 6),
            "udp_rules": sum(1 for r in batch if r.protocol_num == 17),
            "icmp_rules": sum(1 for r in batch if r.protocol_num == 1),
            "rules": [(r.sid, r.msg) for r in batch],
        }

    def export_batch_code(self, batch_num: int, output_dir: str) -> bool:
        """Export batch code to file"""
        code_dict = self.kernel_functions.get(batch_num, {})
        if not code_dict:
            return False

        os.makedirs(output_dir, exist_ok=True)
        for proto, code in code_dict.items():
            filename = os.path.join(output_dir, f"batch_{batch_num}_{proto}_rules.c")
            with open(filename, "w") as f:
                f.write(code)
            print(f"✓ Exported {filename}")
        return True


if __name__ == "__main__":
    print("eBPF OOP Code Generator Module Loaded")
    # Example usage can be added here
