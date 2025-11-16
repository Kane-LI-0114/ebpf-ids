#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eBPF IDS 用户空间管理程序
"""

import os
from pathlib import Path
import sys
import json
import signal
import socket
import fcntl
import struct
import array
from datetime import datetime
from typing import Optional, Union

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from utils import SnortRuleParser

def get_active_interface():
    """自动检测活动的网络接口"""
    try:
        with open('/proc/net/dev', 'r', encoding='utf-8') as f:
            lines = f.readlines()
        interfaces = []
        for line in lines[2:]:
            if ':' in line:
                iface_name = line.split(':')[0].strip()
                if iface_name != 'lo':
                    interfaces.append(iface_name)
        if interfaces:
            return interfaces[0]
        return 'eth0'
    except Exception as e:
        print(f"警告: 无法自动检测网络接口: {e}")
        return 'eth0'

class RuleManager:
    """规则管理器"""
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.ebpf_configs = []
        self.parser = SnortRuleParser()
        from ebpf_codegen import TCPRulesEBPFManager
        self.tcp_codegen = TCPRulesEBPFManager()
        # Add a mapping of SID to rule info for alert lookup
        self.sid_to_rule = {}

    def load_rules(self, rule_file: Optional[Union[str, Path]] = None):
        """从规则目录加载规则（支持动态路径）"""
        if rule_file is None:
            project_root = Path(__file__).resolve().parents[2]
            file_path = project_root / "snort3-community.rules"
        else:
            file_path = Path(rule_file).expanduser().resolve()
        
        try:
            parsed_rules = self.parser.parse_file(str(file_path))
            for rule in parsed_rules:
                if self.validate_rule(rule):
                    self.rules.append(rule)
                    ebpf_config = self.parser.to_ebpf_config(rule)
                    self.ebpf_configs.append(ebpf_config)
                    # Store SID mapping
                    if 'sid' in ebpf_config:
                        self.sid_to_rule[ebpf_config['sid']] = {
                            'msg': ebpf_config.get('msg', 'Unknown'),
                            'priority': ebpf_config.get('priority', 3),
                            'classtype': ebpf_config.get('classtype', 'unknown')
                        }
        except Exception as e:
            print(f"加载失败: {e} (规则文件: {file_path})")

    def generate_ebpf_code(self):
        return self.tcp_codegen.generate_all_code()

    def load_tcp_rules(self):
        self.load_rules()
        tcp_count = 0
        for config in self.ebpf_configs:
            if config.get("protocol_num") == 6:
                self.tcp_codegen.add_rule(config)
                tcp_count += 1
        print(f"✓ 已加载 {tcp_count} 条 TCP 规则到代码生成器")
        return tcp_count

    def parse_rule(self, rule_line):
        """解析单条规则"""
        if isinstance(rule_line, str):
            ir = self.parser.parse_rule(rule_line)
            if ir and self.validate_rule(ir):
                self.rules.append(ir)
                ebpf_config = self.parser.to_ebpf_config(ir)
                self.ebpf_configs.append(ebpf_config)
                return ir
        return None

    def validate_rule(self, rule):
        """验证规则"""
        required_fields = ['action', 'protocol', 'src_ip', 'src_port',
                          'direction', 'dst_ip', 'dst_port']
        return all(field in rule for field in required_fields)

    def get_rules(self):
        """获取所有规则"""
        return self.rules

    def debug_print_rules(self):
        """打印已解析的规则及生成的 eBPF 配置"""
        print("\n" + "=" * 60)
        print("已解析的 Snort 规则 与 eBPF 配置预览")
        print("=" * 60)
        for idx, (rule, cfg) in enumerate(zip(self.rules, self.ebpf_configs), start=1):
            print(f"\n[规则 #{idx}] 原始解析结果:")
            print(rule)
            print(f"\n[规则 #{idx}] 对应 eBPF 配置:")
            try:
                print(json.dumps(cfg, ensure_ascii=False, indent=2))
            except TypeError:
                print(cfg)
        print("\n" + "=" * 60)


class EventHandler:
    """事件处理器 - Enhanced with alert reporting"""
    def __init__(self, rule_manager, log_file="ids_alerts.log"):
        self.rule_manager = rule_manager
        self.event_count = 0
        self.alert_count = 0
        self.log_file = log_file
        # Create log file with header
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"IDS Alert Log - Session started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n\n")

    def handle_alert(self, cpu, data, size):
        """处理 eBPF 告警事件 - NEW METHOD"""
        import ctypes as ct
        
        # Define alert structure matching eBPF C code
        class AlertEvent(ct.Structure):
            _fields_ = [
                ("rule_id", ct.c_uint32),
                ("priority", ct.c_uint32),
                ("src_ip", ct.c_uint32),
                ("dst_ip", ct.c_uint32),
                ("src_port", ct.c_uint16),
                ("dst_port", ct.c_uint16),
                ("msg", ct.c_char * 256)
            ]
        
        alert = ct.cast(data, ct.POINTER(AlertEvent)).contents
        self.alert_count += 1
        
        # Format IP addresses
        src_ip = self.format_ip(alert.src_ip)
        dst_ip = self.format_ip(alert.dst_ip)
        
        # Get rule info from rule manager
        rule_info = self.rule_manager.sid_to_rule.get(alert.rule_id, {})
        rule_msg = alert.msg.decode('utf-8', errors='ignore').rstrip('\x00')
        
        # Create alert info
        alert_info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "alert_id": self.alert_count,
            "rule_id": alert.rule_id,
            "priority": alert.priority,
            "message": rule_msg or rule_info.get('msg', 'Unknown'),
            "classification": rule_info.get('classtype', 'unknown'),
            "src_ip": src_ip,
            "src_port": alert.src_port,
            "dst_ip": dst_ip,
            "dst_port": alert.dst_port,
            "protocol": "TCP"
        }
        
        # Log the alert
        self.log_alert(alert_info)

    def handle_event(self, cpu, data, size):
        """处理 eBPF 数据包事件"""
        import ctypes as ct
        
        class PacketEvent(ct.Structure):
            _fields_ = [
                ("src_ip", ct.c_uint32),
                ("dst_ip", ct.c_uint32),
                ("src_port", ct.c_uint16),
                ("dst_port", ct.c_uint16),
                ("protocol", ct.c_uint8),
                ("payload_len", ct.c_uint32),
                ("payload", ct.c_uint8 * 256)
            ]
        
        event = ct.cast(data, ct.POINTER(PacketEvent)).contents
        self.event_count += 1
        
        src_ip = self.format_ip(event.src_ip)
        dst_ip = self.format_ip(event.dst_ip)
        
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_map.get(event.protocol, f"Protocol-{event.protocol}")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [事件 #{self.event_count}] {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} "
              f"| {protocol_name} | Payload: {event.payload_len} bytes")

    def format_ip(self, ip_int):
        """格式化 IP 地址"""
        return ".".join(map(str, [
            ip_int & 0xFF,
            (ip_int >> 8) & 0xFF,
            (ip_int >> 16) & 0xFF,
            (ip_int >> 24) & 0xFF
        ]))

    def log_alert(self, alert_info):
        """记录告警信息到控制台和文件"""
        # Console output with color
        alert_line = (
            f"\n{'🚨 ALERT' if alert_info['priority'] <= 2 else '⚠️  ALERT'} "
            f"[{alert_info['timestamp']}] #{alert_info['alert_id']}\n"
            f"  Rule ID: {alert_info['rule_id']} | Priority: {alert_info['priority']}\n"
            f"  Message: {alert_info['message']}\n"
            f"  Classification: {alert_info['classification']}\n"
            f"  Connection: {alert_info['src_ip']}:{alert_info['src_port']} -> "
            f"{alert_info['dst_ip']}:{alert_info['dst_port']}\n"
            f"  Protocol: {alert_info['protocol']}\n"
            f"{'-'*80}"
        )
        print(alert_line)
        
        # File output (append mode)
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{alert_line}\n")
        except Exception as e:
            print(f"Warning: Failed to write alert to log file: {e}")
        
        # Optional: Send to external system (e.g., syslog, SIEM)
        # self.send_to_siem(alert_info)

    def process_packet(self, event):
        """处理数据包事件"""
        # Additional packet processing logic can go here
        pass

    def get_stats(self):
        """获取统计信息"""
        return {
            "total_events": self.event_count,
            "total_alerts": self.alert_count
        }
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDS Manager for eBPF-based TCP rule engine.

- Loads parsed Snort TCP rules from JSON.
- Uses TCPRulesEBPFManager to generate eBPF C code and metadata.
- Compiles and loads the eBPF program via BCC.
"""

import os
import sys
import json
from bcc import BPF

from ebpf_codegen import TCPRulesEBPFManager


# -----------------------------------------------------------------------------
# Path configuration (FIX: avoid extremely long, repeated paths)
# -----------------------------------------------------------------------------

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Assuming this file lives at: <project_root>/src/userspace/ebpf-ids/ids_manager.py
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
KERNEL_DIR = os.path.join(PROJECT_ROOT, "src", "kernel")
USERSAPCE_DIR = os.path.join(PROJECT_ROOT, "src", "userspace", "ebpf-ids")

TCP_RULES_C_PATH = os.path.join(KERNEL_DIR, "tcp_rules.c")
TCP_RULES_META_PATH = os.path.join(KERNEL_DIR, "tcp_rules_metadata.json")

# Example rules JSON location; adjust to your actual path
SNORT_RULES_JSON = os.path.join(PROJECT_ROOT, "snort_rules_ebpf.json")


class IDSManager:
    def __init__(self):
        self.bpf = None
        self.tcp_rules_manager = TCPRulesEBPFManager()

    # -------------------------------------------------------------------------
    # Rule loading and codegen
    # -------------------------------------------------------------------------

    def load_rules(self, json_path: str = SNORT_RULES_JSON):
        """Load parsed Snort rules from JSON and add TCP rules to the codegen."""
        print("初始化 eBPF IDS 系统...")

        if not os.path.isfile(json_path):
            raise FileNotFoundError(f"规则文件未找到: {json_path}")

        with open(json_path, "r") as f:
            all_rules = json.load(f)

        tcp_rules = [r for r in all_rules if r.get("protocol_num") == 6]

        print(f"✓ 已加载 {len(tcp_rules)} 条 TCP 规则到代码生成器")

        for rule in tcp_rules:
            added = self.tcp_rules_manager.add_rule(rule)
            if not added:
                # 非 TCP 规则或解析失败
                continue

    def generate_tcp_rules_code(self):
        """Generate eBPF C code for all TCP rules and export to kernel src dir."""
        print("正在生成 TCP 规则的 eBPF 代码...")
        result = self.tcp_rules_manager.generate_all_code()
        print(f"✓ 已生成 {result['count']} 条 TCP 规则的 eBPF 代码")

        # Ensure kernel directory exists
        os.makedirs(KERNEL_DIR, exist_ok=True)

        # Export code and metadata to short, stable paths
        self.tcp_rules_manager.export_code(TCP_RULES_C_PATH)
        print(f"✓ 已导出 eBPF 代码到: {TCP_RULES_C_PATH}")

        self.tcp_rules_manager.export_metadata(TCP_RULES_META_PATH)
        print(f"✓ 已导出规则元数据到: {TCP_RULES_META_PATH}")

    # -------------------------------------------------------------------------
    # eBPF program compilation and loading
    # -------------------------------------------------------------------------

    def load_ebpf_program(self):
        """Compile and load the generated eBPF program using BCC."""
        print("正在编译 eBPF 程序...")

        # Read generated kernel code
        if not os.path.isfile(TCP_RULES_C_PATH):
            raise FileNotFoundError(f"未找到生成的 eBPF 内核代码: {TCP_RULES_C_PATH}")

        with open(TCP_RULES_C_PATH, "r") as f:
            kernel_code = f.read()

        try:
            # FIX: ensure cwd is a short path so getcwd() inside BCC/Clang does not
            # hit PATH_MAX and return ERANGE ("Numerical result out of range").
            os.chdir(PROJECT_ROOT)

            # Compile BPF from text
            self.bpf = BPF(text=kernel_code)

            # Attach XDP / TC / kprobe, etc., according to your design.
            # Example (XDP on interface eth0):
            # fn = self.bpf.load_func("ids_filter", BPF.XDP)
            # BPF.attach_xdp("eth0", fn, 0)

            print("✓ eBPF 程序编译并加载成功")
        except Exception as e:
            print("getcwd:", os.getcwd())
            print(f"✗ 加载 eBPF 程序失败: {e}")
            raise

    # -------------------------------------------------------------------------
    # High-level orchestration
    # -------------------------------------------------------------------------

    def init_ids(self):
        """High-level initialization sequence."""
        try:
            self.load_rules()
            self.generate_tcp_rules_code()
            self.load_ebpf_program()
            print("✓ IDS 初始化完成")
        except Exception as e:
            print(f"✗ IDS 初始化失败: {e}")
            raise


def main():
    manager = IDSManager()
    manager.init_ids()


if __name__ == "__main__":
    # When invoked directly, ensure we start from the project root or above.
    # This also avoids very long absolute paths if the script is symlinked.
    try:
        os.chdir(PROJECT_ROOT)
    except Exception:
        # If changing directory fails, continue; the manager will still try to
        # correct cwd before BPF(text=...) is called.
        pass

    main()
