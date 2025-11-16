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


class IDSManager:
    """IDS 主管理类"""
    def __init__(self, rules_dir, interface=None):
        self.rules_dir = rules_dir
        if interface is None:
            self.interface = get_active_interface()
        else:
            self.interface = interface
        self.bpf = None
        self.rule_manager = RuleManager(rules_dir)
        self.event_handler = None
        self.project_root = Path(__file__).resolve().parents[2]
        self.default_rule_file = self.project_root / "snort3-community.rules"

    def load_ebpf_program(self):
        try:
            print("正在生成 TCP 规则的 eBPF 代码...")
            result = self.rule_manager.tcp_codegen.generate_all_code()
            print(f"✓ 已生成 {result['count']} 条 TCP 规则的 eBPF 代码")
            
            kernel_code_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "kernel",
                "tcp_rules.c"
            )
            
            self.rule_manager.tcp_codegen.export_code(kernel_code_path)
            print(f"✓ 已导出 eBPF 代码到: {kernel_code_path}")
            
            metadata_path = kernel_code_path.replace(".c", "_metadata.json")
            self.rule_manager.tcp_codegen.export_metadata(metadata_path)
            print(f"✓ 已导出规则元数据到: {metadata_path}")
            
            with open(kernel_code_path, 'r') as f:
                kernel_code = f.read()
            
            print("正在编译 eBPF 程序...")
            from bcc import BPF
            self.bpf = BPF(text=kernel_code)
            print("✓ eBPF 程序编译成功")
            return True
            
        except Exception as e:
            print(f"✗ 加载 eBPF 程序失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def attach_probes(self):
        """附加探针到网络接口"""
        try:
            print(f"附加 eBPF 程序到网络接口: {self.interface}")
            # Uncomment and implement actual attachment
            # function_ids_filter = self.bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
            # BPF.attach_raw_socket(function_ids_filter, self.interface)
            print(f"✓ 已附加到 {self.interface}")
            return True
        except Exception as e:
            print(f"✗ 附加探针失败: {e}")
            print(f"提示: 请确保网络接口 '{self.interface}' 存在")
            print(f"可用接口列表: 运行 'ip link show' 查看")
            return False

    def initialize(self):
        print(f"初始化 eBPF IDS 系统...")
        tcp_count = self.rule_manager.load_tcp_rules()
        
        if not self.load_ebpf_program():
            return False
        
        # Create event handler with alert logging
        self.event_handler = EventHandler(self.rule_manager, log_file="ids_alerts.log")
        
        if not self.attach_probes():
            return False
        
        return True

    def start(self):
        """启动 IDS 监控"""
        if not self.initialize():
            print("✗ IDS 初始化失败")
            return
        
        print("=" * 60)
        print("✓ eBPF IDS 启动成功，开始监控网络流量...")
        print(f"✓ 告警日志文件: {self.event_handler.log_file}")
        print("=" * 60)
        print("按 Ctrl+C 停止监控\n")
        
        # Open perf buffers for both alerts and events
        try:
            # Attach alert handler to "alerts" perf buffer
            self.bpf["alerts"].open_perf_buffer(self.event_handler.handle_alert)
            print("✓ Alert perf buffer 已连接")
        except KeyError:
            print("⚠️  警告: 'alerts' perf buffer 未找到，告警功能可能不可用")
        
        try:
            # Optional: attach packet event handler if needed
            # self.bpf["events"].open_perf_buffer(self.event_handler.handle_event)
            pass
        except KeyError:
            pass
        
        # Event polling loop
        try:
            print("开始轮询事件...\n")
            while True:
                self.bpf.perf_buffer_poll(timeout=100)  # Poll with 100ms timeout
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """停止 IDS"""
        print("\n" + "=" * 60)
        if self.event_handler:
            stats = self.event_handler.get_stats()
            print(f"监控已停止")
            print(f"  总事件数: {stats['total_events']}")
            print(f"  总告警数: {stats['total_alerts']}")
            print(f"  告警日志: {self.event_handler.log_file}")
        print("=" * 60)


def main():
    """主函数"""
    rules_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "rules"
    )
    
    ids = IDSManager(rules_dir=rules_dir)
    
    def signal_handler(sig, frame):
        ids.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    ids.start()


if __name__ == "__main__":
    main()
