#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF IDS 用户空间管理程序
"""

import os
import sys
import json
import signal
import socket
import fcntl
import struct
import array
from bcc import BPF
from datetime import datetime
from dataclasses import dataclass, field

@dataclass
class DebugConfig:
    """调试配置"""
    enabled: bool = True                        # 是否启用调试模式
    print_interval: int = 100                   # 每 N 个事件打印一次普通流量
    stats_interval: int = 5                     # 每 N 秒打印一次统计信息
    ssh_interval: int = 1000                    # SSH 流量每 N 个包打印一次
    icmp_interval: int = 10                     # ICMP 流量每 N 个包打印一次
    important_ports: list = field(default_factory=lambda: [80, 443, 8080, 21, 23, 3306, 5432])
    alert_dedup_timeout: int = 10               # 告警去重时间（秒）

debug = DebugConfig()

def get_active_interface():
    """自动检测活动的网络接口"""
    try:
        # 读取 /proc/net/dev 获取所有网络接口
        with open('/proc/net/dev', 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        interfaces = []
        for line in lines[2:]:  # 跳过头两行
            if ':' in line:
                iface_name = line.split(':')[0].strip()
                # 排除回环接口
                if iface_name != 'lo':
                    interfaces.append(iface_name)
        
        if interfaces:
            # 返回第一个非回环接口
            return interfaces[0]
        
        # 如果没有找到，返回默认值
        return 'eth0'
    
    except Exception as e:
        print(f"警告: 无法自动检测网络接口: {e}")
        return 'eth0'


class RuleManager:
    """规则管理器"""
    
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = []
        self.rules_by_sid = {}  # SID -> 规则映射
        self.loaded = False
        
    def load_rules(self):
        """从规则目录加载规则"""
        from rule_loader import RuleLoader, RuleParser
        
        print(f"正在从 {self.rules_dir} 加载规则...")
        
        loader = RuleLoader(self.rules_dir)
        raw_rules = loader.load_all_rules()
        
        if not raw_rules:
            print("  警告: 未找到规则文件")
            return
        
        print(f"正在解析 {len(raw_rules)} 条规则...")
        self.rules = RuleParser.compile_rules(raw_rules)
        
        # 建立 SID 索引
        for rule in self.rules:
            sid = rule['sid']
            self.rules_by_sid[sid] = rule
        
        print(f"✓ 成功加载 {len(self.rules)} 条规则")
        self.loaded = True
        
        # 打印规则统计
        self._print_statistics()
    
    def _print_statistics(self):
        """打印规则统计信息"""
        if not self.rules:
            return
        
        # 统计协议
        protocol_count = {}
        for rule in self.rules:
            proto = rule['protocol']
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 0: 'ANY'}.get(proto, f'Proto-{proto}')
            protocol_count[proto_name] = protocol_count.get(proto_name, 0) + 1
        
        print("\n规则统计:")
        print(f"  总规则数: {len(self.rules)}")
        print(f"  协议分布:")
        for proto, count in sorted(protocol_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"    - {proto}: {count}")
    
    def get_rule_by_sid(self, sid):
        """根据 SID 获取规则"""
        return self.rules_by_sid.get(sid)
    
    def match_rule(self, packet_event):
        """
        匹配数据包与规则
        返回: 匹配的规则列表
        """
        matched_rules = []
        
        for rule in self.rules[:100]:  # 先只检查前100条规则（性能优化）
            if self._match_single_rule(rule, packet_event):
                matched_rules.append(rule)
        
        return matched_rules
    
    def _match_single_rule(self, rule, event):
        """
        检查单条规则是否匹配
        """
        # 1. 匹配协议
        if rule['protocol'] != 0 and rule['protocol'] != event.protocol:
            return False
    
        # 2. 对于ICMP协议，跳过端口检查
        if event.protocol == 1:  # ICMP
            # ICMP没有端口概念，只要协议匹配就继续检查content
            pass
        else:
            # 对于TCP/UDP，检查端口
            if not self._match_port(rule['src_port'], event.src_port):
                return False
            if not self._match_port(rule['dst_port'], event.dst_port):
                return False
    
        # 3. 匹配 content (如果有)
        if rule['content'] and len(rule['content']) > 0:
            if event.protocol == 1:
                print(f"[CONTENT调试] 实际payload: {event.payload} ")
            if not self._match_content(rule['content'], event.payload, 
                                       event.payload_len, rule['content_depth']):
                return False
        
        return True
    
    def _match_port(self, port_rule, packet_port):
        """
        匹配端口
        port_rule: (type, value1, value2)
        """
        port_type, val1, val2 = port_rule
        
        if port_type == 0:  # any
            return True
        elif port_type == 1:  # single
            return packet_port == val1
        elif port_type == 2:  # range
            return val1 <= packet_port <= val2
        elif port_type == 3:  # list
            return packet_port == val1 or packet_port == val2
        
        return False
    
    def _match_content(self, pattern, payload, payload_len, depth):
        """
        在 payload 中搜索 pattern
        """
        if payload_len < len(pattern):
            return False
    
        search_len = min(depth, payload_len) if depth > 0 else payload_len
    
        # 转换 payload 为 bytes
        payload_bytes = bytes(payload[:payload_len])
    
        # 在指定深度内搜索
        search_area = payload_bytes[:search_len]
        return pattern in search_area
    
    def get_rules(self):
        """获取所有规则"""
        return self.rules


class EventHandler:
    """事件处理器"""
    
    def __init__(self, rule_manager):
        self.rule_manager = rule_manager
        self.event_count = 0
        self.alert_count = 0
        self.last_alerts = {}  # 用于去重：(src_ip, dst_ip, sid) -> timestamp
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        
    def handle_event(self, cpu, data, size):
        """处理 eBPF 事件"""
        import ctypes as ct
        from datetime import datetime
        import time
        
        # 定义数据结构以匹配 C 结构体
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
        
        # 统计协议
        if event.protocol == 6:
            self.tcp_count += 1
        elif event.protocol == 17:
            self.udp_count += 1
        elif event.protocol == 1:
            self.icmp_count += 1
        
        # 格式化 IP 地址
        src_ip = self.format_ip(event.src_ip)
        dst_ip = self.format_ip(event.dst_ip)
        
        # 协议名称映射
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_map.get(event.protocol, f"Protocol-{event.protocol}")
        
        # 调试输出：根据配置决定是否打印
        if debug.enabled:
            should_print = False
            if event.protocol == 6:  # TCP
                # 重要端口立即打印（排除22端口避免SSH刷屏）
                if event.dst_port in debug.important_ports:
                    should_print = True
                # SSH 端口按配置频率打印
                elif event.dst_port == 22 and self.tcp_count % debug.ssh_interval == 1:
                    should_print = True
            elif event.protocol == 1:  # ICMP
                should_print = (self.icmp_count % debug.icmp_interval == 1)
            
            if should_print or self.event_count % debug.print_interval == 0:
                print(f"[调试] 事件#{self.event_count} | {protocol_name} | {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} | Payload: {event.payload_len}B")
        
        # 匹配规则
        matched_rules = self.rule_manager.match_rule(event)
        
        if matched_rules:
            # 有规则匹配，生成告警
            for rule in matched_rules:
                # 去重检查（同一个源目标对，同一规则，在配置的时间内只告警一次）
                alert_key = (event.src_ip, event.dst_ip, rule['sid'])
                current_time = time.time()
                
                if alert_key in self.last_alerts:
                    if current_time - self.last_alerts[alert_key] < debug.alert_dedup_timeout:
                        continue  # 跳过重复告警
                
                self.last_alerts[alert_key] = current_time
                self.alert_count += 1
                
                # 打印告警
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n{'='*80}")
                print(f"[ALERT #{self.alert_count}] {timestamp}")
                print(f"{'='*80}")
                print(f"规则: [{rule['sid']}] {rule['msg']}")
                print(f"分类: {rule['classtype']} | 优先级: {rule['priority']}")
                print(f"协议: {protocol_name}")
                print(f"源地址: {src_ip}:{event.src_port}")
                print(f"目标地址: {dst_ip}:{event.dst_port}")
                
                # 显示匹配的内容
                if rule['content'] and event.payload_len > 0:
                    print(f"匹配内容: {self._format_payload(rule['content'])}")
                    print(f"数据包载荷: {self._format_payload(bytes(event.payload[:min(32, event.payload_len)]))}")
                
                print(f"{'='*80}\n")
        # else 分支已被调试输出替代
    
    def format_ip(self, ip_int):
        """格式化 IP 地址"""
        return ".".join(map(str, [
            ip_int & 0xFF,
            (ip_int >> 8) & 0xFF,
            (ip_int >> 16) & 0xFF,
            (ip_int >> 24) & 0xFF
        ]))
    
    def _format_payload(self, data):
        """格式化 payload 为十六进制和 ASCII"""
        hex_str = ' '.join(f'{b:02x}' for b in data[:32])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:32])
        return f"{hex_str} | {ascii_str}"
    
    def get_statistics(self):
        """获取统计信息"""
        return {
            'total_events': self.event_count,
            'total_alerts': self.alert_count,
        }


class IDSManager:
    """IDS 主管理类"""
    
    def __init__(self, rules_dir, interface=None):
        self.rules_dir = rules_dir
        # 如果没有指定接口，自动检测
        if interface is None:
            self.interface = get_active_interface()
        else:
            self.interface = interface
        self.bpf = None
        self.rule_manager = RuleManager(rules_dir)
        self.event_handler = None
        
    def load_ebpf_program(self):
        """加载 eBPF 程序"""
        kernel_code_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "kernel",
            "ids_ebpf.c"
        )
        
        try:
            print(f"正在加载 eBPF 程序: {kernel_code_path}")
            with open(kernel_code_path, 'r') as f:
                kernel_code = f.read()
            
            print("编译 eBPF 程序...")
            self.bpf = BPF(text=kernel_code)
            print("✓ eBPF 程序编译成功")
            
        except Exception as e:
            print(f"✗ 加载 eBPF 程序失败: {e}")
            return False
        
        return True
    
    def attach_probes(self):
        """附加探针到网络接口"""
        try:
            print(f"附加 eBPF 程序到网络接口: {self.interface}")
            function_ids_filter = self.bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
            BPF.attach_raw_socket(function_ids_filter, self.interface)
            print(f"✓ 已附加到 {self.interface}")
            return True
        except Exception as e:
            print(f"✗ 附加探针失败: {e}")
            print(f"提示: 请确保网络接口 '{self.interface}' 存在")
            print(f"可用接口列表: 运行 'ip link show' 查看")
            return False
    
    def initialize(self):
        """初始化 IDS 系统"""
        print(f"初始化 eBPF IDS 系统...")
        print(f"规则目录: {self.rules_dir}")
        print(f"网络接口: {self.interface}")
        
        # 加载规则
        self.rule_manager.load_rules()
        
        # 加载 eBPF 程序
        if not self.load_ebpf_program():
            return False
        
        # 创建事件处理器
        self.event_handler = EventHandler(self.rule_manager)
        
        # 附加探针
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
        print("=" * 60)
        print("按 Ctrl+C 停止监控\n")
        
        # 打开 perf buffer 并设置回调
        self.bpf["events"].open_perf_buffer(self.event_handler.handle_event)
        
        # 事件轮询循环
        import time
        last_stats_time = time.time()
        
        try:
            while True:
                self.bpf.perf_buffer_poll(timeout=100)
                
                # 根据配置定期打印调试统计
                current_time = time.time()
                if debug.enabled and current_time - last_stats_time >= debug.stats_interval:
                    self._print_debug_stats()
                    last_stats_time = current_time
        except KeyboardInterrupt:
            print("\n" + "=" * 60)
            print(f"监控已停止，共捕获 {self.event_handler.event_count} 个事件")
            print("=" * 60)
    
    def _print_debug_stats(self):
        """打印调试统计信息"""
        try:
            debug_map = self.bpf.get_table("debug_counters")
            print("\n" + "="*60)
            print("[调试统计]")
            print(f"  eBPF 内核计数器:")
            print(f"    总数据包: {debug_map[0].value}")
            print(f"    IP 数据包: {debug_map[1].value}")
            print(f"    TCP 数据包: {debug_map[2].value}")
            print(f"    UDP 数据包: {debug_map[3].value}")
            print(f"    ICMP 数据包: {debug_map[4].value}")
            print(f"    匹配的数据包: {debug_map[5].value}")
            print(f"    解析错误: {debug_map[6].value}")
            print(f"    已提交事件: {debug_map[7].value}")
            print(f"  用户空间计数器:")
            print(f"    接收事件数: {self.event_handler.event_count}")
            print(f"    TCP: {self.event_handler.tcp_count}")
            print(f"    UDP: {self.event_handler.udp_count}")
            print(f"    ICMP: {self.event_handler.icmp_count}")
            print(f"    告警数: {self.event_handler.alert_count}")
            print("="*60 + "\n")
        except Exception as e:
            print(f"[调试] 无法读取调试统计: {e}")
    
    def stop(self):
        """停止 IDS"""
        print("\n正在停止 IDS...")
        
        if self.event_handler:
            stats = self.event_handler.get_statistics()
            print(f"\n最终统计:")
            print(f"  总事件数: {stats['total_events']}")
            print(f"  告警次数: {stats['total_alerts']}")
            
        print("IDS 已停止")


def main():
    """主函数"""
    # 规则目录路径
    rules_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "rules"
    )
    
    # 创建 IDS 管理器
    ids = IDSManager(rules_dir=rules_dir)
    
    # 设置信号处理
    def signal_handler(sig, frame):
        ids.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动 IDS
    ids.start()


if __name__ == "__main__":
    main()
