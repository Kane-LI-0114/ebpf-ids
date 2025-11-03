#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF IDS 用户空间管理程序
"""

import os
import sys
import json
import signal
from bcc import BPF
from datetime import datetime


class RuleManager:
    """规则管理器"""
    
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = []
        
    def load_rules(self):
        """从规则目录加载规则"""
        # TODO: 实现规则加载逻辑
        pass
    
    def parse_rule(self, rule_data):
        """解析单条规则"""
        # TODO: 实现规则解析逻辑
        pass
    
    def validate_rule(self, rule):
        """验证规则有效性"""
        # TODO: 实现规则验证逻辑
        return True
    
    def get_rules(self):
        """获取所有规则"""
        return self.rules


class EventHandler:
    """事件处理器"""
    
    def __init__(self, rule_manager):
        self.rule_manager = rule_manager
        self.event_count = 0
        
    def handle_event(self, cpu, data, size):
        """处理 eBPF 事件"""
        import ctypes as ct
        
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
        
        # 格式化 IP 地址
        src_ip = self.format_ip(event.src_ip)
        dst_ip = self.format_ip(event.dst_ip)
        
        # 协议名称映射
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_map.get(event.protocol, f"Protocol-{event.protocol}")
        
        # 打印事件日志
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
    
    def process_packet(self, event):
        """处理数据包事件"""
        # TODO: 实现数据包处理逻辑
        pass
    
    def log_alert(self, alert_info):
        """记录告警信息"""
        # TODO: 实现告警日志记录
        pass


class IDSManager:
    """IDS 主管理类"""
    
    def __init__(self, rules_dir, interface="eth0"):
        self.rules_dir = rules_dir
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
        except Exception as e:
            print(f"✗ 附加探针失败: {e}")
            print(f"提示: 请确保网络接口 '{self.interface}' 存在")
            print(f"可用接口列表: 运行 'ip link show' 查看")
    
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
        self.attach_probes()
        
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
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n" + "=" * 60)
            print(f"监控已停止，共捕获 {self.event_handler.event_count} 个事件")
            print("=" * 60)
    
    def stop(self):
        """停止 IDS"""
        print("正在停止 IDS...")
        # TODO: 实现清理逻辑
        pass


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
