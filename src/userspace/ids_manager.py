#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""
eBPF IDS 用户空间管理程序
"""

import os
from pathlib import Path  # at top of file
import sys
import json
import signal
import socket
import fcntl
import struct
import array
from datetime import datetime
import sys
import os
from typing import Optional, Union

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from utils import SnortRuleParser

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

from pathlib import Path
from typing import Optional, Union

class RuleManager:
    """规则管理器"""
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.ebpf_configs = []
        self.parser = SnortRuleParser()
        from ebpf_codegen import TCPRulesEBPFManager
        self.tcp_codegen = TCPRulesEBPFManager()


    def load_rules(
        self,
        rule_file: Optional[Union[str, Path]] = None,
    ):
        """从规则目录加载规则（支持动态路径）"""

        if rule_file is None:
            # 方案 A：规则文件放在 rules 目录
            # file_path = self.rules_dir / "snort3-community.rules"

            # 方案 B：规则文件放在项目根目录（和原来一样）
            project_root = Path(__file__).resolve().parents[2]
            file_path = project_root / "snort3-community.rules"
        else:
            # 支持 "~" 等写法，并转换成绝对路径
            file_path = Path(rule_file).expanduser().resolve()

        try:
            parsed_rules = self.parser.parse_file(str(file_path))
            for rule in parsed_rules:
                if self.validate_rule(rule):
                    self.rules.append(rule)
                    ebpf_config = self.parser.to_ebpf_config(rule)
                    self.ebpf_configs.append(ebpf_config)
        except Exception as e:
            print(f"加载失败: {e} (规则文件: {file_path})")

    def generate_ebpf_code(self):
        return self.tcp_codegen.generate_all_code()
    
    def load_tcp_rules(self):
    # Load all rules first
        self.load_rules()
    
    # Filter TCP rules (protocol_num == 6) and add to code generator
        tcp_count = 0
        for config in self.ebpf_configs:
            if config.get("protocol_num") == 6:  # TCP only
                self.tcp_codegen.add_rule(config)
                tcp_count += 1
    
        print(f"✓ 已加载 {tcp_count} 条 TCP 规则到代码生成器")
        return tcp_count

    
    def parse_rule(self, rule_line):
        """解析单条规则"""
        if isinstance(rule_line, str):
            # 调用 parser 实例的方法
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
            # 如果 ebpf_config 是 dict 或 list，使用 JSON 格式输出更清晰
            try:
                print(json.dumps(cfg, ensure_ascii=False, indent=2))
            except TypeError:
                # 不可 JSON 序列化时退回到 pprint
                print(cfg)
        print("\n" + "=" * 60)

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
          # 项目根目录：.../ebpf-ids
        self.project_root = Path(__file__).resolve().parents[2]
        # 规则文件默认路径
        self.default_rule_file = self.project_root / "snort3-community.rules"

    def load_ebpf_program(self):
        try:
            print("正在生成 TCP 规则的 eBPF 代码...")
        
        # Step 1: Generate TCP rule eBPF code
            result = self.rule_manager.tcp_codegen.generate_all_code()
            print(f"✓ 已生成 {result['count']} 条 TCP 规则的 eBPF 代码")
        
        # Step 2: Export generated code to file
            kernel_code_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "kernel",
            "tcp_rules.c"  # Changed from "ids_ebpf.c" to "tcp_rules.c"
            )
            self.rule_manager.tcp_codegen.export_code(kernel_code_path)
            print(f"✓ 已导出 eBPF 代码到: {kernel_code_path}")
        
        # Step 3: Export metadata for reference
            metadata_path = kernel_code_path.replace(".c", "_metadata.json")
            self.rule_manager.tcp_codegen.export_metadata(metadata_path)
            print(f"✓ 已导出规则元数据到: {metadata_path}")
        
        # Step 4: Read the generated code
            with open(kernel_code_path, 'r') as f:
             kernel_code = f.read()
        
        # Step 5: Compile eBPF code
            print("正在编译 eBPF 程序...")
            from bcc import BPF
            self.bpf = BPF(text=kernel_code)
            print("✓ eBPF 程序编译成功")
        
            return True
        
        except Exception as e:
               print(f"✗ 加载 eBPF 程序失败: {e}")
               import traceback
               traceback.print_exc()  # Print full error traceback for debugging
               return False

    def attach_probes(self):
        """附加探针到网络接口"""
        try:
            print(f"附加 eBPF 程序到网络接口: {self.interface}")
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
    
    # Load TCP rules and prepare code generator
        tcp_count = self.rule_manager.load_tcp_rules()
    
    # Load eBPF program (which will generate and compile code)
        if not self.load_ebpf_program():
         return False
    
    # Create event handler
        self.event_handler = EventHandler(self.rule_manager)
    
    # Attach probes
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
        # self.bpf["events"].open_perf_buffer(self.event_handler.handle_event)

        # 事件轮询循环
        try:
            while True:
                pass
                # self.bpf.perf_buffer_poll()
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
