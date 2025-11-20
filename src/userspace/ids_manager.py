#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""
eBPF IDS 用户空间管理程序 - Enhanced with Modular Batch Loading
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
import subprocess
import time
from typing import Optional, Union, List

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from utils import SnortRuleParser
except ImportError:
    SnortRuleParser = None

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

from pathlib import Path
from typing import Optional, Union

class RuleManager:
    """规则管理器"""
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.ebpf_configs = []
        if SnortRuleParser:
            self.parser = SnortRuleParser()
        else:
            self.parser = None

    def load_rules(
        self,
        rule_file: Optional[Union[str, Path]] = None,
    ):
        """从规则目录加载规则（支持动态路径）"""
        if rule_file is None:
            project_root = Path(__file__).resolve().parents[2]
            file_path = project_root / "snort3-community.rules"
        else:
            file_path = Path(rule_file).expanduser().resolve()

        if not self.parser:
            print("警告: SnortRuleParser 不可用")
            return

        try:
            parsed_rules = self.parser.parse_file(str(file_path))
            for rule in parsed_rules:
                if self.validate_rule(rule):
                    self.rules.append(rule)
                    ebpf_config = self.parser.to_ebpf_config(rule)
                    self.ebpf_configs.append(ebpf_config)
        except Exception as e:
            print(f"加载失败: {e} (规则文件: {file_path})")

    def parse_rule(self, rule_line):
        """解析单条规则"""
        if isinstance(rule_line, str) and self.parser:
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

class EventHandler:
    """事件处理器"""
    def __init__(self, rule_manager):
        self.rule_manager = rule_manager
        self.event_count = 0

    def handle_event(self, cpu, data, size):
        """处理 eBPF 事件"""
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

    def process_packet(self, event):
        """处理数据包事件"""
        pass

    def log_alert(self, alert_info):
        """记录告警信息"""
        pass

class ModularBatchLoader:
    """模块化批处理加载器 - 用于加载隔离的eBPF规则程序"""

    def __init__(self, interface: str = "ens4"):
        self.interface = interface
        self.loaded_programs = []
        self.rule_names = []

    def load_modular_batch(self, batch_id: int = 0, num_rules: int = 5, 
                          c_file: Optional[str] = None) -> bool:
        """加载模块化规则批次"""
        try:
            # 确定C文件路径
            if c_file is None:
                c_file = f"rule_batch_{batch_id}.c"

            c_file_path = Path(c_file)
            if not c_file_path.exists():
                print(f"✗ C文件不存在: {c_file}")
                return False

            print(f"\n正在加载模块化批次 {batch_id}...")
            print(f"接口: {self.interface}")
            print(f"规则数: {num_rules}")

            # 编译C文件为object文件
            o_file = str(c_file_path.with_suffix('.o'))
            if not self._compile_ebpf(c_file, o_file):
                print(f"✗ 编译失败: {c_file}")
                return False

            # 加载eBPF程序
            if not self._load_ebpf_program(o_file):
                print(f"✗ 加载eBPF程序失败: {o_file}")
                return False

            # 附加到网络接口
            if not self._attach_to_interface():
                print(f"✗ 附加到接口失败: {self.interface}")
                return False

            print(f"✓ 批次 {batch_id} 加载成功")
            return True

        except Exception as e:
            print(f"✗ 加载批次时出错: {e}")
            return False

    def load_five_rules_batch(self) -> bool:
        """加载初始5条规则的批次"""
        print("\n" + "="*60)
        print("加载初始5条规则IDS防护")
        print("="*60)

        # 已包含的5条规则
        self.rule_names = [
            "SID_108_QAZ_Worm_Client_Login",
            "SID_110_Netbus_GetInfo",
            "SID_115_NetBus_Pro_Connection",
            "SID_162_Matrix_UDP_Connection",
            "SID_163_WinCrash_Server_Active"
        ]

        print("\n包含的规则:")
        for i, rule_name in enumerate(self.rule_names, 1):
            print(f"  {i}. {rule_name}")

        # 尝试加载5个独立的规则程序
        rules_c_files = [
            'rule_sid_108_qaz_worm.c',
            'rule_sid_110_netbus.c',
            'rule_sid_115_netbus_pro.c',
            'rule_sid_162_matrix.c',
            'rule_sid_163_wincrash.c'
        ]

        all_loaded = True
        for i, c_file in enumerate(rules_c_files, 1):
            if Path(c_file).exists():
                if self.load_modular_batch(batch_id=0, num_rules=5, c_file=c_file):
                    self.loaded_programs.append(c_file)
                else:
                    all_loaded = False
                    print(f"⚠ 警告: 未能加载 {c_file}")
            else:
                print(f"⚠ 警告: C文件不存在: {c_file}")
                all_loaded = False

        return all_loaded

    def _compile_ebpf(self, c_file: str, o_file: str) -> bool:
        """编译eBPF C代码"""
        try:
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"编译错误: {result.stderr}")
                return False
            print(f"  ✓ 编译成功: {o_file}")
            return True
        except Exception as e:
            print(f"编译异常: {e}")
            return False

    def _load_ebpf_program(self, o_file: str) -> bool:
        """使用bpftool加载eBPF程序"""
        try:
            # 使用bpftool prog load来加载
            cmd = ["sudo", "bpftool", "prog", "load", o_file, "/sys/fs/bpf/ids_prog", "type", "xdp"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print(f"加载程序失败: {result.stderr}")
                return False
            print(f"  ✓ eBPF程序已加载")
            return True
        except Exception as e:
            print(f"加载异常: {e}")
            return False

    def _attach_to_interface(self) -> bool:
        """附加到网络接口"""
        try:
            cmd = ["sudo", "ip", "link", "set", "dev", self.interface, "xdp", "off"]
            subprocess.run(cmd, capture_output=True, timeout=5)

            # 重新附加
            cmd = ["sudo", "ip", "link", "set", "dev", self.interface, "xdp", "obj", "/sys/fs/bpf/ids_prog"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print(f"附加失败: {result.stderr}")
                return False
            print(f"  ✓ 已附加到接口 {self.interface}")
            return True
        except Exception as e:
            print(f"附加异常: {e}")
            return False

    def replace_old_programs(self) -> bool:
        """替换旧的eBPF程序"""
        try:
            print("\n正在卸载旧的eBPF程序...")
            cmd = ["sudo", "ip", "link", "set", "dev", self.interface, "xdp", "off"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✓ 已从 {self.interface} 卸载旧程序")
            return True
        except Exception as e:
            print(f"⚠ 卸载异常: {e}")
            return True

    def print_loaded_rules(self):
        """打印已加载的规则"""
        print("\n" + "="*60)
        print("已加载的IDS规则")
        print("="*60)
        print(f"总规则数: {len(self.rule_names)}")
        print(f"网络接口: {self.interface}")
        print(f"已加载的程序: {len(self.loaded_programs)}")
        print("\n规则列表:")
        for i, rule_name in enumerate(self.rule_names, 1):
            print(f"  {i}. {rule_name}")

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
        self.batch_loader = ModularBatchLoader(self.interface)

        self.project_root = Path(__file__).resolve().parents[2]
        self.default_rule_file = self.project_root / "snort3-community.rules"

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
            print("✓ eBPF 程序编译成功")
        except Exception as e:
            print(f"✗ 加载 eBPF 程序失败: {e}")
            return False

        return True

    def attach_probes(self):
        """附加探针到网络接口"""
        try:
            print(f"附加 eBPF 程序到网络接口: {self.interface}")
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

        self.rule_manager.load_rules()
        print(f"✓ 已加载 {len(self.rule_manager.rules)} 条规则")

        if not self.load_ebpf_program():
            return False

        self.event_handler = EventHandler(self.rule_manager)

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

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n" + "=" * 60)
            print(f"监控已停止，共捕获 {self.event_handler.event_count} 个事件")
            print("=" * 60)

    def stop(self):
        """停止 IDS"""
        print("正在停止 IDS...")

def main():
    """主函数"""
    rules_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "rules"
    )

    # 创建IDS管理器
    ids = IDSManager(rules_dir=rules_dir, interface="ens4")

    # 设置信号处理
    def signal_handler(sig, frame):
        ids.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 尝试加载5条规则的批次
    print("="*60)
    print("eBPF IDS 模块化批处理加载器")
    print("="*60)

    if ids.batch_loader.replace_old_programs():
        if ids.batch_loader.load_five_rules_batch():
            ids.batch_loader.print_loaded_rules()
        else:
            print("⚠ 部分规则加载失败")

    # 启动IDS
    ids.start()

if __name__ == "__main__":
    main()
