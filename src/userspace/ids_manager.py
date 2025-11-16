#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF IDS 用户空间管理程序

- 使用 SnortRuleParser 解析 snort3-community.rules（用于告警信息映射）
- 使用 TCPRulesEBPFManager 生成 eBPF C 代码并导出到内核目录
- 使用 BCC 编译、加载、挂载 eBPF 程序（SOCKET_FILTER）
- 打开 perf buffer alerts，使用 EventHandler 接收并输出告警
- 进入循环，持续从内核读取事件
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

from bcc import BPF

# 让 utils.SnortRuleParser 可以被导入
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from utils import SnortRuleParser


# ---------------------------------------------------------------------------
# 工具函数：自动检测活动网口
# ---------------------------------------------------------------------------

def get_active_interface() -> str:
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


# ---------------------------------------------------------------------------
# 规则管理器：使用 SnortRuleParser 解析规则，并构建 SID -> 规则信息 映射
# ---------------------------------------------------------------------------

class RuleManager:
    """规则管理器"""

    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.ebpf_configs = []
        self.parser = SnortRuleParser()

        # eBPF 代码生成管理器
        from ebpf_codegen import TCPRulesEBPFManager
        self.tcp_codegen = TCPRulesEBPFManager()

        # SID 映射: {sid: {msg, priority, classtype}}
        self.sid_to_rule = {}

    def load_rules(self, rule_file: Optional[Union[str, Path]] = None):
        """从规则目录加载规则（支持动态路径），并构建 sid_to_rule"""
        if rule_file is None:
            # 默认从项目根目录/snort3-community.rules 读取
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

                    # 存储 SID 映射（供 EventHandler 使用）
                    if 'sid' in ebpf_config:
                        self.sid_to_rule[ebpf_config['sid']] = {
                            'msg': ebpf_config.get('msg', 'Unknown'),
                            'priority': ebpf_config.get('priority', 3),
                            'classtype': ebpf_config.get('classtype', 'unknown'),
                        }
        except Exception as e:
            print(f"加载失败: {e} (规则文件: {file_path})")

    def generate_ebpf_code(self):
        """示例：如果你还需要用 RuleManager 来生成代码"""
        return self.tcp_codegen.generate_all_code()

    def load_tcp_rules(self) -> int:
        """将 TCP 规则加入代码生成器（如果你想通过 RuleManager 来做）"""
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

    @staticmethod
    def validate_rule(rule) -> bool:
        """验证规则"""
        required_fields = [
            'action', 'protocol', 'src_ip', 'src_port',
            'direction', 'dst_ip', 'dst_port'
        ]
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


# ---------------------------------------------------------------------------
# 事件处理器：接收 eBPF perf buffer 中的告警
# ---------------------------------------------------------------------------

class EventHandler:
    """事件处理器 - Enhanced with alert reporting"""

    def __init__(self, rule_manager: RuleManager, log_file: str = "ids_alerts.log"):
        self.rule_manager = rule_manager
        self.event_count = 0
        self.alert_count = 0
        self.log_file = log_file

        # 创建日志文件头
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'=' * 80}\n")
            f.write(
                f"IDS Alert Log - Session started at "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write(f"{'=' * 80}\n\n")

    def handle_alert(self, cpu, data, size):
        """处理 eBPF 告警事件"""
        import ctypes as ct

        # 要保证这里的结构体布局和内核 C 代码中 perf 事件结构体完全一致
        class AlertEvent(ct.Structure):
            _fields_ = [
                ("rule_id", ct.c_uint32),
                ("priority", ct.c_uint32),
                ("src_ip", ct.c_uint32),
                ("dst_ip", ct.c_uint32),
                ("src_port", ct.c_uint16),
                ("dst_port", ct.c_uint16),
                ("msg", ct.c_char * 256),
            ]

        alert = ct.cast(data, ct.POINTER(AlertEvent)).contents
        self.alert_count += 1

        # 格式化 IP
        src_ip = self.format_ip(alert.src_ip)
        dst_ip = self.format_ip(alert.dst_ip)

        # 从 RuleManager 里查 rule_id 对应信息
        rule_info = self.rule_manager.sid_to_rule.get(alert.rule_id, {})
        rule_msg = alert.msg.decode('utf-8', errors='ignore').rstrip('\x00')

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
            "protocol": "TCP",
        }

        self.log_alert(alert_info)

    @staticmethod
    def format_ip(ip_int: int) -> str:
        """格式化 IP 地址（假定小端存储）"""
        return ".".join(
            map(
                str,
                [
                    ip_int & 0xFF,
                    (ip_int >> 8) & 0xFF,
                    (ip_int >> 16) & 0xFF,
                    (ip_int >> 24) & 0xFF,
                ],
            )
        )

    def log_alert(self, alert_info: dict):
        """记录告警信息到控制台和文件"""
        # 控制台输出
        alert_line = (
            f"\n{'🚨 ALERT' if alert_info['priority'] <= 2 else '⚠️ ALERT'} "
            f"[{alert_info['timestamp']}] #{alert_info['alert_id']}\n"
            f" Rule ID: {alert_info['rule_id']} | Priority: {alert_info['priority']}\n"
            f" Message: {alert_info['message']}\n"
            f" Classification: {alert_info['classification']}\n"
            f" Connection: {alert_info['src_ip']}:{alert_info['src_port']} -> "
            f"{alert_info['dst_ip']}:{alert_info['dst_port']}\n"
            f" Protocol: {alert_info['protocol']}\n"
            f"{'-' * 80}"
        )

        print(alert_line)

        # 写入文件
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{alert_line}\n")
        except Exception as e:
            print(f"Warning: Failed to write alert to log file: {e}")

    def process_packet(self, event):
        """可选：额外的数据包处理逻辑"""
        pass

    def get_stats(self):
        """获取统计信息"""
        return {
            "total_events": self.event_count,
            "total_alerts": self.alert_count,
        }


# ---------------------------------------------------------------------------
# IDS Manager: 规则加载 + eBPF 生成 + 编译加载 + 挂载 + 事件循环
# ---------------------------------------------------------------------------

# 路径配置（基于你原来的版本）
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
KERNEL_DIR = os.path.join(PROJECT_ROOT, "src", "kernel")
USERSPACE_DIR = os.path.join(PROJECT_ROOT, "src", "userspace", "ebpf-ids")

TCP_RULES_C_PATH = os.path.join(KERNEL_DIR, "tcp_rules.c")
TCP_RULES_META_PATH = os.path.join(KERNEL_DIR, "tcp_rules_metadata.json")
SNORT_RULES_JSON = os.path.join(PROJECT_ROOT, "snort_rules_ebpf.json")


from ebpf_codegen import TCPRulesEBPFManager


class IDSManager:
    def __init__(self):
        self.bpf: Optional[BPF] = None
        self.tcp_rules_manager = TCPRulesEBPFManager()

        # 用 RuleManager 只做“规则元数据 + sid_to_rule 映射”
        self.rule_manager = RuleManager(rules_dir=PROJECT_ROOT)
        self.event_handler = EventHandler(self.rule_manager)

        # 保存 raw socket 对象，避免被 GC 回收
        self.sock = None

    # ----------------------- 规则加载与代码生成 -----------------------

    def load_rules_for_codegen(self, json_path: str = SNORT_RULES_JSON):
        """
        从 JSON 加载已经解析好的 Snort 规则，并将 TCP 规则加入 eBPF 代码生成器。
        这个 JSON 是你前置脚本生成的（比如从 SnortRuleParser 导出）。
        """
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
                continue

    def generate_tcp_rules_code(self):
        """生成 eBPF C 代码并导出到内核目录"""
        print("正在生成 TCP 规则的 eBPF 代码...")
        result = self.tcp_rules_manager.generate_all_code()
        print(f"✓ 已生成 {result['count']} 条 TCP 规则的 eBPF 代码")

        os.makedirs(KERNEL_DIR, exist_ok=True)

        # 导出 C 代码和元数据
        self.tcp_rules_manager.export_code(TCP_RULES_C_PATH)
        print(f"✓ 已导出 eBPF 代码到: {TCP_RULES_C_PATH}")

        self.tcp_rules_manager.export_metadata(TCP_RULES_META_PATH)
        print(f"✓ 已导出规则元数据到: {TCP_RULES_META_PATH}")

    # ----------------------- eBPF 编译、加载、挂载 -----------------------

    def load_ebpf_program(self):
        """编译和加载 eBPF 程序，并作为 socket filter 挂载到接口"""
        print("正在编译 eBPF 程序...")

        if not os.path.isfile(TCP_RULES_C_PATH):
            raise FileNotFoundError(f"未找到生成的 eBPF 内核代码: {TCP_RULES_C_PATH}")

        with open(TCP_RULES_C_PATH, "r") as f:
            kernel_code = f.read()

        try:
            # 避免路径过长导致 getcwd() 问题
            os.chdir(PROJECT_ROOT)

            # 编译 BPF
            self.bpf = BPF(text=kernel_code)

            # 内核中主函数为：int ids_filter(struct __sk_buff *skb)
            iface = get_active_interface()
            try:
                fn = self.bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
                # 作为 raw socket filter 挂载到网卡
                self.sock = self.bpf.attach_raw_socket(fn, iface)
                print(f"✓ eBPF 程序编译并作为 socket filter 挂载到接口 {iface}")
            except Exception as e:
                print(f"⚠️ 无法挂载 socket filter 程序（请检查函数名/权限）: {e}")

        except Exception as e:
            print("getcwd:", os.getcwd())
            print(f"✗ 加载 eBPF 程序失败: {e}")
            raise

    # ----------------------- perf buffer 注册与轮询 -----------------------

    def setup_event_buffers(self):
        """打开 perf buffer，将回调函数绑定到对应的 map 上"""
        if self.bpf is None:
            raise RuntimeError("BPF 程序尚未加载，无法设置事件缓冲区")

        # eBPF 端定义为：BPF_PERF_OUTPUT(alerts);
        try:
            self.bpf["alerts"].open_perf_buffer(
                self.event_handler.handle_alert
            )
            print("✓ 已打开 alerts perf buffer")
        except KeyError:
            print("⚠️ 未找到名为 'alerts' 的 perf buffer，请检查 eBPF 程序中的 map 名称")

        # 当前生成的 eBPF 代码没有 packet_events 之类的额外 map，这里就不再订阅

    def run(self):
        """进入监控循环，持续从 perf buffer 读取事件"""
        if self.bpf is None:
            raise RuntimeError("BPF 程序尚未加载，无法运行监控循环")

        print("开始监控内核告警，按 Ctrl+C 退出...")

        # 支持 Ctrl+C 友好退出
        def handle_sigint(signum, frame):
            raise KeyboardInterrupt()

        signal.signal(signal.SIGINT, handle_sigint)

        try:
            while True:
                # perf_buffer_poll 会调用前面注册的回调
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n收到中断信号，停止 IDS 监控")
        finally:
            # 关闭 raw socket，防止资源泄漏
            try:
                if self.sock is not None:
                    self.sock.close()
                    print("✓ 已关闭 raw socket")
            except Exception as e:
                print(f"⚠️ 关闭 raw socket 时出错: {e}")

    # ----------------------- 总初始化流程 -----------------------

    def init_ids(self):
        """高层初始化流程：规则 -> C 代码 -> eBPF 程序"""
        try:
            # 1. 解析原始 Snort 规则，用于 EventHandler 的 sid_to_rule 映射
            self.rule_manager.load_rules()

            # 2. 从 JSON 加载规则到 eBPF 代码生成器
            self.load_rules_for_codegen()

            # 3. 生成 C 代码并导出到内核目录
            self.generate_tcp_rules_code()

            # 4. 编译、加载并挂载 eBPF 程序
            self.load_ebpf_program()

            print("✓ IDS 初始化完成")
        except Exception as e:
            print(f"✗ IDS 初始化失败: {e}")
            raise


# ---------------------------------------------------------------------------
# 程序入口
# ---------------------------------------------------------------------------

def main():
    # 确保工作目录在 PROJECT_ROOT，避免路径过长问题
    try:
        os.chdir(PROJECT_ROOT)
    except Exception:
        pass

    manager = IDSManager()
    manager.init_ids()
    manager.setup_event_buffers()
    manager.run()


if __name__ == "__main__":
    main()
