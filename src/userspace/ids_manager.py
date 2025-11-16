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

from rule_loader import RuleCompiler


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
        
        # 2. 匹配源端口
        if not self._match_port(rule['src_port'], event.src_port):
            return False
        
        # 3. 匹配目标端口
        if not self._match_port(rule['dst_port'], event.dst_port):
            return False
        
        # 4. 匹配 content (如果有)
        if rule['content'] and len(rule['content']) > 0:
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

    def handle_event(self, cpu, data, size):
        """处理 eBPF 事件 - 自动转换 IP/端口"""
        import ctypes as ct
        from datetime import datetime
        import time
        import socket, struct

        class PacketEvent(ct.Structure):
            _fields_ = [
                ("src_ip", ct.c_uint32),
                ("dst_ip", ct.c_uint32),
                ("src_port", ct.c_uint16),
                ("dst_port", ct.c_uint16),
                ("protocol", ct.c_uint8),
                ("_pad", ct.c_ubyte * 3),
                ("sid", ct.c_uint32),
            ]

        try:
            if size < ct.sizeof(PacketEvent):
                print(f"[调试] 事件大小不足: {size} < {ct.sizeof(PacketEvent)}")
                return

            event = ct.cast(data, ct.POINTER(PacketEvent)).contents
            self.event_count += 1

            # 转换 IP/端口
            src_ip = socket.inet_ntoa(struct.pack("<I", event.src_ip))
            dst_ip = socket.inet_ntoa(struct.pack("<I", event.dst_ip))
            if event.protocol in (6, 17):  # TCP/UDP
                src_port = socket.ntohs(event.src_port)
                dst_port = socket.ntohs(event.dst_port)
            else:  # ICMP 等
                src_port = 0
                dst_port = 0

            matched_rule = self.rule_manager.get_rule_by_sid(event.sid)

            if matched_rule and event.sid != 0:
                # 去重
                alert_key = (event.src_ip, event.dst_ip, event.sid)
                current_time = time.time()
                if alert_key in self.last_alerts and current_time - self.last_alerts[alert_key] < 10:
                    return
                self.last_alerts[alert_key] = current_time
                self.alert_count += 1

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
                protocol_name = protocol_map.get(event.protocol, f"Protocol-{event.protocol}")

                print(f"\n{'=' * 80}")
                print(f"[ALERT #{self.alert_count}] {timestamp}")
                print(f"{'=' * 80}")
                print(f"规则: [{matched_rule['sid']}] {matched_rule['msg']}")
                print(f"分类: {matched_rule['classtype']} | 优先级: {matched_rule['priority']}")
                print(f"协议: {protocol_name}")
                print(f"源地址: {src_ip}:{src_port}")
                print(f"目标地址: {dst_ip}:{dst_port}")
                print(f"{'=' * 80}\n")
            else:
                # 普通流量日志
                if self.event_count % 10 == 0:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
                    protocol_name = protocol_map.get(event.protocol, f"Protocol-{event.protocol}")
                    print(
                        f"[{timestamp}] [事件 #{self.event_count}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol_name}")

        except Exception as e:
            print(f"[错误] 事件处理异常: {e}")


    def _generate_alert(self, event, rule):
        """生成规则匹配告警"""
        # 使用现有的告警生成逻辑，但数据来源改为编译后的规则
        src_ip = self.format_ip(event.src_ip)
        dst_ip = self.format_ip(event.dst_ip)
    
        # 去重检查（保持现有逻辑）
        alert_key = (event.src_ip, event.dst_ip, rule['sid'])
        current_time = time.time()
    
        if alert_key in self.last_alerts:
            if current_time - self.last_alerts[alert_key] < 10:
                return
    
        self.last_alerts[alert_key] = current_time
        self.alert_count += 1
    
        # 显示告警（保持现有格式）
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{'='*80}")
        print(f"[ALERT #{self.alert_count}] {timestamp}")
        print(f"{'='*80}")
        print(f"规则: [{rule['sid']}] {rule['msg']}")
        print(f"分类: {rule['classtype']} | 优先级: {rule['priority']}")
        print(f"协议: {self._get_protocol_name(event.protocol)}")
        print(f"源地址: {src_ip}:{event.src_port}")
        print(f"目标地址: {dst_ip}:{event.dst_port}")
        print(f"{'='*80}\n")

    def _get_protocol_name(self, protocol_num):
        """获取协议名称"""
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        return protocol_map.get(protocol_num, f"Protocol-{protocol_num}")
    
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
    def __init__(self, rules_dir, interface=None):
        self.rules_dir = rules_dir
        self.interface = interface or get_active_interface()
        self.bpf = None
        self.rule_manager = RuleManager(rules_dir)
        self.event_handler = None
        self.running = False

    def load_ebpf_program(self):
        print("正在动态生成并编译 eBPF 程序...")
        try:
            # 1️⃣ 读取规则
            rules = self.rule_manager.get_rules()
            if not rules:
                print("⚠ 未找到任何规则文件，请检查 rules_dir 是否正确。")
                return False

            # 1.1️⃣ 快速筛选 attempted-recon
            filtered_rules = filter_rules(rules)
            # recon_rules = [r for r in rules if r.get("classtype") == "attempted-recon"][:20]
            print(f"✓ 共筛选出 {len(filtered_rules)} 条 attempted-recon 规则")

            if not recon_rules:
                print("⚠ 没有 attempted-recon 类型规则，跳过 eBPF 编译")
                return False

            # 2️⃣ 动态生成 eBPF C 代码
            compiler = RuleCompiler()
            ebpf_source = compiler.compile_rules(filtered_rules)
            print(f"生成的 C 代码长度: {len(ebpf_source)}")

            # 3️⃣ 写入临时文件以供调试
            gen_path = "/tmp/generated_ebpf.c"
            with open(gen_path, "w") as f:
                f.write(ebpf_source)
            print(f"✓ 已生成 eBPF 源码: {gen_path}")

            # 4️⃣ 自动查找 Linux 头文件路径
            kernel_release = os.uname().release
            include_path = f"/usr/src/linux-headers-{kernel_release}/tools/include"

            # 5️⃣ 编译加载 eBPF
            self.bpf = BPF(
                text=ebpf_source.encode('utf-8'),
                cflags=[
                    "-I/usr/include",
                    "-I/usr/include/bpf",
                    f"-I{include_path}",
                ],
            )
            print("✓ eBPF 编译成功")
            return True

        except Exception as e:
            print(f"✗ eBPF 编译失败: {e}")
            return False

    def filter_rules(rules):
        filtered = []

        for rule in rules:
            # 1) 只要 attempted-recon
            if rule.get("classtype") != "attempted-recon":
                continue

            # 2) 只允许 L3/L4 协议（TCP/UDP/ICMP）
            if rule.get("protocol_num") not in [1, 6, 17]:
                continue

            # 3) 不允许 content/payload 匹配（eBPF 做不了）
            if "content" in rule and rule["content"]:
                continue

            # 4) dst_port 必须存在且是 single 类型（多端口太复杂）
            dp = rule.get("dst_port")
            if not dp:
                continue
            if dp["type"] != "single":
                continue

            # 5) port 必须是有效端口
            port = dp.get("port")
            if not isinstance(port, int) or port <= 0 or port > 65535:
                continue

            # 6) SRC_PORT 不允许存在复杂条件
            sp = rule.get("src_port")
            if sp and sp.get("type") != "single":
                continue

            filtered.append(rule)

        return filtered

    def attach_probes(self):
        try:
            func = self.bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
            self.bpf.attach_raw_socket(func, self.interface)
            print(f"✓ 已附加到接口: {self.interface}")
            return True
        except Exception as e:
            print(f"✗ 附加探针失败: {e}")
            return False

    def initialize(self):
        print("初始化 IDS ...")

        # 加载规则
        self.rule_manager.load_rules()

        # 加载动态 eBPF
        if not self.load_ebpf_program():
            return False

        # 填充规则映射（如果 RuleCompiler 生成了 rules_map）
        if "rules_map" in self.bpf:
            rules_map = self.bpf.get_table("rules_map")
            rules = self.rule_manager.get_rules()
            print(f"填充 {len(rules)} 条规则到 eBPF 映射...")

            for i, rule in enumerate(rules[:1024]):
                try:
                    rule_struct = rules_map.Leaf()
                    rule_struct.protocol = rule.get("protocol", 0)
                    rule_struct.dport = rule.get("dport", 0)
                    rule_struct.sport = rule.get("sport", 0)
                    rule_struct.sid = rule.get("sid", 0)
                    rules_map[i] = rule_struct
                except Exception as e:
                    print(f"⚠ 填充规则 {i} 失败: {e}")

        # 注册事件处理器
        self.event_handler = EventHandler(self.rule_manager)

        # 附加探针
        return self.attach_probes()

    def start(self):
        if not self.initialize():
            print("初始化失败")
            return

        print("✓ IDS 启动成功，开始监控流量...")
        self.bpf["events"].open_perf_buffer(self.event_handler.handle_event)
        self.running = True

        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break

        self.stop()

    def stop(self):
        print("正在停止 IDS ...")
        self.running = False
        if self.event_handler:
            stats = self.event_handler.get_statistics()
            print(f"总事件: {stats['total_events']}, 告警: {stats['total_alerts']}")


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
