#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
规则加载和解析模块
"""

import os
import json
import re
import binascii

try:
    import yaml
except ImportError:
    yaml = None


class RuleLoader:
    """规则加载器"""
    
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        
    def load_from_json(self, filepath):
        """从 JSON 文件加载规则"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except (IOError, json.JSONDecodeError) as e:
            print(f"加载 JSON 规则失败: {filepath}, 错误: {e}")
            return None
    
    def load_from_yaml(self, filepath):
        """从 YAML 文件加载规则"""
        if yaml is None:
            print("PyYAML 未安装，无法加载 YAML 规则")
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            return data
        except (IOError, yaml.YAMLError) as e:
            print(f"加载 YAML 规则失败: {filepath}, 错误: {e}")
            return None
    
    def load_all_rules(self):
        """加载规则目录下的所有规则文件"""
        rules = []
        
        if not os.path.exists(self.rules_dir):
            print(f"规则目录不存在: {self.rules_dir}")
            return rules
        
        for filename in os.listdir(self.rules_dir):
            filepath = os.path.join(self.rules_dir, filename)
            
            if not os.path.isfile(filepath):
                continue
            
            # 只加载 snort_rules_ebpf.json
            if filename == 'snort_rules_ebpf.json':
                print(f"正在加载规则文件: {filename}")
                rule_data = self.load_from_json(filepath)
                if rule_data and isinstance(rule_data, list):
                    print(f"  ✓ 成功加载 {len(rule_data)} 条规则")
                    return rule_data
            elif filename.endswith('.json'):
                rule_data = self.load_from_json(filepath)
                if rule_data:
                    if isinstance(rule_data, list):
                        rules.extend(rule_data)
                    else:
                        rules.append(rule_data)
            elif filename.endswith(('.yaml', '.yml')):
                rule_data = self.load_from_yaml(filepath)
                if rule_data:
                    if isinstance(rule_data, list):
                        rules.extend(rule_data)
                    else:
                        rules.append(rule_data)
        
        return rules


class RuleParser:
    """规则解析器 - 将JSON规则转换为内部表示"""
    
    @staticmethod
    def parse_port(port_obj):
        """
        解析端口对象
        返回: (type, value1, value2)
        type: 0=any, 1=single, 2=range, 3=list
        """
        if port_obj is None:
            return (0, 0, 0)  # any
        
        port_type = port_obj.get('type', 'single')
        
        if port_type == 'single':
            port = port_obj.get('port', 0)
            return (1, port, 0)
        elif port_type == 'range':
            start = port_obj.get('start', 0)
            end = port_obj.get('end', 0)
            return (2, start, end)
        elif port_type == 'list':
            ports = port_obj.get('ports', [])
            # 简化处理：只取前两个端口
            p1 = ports[0] if len(ports) > 0 else 0
            p2 = ports[1] if len(ports) > 1 else 0
            return (3, p1, p2)
        
        return (0, 0, 0)
    
    @staticmethod
    def parse_content(content_str):
        """
        解析 content 字段，转换为字节数组
        例如: "2|00 00 00 06 00 00 00|Drives|24 00|",depth 16
        返回: (bytes_array, depth)
        """
        if not content_str:
            return (b'', 0)
        
        # 移除 depth 参数
        depth = 0
        if 'depth' in content_str:
            match = re.search(r'depth\s+(\d+)', content_str)
            if match:
                depth = int(match.group(1))
            content_str = re.sub(r',\s*depth\s+\d+', '', content_str)
            content_str = re.sub(r'\s*depth\s+\d+', '', content_str)
        
        # 移除引号和其他选项
        content_str = content_str.strip('"\'')
        content_str = re.sub(r',\s*(nocase|fast_pattern|offset\s+\d+|distance\s+\d+|within\s+\d+).*', '', content_str)
        
        result = bytearray()
        i = 0
        
        while i < len(content_str):
            if content_str[i] == '|':
                # 十六进制字节
                i += 1
                hex_end = content_str.find('|', i)
                if hex_end == -1:
                    break
                hex_str = content_str[i:hex_end].strip()
                # 解析十六进制
                hex_bytes = hex_str.split()
                for hb in hex_bytes:
                    try:
                        result.append(int(hb, 16))
                    except ValueError:
                        pass
                i = hex_end + 1
            elif content_str[i] == '\\':
                # 转义字符（简化处理）
                i += 2
            else:
                # 普通字符
                result.append(ord(content_str[i]))
                i += 1
        
        return (bytes(result), depth if depth > 0 else len(result))
    
    @staticmethod
    def parse_tcp_flags(flags_obj):
        """
        解析 TCP 标志
        返回: 标志位掩码
        """
        if not flags_obj:
            return 0
        
        flag_map = {
            'FIN': 0x01,
            'SYN': 0x02,
            'RST': 0x04,
            'PSH': 0x08,
            'ACK': 0x10,
            'URG': 0x20,
        }
        
        flags = 0
        for flag_name, flag_value in flag_map.items():
            if flags_obj.get(flag_name, False):
                flags |= flag_value
        
        return flags
    
    @staticmethod
    def parse_flow(flow_str):
        """
        解析 flow 字段
        返回: (direction, state)
        direction: 0=any, 1=to_client, 2=to_server
        state: 0=any, 1=established, 2=stateless
        """
        if not flow_str:
            return (0, 0)
        
        direction = 0
        state = 0
        
        if 'to_client' in flow_str:
            direction = 1
        elif 'to_server' in flow_str:
            direction = 2
        
        if 'established' in flow_str:
            state = 1
        elif 'stateless' in flow_str:
            state = 2
        
        return (direction, state)
    
    @staticmethod
    def parse_rule(rule):
        """
        解析单条规则，转换为标准格式
        """
        parsed = {
            'sid': rule.get('sid', 0),
            'msg': rule.get('msg', ''),
            'action': rule.get('action', 'alert'),
            'protocol': rule.get('protocol_num', 0),
            'priority': rule.get('priority', 3),
            'classtype': rule.get('classtype', ''),
        }
        
        # 解析端口
        src_port = RuleParser.parse_port(rule.get('src_port'))
        dst_port = RuleParser.parse_port(rule.get('dst_port'))
        parsed['src_port'] = src_port
        parsed['dst_port'] = dst_port
        
        # 解析 content
        content_data = rule.get('content', '')
        if isinstance(content_data, list):
            # 处理多个 content（只取第一个）
            content_data = content_data[0] if content_data else ''
        
        content_bytes, depth = RuleParser.parse_content(content_data)
        parsed['content'] = content_bytes
        parsed['content_depth'] = depth
        
        # 解析 TCP 标志
        parsed['tcp_flags'] = RuleParser.parse_tcp_flags(rule.get('tcp_flags', {}))
        
        # 解析 flow
        flow_direction, flow_state = RuleParser.parse_flow(rule.get('flow', ''))
        parsed['flow_direction'] = flow_direction
        parsed['flow_state'] = flow_state
        
        # IP 地址（暂时不解析变量）
        parsed['src_ip'] = rule.get('src_ip', 'any')
        parsed['dst_ip'] = rule.get('dst_ip', 'any')
        
        return parsed
    
    @staticmethod
    def compile_rules(rules):
        """
        批量编译规则
        """
        compiled_rules = []
        error_count = 0
        
        for rule in rules:
            try:
                parsed_rule = RuleParser.parse_rule(rule)
                compiled_rules.append(parsed_rule)
            except Exception as e:
                error_count += 1
                if error_count <= 5:  # 只打印前5个错误
                    print(f"  警告: 解析规则失败 (SID={rule.get('sid', 'unknown')}): {e}")
        
        if error_count > 5:
            print(f"  警告: 还有 {error_count - 5} 条规则解析失败")
        
        return compiled_rules


class RuleCompiler:
    def __init__(self):
        self.header = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>

BPF_PERF_OUTPUT(events);
BPF_HASH(rule_stats, __u32, __u64, 1000);

struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 sid;
};

// 安全读取 skb 内字节
static __always_inline int safe_load_byte(struct __sk_buff *skb, __u32 off, unsigned char *out) {
    return bpf_skb_load_bytes(skb, off, out, 1);
}
"""

    def compile_rules(self, rules, max_content_depth=8):
        """
        rules 已经是 attempted-recon 类型
        支持 content 为 str 或 list
        """
        parts = [self.header]
        parts.append("int ids_filter(struct __sk_buff *skb) {")
        parts.append("    unsigned char tmp = 0;")

        for r in rules:
            sid = int(r.get("sid", 0))
            proto = int(r.get("protocol_num", 0) or 0)
            dst_port = r.get("dst_port", None)
            content = r.get("content", b"") or b""

            # 展平 content
            if isinstance(content, list):
                content = b"".join([c.encode("latin1") if isinstance(c, str) else c for c in content])
            elif isinstance(content, str):
                content = content.encode("latin1")

            # 截断 content 避免 verifier 报错
            content = content[:max_content_depth]
            clen = len(content)

            parts.append(f"    /* rule {sid} start */")
            parts.append("    do {")

            # 读取协议
            parts.append("        unsigned char proto_b = 0;")
            parts.append("        if (bpf_skb_load_bytes(skb, 23, &proto_b, 1) < 0) break;")  # IP header 9 + eth 14
            if proto != 0:
                parts.append(f"        if (proto_b != {proto}) break;")

            # dst port
            if dst_port and isinstance(dst_port, dict) and dst_port.get("type") == "list":
                ports = dst_port.get("ports", [])
                if ports:
                    parts.append("        unsigned char p0=0, p1=0;")
                    parts.append("        if (bpf_skb_load_bytes(skb, 34, &p0, 1) < 0) break;")  # TCP start at 14+IP(20)
                    parts.append("        if (bpf_skb_load_bytes(skb, 35, &p1, 1) < 0) break;")
                    parts.append("        unsigned short dst_port = (p0 << 8) | p1;")
                    ports_check = " && ".join([f"(dst_port != {p})" for p in ports])
                    parts.append(f"        if ({ports_check}) break;")
            else:
                parts.append("        unsigned short dst_port = 0;")

            # payload content
            if clen > 0:
                parts.append("        unsigned int payload_off = 14 + 20;")  # 简单固定 IP header 20B
                parts.append("        unsigned char btmp = 0;")
                for i, b in enumerate(content):
                    parts.append(f"        if (bpf_skb_load_bytes(skb, payload_off + {i}, &btmp, 1) < 0) break;")
                    parts.append(f"        if (btmp != 0x{b:02x}) break;")

            # 命中规则 -> 更新统计 & 提交事件
            parts.append(f"        __u32 _k = {sid};")
            parts.append("        __u64 *_c = rule_stats.lookup(&_k);")
            parts.append("        if (_c) (*_c)++; else { __u64 _i = 1; rule_stats.update(&_k, &_i); }")

            # 构造事件（简单示例）
            parts.append("        struct packet_event evt = {0};")
            parts.append(f"        evt.sid = {sid}; evt.protocol = proto_b;")
            parts.append("        events.perf_submit(skb, &evt, sizeof(evt));")
            parts.append("        return 0;")
            parts.append("    } while(0);")
            parts.append(f"    /* rule {sid} end */")

        parts.append("    return 0;")
        parts.append("}")
        return "\n".join(parts)
