#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
规则加载和解析模块
"""

import os
import json
import re

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
    """规则编译器 - 使用与硬编码版本相同的结构"""

    def __init__(self):
        # 直接使用你原有的完整eBPF代码作为基础
        self.ebpf_base = """
        #include <uapi/linux/if_ether.h>
        #include <uapi/linux/ip.h>
        #include <uapi/linux/tcp.h>
        #include <uapi/linux/udp.h>
        #include <uapi/linux/icmp.h>
        #include <uapi/linux/in.h>
        #include <uapi/linux/pkt_cls.h>

        // 定义事件数据结构 - 添加 sid 字段
        struct packet_event {
            __u32 src_ip;
            __u32 dst_ip;
            __u16 src_port;
            __u16 dst_port;
            __u8 protocol;
            __u32 sid;  // 添加这个字段！
            __u32 payload_len;
            __u8 payload[256];
        };

        // eBPF Maps 定义
        BPF_PERF_OUTPUT(events);
        BPF_HASH(rule_cache, __u32, __u32);
        BPF_HASH(connection_state, __u64, __u32);

        // 包解析函数 - 使用你原有的工作版本
        static inline int parse_packet(struct __sk_buff *skb, struct packet_event *evt) {
            __u32 proto;
            __u32 nhoff = 14;  // ETH_HLEN

            // 读取以太网协议类型
            bpf_skb_load_bytes(skb, 12, &proto, 2);
            proto = bpf_ntohs(proto);

            // 检查是否为 IP 协议
            if (proto != 0x0800)  // ETH_P_IP
                return -1;

            // 读取 IP 头部信息
            struct iphdr ip;
            bpf_skb_load_bytes(skb, nhoff, &ip, sizeof(ip));

            // 填充基本 IP 信息
            evt->src_ip = ip.saddr;
            evt->dst_ip = ip.daddr;
            evt->protocol = ip.protocol;
            evt->sid = 0;  // 初始化为0

            __u32 l4_offset = nhoff + (ip.ihl * 4);

            // 根据协议类型解析传输层
            if (ip.protocol == 6) {  // TCP
                struct tcphdr tcp;
                bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp));
                evt->src_port = bpf_ntohs(tcp.source);
                evt->dst_port = bpf_ntohs(tcp.dest);
            } else if (ip.protocol == 17) {  // UDP
                struct udphdr udp;
                bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp));
                evt->src_port = bpf_ntohs(udp.source);
                evt->dst_port = bpf_ntohs(udp.dest);
            } else {
                evt->src_port = 0;
                evt->dst_port = 0;
            }

            return 0;
        }

        // 规则匹配函数 - 我们将修改这个部分
        static inline int match_rules(struct packet_event *evt) {
            // 原有的硬编码检测逻辑
            if (evt->protocol == 1) {  // ICMP
                return 1000;  // 返回测试SID
            }

            // 新添加的动态规则检查
            %s

            return 0;
        }

        // 主钩子函数 - 修复版本
        int ids_filter(struct __sk_buff *skb) {
            struct packet_event evt = {};

            // 解析数据包
            if (parse_packet(skb, &evt) < 0) {
                return 0;
            }

            // 规则匹配并设置SID
            int matched_sid = match_rules(&evt);
            if (matched_sid > 0) {
                evt.sid = matched_sid;  // 关键：设置SID到事件结构
                events.perf_submit(skb, &evt, sizeof(evt));
            }

            return 0;
        }
        """

    def _generate_rule_condition(self, rule):
        """为单条规则生成eBPF检测条件"""
        sid = rule.get('sid', 0)
        protocol = rule.get('protocol', 0)

        conditions = []

        # 协议检查
        if protocol != 0:
            conditions.append(f"evt->protocol == {protocol}")

        # 端口检查
        port_type, val1, val2 = rule.get('dst_port', (0, 0, 0))
        if protocol == 6 and port_type == 1:  # TCP单个端口
            conditions.append(f"evt->dst_port == {val1}")
        elif protocol == 6 and port_type == 2:  # TCP端口范围
            conditions.append(f"(evt->dst_port >= {val1} && evt->dst_port <= {val2})")
        elif protocol == 17 and port_type == 1:  # UDP单个端口
            conditions.append(f"evt->dst_port == {val1}")

        # 生成完整的if条件
        if conditions:
            condition_str = " && ".join(conditions)
            return f"    if ({condition_str}) return {sid};"
        else:
            return f"    return {sid};"

    def compile_rules(self, rules):
        """编译所有规则为eBPF代码 - 修复逻辑顺序"""
        print("正在编译规则为eBPF代码...")

        # 将规则分类：具体规则 vs 通用规则
        specific_rules = []  # 有具体端口条件的规则
        generic_rules = []  # 只有协议条件的通用规则

        # test_rules = rules[:100]  # 你选择的100条规则

        for rule in rules:
            port_type, val1, val2 = rule.get('dst_port', (0, 0, 0))
            protocol = rule.get('protocol', 0)

            # 有具体端口条件的规则
            if port_type != 0 and protocol != 0:
                specific_rules.append(rule)
            # 只有协议条件的通用规则
            elif protocol != 0:
                generic_rules.append(rule)

        print(f"选择 {len(specific_rules)} 条具体规则 + {len(generic_rules)} 条通用规则")

        # 生成规则条件：具体规则在前，通用规则在后
        rule_conditions = []

        # 1. 先处理具体规则
        for rule in specific_rules:
            condition = self._generate_rule_condition(rule)
            if condition:
                rule_conditions.append(condition)

        # 2. 再处理通用规则
        for rule in generic_rules:
            condition = self._generate_rule_condition(rule)
            if condition:
                rule_conditions.append(condition)

        # 使用 else-if 链
        else_if_chain = []
        for i, condition in enumerate(rule_conditions):
            if i == 0:
                else_if_chain.append(condition)
            else:
                # 将 "if" 替换为 "else if"
                else_if_chain.append(condition.replace("    if (", "    else if (", 1))

        complete_ebpf = (self.ebpf_base % "\n".join(else_if_chain))

        print(f"✓ 成功编译 {len(rule_conditions)} 条规则到eBPF（使用else-if链）")
        return complete_ebpf