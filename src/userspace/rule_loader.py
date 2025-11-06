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
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// ==== MAP 定义 ====

struct rule_stat_t {
    __u64 count;
};

// 规则统计表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u64);
} rule_stats SEC(".maps");

// 事件输出缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// ==== 事件结构 ====
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 sid;
};

// ==== 辅助函数 ====
static __always_inline bool check_bound(void *start, void *end, __u64 size) {
    return (start + size) <= end;
}
"""

    def _generate_rule_func(self, rule):
        sid = rule["sid"]
        proto = rule.get("protocol", 0)
        proto_name = {6: "IPPROTO_TCP", 17: "IPPROTO_UDP", 1: "IPPROTO_ICMP"}.get(proto, "IPPROTO_IP")

        content = rule.get("content", b"") or b""
        content_len = len(content)

        code = []
        code.append(f"/* === Rule SID {sid}: {rule.get('msg', '')} === */")
        code.append(f"static __always_inline int check_rule_{sid}(struct iphdr *iph, void *data_end, void *data) {{")

        # 协议过滤
        code.append(f"    if (iph->protocol != {proto_name}) return 0;")

        # TCP/UDP头判断
        if proto == 6:
            code.append("    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);")
            code.append("    if (!check_bound(tcph, data_end, sizeof(*tcph))) return 0;")
            payload_base = "(void *)tcph + (tcph->doff * 4)"
            hdr_name = "tcph"
        elif proto == 17:
            code.append("    struct udphdr *udph = (void *)iph + (iph->ihl * 4);")
            code.append("    if (!check_bound(udph, data_end, sizeof(*udph))) return 0;")
            payload_base = "(void *)udph + sizeof(*udph)"
            hdr_name = "udph"
        else:
            payload_base = "(void *)iph + (iph->ihl * 4)"
            hdr_name = "iph"

        # 端口匹配
        ptype, val1, val2 = rule.get("dst_port", (0, 0, 0))
        if ptype == 1:
            code.append(f"    if (bpf_ntohs({hdr_name}->dest) != {val1}) return 0;")
        elif ptype == 2:
            code.append(f"    if (!(bpf_ntohs({hdr_name}->dest) >= {val1} && bpf_ntohs({hdr_name}->dest) <= {val2})) return 0;")

        # payload 匹配
        if content_len > 0:
            code.append(f"    void *payload = {payload_base};")
            code.append(f"    if (!check_bound(payload, data_end, {content_len})) return 0;")
            code.append("    unsigned char tmp_byte = 0;")
            for i, b in enumerate(content):
                code.append(f"    if (bpf_probe_read(&tmp_byte, 1, payload + {i}) < 0) return 0;")
                code.append(f"    if (tmp_byte != 0x{b:02x}) return 0;")

        # 更新 rule_stats
        code.append(f"    __u32 key = {sid};")
        code.append("    __u64 *cnt = bpf_map_lookup_elem(&rule_stats, &key);")
        code.append("    if (cnt) (*cnt)++; else { __u64 init=1; bpf_map_update_elem(&rule_stats, &key, &init, BPF_ANY); }")

        code.append("    return 1;")
        code.append("}\n")
        return "\n".join(code)

    def compile_rules_inline(self, rules):
        funcs = [self.header]

        # 逐条生成规则函数
        for rule in rules:
            funcs.append(self._generate_rule_func(rule))

        # 主入口
        funcs.append(r"""
SEC("socket")
int ids_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (!check_bound(eth, data_end, sizeof(*eth))) return 0;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return 0;

    struct iphdr *iph = data + sizeof(*eth);
    if (!check_bound(iph, data_end, sizeof(*iph))) return 0;

""")

        # 调用每个规则函数
        for rule in rules:
            sid = rule["sid"]
            funcs.append(f"    if (check_rule_{sid}(iph, data_end, data)) {{")
            funcs.append(f"        struct packet_event evt = {{}};")
            funcs.append(f"        evt.src_ip = iph->saddr;")
            funcs.append(f"        evt.dst_ip = iph->daddr;")
            funcs.append(f"        evt.protocol = iph->protocol;")
            funcs.append(f"        evt.sid = {sid};")
            funcs.append(f"        bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));")
            funcs.append(f"        return 0;")
            funcs.append("    }")

        funcs.append("    return 0;\n}\n")
        funcs.append('char _license[] SEC("license") = "GPL";\n')

        return "\n".join(funcs)

    def compile_rules(self, rules):
        print(f"正在动态生成并编译 eBPF 程序 ({len(rules)} 条规则)...")
        return self.compile_rules_inline(rules)
