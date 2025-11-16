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
        # TCP 模板
        self.template_tcp = r"""
    /* rule {sid} (tcp) */
    int ids_filter(struct __sk_buff *skb) __attribute__((section("socket"), used));
    do {{
        unsigned char iphdr[20];
        if (bpf_skb_load_bytes(skb, 14, iphdr, 20) < 0) break;
        if (iphdr[9] != 6) break;  // TCP

        unsigned int ihl = (iphdr[0] & 0x0F) * 4;
        unsigned int l4 = 14 + ihl;

        unsigned char flags = 0;
        if (bpf_skb_load_bytes(skb, l4 + 13, &flags, 1) < 0) break;

        // required TCP flags
        if (!({flag_expr})) break;

        {content_code}

        // matched
        UPDATE_STATS_AND_EMIT_EVENT({sid});
        return 0;
    }} while (0);
    """

        # UDP 模板
        self.template_udp = r"""
    /* rule {sid} (udp) */
    int ids_filter(struct __sk_buff *skb) __attribute__((section("socket"), used));
    do {{
        unsigned char iphdr[20];
        if (bpf_skb_load_bytes(skb, 14, iphdr, 20) < 0) break;
        if (iphdr[9] != 17) break;  // UDP

        unsigned int ihl = (iphdr[0] & 0x0F) * 4;
        unsigned int l4 = 14 + ihl;

        unsigned short dport = 0;
        unsigned char dp0 = 0, dp1 = 0;
        if (bpf_skb_load_bytes(skb, l4 + 2, &dp0, 1) < 0 ||
            bpf_skb_load_bytes(skb, l4 + 3, &dp1, 1) < 0) break;
        dport = (dp0 << 8) | dp1;

        if ({port_check}) break;

        {content_code}

        UPDATE_STATS_AND_EMIT_EVENT({sid});
        return 0;
    }} while (0);
    """

        # ICMP 模板
        self.template_icmp = r"""
    /* rule {sid} (icmp) */
    int ids_filter(struct __sk_buff *skb) __attribute__((section("socket"), used));
    do {{
        unsigned char proto = 0;
        if (bpf_skb_load_bytes(skb, 14 + 9, &proto, 1) < 0) break;
        if (proto != 1) break; // ICMP

        unsigned char type = 0;
        if (bpf_skb_load_bytes(skb, 14 + 20, &type, 1) < 0) break;

        if (type != {icmp_type}) break;

        UPDATE_STATS_AND_EMIT_EVENT({sid});
        return 0;
    }} while (0);
    """

    # ----------------------------------------------------------------------

    def compile_rules(self, rules):
        """
        输入：json rule 列表（已过滤 attempted-recon）
        输出：拼接好的 C 代码字符串
        """
        output = []
        for r in rules:
            c = self.compile_one_rule(r)
            if c:
                output.append(c)
        return "\n".join(output)

    # ----------------------------------------------------------------------

    def compile_one_rule(self, rule):
        """根据协议类型选择模板"""
        proto = rule.get("protocol_num")

        if proto == 6:
            return self.compile_tcp_rule(rule)
        elif proto == 17:
            return self.compile_udp_rule(rule)
        elif proto == 1:
            return self.compile_icmp_rule(rule)
        else:
            return None

    # ----------------------------------------------------------------------

    def compile_tcp_rule(self, rule):
        sid = rule["sid"]

        # ---------------- generate flags check -------------------
        flags = rule.get("tcp_flags", {})
        flag_expr = self.gen_flag_expr(flags)

        # ---------------- generate content code -------------------
        content_code = self.gen_content_code(rule.get("content", []))

        return self.template_tcp.format(
            sid=sid,
            flag_expr=flag_expr,
            content_code=content_code
        )

    # ----------------------------------------------------------------------

    def compile_udp_rule(self, rule):
        sid = rule["sid"]

        # port check
        dport = rule.get("dst_port")
        if not dport:
            port_check = "0"      # 永远通过
        else:
            port_check = f"dport != {dport['port']}"

        # content
        content_code = self.gen_content_code(rule.get("content", []))

        return self.template_udp.format(
            sid=sid,
            port_check=port_check,
            content_code=content_code
        )

    # ----------------------------------------------------------------------

    def compile_icmp_rule(self, rule):
        sid = rule["sid"]

        icmp_type = rule.get("icmp_type", 8)  # 默认 echo-request

        return self.template_icmp.format(
            sid=sid,
            icmp_type=icmp_type
        )

    # ----------------------------------------------------------------------

    def gen_flag_expr(self, flags):
        """
        生成 flags 表达式，例如：
        TCP SYN → (flags & 0x02)
        TCP NULL → (flags == 0)
        TCP FIN → (flags & 0x01)
        """
        if not flags:
            return "1"  # 不限制

        exprs = []
        if flags.get("syn"):
            exprs.append("(flags & 0x02)")
        if flags.get("fin"):
            exprs.append("(flags & 0x01)")
        if flags.get("null"):
            exprs.append("(flags == 0)")
        if flags.get("xmas"):
            exprs.append("((flags & 0x29) == 0x29)")

        if not exprs:
            return "1"

        return " && ".join(exprs)

    # ----------------------------------------------------------------------

    def gen_content_code(self, content_list):
        """
        content_list 为 Snort content 条件数组，生成 payload 匹配代码
        """
        if not content_list:
            return "// no payload match"

        lines = ["// payload checks"]

        offset = 0
        for item in content_list:
            # e.g.  "BN|10 00 02 00|\",depth 6"
            cond, *rest = item.split(",")
            cond = cond.strip()

            # split raw and depth
            if "|" in cond:
                # "BN|10 00 02 00|" 这种混合格式
                parts = cond.split("|")
                prefix = parts[0]
                raw_bytes = parts[1].strip()
                byte_values = prefix.encode().hex().upper().split()
                if raw_bytes:
                    byte_values += raw_bytes.split()
            else:
                # 单字符串
                byte_values = cond.encode().hex().upper().split()

            depth = 0
            for r in rest:
                if "depth" in r:
                    depth = int(r.split()[-1])

            # eBPF payload match
            for i, bv in enumerate(byte_values):
                off = offset + i
                lines.append(
                    f"unsigned char b{off}=0; "
                    f"if (bpf_skb_load_bytes(skb, payload_off + {off}, &b{off}, 1) < 0 || "
                    f"b{off} != 0x{bv}) break;"
                )

            offset += depth

        return "\n    ".join(lines)