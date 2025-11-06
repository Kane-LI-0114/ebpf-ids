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
        # BCC 兼容头（使用 bcc 提供的宏：BPF_PERF_OUTPUT 等）
        self.header = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <linux/in.h>

BPF_PERF_OUTPUT(events);
BPF_HASH(rule_stats, __u32, __u64, 1000);

// 事件结构（用户侧 ctypes 要与此一致）
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 sid;
};

// 辅助：安全读取 skb 内字节（bcc 提供）
static __always_inline int safe_load_byte(struct __sk_buff *skb, __u32 off, unsigned char *out) {
    // bpf_skb_load_bytes 返回 0 成功，<0 失败
    return bpf_skb_load_bytes(skb, off, out, 1);
}
"""

    def _gen_rule_check_with_skb(self, rule, base_idx=0):
        """
        为单条规则生成 socket-filter 风格的检测代码（使用 bpf_skb_load_bytes）
        返回字符串（代码片段）
        """
        sid = rule.get("sid", 0)
        proto = int(rule.get("protocol", 0) or 0)
        ptype, pval1, pval2 = rule.get("dst_port", (0, 0, 0))
        content = rule.get("content", b"") or b""
        clen = len(content)

        lines = []
        lines.append(f"    /* rule {sid} start */")

        # 1) 读取 IP 协议字段（以太头 14 bytes，IP 协议在 offset 23：14 + 9）
        #    ip header: at offset 14..; ip->protocol is at eth + 9 (relative to IP start),
        #    but easiest: load IP proto at offset 23 (14 + 9). ip header length (ihl) at 14 + 0 (first byte low nibble).
        lines.append("    {")
        lines.append("        unsigned char tmp = 0;")
        # load first byte of IP header to get ihl (offset 14)
        lines.append("        if (bpf_skb_load_bytes(skb, 14, &tmp, 1) < 0) goto __next_rule_%d;" % sid)
        # ihl in low 4 bits *4 gives header length
        lines.append("        unsigned int ihl = (tmp & 0x0f) * 4;")
        # load protocol byte at offset 14 + 9
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 9, &tmp, 1) < 0) goto __next_rule_%d;" % sid)
        if proto != 0:
            lines.append(f"        if (tmp != {proto}) goto __next_rule_{sid};")
        # compute l4 offset
        lines.append("        unsigned int l4_off = 14 + ihl;")

        # 2) 如果需要检查端口，读取 tcp/udp dest port (2 bytes)
        if ptype != 0:
            # need ensure enough bytes for port (2 bytes)
            # read 2 bytes into two tmp bytes
            lines.append("        unsigned char p0=0, p1=0;")
            # read first byte of dest port (offset l4_off + 2) (for TCP header: source(0-1), dest(2-3))
            lines.append("        if (bpf_skb_load_bytes(skb, l4_off + 2, &p0, 1) < 0) goto __next_rule_%d;" % sid)
            lines.append("        if (bpf_skb_load_bytes(skb, l4_off + 3, &p1, 1) < 0) goto __next_rule_%d;" % sid)
            # combine
            lines.append("        unsigned short dst_port = (p0 << 8) | p1;")
            if ptype == 1:
                lines.append(f"        if (dst_port != {pval1}) goto __next_rule_{sid};")
            elif ptype == 2:
                lines.append(f"        if (!(dst_port >= {pval1} && dst_port <= {pval2})) goto __next_rule_{sid};")

        # 3) payload/content check - 逐字节读取并比较
        if clen > 0:
            # compute payload start: l4_off + header_len (for TCP we need data offset)
            # But we don't know TCP doff here easily without reading tcp header first.
            # For simplicity, assume minimal L4 header length: for TCP read data offset (doff) from tcp header first byte at l4_off + 12 (offset 12 -> data offset/flags)
            lines.append("        // content compare (逐字节读取并比较)")
            # try read first byte of L4 header to detect TCP data offset if proto==6
            if proto == 6:
                # read tcp data offset byte (tcp->doff is high 4 bits of offset at offset 12)
                lines.append("        unsigned char tcp_hl = 0;")
                lines.append("        if (bpf_skb_load_bytes(skb, l4_off + 12, &tcp_hl, 1) < 0) goto __next_rule_%d;" % sid)
                lines.append("        unsigned int tcp_hdr_len = (tcp_hl >> 4) * 4;")
                lines.append("        unsigned int payload_off = l4_off + tcp_hdr_len;")
            else:
                # UDP header is fixed 8 bytes
                if proto == 17:
                    lines.append("        unsigned int payload_off = l4_off + 8;")
                else:
                    # for other protocols, assume payload starts immediately after IP header
                    lines.append("        unsigned int payload_off = l4_off;")

            # now compare content bytes one by one
            lines.append(f"        unsigned char btmp = 0;")
            for i, b in enumerate(content[:16]):  # limit to first 16 bytes (safety)
                lines.append("        if (bpf_skb_load_bytes(skb, payload_off + %d, &btmp, 1) < 0) goto __next_rule_%d;" % (i, sid))
                lines.append(f"        if (btmp != 0x{b:02x}) goto __next_rule_{sid};")

        # 4) 命中：提交 event（使用 events.perf_submit 的 BCC 接口）
        # Note: BCC 的 events.perf_submit 需要 skb 和指针，使用 bpf_trace_printk 或 events.perf_submit 来输出
        lines.append("        // rule matched -> update stats and emit event")
        lines.append(f"        {{ __u32 _k = {sid}; __u64 *_c = rule_stats.lookup(&_k); if (_c) (*_c)++; else {{ __u64 _i=1; rule_stats.update(&_k, &_i); }} }}")
        # build minimal event and submit (we'll read ip src/dst and ports similarly)
        # read src ip (offset 14 + 12..15)
        lines.append("        unsigned char ipb0=0, ipb1=0, ipb2=0, ipb3=0;")
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 12 + 0, &ipb0, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 12 + 1, &ipb1, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 12 + 2, &ipb2, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 12 + 3, &ipb3, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        __u32 src_ip = (ipb0) | (ipb1 << 8) | (ipb2 << 16) | (ipb3 << 24);")
        # dst ip
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 16 + 0, &ipb0, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 16 + 1, &ipb1, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 16 + 2, &ipb2, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        if (bpf_skb_load_bytes(skb, 14 + 16 + 3, &ipb3, 1) < 0) goto __next_rule_%d;" % sid)
        lines.append("        __u32 dst_ip = (ipb0) | (ipb1 << 8) | (ipb2 << 16) | (ipb3 << 24);")

        # ports: try fill src/dst if read earlier
        if ptype != 0:
            lines.append("        unsigned short src_port = 0;")
            lines.append("        unsigned char sp0=0, sp1=0;")
            lines.append("        if (bpf_skb_load_bytes(skb, l4_off + 0, &sp0, 1) >= 0 && bpf_skb_load_bytes(skb, l4_off + 1, &sp1, 1) >= 0) {")
            lines.append("            src_port = (sp0 << 8) | sp1;")
            lines.append("        }")
            lines.append("        unsigned short dst_port_out = dst_port;")
        else:
            lines.append("        unsigned short src_port = 0;")
            lines.append("        unsigned short dst_port_out = 0;")

        # Prepare event struct on stack (small) and submit
        lines.append("        struct packet_event evt = {0};")
        lines.append("        evt.src_ip = src_ip; evt.dst_ip = dst_ip; evt.src_port = src_port; evt.dst_port = dst_port_out; evt.protocol = tmp; evt.sid = %d;" % sid)
        # BCC 的 events.perf_submit 接口 in-kernel usage: events.perf_submit(skb, &evt, sizeof(evt));
        lines.append("        events.perf_submit(skb, &evt, sizeof(evt));")
        lines.append("        goto __rule_done_%d;" % sid)

        # labels for normal path
        lines.append("__next_rule_%d: ;" % sid)
        lines.append("__rule_done_%d: ;" % sid)
        lines.append("    }  /* end of rule block */")
        lines.append("    /* rule %d end */" % sid)
        return "\n".join(lines)

    def compile_rules_inline(self, rules, max_content_depth=8, max_inline_rules=200):
        """
        生成 BCC socket-filter 风格的 eBPF 源码
        - max_content_depth: 单条规则最大允许的 content 长度（字节）
        - max_inline_rules: 最多内联多少条规则
        """
        inline = []
        skipped = []

        for r in rules:
            c = r.get("content", b"") or b""
            if len(c) == 0 or len(c) <= max_content_depth:
                inline.append(r)
            else:
                skipped.append((r.get("sid"), len(c)))

        if len(inline) > max_inline_rules:
            extra = inline[max_inline_rules:]
            inline = inline[:max_inline_rules]
            for e in extra:
                skipped.append((e.get("sid"), len(e.get("content", b"") or b"")))

        if skipped:
            print(f"⚠ 跳过 {len(skipped)} 条过大或复杂的规则（仅内联短规则）")
            print("  被跳过的规则示例（SID, content_len）:", skipped[:20])

        parts = [self.header]

        # 生成每条规则检查片段
        for rule in inline:
            parts.append(self._gen_rule_check_with_skb(rule))

        # 生成主 ids_filter (socket filter)
        parts.append(r"""
int ids_filter(struct __sk_buff *skb) {
    // 我们用 bpf_skb_load_bytes 逐字节读取需要的头与 payload，避免直接指针访问 skb->data
    // 若规则匹配，会通过 events.perf_submit 提交事件
""")
        # 调用每条内联规则片段：这些片段已经包含 goto 跳转和提交
        for rule in inline:
            sid = rule.get("sid", 0)
            # 片段本身已经设定 goto 跳转与标签，所以这里只是占位（片段已被拼入）
            # nothing additional required here
            pass

        parts.append("    return 0;\n}\n")
        return "\n".join(parts)

    def compile_rules(self, rules):
        print(f"正在动态生成并编译 eBPF 程序 ({len(rules)} 条规则)...")
        try:
            # 可根据需要调整阈值
            return self.compile_rules_inline(rules, max_content_depth=8, max_inline_rules=200)
        except Exception as e:
            print(f"✗ eBPF 编译失败: {e}")
            raise
