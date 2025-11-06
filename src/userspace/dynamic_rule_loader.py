class DynamicRuleLoader:
    def __init__(self, bpf_program):
        self.bpf = bpf_program
        self.rules_map = bpf_program["rules_map"]

    def load_rules(self, rules):
        """将规则加载到eBPF Map"""
        loaded_count = 0
        for rule in rules[:100]:  # 先加载100条测试
            if self._load_single_rule(rule):
                loaded_count += 1

        print(f"✓ 成功加载 {loaded_count} 条规则到 eBPF Map")

    def _load_single_rule(self, rule):
        """加载单条规则到Map"""
        try:
            # 构建规则键
            key = self._build_rule_key(rule)
            # 构建规则值
            value = self._build_rule_value(rule)
            # 更新到Map
            self.rules_map[key] = value
            return True

        except Exception as e:
            print(f"加载规则失败 SID={rule.get('sid', 'unknown')}: {e}")
            return False

    def _build_rule_key(self, rule):
        key = self.bpf.rule_key()
        key.protocol = rule.get('protocol', 0)  # 注意字段名！

        # 处理源端口
        src_port_type, src_val1, src_val2 = rule.get('src_port', (0, 0, 0))
        if src_port_type == 1:  # single port
            key.src_port = src_val1

        # 处理目标端口
        dst_port_type, dst_val1, dst_val2 = rule.get('dst_port', (0, 0, 0))
        if dst_port_type == 1:  # single port
            key.dst_port = dst_val1
        elif dst_port_type == 2:  # range - 先使用起始端口
            key.dst_port = dst_val1

        return key

    def _build_rule_value(self, rule):
        """构建规则值"""
        value = self.bpf.rule_value()
        value.sid = rule.get('sid', 0)
        value.action = 1  # alert
        value.priority = rule.get('priority', 3)

        # 处理内容
        content = rule.get('content', b'')
        if content and len(content) > 0:
            content_len = min(len(content), 32)
            # 将内容复制到 eBPF 结构体
            for i in range(content_len):
                value.content[i] = content[i]
            value.content_len = content_len
        else:
            value.content_len = 0

        return value