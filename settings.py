#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF IDS 配置文件
"""

from dataclasses import dataclass, field

@dataclass
class DebugConfig:
    """调试配置"""
    enabled: bool = False                        # 是否启用调试模式
    print_interval: int = 100                   # 每 N 个事件打印一次普通流量
    stats_interval: int = 5                     # 每 N 秒打印一次统计信息
    ssh_interval: int = 1000                    # SSH 流量每 N 个包打印一次
    icmp_interval: int = 10                     # ICMP 流量每 N 个包打印一次
    important_ports: list = field(default_factory=lambda: [80, 443, 8080, 21, 23, 3306, 5432])
    alert_dedup_timeout: int = 10               # 告警去重时间（秒）

