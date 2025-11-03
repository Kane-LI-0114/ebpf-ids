#!/bin/bash

# eBPF IDS 启动脚本

echo "================================"
echo "  eBPF IDS 启动脚本"
echo "================================"

# 检查是否以 root 运行
if [ "$EUID" -ne 0 ]; then 
    echo "错误: 请使用 sudo 运行此脚本"
    echo "用法: sudo ./run_ids.sh"
    exit 1
fi

# 检查 Python3
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到 Python3"
    exit 1
fi

# 检查 BCC
echo "检查 BCC 安装..."
python3 -c "from bcc import BPF" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "错误: BCC 未安装或无法导入"
    echo "请安装 BCC: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
    exit 1
fi
echo "✓ BCC 已安装"

# 检查规则文件
if [ ! -f "rules/snort_rules_ebpf.json" ]; then
    echo "错误: 规则文件不存在: rules/snort_rules_ebpf.json"
    exit 1
fi
echo "✓ 规则文件存在"

# 启动 IDS
echo ""
echo "启动 eBPF IDS..."
echo "按 Ctrl+C 停止"
echo ""

cd "$(dirname "$0")"
python3 src/userspace/ids_manager.py
