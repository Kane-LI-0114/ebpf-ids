#!/bin/bash

# eBPF IDS startup script

echo "================================"
echo "  eBPF IDS Startup Script"
echo "================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: Please run this script with sudo"
    echo "Usage: sudo ./run_ids.sh"
    exit 1
fi

# Check Python3on3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 not found"
    exit 1
fi

# Check BCC
echo "Checking BCC installation..."
python3 -c "from bcc import BPF" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: BCC not installed or cannot be imported"
    echo "Please install BCC: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
    exit 1
fi
echo "✓ BCC installed"

# Check rule file
if [ ! -f "rules/snort_rules_ebpf.json" ]; then
    echo "Error: Rule file does not exist: rules/snort_rules_ebpf.json"
    exit 1
fi
echo "✓ Rule file exists"

# Start IDS
echo ""
echo "Starting eBPF IDS..."
echo "Press Ctrl+C to stop"
echo ""

cd "$(dirname "$0")"
python3 src/userspace/ids_manager.py
