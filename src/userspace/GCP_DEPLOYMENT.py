#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF IDS - Google Cloud Deployment Guide
Complete setup, deployment, and testing on GCP Debian Linux

This guide covers:
1. Prerequisites and kernel requirements
2. Installation steps
3. Loading eBPF code to kernel
4. Expected alert behavior
5. Real machine vs test mode differences
6. Monitoring and troubleshooting
"""

import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime


class GCPDeploymentGuide:
    """Complete guide for GCP deployment"""

    SETUP_SCRIPT = """#!/bin/bash
# Google Cloud Debian Linux - eBPF IDS Setup Script

set -e

echo "====== eBPF IDS - GCP Setup ======"
echo "Target: Debian Linux on Google Cloud"
echo "Date: $(date)"

# Step 1: Check prerequisites
echo ""
echo "[1] Checking prerequisites..."

# Check kernel version (need 4.8+)
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
echo "Kernel version: $(uname -r)"

# Check if BPF available
if [ -d /sys/kernel/debug/tracing ]; then
    echo "✓ BPF tracing available"
else
    echo "⚠ BPF tracing may not be available"
fi

# Check if BCC tools available
if command -v python3 &> /dev/null; then
    echo "✓ Python3 installed"
else
    echo "✗ Python3 not found - installing..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip
fi

# Step 2: Install dependencies
echo ""
echo "[2] Installing BCC (Berkeley Packet Filter Compiler)..."

sudo apt-get update
sudo apt-get install -y \\
    build-essential \\
    libelf-dev \\
    libllvm-dev \\
    llvm-dev \\
    clang \\
    python3-pip \\
    python3-dev \\
    git \\
    linux-headers-$(uname -r) \\
    bpftool

# Install BCC from pip (easier on GCP)
pip3 install bcc

echo "✓ Dependencies installed"

# Step 3: Verify BCC installation
echo ""
echo "[3] Verifying BCC installation..."

python3 -c "from bcc import BPF; print('✓ BCC library loaded successfully')" || \\
    echo "⚠ BCC verification may need manual setup"

# Step 4: Check network interfaces
echo ""
echo "[4] Detecting network interfaces..."

ip link show | grep "^[0-9]" | grep -v "^1:" | awk '{print $2}' | tr -d ':' | while read iface; do
    echo "Found interface: $iface"
done

echo ""
echo "====== Setup Complete ======"
echo "Next: Run 'python3 ids_manager_new.py --status' to verify"
"""

    KERNEL_LOADER = """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

\"\"\"
eBPF IDS - Kernel Loader for Real Machines
Loads compiled eBPF code to kernel and captures live alerts

This is used AFTER exporting code and compiling with BCC
\"\"\"

import os
import sys
import subprocess
from pathlib import Path
from bcc import BPF
import ctypes
from datetime import datetime


class KernelEBPFLoader:
    \"\"\"Load and manage eBPF programs in kernel\"\"\"

    def __init__(self, generated_code_dir: str = "generated_ebpf",
                 interface: str = None, batch_num: int = 0):
        self.code_dir = Path(generated_code_dir)
        self.batch_num = batch_num
        self.interface = interface
        self.bpf_programs = {}
        self.sockets = {}        # <--- add this
        self.running = False

    def auto_detect_interface(self) -> str:
        \"\"\"Auto-detect primary network interface\"\"\"
        try:
            # Get default route interface
            result = subprocess.run(
                "ip route | grep default | awk '{print $5}'",
                shell=True,
                capture_output=True,
                text=True
            )
            if_name = result.stdout.strip().split('\\n')[0]
            if if_name:
                return if_name
        except:
            pass

        # Fallback: check common interface names
        for iface in ['ens4', 'eth0', 'ens3', 'wlan0']:  # ens4 checked first
            if Path(f'/sys/class/net/{iface}').exists():
                return iface

        print("✗ Could not auto-detect interface")
        return None

    def load_tcp_rules(self, batch_num: int) -> bool:
        \"\"\"Load TCP rules for batch\"\"\"
        tcp_file = self.code_dir / f"batch_{batch_num}_tcp_rules.c"
        
        if not tcp_file.exists():
            print(f"✗ TCP rules file not found: {tcp_file}")
            return False

        try:
            print(f"📦 Loading TCP rules from batch {batch_num}...")
            
            with open(tcp_file, 'r') as f:
                code = f.read()

            # Add BCC-specific template
            bcc_code = self._wrap_bcc_code(code, 'tcp')
            
            # Load to kernel
            from bcc import BPF  # already at top

            bpf = BPF(text=bcc_code)
            self.bpf_programs['tcp'] = bpf

            # Attach to network interface
            if not self.interface:
                self.interface = self.auto_detect_interface()
            if not self.interface:
                print("✗ No interface available")
                return False

            # Load socket filter function and attach to interface
            fn = bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
            BPF.attach_raw_socket(fn, self.interface)

            # Remember the socket FD so we can close it later
            self.sockets['tcp'] = fn.sock

            print(f"✓ TCP rules loaded on {self.interface}")

            return True

        except Exception as e:
            print(f"✗ Failed to load TCP rules: {e}")
            return False

    def load_udp_rules(self, batch_num: int) -> bool:
        \"\"\"Load UDP rules for batch\"\"\"
        udp_file = self.code_dir / f"batch_{batch_num}_udp_rules.c"
        
        if not udp_file.exists():
            print(f"⚠ UDP rules file not found: {udp_file}")
            return True  # Not critical

        try:
            print(f"📦 Loading UDP rules from batch {batch_num}...")
            
            with open(udp_file, 'r') as f:
                code = f.read()

            bcc_code = self._wrap_bcc_code(code, 'udp')
            bpf = BPF(text=bcc_code)
            self.bpf_programs['udp'] = bpf

            fn = bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
            BPF.attach_raw_socket(fn, self.interface)
            self.sockets['udp'] = fn.sock

            print(f"✓ UDP rules loaded on {self.interface}")

            return True

        except Exception as e:
            print(f"✗ Failed to load UDP rules: {e}")
            return False

    def _wrap_bcc_code(self, code: str, proto: str) -> str:
        \"\"\"Wrap generated code with BCC template\"\"\"
        return f'''
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// ====== Generated Code ======
{code}

// ====== Entry Point ======
int ids_filter(struct __sk_buff *skb) {{
    // Call protocol-specific handler
    if (tcp_rules_batch_{self.batch_num})
        return tcp_rules_batch_{self.batch_num}(skb);
    
    return 0;
}}
        '''

    def setup_perf_output(self):
        \"\"\"Setup perf buffer for alerts\"\"\"
        for name, bpf in self.bpf_programs.items():
            try:
                alert_output = bpf["alerts"]
                alert_output.open_perf_buffer(self.handle_alert)
                print(f"✓ Perf buffer setup for {name}")
            except:
                pass

    def handle_alert(self, cpu, data, size):
        \"\"\"Handle incoming alert from kernel\"\"\"
        class AlertEvent(ctypes.Structure):
            _fields_ = [
                ("rule_id", ctypes.c_uint32),
                ("priority", ctypes.c_uint32),
                ("src_ip", ctypes.c_uint32),
                ("dst_ip", ctypes.c_uint32),
                ("src_port", ctypes.c_uint16),
                ("dst_port", ctypes.c_uint16),
                ("msg", ctypes.c_char * 256),
            ]

        alert = ctypes.cast(data, ctypes.POINTER(AlertEvent)).contents
        
        src_ip = self._format_ip(alert.src_ip)
        dst_ip = self._format_ip(alert.dst_ip)
        msg = alert.msg.decode('utf-8', errors='ignore').rstrip('\\x00')

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert_line = (
            f"[{timestamp}] 🚨 ALERT TRIGGERED\\n"
            f"  Rule ID: {alert.rule_id}\\n"
            f"  Priority: {alert.priority}\\n"
            f"  Message: {msg}\\n"
            f"  Source: {src_ip}:{alert.src_port}\\n"
            f"  Destination: {dst_ip}:{alert.dst_port}\\n"
        )
        
        print(alert_line)
        
        # Log to file
        self._log_alert(alert_line)

    @staticmethod
    def _format_ip(ip_int: int) -> str:
        \"\"\"Convert integer IP to dotted notation\"\"\"
        return ".".join([
            str((ip_int >> (i * 8)) & 0xFF) for i in range(4)
        ])

    def _log_alert(self, alert_line: str):
        \"\"\"Write alert to log file\"\"\"
        try:
            with open("ids_alerts.log", 'a') as f:
                f.write(alert_line + "\\n")
        except Exception as e:
            print(f"⚠ Failed to log alert: {e}")

    def start_monitoring(self):
        \"\"\"Start live monitoring for alerts\"\"\"
        self.running = True
        print("\\n" + "=" * 80)
        print("🔍 LIVE MONITORING - Press Ctrl+C to stop")
        print("=" * 80)

        try:
            while self.running:
                # Poll perf buffers
                for bpf in self.bpf_programs.values():
                    try:
                        bpf.perf_buffer_poll(1)
                    except:
                        pass
        except KeyboardInterrupt:
            print("\\n✓ Monitoring stopped")
            self.running = False

    def unload_all(self):
        # Close any raw sockets we attached
        for name, sock_fd in self.sockets.items():
            try:
                os.close(sock_fd)
                print(f"✓ Closed {name} socket on {self.interface}")
            except OSError as e:
                print(f"⚠ Failed to close {name} socket: {e}")
        self.sockets.clear()
        # BPF objects will be cleaned up when the process exits


if __name__ == "__main__":
    loader = KernelEBPFLoader()
    
    print("\\n" + "=" * 80)
    print("eBPF IDS - Kernel Loader (Real Machine)")
    print("=" * 80)

    # Auto-detect interface
    if not loader.interface:
        loader.interface = loader.auto_detect_interface()
        if loader.interface:
            print(f"✓ Detected interface: {loader.interface}")
        else:
            print("✗ Could not detect interface")
            sys.exit(1)

    # Load batch 0
    if not loader.load_tcp_rules(0):
        sys.exit(1)

    loader.load_udp_rules(0)

    # Setup alerts
    loader.setup_perf_output()

    # Start monitoring
    loader.start_monitoring()

    # Cleanup
    loader.unload_all()
"""

    @staticmethod
    def create_setup_script(output_file: str = "gcp_setup.sh"):
        """Create GCP setup script"""
        with open(output_file, 'w') as f:
            f.write(GCPDeploymentGuide.SETUP_SCRIPT)
        os.chmod(output_file, 0o755)
        print(f"✓ Created setup script: {output_file}")

    @staticmethod
    def create_kernel_loader(output_file: str = "kernel_loader.py"):
        """Create kernel loader script"""
        with open(output_file, 'w') as f:
            f.write(GCPDeploymentGuide.KERNEL_LOADER)
        os.chmod(output_file, 0o755)
        print(f"✓ Created kernel loader: {output_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="GCP eBPF IDS Deployment Guide")
    parser.add_argument("--generate-setup", action="store_true",
                       help="Generate GCP setup script")
    parser.add_argument("--generate-loader", action="store_true",
                       help="Generate kernel loader")
    parser.add_argument("--all", action="store_true",
                       help="Generate all scripts")

    args = parser.parse_args()

    if args.generate_setup or args.all:
        GCPDeploymentGuide.create_setup_script()

    if args.generate_loader or args.all:
        GCPDeploymentGuide.create_kernel_loader()

    if args.all:
        print("\n✓ All scripts generated!")
        print("Next steps:")
        print("  1. chmod +x gcp_setup.sh")
        print("  2. ./gcp_setup.sh")
        print("  3. python3 ids_manager_new.py --export")
        print("  4. python3 kernel_loader.py")


if __name__ == "__main__":
    main()
