#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Refactored IDS Manager - Clean OOP Architecture
Uses ebpf_oop_generator for progressive rule deployment
Replaces all broken eBPF code with new OOP-based generator

"""
import os
import json
import sys
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
import signal
import time
import subprocess
from bcc import BPF
from ebpf_oop_generator import DeploymentManager

# Import the OOP generator
from ebpf_oop_generator import (
    DeploymentManager, RuleBatcher, IPConfig,
    TCPRuleEBPFGenerator, UDPRuleEBPFGenerator,
    RulePatternFactory
)

# ============================================================================
# CONFIGURATION
# ============================================================================

class IDSConfig:
    """Centralized IDS configuration"""
    def __init__(self):
        # Project paths - FIXED
        self.current_dir = Path(__file__).resolve().parent

        # FIX: Detect if we're in src/userspace or ebpf-ids root
        if self.current_dir.name == "userspace":
            # Running from: .../src/userspace/
            self.project_root = self.current_dir.parent.parent
            self.userspace_dir = self.current_dir
        elif self.current_dir.name == "ebpf-ids" and (self.current_dir / "src").exists():
            # Running from: .../ebpf-ids/
            self.project_root = self.current_dir
            self.userspace_dir = self.current_dir / "src" / "userspace"
        else:
            # Default fallback
            self.project_root = self.current_dir.parent.parent
            self.userspace_dir = self.current_dir.parent.parent / "src" / "userspace"

        self.kernel_dir = self.project_root / "src" / "kernel"
        self.snort_json = self.project_root / "snort_rules_ebpf.json"

        # Output paths - Create in userspace directory
        self.output_dir = self.userspace_dir / "generated_ebpf"
        self.alerts_log = self.userspace_dir / "ids_alerts.log"

        # eBPF configuration
        self.batch_size = 5 # Start with 5 rules per batch
        self.max_rules_per_function = 10

        # IP configuration
        self.ip_config = IPConfig(
            home_net="10.10.0.0/16", # Your GCP VPC subnet
            external_net="0.0.0.0/0"
        )

# ============================================================================
# RULE MANAGER (OOP)
# ============================================================================

class RuleManager:
    """Manages rule loading, analysis, and eBPF code generation"""
    def __init__(self, config: IDSConfig):
        self.config = config
        self.deployment_manager: Optional[DeploymentManager] = None
        self.rule_count = 0
        self.batch_count = 0

    def initialize(self) -> bool:
        """Initialize rule manager and load rules"""
        try:
            if not self.config.snort_json.exists():
                print(f"❌ Snort rules JSON not found: {self.config.snort_json}")
                return False

            print(f"📂 Loading rules from: {self.config.snort_json}")
            self.deployment_manager = DeploymentManager(
                str(self.config.snort_json),
                batch_size=self.config.batch_size,
                ip_config=self.config.ip_config
            )

            self.rule_count = self.deployment_manager.load_and_batch_rules()
            self.batch_count = self.deployment_manager.batcher.get_batch_count()
            return True
        except Exception as e:
            print(f"❌ Failed to initialize rule manager: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_batch_code(self, batch_num: int) -> bool:
        """Generate eBPF code for specific batch"""
        if not self.deployment_manager:
            return False
        return self.deployment_manager.generate_batch_code(batch_num)

    def export_generated_code(self) -> bool:
        """Export all generated code to output directory"""
        if not self.deployment_manager:
            return False
        try:
            # FIX: Ensure output directory exists
            self.config.output_dir.mkdir(parents=True, exist_ok=True)
            print(f"✓ Created output directory: {self.config.output_dir}")

            success_count = 0
            failed_count = 0

            for i in range(self.batch_count):
                if self.generate_batch_code(i):
                    # FIX: Handle return value properly
                    if self.deployment_manager.export_batch_code(i, str(self.config.output_dir)):
                        success_count += 1
                    else:
                        failed_count += 1
                else:
                    failed_count += 1
            
            print(f"\\n✓ Export Summary: {success_count} batches exported, {failed_count} failed")
            if success_count > 0:
                print(f"✓ Files exported to: {self.config.output_dir}")
                print(f"✓ Verify with: ls -la {self.config.output_dir}")
                return True
            else:
                return False

        except Exception as e:
            print(f"❌ Export failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_batch_info(self, batch_num: int) -> Dict:
        """Get information about specific batch"""
        if not self.deployment_manager:
            return {}
        return self.deployment_manager.get_batch_info(batch_num)

    def get_test_command(self, batch_num: int) -> str:
        """Get nmap test command for batch"""
        if not self.deployment_manager:
            return ""
        return self.deployment_manager.generate_test_command(batch_num)

    def print_summary(self):
        """Print summary of all loaded rules and batches"""
        if not self.deployment_manager:
            return

        print("\\n" + "=" * 80)
        print("RULE LOADING SUMMARY")
        print("=" * 80)
        print(f"Total Rules Loaded: {self.rule_count}")
        print(f"Batch Size: {self.config.batch_size}")
        print(f"Total Batches: {self.batch_count}")
        print()

        for i in range(min(self.batch_count, 10)): # Show first 10 batches
            info = self.get_batch_info(i)
            if info:
                print(f"Batch {i}: {info['total_rules']} rules \\n"
                      f"(TCP: {info['tcp_rules']}, UDP: {info['udp_rules']}, ICMP: {info['icmp_rules']})")

# ============================================================================
# EVENT HANDLER (OOP)
# ============================================================================

class EventHandler:
    """Handles eBPF perf buffer events"""
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.event_count = 0
        self.alert_count = 0
        self._init_log()

    def _init_log(self):
        """Initialize alert log file"""
        try:
            # FIX: Ensure parent directory exists
            Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, 'a') as f:
                f.write("\\n" + "=" * 80 + "\\n")
                f.write(f"Session started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
                f.write("=" * 80 + "\\n\\n")
        except Exception as e:
            print(f"⚠️ Failed to initialize log file: {e}")

    def handle_alert(self, cpu, data, size):
        """Handle eBPF alert event"""
        import ctypes as ct

        class AlertEvent(ct.Structure):
            _fields_ = [
                ("rule_id", ct.c_uint32),
                ("priority", ct.c_uint32),
                ("src_ip", ct.c_uint32),
                ("dst_ip", ct.c_uint32),
                ("src_port", ct.c_uint16),
                ("dst_port", ct.c_uint16),
                ("msg", ct.c_char * 256),
            ]

        try:
            alert = ct.cast(data, ct.POINTER(AlertEvent)).contents
            self.alert_count += 1
            src_ip = self._format_ip(alert.src_ip)
            dst_ip = self._format_ip(alert.dst_ip)
            msg = alert.msg.decode('utf-8', errors='ignore').rstrip('\\x00')

            alert_line = (
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"Alert #{self.alert_count}: Rule {alert.rule_id} (Priority {alert.priority})\\n"
                f"  {msg}\\n"
                f"  {src_ip}:{alert.src_port} → {dst_ip}:{alert.dst_port}\\n"
            )

            print(alert_line)
            self._log_alert(alert_line)
        except Exception as e:
            print(f"❌ Error handling alert: {e}")

    @staticmethod
    def _format_ip(ip_int: int) -> str:
        """Format IP from integer"""
        return ".".join([
            str((ip_int >> (i * 8)) & 0xFF) for i in range(4)
        ])

    def _log_alert(self, alert_line: str):
        """Write alert to log file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(alert_line + "\\n")
        except Exception as e:
            print(f"⚠️ Failed to write alert log: {e}")

    def get_stats(self) -> Dict:
        """Get alert statistics"""
        return {
            "total_events": self.event_count,
            "total_alerts": self.alert_count,
        }

# ============================================================================
# DEPLOYMENT CONTROLLER (OOP)
# ============================================================================

class DeploymentController:
    """Controls the deployment and lifecycle of eBPF programs"""

    def __init__(self, config: IDSConfig, rule_manager: RuleManager, event_handler: EventHandler):
        self.config = config
        self.rule_manager = rule_manager
        self.event_handler = event_handler
        self.bpf_instances: Dict[str, BPF] = {}
        self.running = True
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

    def _handle_exit(self, signum, frame):
        """Handle graceful shutdown"""
        print("\\n gracefully shutting down...")
        self.running = False
        # Detach BPF programs?
        # In this model, exit is sufficient
        sys.exit(0)

    def deploy_and_monitor(self):
        """Main deployment and monitoring loop"""
        if not self.rule_manager.deployment_manager:
            return

        # Get the primary interface
        interface = self._get_primary_interface()
        if not interface:
            print("❌ Could not determine primary network interface.")
            return

        print(f"✓ Using network interface: {interface}")

        # Iterate through batches and deploy
        for i in range(self.rule_manager.batch_count):
            if not self.running:
                break

            batch_info = self.rule_manager.get_batch_info(i)
            print("\\n" + "=" * 80)
            print(f"🚀 DEPLOYING BATCH {i}/{self.rule_manager.batch_count - 1}")
            print("=" * 80)

            # Load and attach TCP rules
            if batch_info.get('tcp_rules', 0) > 0:
                if not self._load_and_attach_bpf(i, 'tcp', interface):
                    continue # Skip to next batch on failure

            # Load and attach UDP rules
            if batch_info.get('udp_rules', 0) > 0:
                if not self._load_and_attach_bpf(i, 'udp', interface):
                    continue

            # Add ICMP later if needed

            print(f"✓ Batch {i} loaded. Monitoring for alerts...")
            print("💡 Press Ctrl+C to stop.")

            # Test command
            test_cmd = self.rule_manager.get_test_command(i)
            if test_cmd:
                print(f"🧪 To test, run: sudo {test_cmd}")

            # Monitor for a bit before the next batch
            self._poll_for_alerts(5)

        if self.running:
            print("\\n" + "=" * 80)
            print("✅ All batches deployed. Continuous monitoring active.")
            print("=" * 80)
            while self.running:
                self._poll_for_alerts(1)

    def _load_and_attach_bpf(self, batch_num: int, proto: str, interface: str) -> bool:
        """Loads, compiles, and attaches a BPF program"""
        bpf_file = self.config.output_dir / f"bpf_{proto}_batch_{batch_num}.c"
        if not bpf_file.exists():
            print(f"⚠️ BPF file not found for batch {batch_num} ({proto}): {bpf_file}")
            return False

        print(f"📄 Loading eBPF code from: {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()

        try:
            # Compile the BPF program
            bpf = BPF(text=bpf_text)
            self.bpf_instances[f"{proto}_{batch_num}"] = bpf

            # Attach the filter
            if not self._attach_raw_socket_filter(bpf, interface):
                return False

            # Open perf buffer for alerts
            bpf["alerts"].open_perf_buffer(self.event_handler.handle_alert)
            print(f"✓ Successfully loaded and attached {proto.upper()} rules for batch {batch_num}")
            return True

        except Exception as e:
            print(f"❌ Failed to load {proto.upper()} rules for batch {batch_num}: {e}")
            # Consider adding more detailed error logging, e.g., from the BPF compiler
            return False

    def _attach_raw_socket_filter(self, bpf: BPF, interface: str) -> bool:
        """Attach the BPF program to a raw socket"""
        import socket
        from socket import AF_PACKET, SOCK_RAW, htons
        ETH_P_ALL = 0x0003  # Listen for all ethernet protocols

        try:
            # Load the BPF program function
            bpf_prog = bpf.load_func("socket_filter", BPF.SOCKET_FILTER)

            # Create a raw socket and bind it to the interface
            sock = socket.socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
            sock.bind((interface, 0))

            # Attach the eBPF program to the raw socket
            bpf.attach_raw_socket(sock, bpf_prog)

            return True

        except Exception as e:
            print(f"❌ Failed to attach socket filter: {e}")
            return False

    def _poll_for_alerts(self, duration: int):
        """Poll all BPF instances for alerts for a given duration"""
        start_time = time.time()
        while time.time() - start_time < duration:
            if not self.running:
                break
            for bpf in self.bpf_instances.values():
                bpf.perf_buffer_poll(100) # Poll with a timeout
            time.sleep(0.1) # Brief sleep to avoid busy-waiting

    @staticmethod
    def _get_primary_interface() -> Optional[str]:
        """Get the primary (default) network interface"""
        try:
            result = subprocess.run(
                ['/bin/bash', '-c', "ip route | grep default | sed -e 's/^.*dev.//' -e 's/.proto.*//'"],
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"⚠️ Could not get primary interface: {e}")
            # Fallback for different systems
            try:
                # A less reliable but common fallback
                with open('/proc/net/route') as f:
                    for line in f:
                        fields = line.strip().split()
                        if fields[1] == '00000000' and int(fields[3], 16) & 2:
                            return fields[0]
            except:
                return None

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main function"""
    print("=" * 80)
    print("eBPF IDS Manager - Refactored OOP Edition")
    print("=" * 80)

    # 1. Configuration
    config = IDSConfig()
    print(f"Project Root: {config.project_root}")
    print(f"Userspace Dir: {config.userspace_dir}")

    # 2. Initialize Managers
    rule_manager = RuleManager(config)
    event_handler = EventHandler(str(config.alerts_log))

    if not rule_manager.initialize():
        print("❌ Halting due to rule initialization failure.")
        sys.exit(1)

    # 3. Print Summary
    rule_manager.print_summary()

    # 4. Generate and Export eBPF Code
    if not rule_manager.export_generated_code():
        print("❌ Halting due to eBPF code generation failure.")
        sys.exit(1)

    # 5. Deploy and Monitor
    controller = DeploymentController(config, rule_manager, event_handler)
    controller.deploy_and_monitor()

    print("\\n" + "=" * 80)
    print("✅ IDS Shutdown Complete")
    stats = event_handler.get_stats()
    print(f"Final Stats: {stats['total_alerts']} alerts recorded.")
    print(f"See log for details: {config.alerts_log}")
    print("=" * 80)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ This script requires root privileges to attach eBPF programs.")
        print("   Please run with 'sudo'.")
        sys.exit(1)
    main()

