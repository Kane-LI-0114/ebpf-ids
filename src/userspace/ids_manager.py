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
        self.batch_size = 5  # Start with 5 rules per batch
        self.max_rules_per_function = 10
        
        # IP configuration
        self.ip_config = IPConfig(
            home_net="10.10.0.0/16",      # Your GCP VPC subnet
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
            
            print(f"\n✓ Export Summary: {success_count} batches exported, {failed_count} failed")
            
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
        
        print("\n" + "=" * 80)
        print("RULE LOADING SUMMARY")
        print("=" * 80)
        print(f"Total Rules Loaded: {self.rule_count}")
        print(f"Batch Size: {self.config.batch_size}")
        print(f"Total Batches: {self.batch_count}")
        print()
        
        for i in range(min(self.batch_count, 10)):  # Show first 10 batches
            info = self.get_batch_info(i)
            if info:
                print(f"Batch {i}: {info['total_rules']} rules "
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
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Session started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
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
            msg = alert.msg.decode('utf-8', errors='ignore').rstrip('\x00')
            
            alert_line = (
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"Alert #{self.alert_count}: Rule {alert.rule_id} (Priority {alert.priority})\n"
                f"  {msg}\n"
                f"  {src_ip}:{alert.src_port} → {dst_ip}:{alert.dst_port}\n"
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
                f.write(alert_line + "\n")
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
    """Controls eBPF program deployment to kernel"""
    
    def __init__(self, config: IDSConfig):
        self.config = config
        self.rule_manager = RuleManager(config)
        self.event_handler = EventHandler(str(config.alerts_log))
        self.current_batch = 0
    
    def initialize(self) -> bool:
        """Initialize IDS system"""
        print("🚀 Initializing IDS System...")
        
        if not self.rule_manager.initialize():
            return False
        
        self.rule_manager.print_summary()
        return True
    
    def prepare_batch(self, batch_num: int) -> bool:
        """Prepare eBPF code for specific batch"""
        if batch_num >= self.rule_manager.batch_count:
            print(f"❌ Batch {batch_num} out of range (max: {self.rule_manager.batch_count - 1})")
            return False
        
        print(f"\n📦 Preparing Batch {batch_num}...")
        
        if self.rule_manager.generate_batch_code(batch_num):
            info = self.rule_manager.get_batch_info(batch_num)
            print(f"✓ Generated code for {info['total_rules']} rules")
            
            # Show test command
            test_cmd = self.rule_manager.get_test_command(batch_num)
            if test_cmd:
                print(f"✓ Test command: {test_cmd}")
            
            return True
        
        return False
    
    def deploy_batch_progressive(self, start_batch: int = 0, num_batches: int = 1) -> bool:
        """Deploy batches progressively (5, 10, 20, etc.)"""
        print(f"\n📡 Progressive Deployment Starting...")
        print(f"Starting from batch {start_batch}, loading {num_batches} batch(es)\n")
        
        for i in range(start_batch, min(start_batch + num_batches, self.rule_manager.batch_count)):
            if not self.prepare_batch(i):
                print(f"❌ Failed to prepare batch {i}")
                return False
            
            self.current_batch = i
            print(f"✓ Batch {i} ready for deployment\n")
        
        return True
    
    def export_all_code(self) -> bool:
        """Export all generated eBPF code"""
        print("\n💾 Exporting all generated code...")
        
        if self.rule_manager.export_generated_code():
            print(f"✓ Exported to: {self.config.output_dir}")
            return True
        
        return False
    
    def get_deployment_status(self) -> Dict:
        """Get current deployment status"""
        return {
            "initialized": self.rule_manager.deployment_manager is not None,
            "total_rules": self.rule_manager.rule_count,
            "total_batches": self.rule_manager.batch_count,
            "current_batch": self.current_batch,
            "alerts_log": str(self.config.alerts_log),
        }


# ============================================================================
# MAIN IDS MANAGER
# ============================================================================
import os
import time
import subprocess
from bcc import BPF
from ebpf_oop_generator import DeploymentManager

class IDSManager:
    """
    Manages the lifecycle of the eBPF-based IDS, including rule loading,
    eBPF program compilation, kernel attachment, and event monitoring.
    """
    def __init__(self, json_path: str, interface: str, batch_size: int = 5):
        """
        Initializes the IDSManager.
        Args:
            json_path: Path to the JSON file containing Snort rules.
            interface: The network interface to monitor (e.g., 'ens4').
            batch_size: The number of rules to include in each eBPF batch.
        """
        self.json_path = json_path
        self.interface = interface
        self.batch_size = batch_size
        self.deployment_manager = DeploymentManager(json_path, batch_size)
        self.loaded_bpf_programs = []

    def run(self):
        """
        Starts the IDS. Loads rules, attaches eBPF programs, and monitors for alerts.
        """
        print("================================================================================")
        print("eBPF IDS - Kernel Loader (Real Machine)")
        print("================================================================================")
        
        self._detect_interface()
        
        self.deployment_manager.load_and_batch_rules()
        
        # Load and attach all batches
        for i in range(self.deployment_manager.batcher.get_batch_count()):
            self.load_and_attach_batch(i)

        print("\n✅ All eBPF programs attached. Monitoring for alerts...")
        self._monitor_alerts()

    def cleanup(self):
        """
        Detaches all loaded eBPF programs from the interface to clean up.
        """
        print("\n🧹 Cleaning up and detaching eBPF programs...")
        for bpf in self.loaded_bpf_programs:
            bpf.remove_xdp(self.interface, 0)
        self.loaded_bpf_programs = []
        print("✅ Cleanup complete.")

    def _detect_interface(self):
        """
        Checks if the specified network interface exists.
        """
        try:
            subprocess.check_output(['ip', 'link', 'show', self.interface])
            print(f"✓ Detected interface: {self.interface}")
        except subprocess.CalledProcessError:
            print(f"✗ Error: Network interface '{self.interface}' not found.")
            exit(1)

    def load_and_attach_batch(self, batch_num: int):
        """
        Generates, loads, and attaches a specific batch of eBPF rules to the kernel.
        """
        self.deployment_manager.generate_batch_code(batch_num)
        code_dict = self.deployment_manager.kernel_functions.get(batch_num, {})

        # Process each protocol's generated code (e.g., tcp, udp)
        for proto, generated_c_code in code_dict.items():
            print(f"📦 Loading {proto.upper()} rules from batch {batch_num}...")
            
            try:
                # 1. Initialize BPF with the generated C code
                bpf = BPF(text=generated_c_code)
                
                # 2. Determine the function name from our generator convention
                function_name = f"{proto}_rules_batch_{batch_num}"
                
                # 3. Load the specific function from the compiled BPF code
                fn = bpf.load_func(function_name, BPF.XDP)
                
                # 4. Attach the function to the XDP hook of the network interface
                bpf.attach_xdp(dev=self.interface, fn=fn, flags=0)
                
                self.loaded_bpf_programs.append(bpf)
                print(f"✓ Successfully attached {proto.upper()} batch {batch_num} to '{self.interface}' via XDP")

            except Exception as e:
                print(f"✗ Failed to load {proto.upper()} rules: {e}")
                # Optional: decide if you want to exit or continue if a batch fails
                # exit(1) 

    def _monitor_alerts(self):
        """
        Sets up the alert monitoring loop and prints alerts as they arrive.
        """
        def print_event(cpu, data, size):
            """Callback function for handling alerts from the kernel."""
            event = bpf["alerts"].event(data)
            print(f"[ALERT] Rule SID: {event.rule_id} | Priority: {event.priority} | "
                  f"SRC: {self._ip_to_str(event.src_ip)}:{event.src_port} -> "
                  f"DST: {self._ip_to_str(event.dst_ip)}:{event.dst_port} | "
                  f"MSG: {event.msg.decode('utf-8', 'ignore')}")

        # Attach the callback to the 'alerts' perf buffer for each loaded BPF program
        for bpf in self.loaded_bpf_programs:
            bpf["alerts"].open_perf_buffer(print_event)

        # Main loop to poll for alerts
        try:
            while True:
                for bpf in self.loaded_bpf_programs:
                    bpf.perf_buffer_poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n🛑 IDS stopped by user.")
            self.cleanup()
            
    def _ip_to_str(self, ip_int):
        """Converts an integer IP address to its string representation."""
        import socket
        import struct
        return socket.inet_ntoa(struct.pack("!I", ip_int))

    if __name__ == '__main__':
        # Configuration
        INTERFACE = "ens4" 
        JSON_RULES_PATH = "community_rules.json" 
        BATCH_SIZE = 10

        # Create and run the IDS
        ids = IDSManager(json_path=JSON_RULES_PATH, interface=INTERFACE, batch_size=BATCH_SIZE)
        ids.run()

# ============================================================================
# UTILITY FUNCTIONS & MAIN
# ============================================================================

def print_help():
    """Print usage instructions"""
    help_text = """
╔════════════════════════════════════════════════════════════════╗
║     eBPF IDS Manager - OOP-Based Rule Deployment System       ║
╚════════════════════════════════════════════════════════════════╝

USAGE EXAMPLES:

1. Test with single batch (verify deployment works):
   manager = IDSManager()
   manager.deploy_test_batch(batch_num=0, test_nmap=True)

2. Export all generated code:
   manager = IDSManager()
   manager.export_code()

3. Deploy progressively (5 → 10 → 20 rules):
   manager = IDSManager()
   manager.deploy_production()

4. Check deployment status:
   manager = IDSManager()
   status = manager.get_status()
   print(json.dumps(status, indent=2))

KEY FEATURES:
✓ OOP-based modular design
✓ Progressive batch deployment (5-10-20+ rules)
✓ Automatic nmap test command generation
✓ $HOME_NET and $EXTERNAL_NET variable resolution
✓ Separate functions for each protocol (TCP/UDP/ICMP)
✓ Alert logging to file
✓ Clean separation of concerns

TESTING GUIDANCE:
1. Start with batch 0 (5 rules)
2. Generate nmap command: manager.deploy_test_batch(0, test_nmap=True)
3. Run nmap against target ports
4. Check ids_alerts.log for detections
5. If successful, deploy next batch
"""
    print(help_text)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="eBPF IDS Manager")
    parser.add_argument("--test-batch", type=int, default=0,
                       help="Test specific batch number")
    parser.add_argument("--export", action="store_true",
                       help="Export all code without deployment")
    parser.add_argument("--help-usage", action="store_true",
                       help="Show detailed usage examples")
    parser.add_argument("--status", action="store_true",
                       help="Show current status")
    
    args = parser.parse_args()
    
    if args.help_usage:
        print_help()
    else:
        manager = IDSManager()
        
        if args.export:
            print("📤 Exporting all generated code...")
            if manager.export_code():
                print("✅ Export successful")
            else:
                print("❌ Export failed")
        
        elif args.status:
            manager.start()
            status = manager.get_status()
            print(json.dumps(status, indent=2))
        
        else:
            print(f"🧪 Testing batch {args.test_batch}...")
            if manager.deploy_test_batch(args.test_batch, test_nmap=True):
                print("✅ Batch ready for testing")
            else:
                print("❌ Test failed")
