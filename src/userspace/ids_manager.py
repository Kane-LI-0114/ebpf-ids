#!/usr/bin/env python3
# -- coding: utf-8 --

import os
import sys
import json
import signal
import socket
import fcntl
import struct
import array
from datetime import datetime
from typing import Optional, Union
from pathlib import Path

from bcc import BPF

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from utils.snort_parser import SnortRuleParser
from src.userspace.udp_codegen import UDPRulesEBPFManager


# ---------------------------------------------------------------------------
# Helper function to get the active network interface and its IP address.
# ---------------------------------------------------------------------------
def get_interface_and_ip():
    """
    Identifies the default network interface and its IPv4 address.
    """
    # Get all network interfaces
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # This doesn't actually connect, but finds the interface used for the default route
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        
        # Find the interface name associated with this IP
        for iface in socket.if_nameindex():
            ifaddrs = socket.getaddrinfo(ip_address, None, socket.AF_INET)
            if ifaddrs and ifaddrs[0][4][0] == ip_address:
                return iface[1], ip_address

    except Exception as e:
        print(f"Could not determine the active interface and IP: {e}")
        # Fallback for environments where the above method fails
        try:
            with open("/proc/net/dev") as f:
                lines = f.readlines()
                for line in lines[2:]:
                    iface = line.split(":")[0].strip()
                    if iface != "lo":
                        return iface, "0.0.0.0" # Unable to determine IP
        except:
            return "eth0", "0.0.0.0" # Default fallback
    finally:
        s.close()

    return "eth0", "0.0.0.0" # Default if no interface is found


# ---------------------------------------------------------------------------
# Main IDS Manager Class
# ---------------------------------------------------------------------------
class IDSManager:
    """
    Manages the eBPF-based IDS, including rule loading, code generation,
    and event handling.
    """
    def __init__(self):
        self.bpf: Optional[BPF] = None
        self.udp_rules_manager = UDPRulesEBPFManager()
        self.rule_manager = RuleManager(rules_dir=PROJECT_ROOT)
        self.event_handler = EventHandler(self.rule_manager)
        self.sock = None  # To hold the raw socket and prevent it from being garbage-collected
        self.iface: Optional[str] = None

    def init_ids(self, iface: Optional[str] = None):
        """
        Initializes the IDS:
        1. Loads Snort rules and prepares them for the EventHandler.
        2. Generates and loads the eBPF C code for UDP rules.
        3. Compiles and attaches the eBPF program to a socket.
        """
        try:
            # 1. Load Snort rules for the EventHandler (to map SIDs to messages)
            print("✓ Loading Snort rules...")
            self.rule_manager.load_rules()
            
            # 2. Load UDP rules and generate the eBPF C code
            self.load_udp_rules()
            self.generate_udp_rules_code()

            # 3. Determine the interface and load the eBPF program
            if iface:
                self.iface = iface
            else:
                self.iface, victim_ip = get_interface_and_ip()
                print(f"✓ Automatically selected interface '{self.iface}' with IP '{victim_ip}'")

            self.load_ebpf_program(iface=self.iface)
            print("✓ IDS initialization complete")

        except Exception as e:
            print(f"✗ Error during IDS initialization: {e}")
            raise

    def load_udp_rules(self, json_path: str = SNORT_RULES_JSON):
        """
        Loads UDP rules from a JSON file.
        """
        with open(json_path, "r") as f:
            all_rules = json.load(f)
        
        udp_count = 0
        for rule in all_rules:
            if rule.get("protocol_num") == 17:
                if self.udp_rules_manager.add_rule(rule):
                    udp_count += 1
        
        print(f"✓ Loaded {udp_count} UDP rules")
        return udp_count

    def generate_udp_rules_code(self):
        """
        Generates the eBPF code for UDP rules.
        """
        print("Generating UDP rules eBPF code...")
        result = self.udp_rules_manager.generate_all_code(output_dir=KERNEL_DIR)
        print(f"✓ Generated {result['count']} UDP rules")
        return result

    def load_ebpf_program(self, iface: Optional[str] = None):
        """
        Loads the eBPF socket filter program and attaches it to a raw socket.
        """
        print("Compiling eBPF program...")
        if not os.path.isfile(UDP_RULES_C_PATH):
            raise FileNotFoundError(f"eBPF C code not found at: {UDP_RULES_C_PATH}")

        with open(UDP_RULES_C_PATH, "r") as f:
            kernel_code = f.read()

        try:
            # Change to project root for bcc to handle includes correctly
            os.chdir(PROJECT_ROOT)
            
            # Initialize BPF with the generated C code
            self.bpf = BPF(text=kernel_code)
            
            # Load and attach the socket filter
            fn = self.bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
            
            # Attach the filter to a raw socket
            self.sock = self.bpf.attach_raw_socket(fn, iface)
            
            print(f"✓ eBPF program compiled and attached as a socket filter to interface '{iface}'")

        except Exception as e:
            print(f"✗ Failed to load eBPF program. CWD: {os.getcwd()}")
            print(f"  Error: {e}")
            raise

    def set_up_event_buffers(self):
        """
        Sets up the perf buffer for receiving alerts from the kernel.
        """
        if self.bpf is None:
            raise RuntimeError("BPF program not loaded.")
        
        try:
            self.bpf["alerts"].open_perf_buffer(self.event_handler.handle_alert)
            print("✓ Opened 'alerts' perf buffer")
        except KeyError:
            print("✗ Warning: 'alerts' perf buffer not found in eBPF map.")

    def run(self):
        """
        Starts polling the perf buffer for events.
        """
        if self.bpf is None:
            raise RuntimeError("BPF program not loaded.")

        print("Starting to monitor for kernel alerts, press Ctrl+C to exit...")

        # Set up signal handler for graceful exit
        def handle_sigint(signum, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, handle_sigint)

        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n✓ IDS stopped by user.")
        finally:
            self.cleanup()

    def cleanup(self):
        """
        Cleans up resources, such as closing the raw socket.
        """
        print("Cleaning up resources...")
        try:
            if self.sock is not None:
                self.sock.close()
                print("✓ Closed raw socket")
        except Exception as e:
            print(f"✗ Warning: Failed to close raw socket: {e}")


# ---------------------------------------------------------------------------
# Rule and Event Handling Classes
# ---------------------------------------------------------------------------
class RuleManager:
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.ebpf_configs = []
        self.parser = SnortRuleParser()
        self.sid_to_rule = {}

    def load_rules(self, rule_file: Optional[Union[str, Path]] = None):
        if rule_file is None:
            project_root = Path(__file__).resolve().parents[2]
            file_path = project_root / "snort3-community.rules"
        else:
            file_path = Path(rule_file).expanduser().resolve()
        
        try:
            parsed_rules = self.parser.parse_file(str(file_path))
            for rule in parsed_rules:
                if self.validate_rule(rule):
                    self.rules.append(rule)
                    ebpf_config = self.parser.to_ebpf_config(rule)
                    self.ebpf_configs.append(ebpf_config)
                    if "sid" in ebpf_config:
                        self.sid_to_rule[ebpf_config["sid"]] = {
                            "msg": ebpf_config.get("msg", "Unknown"),
                            "priority": ebpf_config.get("priority", 3),
                            "classtype": ebpf_config.get("classtype", "unknown"),
                        }
        except Exception as e:
            print(f"Could not parse rule file: {file_path}. Error: {e}")

    @staticmethod
    def validate_rule(rule: dict) -> bool:
        required_fields = ["action", "protocol", "src_ip", "src_port", "direction", "dst_ip", "dst_port"]
        return all(field in rule for field in required_fields)


class EventHandler:
    def __init__(self, rule_manager: RuleManager, log_file: str = "ids-alerts.log"):
        self.rule_manager = rule_manager
        self.alert_count = 0
        self.log_file = log_file
        
        # Initialize log file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f" IDS Alert Log - Session started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n")

    def handle_alert(self, cpu, data, size):
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
        
        alert = ct.cast(data, ct.POINTER(AlertEvent)).contents
        self.alert_count += 1

        src_ip = self.format_ip(alert.src_ip)
        dst_ip = self.format_ip(alert.dst_ip)
        
        rule_info = self.rule_manager.sid_to_rule.get(alert.rule_id, {})
        rule_msg = alert.msg.decode('utf-8', errors='ignore').rstrip('\x00')

        alert_info = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            "alert_id": self.alert_count,
            "rule_id": alert.rule_id,
            "priority": alert.priority,
            "message": rule_msg or rule_info.get("msg", "Unknown"),
            "classification": rule_info.get("classtype", "unknown"),
            "src_ip": src_ip,
            "src_port": alert.src_port,
            "dst_ip": dst_ip,
            "dst_port": alert.dst_port,
            "protocol": "UDP",
        }
        
        self.log_alert(alert_info)

    @staticmethod
    def format_ip(ip_int: int) -> str:
        return ".".join(map(str, [ip_int & 0xFF, (ip_int >> 8) & 0xFF, (ip_int >> 16) & 0xFF, (ip_int >> 24) & 0xFF]))

    def log_alert(self, alert_info: dict):
        alert_line = (
            f"ALERT! (Priority: {alert_info['priority']})\n"
            f"  Timestamp: {alert_info['timestamp']} | Alert ID: {alert_info['alert_id']}\n"
            f"  Rule ID: {alert_info['rule_id']} | Priority: {alert_info['priority']}\n"
            f"  Message: {alert_info['message']}\n"
            f"  Classification: {alert_info['classification']}\n"
            f"  Connection: {alert_info['src_ip']}:{alert_info['src_port']} -> {alert_info['dst_ip']}:{alert_info['dst_port']}\n"
            f"  Protocol: {alert_info['protocol']}\n"
            f"-"*80
        )
        print(alert_line)
        
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(alert_line + "\n")
        except Exception as e:
            print(f"Warning: Failed to write alert to log file: {e}")


# ---------------------------------------------------------------------------
# Paths and Main Execution
# ---------------------------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '..', '..'))
KERNEL_DIR = os.path.join(PROJECT_ROOT, "src", "kernel")
USERSPACE_DIR = os.path.join(PROJECT_ROOT, "src", "userspace")

UDP_RULES_C_PATH = os.path.join(KERNEL_DIR, "udp_rules_generated.c")
UDP_RULES_METADATA_PATH = os.path.join(KERNEL_DIR, "udp_rules_metadata.json")
SNORT_RULES_JSON = os.path.join(PROJECT_ROOT, "snort_rules.ebpf.json")

def main():
    """
    Main function to run the IDS.
    """
    try:
        # Change to project root to resolve relative paths
        os.chdir(PROJECT_ROOT)
    except Exception:
        pass
    
    manager = IDSManager()
    
    # Determine the interface to use (you can pass one from the command line)
    victim_iface = sys.argv[1] if len(sys.argv) > 1 else None
    
    manager.init_ids(iface=victim_iface)
    manager.set_up_event_buffers()
    manager.run()


if __name__ == "__main__":
    main()
