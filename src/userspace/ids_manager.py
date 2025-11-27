

#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
eBPF IDS userspace management program
"""


import os
import sys
import json
import signal
import socket
import fcntl
import struct
import array
from bcc import BPF
from datetime import datetime
from dataclasses import dataclass, field
from datetime import datetime, timezone



@dataclass
class DebugConfig:
   """Debug configuration"""
   enabled: bool = False                        # Whether to enable debug mode
   print_interval: int = 100                   # Print normal traffic every N events
   stats_interval: int = 5                     # Print statistics every N seconds
   ssh_interval: int = 1000                    # Print SSH traffic every N packets
   icmp_interval: int = 10                     # Print ICMP traffic every N packets
   important_ports: list = field(default_factory=lambda: [80, 443, 8080, 21, 23, 3306, 5432])
   alert_dedup_timeout: int = 10               # Alert deduplication timeout (seconds)


debug = DebugConfig()


def get_active_interface():
   """Automatically detect active network interface"""
   try:
       # Read /proc/net/dev to get all network interfaces
       with open('/proc/net/dev', 'r', encoding='utf-8') as f:
           lines = f.readlines()
      
       interfaces = []
       for line in lines[2:]:  # Skip first two lines
           if ':' in line:
               iface_name = line.split(':')[0].strip()
               # Exclude loopback interface
               if iface_name != 'lo':
                   interfaces.append(iface_name)
      
       if interfaces:
           # Return first non-loopback interface
           return interfaces[0]
      
       # If not found, return default value
       return 'eth0'
  
   except Exception as e:
       print(f"Warning: Cannot automatically detect the network port: {e}")
       return 'eth0'




class RuleManager:
   """Rule manager"""
  
   def __init__(self, rules_dir):
       self.rules_dir = rules_dir
       self.rules = []
       self.rules_by_sid = {}  # SID -> rule mapping
       self.loaded = False
      
   def load_rules(self):
       """Load rules from rules directory"""
       from rule_loader import RuleLoader, RuleParser
      
       print(f"Loading rules from {self.rules_dir}...")
      
       loader = RuleLoader(self.rules_dir)
       raw_rules = loader.load_all_rules()
      
       if not raw_rules:
           print("  Warning: Cannot find the rule json")
           return
      
       print(f"Analyzing {len(raw_rules)} rules...")
       self.rules = RuleParser.compile_rules(raw_rules)
      
       # Build SID index
       for rule in self.rules:
           sid = rule['sid']
           self.rules_by_sid[sid] = rule
      
       print(f"✓ Successfully loaded {len(self.rules)} rules")
       self.loaded = True
      
       # Print rule statistics
       self._print_statistics()
  
   def _print_statistics(self):
       """Print rule statistics"""
       if not self.rules:
           return
      
       # Count protocols
       protocol_count = {}
       for rule in self.rules:
           proto = rule['protocol']
           proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 0: 'ANY'}.get(proto, f'Proto-{proto}')
           protocol_count[proto_name] = protocol_count.get(proto_name, 0) + 1
      
       print("\nRule Summary:")
       print(f"  Total rules: {len(self.rules)}")
       print(f"  Rule distribution:")
       for proto, count in sorted(protocol_count.items(), key=lambda x: x[1], reverse=True)[:5]:
           print(f"    - {proto}: {count}")
  
   def get_rule_by_sid(self, sid):
       """Get rule by SID"""
       return self.rules_by_sid.get(sid)
  
   def match_rule(self, packet_event):
       """
       Match packet with rules
       Returns: list of matched rules
       """
       matched_rules = []
      
       for rule in self.rules[:100]:  # Only check first 100 rules (performance optimization)
           if self._match_single_rule(rule, packet_event):
               matched_rules.append(rule)
      
       return matched_rules
  
   def _match_single_rule(self, rule, event):
       """
       Check if a single rule matches
       """
       # 1. Match protocol
       if rule['protocol'] != 0 and rule['protocol'] != event.protocol:
           return False
      
       # 2. Match source port
       if not self._match_port(rule['src_port'], event.src_port):
           return False
      
       # 3. Match destination port
       if not self._match_port(rule['dst_port'], event.dst_port):
           return False
      
       # 4. Match content (if any)
       if rule['content'] and len(rule['content']) > 0:
           if not self._match_content(rule['content'], event.payload,
                                      event.payload_len, rule['content_depth']):
               return False
      
       return True
  
   def _match_port(self, port_rule, packet_port):
       """
       Match port
       port_rule: (type, value1, value2)
       """
       port_type, val1, val2 = port_rule
      
       if port_type == 0:  # any
           return True
       elif port_type == 1:  # single
           return packet_port == val1
       elif port_type == 2:  # range
           return val1 <= packet_port <= val2
       elif port_type == 3:  # list
           return packet_port == val1 or packet_port == val2
      
       return False
  
   def _match_content(self, pattern, payload, payload_len, depth):
       """
       Search for pattern in payload
       """
       if payload_len < len(pattern):
           return False
      
       search_len = min(depth, payload_len) if depth > 0 else payload_len
      
       # Convert payload to bytes
       payload_bytes = bytes(payload[:payload_len])
      
       # Search within specified depth
       search_area = payload_bytes[:search_len]
       return pattern in search_area
  
   def get_rules(self):
       """Get all rules"""
       return self.rules




class EventHandler:
   """Event handler"""
  
   def __init__(self, rule_manager):
       self.rule_manager = rule_manager
       self.event_count = 0
       self.alert_count = 0
       self.last_alerts = {}  # For deduplication: (src_ip, dst_ip, sid) -> timestamp
       self.tcp_count = 0
       self.udp_count = 0
       self.icmp_count = 0
       self.log_path = "/var/log/snort_alert.log"

    


   def _log_alert(self, action, protocol, src_ip, src_port,dst_ip, dst_port, options_str):

        # Generate ISO8601 timestamp, e.g. 2025-11-23T12:04:22+00:00
        now = datetime.now(timezone.utc).isoformat()

        line = (
            f"{now} {action} {protocol} "
            f"{src_ip} {src_port} -> {dst_ip} {dst_port} "
            f"({options_str})\n"
        )

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except PermissionError:
            # If no permission to write to /var/log, print a warning
            print(f"[WARN] Cannot write to {self.log_path}, "
                  f"please check permissions (need root).")
        except Exception as e:
            print(f"[WARN] Failed to write alert log: {e}")   
      
   def handle_event(self, cpu, data, size):
       """Handle eBPF event"""
       import ctypes as ct
       from datetime import datetime
       import time
      
       # Define data structure to match C struct
       class PacketEvent(ct.Structure):
           _fields_ = [
               ("src_ip", ct.c_uint32),
               ("dst_ip", ct.c_uint32),
               ("src_port", ct.c_uint16),
               ("dst_port", ct.c_uint16),
               ("protocol", ct.c_uint8),
               ("anomaly_type", ct.c_uint8),
               ("app_proto", ct.c_uint8),     # Application protocol
               ("_pad", ct.c_uint8),          # Padding
               ("payload_len", ct.c_uint32),
               ("payload", ct.c_uint8 * 256)
           ]
      
       event = ct.cast(data, ct.POINTER(PacketEvent)).contents
       self.event_count += 1
      
       # Count protocols
       if event.protocol == 6:
           self.tcp_count += 1
       elif event.protocol == 17:
           self.udp_count += 1
       elif event.protocol == 1:
           self.icmp_count += 1
      
       # Format IP addresses
       src_ip = self.format_ip(event.src_ip)
       dst_ip = self.format_ip(event.dst_ip)
      
       # Protocol name mapping
       protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
       protocol_name = protocol_map.get(event.protocol, f"Protocol-{event.protocol}")

       # Application layer protocol identification (using kernel analyze_protocol result)
       app_proto_map = {
           1: "HTTP",
           2: "FTP",
           3: "SSH",
           4: "DNS",
           5: "DHCP"
       }
       if event.app_proto > 0:
           app_name = app_proto_map.get(event.app_proto)
           if app_name:
               protocol_name = f"{protocol_name}/{app_name}"
      
       # Debug output: print based on configuration
       if debug.enabled:
           should_print = False
           if event.protocol == 6:  # TCP
               # Print important ports immediately (exclude port 22 to avoid SSH spam)
               if event.dst_port in debug.important_ports:
                   should_print = True
               # Print SSH port at configured frequency
               elif event.dst_port == 22 and self.tcp_count % debug.ssh_interval == 1:
                   should_print = True
           elif event.protocol == 1:  # ICMP
               should_print = (self.icmp_count % debug.icmp_interval == 1)
          
           if should_print or self.event_count % debug.print_interval == 0:
               print(f"[Testing] Event#{self.event_count} | {protocol_name} | {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} | Payload: {event.payload_len}B")
      
       # Match rules
       matched_rules = self.rule_manager.match_rule(event)
      
       # Handle anomalies detected by kernel
       if event.anomaly_type > 0:
           self.alert_count += 1
           timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
           
           anomaly_msg = "Unknown Anomaly"
           if event.anomaly_type == 1: anomaly_msg = "Potential DDoS Attack (High Connection Rate)"
           elif event.anomaly_type == 2: anomaly_msg = "Suspicious High Port Connection (>50000)"
           elif event.anomaly_type == 3: anomaly_msg = "Abnormal Payload Size"
           elif event.anomaly_type == 4: anomaly_msg = "Suspicious Shell Command Pattern"
           elif event.anomaly_type == 5: anomaly_msg = "Suspicious XSS Pattern"
           elif event.anomaly_type == 6: anomaly_msg = "Invalid Source IP (0.0.0.0)"

           print(f"\n{'='*80}")
           print(f"[ANOMALY ALERT #{self.alert_count}] {timestamp}")
           print(f"{'='*80}")
           print(f"Type: Anomaly Detection | ID: {event.anomaly_type}")
           print(f"Message: {anomaly_msg}")
           print(f"Protocol: {protocol_name}")
           print(f"Source address: {src_ip}:{event.src_port}")
           print(f"Target address: {dst_ip}:{event.dst_port}")
           print(f"{'='*80}\n")
           # Log to Snort-style log
           anomaly_options = f'msg:"{anomaly_msg}"; anomaly_type:{event.anomaly_type};'
           self._log_alert(
                action="alert",
                protocol=protocol_name.lower(),  # "tcp"/"udp"/"icmp"
                src_ip=src_ip,
                src_port=event.src_port,
                dst_ip=dst_ip,
                dst_port=event.dst_port,
                options_str=anomaly_options,
            )

       if matched_rules:
           # Rules matched, generate alerts
           for rule in matched_rules:
               # Deduplication check (same source-destination pair, same rule, alert only once within configured time)
               alert_key = (event.src_ip, event.dst_ip, rule['sid'])
               current_time = time.time()
              
               if alert_key in self.last_alerts:
                   if current_time - self.last_alerts[alert_key] < debug.alert_dedup_timeout:
                       continue  # Skip duplicate alerts
              
               self.last_alerts[alert_key] = current_time
               self.alert_count += 1
              
               # Print alert
               timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
               print(f"\n{'='*80}")
               print(f"[ALERT #{self.alert_count}] {timestamp}")
               print(f"{'='*80}")
               print(f"Rule: [{rule['sid']}] {rule['msg']}")
               print(f"Type: {rule['classtype']} | Priority: {rule['priority']}")
               print(f"Protocol: {protocol_name}")
               print(f"Source address: {src_ip}:{event.src_port}")
               print(f"Target address: {dst_ip}:{event.dst_port}")
              
               # Show matched content
               if rule['content'] and event.payload_len > 0:
                   print(f"Matched content: {self._format_payload(rule['content'])}")
                   print(f"Packet payload: {self._format_payload(bytes(event.payload[:min(32, event.payload_len)]))}")
              
               print(f"{'='*80}\n")
               # Assemble Snort-style options
               options_parts = []
               if "msg" in rule:
                    options_parts.append(f'msg:"{rule["msg"]}"')
               if "classtype" in rule and rule["classtype"]:
                    options_parts.append(f"classtype:{rule['classtype']}")
               if "priority" in rule and rule["priority"] is not None:
                    options_parts.append(f"priority:{rule['priority']}")
               if "sid" in rule:
                    options_parts.append(f"sid:{rule['sid']}")

               options_str = "; ".join(options_parts) + ";"

                # If you have raw option string in RuleParser, e.g. rule["options_raw"],
                # you can override the above concatenation with this line:
                # options_str = rule.get("options_raw", options_str)

               self._log_alert(
                    action="alert",
                    protocol=protocol_name.lower(),
                    src_ip=src_ip,
                    src_port=event.src_port,
                    dst_ip=dst_ip,
                    dst_port=event.dst_port,
                    options_str=options_str,
                )
            
       # else branch has been replaced by debug output
  
   def format_ip(self, ip_int):
       """Format IP address"""
       return ".".join(map(str, [
           ip_int & 0xFF,
           (ip_int >> 8) & 0xFF,
           (ip_int >> 16) & 0xFF,
           (ip_int >> 24) & 0xFF
       ]))
  
   def _format_payload(self, data):
       """Format payload as hexadecimal and ASCII"""
       hex_str = ' '.join(f'{b:02x}' for b in data[:32])
       ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:32])
       return f"{hex_str} | {ascii_str}"
  
   def get_statistics(self):
       """Get statistics"""
       return {
           'total_events': self.event_count,
           'total_alerts': self.alert_count,
       }




class IDSManager:
   """IDS main management class"""
  
   def __init__(self, rules_dir, interface=None):
       self.rules_dir = rules_dir
       # If no interface specified, auto-detect
       if interface is None:
           self.interface = get_active_interface()
       else:
           self.interface = interface
       self.bpf = None
       self.rule_manager = RuleManager(rules_dir)
       self.event_handler = None
      
   def load_ebpf_program(self):
       """Load eBPF program"""
       kernel_code_path = os.path.join(
           os.path.dirname(os.path.dirname(__file__)),
           "kernel",
           "ids_ebpf.c"
       )
      
       try:
           print(f"Loading eBPF program: {kernel_code_path}")
           with open(kernel_code_path, 'r') as f:
               kernel_code = f.read()
          
           print("Compiling eBPF Program...")
           self.bpf = BPF(text=kernel_code)
           print("✓ eBPF Compilation Success")
          
       except Exception as e:
           print(f"✗ Failed to load eBPF program: {e}")
           return False
      
       return True
  
   def attach_probes(self):
       """Attach probes to network interface"""
       try:
           print(f"Attaching eBPF program to interface: {self.interface}")
           function_ids_filter = self.bpf.load_func("ids_filter", BPF.SOCKET_FILTER)
           BPF.attach_raw_socket(function_ids_filter, self.interface)
           print(f"✓ Attached to {self.interface}")
           return True
       except Exception as e:
           print(f"✗ Failed to attach interface: {e}")
           print(f"Reminder: Please ensure the interface '{self.interface}' exists")
           print(f"Available interfaces: run 'ip link show' to check")
           return False
  
   def update_kernel_maps(self):
       """Update monitored ports in kernel map"""
       print("Updating kernel maps with rule ports...")
       try:
           monitored_ports = self.bpf.get_table("monitored_ports")
       except Exception as e:
           print(f"Warning: Cannot find 'monitored_ports' map: {e}")
           return

       ports_to_monitor = set()
       # Add default important ports
       for p in [21, 22, 80, 443, 8080, 3306, 53]:
           ports_to_monitor.add(p)

       for rule in self.rule_manager.rules:
           # rule['dst_port'] is (type, val1, val2)
           p_type, val1, val2 = rule['dst_port']
           if p_type == 1: # single
               ports_to_monitor.add(val1)
           elif p_type == 2: # range
               if val2 - val1 < 100:
                   for p in range(val1, val2 + 1):
                       ports_to_monitor.add(p)
               else:
                   ports_to_monitor.add(val1)
                   ports_to_monitor.add(val2)
           elif p_type == 3: # list
               ports_to_monitor.add(val1)
               ports_to_monitor.add(val2)
               
       count = 0
       import ctypes as ct
       for port in ports_to_monitor:
           if 0 < port <= 65535:
               try:
                   monitored_ports[ct.c_uint16(port)] = ct.c_uint8(1)
                   count += 1
               except Exception:
                   pass
       print(f"✓ Added {count} ports to kernel monitoring map")

   def initialize(self):
       """Initialize IDS system"""
       print(f"Initializing eBPF IDS system...")
       print(f"Rule Directory: {self.rules_dir}")
       print(f"Network interface: {self.interface}")
      
       # Load rules
       self.rule_manager.load_rules()
      
       # Load eBPF program
       if not self.load_ebpf_program():
           return False
           
       # Update kernel map
       self.update_kernel_maps()
      
       # Create event handler
       self.event_handler = EventHandler(self.rule_manager)
      
       # Attach probes
       if not self.attach_probes():
           return False
      
       return True
  
   def start(self):
       """Start IDS monitoring"""
       if not self.initialize():
           print("✗ IDS initialization failed, exiting...")
           return
      
       print("=" * 60)
       print("✓ eBPF IDS started, monitoring network...")
       print("=" * 60)
       print("Press Ctrl+C to stop monitoring\n")
      
       # Open perf buffer and set callback
       self.bpf["events"].open_perf_buffer(self.event_handler.handle_event)
      
       # Event polling loop
       import time
       last_stats_time = time.time()
      
       try:
           while True:
               self.bpf.perf_buffer_poll(timeout=100)
              
               # Periodically print debug statistics based on configuration
               current_time = time.time()
               if debug.enabled and current_time - last_stats_time >= debug.stats_interval:
                   self._print_debug_stats()
                   last_stats_time = current_time
       except KeyboardInterrupt:
           print("\n" + "=" * 60)
           print(f"Monitoring stopped, total captured {self.event_handler.event_count} events")
           print("=" * 60)
  
   def _print_debug_stats(self):
       """Print debug statistics"""
       try:
           debug_map = self.bpf.get_table("debug_counters")
           print("\n" + "="*60)
           print("[Stats] eBPF IDS Debug Statistics:")
           print(f"  eBPF kernel counters:")
           print(f"    Total network packets: {debug_map[0].value}")
           print(f"    IP packets: {debug_map[1].value}")
           print(f"    TCP packets: {debug_map[2].value}")
           print(f"    UDP packets: {debug_map[3].value}")
           print(f"    ICMP packets: {debug_map[4].value}")
           print(f"    Matched packets: {debug_map[5].value}")
           print(f"    Parse errors: {debug_map[6].value}")
           print(f"    Submitted events: {debug_map[7].value}")
           print(f"  Userspace counters:")
           print(f"    Received events: {self.event_handler.event_count}")
           print(f"    TCP: {self.event_handler.tcp_count}")
           print(f"    UDP: {self.event_handler.udp_count}")
           print(f"    ICMP: {self.event_handler.icmp_count}")
           print(f"    Alerts: {self.event_handler.alert_count}")
           print("="*60 + "\n")
       except Exception as e:
           print(f"[Debug] Cannot read eBPF debug statistics: {e}")
  
   def stop(self):
       """Stop IDS"""
       print("\nStopping IDS...")
      
       if self.event_handler:
           stats = self.event_handler.get_statistics()
           print(f"\nFinal Statistics:")
           print(f"  Total events: {stats['total_events']}")
           print(f"  Total alerts: {stats['total_alerts']}")
          
       print("IDS stopped.")




def main():
   """Main function"""
   # Rules directory path
   rules_dir = os.path.join(
       os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
       "rules"
   )
  
   # Create IDS manager
   ids = IDSManager(rules_dir=rules_dir)
  
   # Setup signal handlers
   def signal_handler(sig, frame):
       ids.stop()
       sys.exit(0)
  
   signal.signal(signal.SIGINT, signal_handler)
   signal.signal(signal.SIGTERM, signal_handler)
  
   # Start IDS
   ids.start()




if __name__ == "__main__":
   main()







