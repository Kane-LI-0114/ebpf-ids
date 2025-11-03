#!/usr/bin/env python3

# snort_rule_parser.py
# Parser for Snort3 community rules
# Converts rules to intermediate representation for eBPF

import re
import json
import sys

class SnortRuleParser:
    """
    Snort3 rule parser for eBPF conversion
    Supports: protocol, IPs, ports, direction, flags, msg, sid, content
    Does NOT support: complex content matching, payload inspection, flow state
    """
    def __init__(self):
    # Regular expression to parse rule header
        self.header_re = re.compile(
        r'^(\w+)\s+' # action: alert, log, pass, drop, reject
        r'([\w-]+)\s+' # protocol: tcp, udp, icmp, ip, http, ssl
        r'([\w\.$/!,\[\]]+|\bany\b)\s+' # source IP - ADD / for CIDR notation
        r'([!\w:,$/\[\]]+|\bany\b)\s+' # source port
        r'(<>|->)\s+' # direction: -> or <>
        r'([\w\.$/!,\[\]]+|\bany\b)\s+' # dest IP - ADD / for CIDR notation
        r'([!\w:,$/\[\]]+|\bany\b)' # dest port
    )



    
    def parse_file(self, filename):
        """Parse a Snort rules file and return list of intermediate representations"""
        rules = []
        with open(filename, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                ir = self.parse_rule(line)
                if ir:
                    ir['line_number'] = line_num
                    rules.append(ir)
        return rules
    
    def parse_rule(self, rule_line):
        """Parse a single Snort rule into intermediate representation"""
        # Remove comments and extra whitespace
        rule_line = rule_line.strip()
        
        # Skip comments and empty lines
        if rule_line.startswith('#') or not rule_line:
            return None
        
        # Split header and options
        try:
            if '(' not in rule_line:
                print(f"Warning: Rule has no options: {rule_line[:50]}...")
                return None
            
            header_part, options_part = rule_line.split('(', 1)
            options_part = options_part.rsplit(')', 1)[0]
        except ValueError:
            print(f"Error: Malformed rule: {rule_line[:50]}...")
            return None
        
        # Parse header - try traditional format first
        match = self.header_re.match(header_part.strip())
        
        if not match:
            # Try simplified Snort3 format: action protocol (options)
            simple_match = re.match(r'^(\w+)\s+([\w-]+)\s*$', header_part.strip())
            
            if simple_match:
                action, protocol = simple_match.groups()
                # Use defaults for simplified format
                src_ip = 'any'
                src_port = 'any'
                direction = '->'
                dst_ip = 'any'
                dst_port = 'any'
            else:
                print(f"Error: Cannot parse header: {header_part[:50]}...")
                return None
        else:
            action, protocol, src_ip, src_port, direction, dst_ip, dst_port = match.groups()
        
        # Parse options (rest of the code remains the same)
        options = {}
        
        for opt in options_part.split(';'):
            opt = opt.strip()
            if not opt:
                continue
            
            if ':' in opt:
                key, value = opt.split(':', 1)
                key = key.strip()
                value = value.strip().strip('"')
                
                # Handle multiple values for same key
                if key in options:
                    if not isinstance(options[key], list):
                        options[key] = [options[key]]
                    options[key].append(value)
                else:
                    options[key] = value
            else:
                # Options without values
                options[opt] = True
        
        # Build intermediate representation
        ir = {
            'action': action,
            'protocol': protocol.upper(),
            'src_ip': src_ip,
            'src_port': src_port,
            'direction': direction,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'options': options
        }
        
        return ir

    
    def to_ebpf_config(self, ir):
        """
        Convert intermediate representation to eBPF-compatible config
        This would be written to BPF maps for the kernel program to read
        """
        config = {
            'action': ir['action'],
            'protocol_num': self._protocol_to_num(ir['protocol']),
            'src_ip': ir['src_ip'],
            'src_port': self._parse_port(ir['src_port']),
            'dst_ip': ir['dst_ip'],
            'dst_port': self._parse_port(ir['dst_port']),
            'tcp_flags': self._parse_flags(ir['options'].get('flags', '')),
            'msg': ir['options'].get('msg', 'Rule match'),
            'sid': int(ir['options'].get('sid', 0)),
            'rev': int(ir['options'].get('rev', 1)),
            'classtype': ir['options'].get('classtype', 'unknown'),
            'priority': int(ir['options'].get('priority', 3))
        }
        
        # Add content matching if present
        if 'content' in ir['options']:
            config['content'] = ir['options']['content']
        
        # Add flow direction if present
        if 'flow' in ir['options']:
            config['flow'] = ir['options']['flow']
        
        return config
    
    def _protocol_to_num(self, protocol):
        """Convert protocol name to number"""
        mapping = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'IP': 0
        }
        return mapping.get(protocol, 0)
    
    def _parse_port(self, port_str):
        """Parse port specification"""
        if port_str == 'any':
            return None
        
        # Handle port ranges
        if ':' in port_str:
            parts = port_str.split(':')
            try:
                return {
                    'type': 'range',
                    'start': int(parts[0]) if parts[0] else 0,
                    'end': int(parts[1]) if parts[1] else 65535
                }
            except (ValueError, IndexError):
                return None
        
        # Handle port lists
        if ',' in port_str:
            try:
                return {
                    'type': 'list',
                    'ports': [int(p.strip()) for p in port_str.split(',') if p.strip().isdigit()]
                }
            except ValueError:
                return None
        
        # Handle variables (e.g., $HTTP_PORTS)
        if port_str.startswith('$'):
            return {'type': 'variable', 'name': port_str}
        
        # Single port
        try:
            return {'type': 'single', 'port': int(port_str)}
        except ValueError:
            return None
    
    def _parse_flags(self, flags_str):
        """Parse TCP flags option"""
        if not flags_str:
            return {}
        
        flag_map = {
            'S': 'SYN',
            'A': 'ACK',
            'F': 'FIN',
            'R': 'RST',
            'P': 'PSH',
            'U': 'URG'
        }
        
        flags = {}
        for char in flags_str.upper():
            if char in flag_map:
                flags[flag_map[char]] = True
        
        return flags
    
    def export_to_json(self, rules, output_file):
        """Export parsed rules to JSON file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2)
    
    def export_to_ebpf_configs(self, rules, output_file):
        """Export eBPF configurations to JSON file"""
        configs = [self.to_ebpf_config(rule) for rule in rules]
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(configs, f, indent=2)

# Example usage
if __name__ == "__main__":
    parser = SnortRuleParser()
    
    # Check if file argument provided
    if len(sys.argv) > 1:
        rules_file = sys.argv[1]
        print(f"=== Parsing Snort Rules File: {rules_file} ===\n")
        
        # Parse the rules file
        rules = parser.parse_file(rules_file)
        print(f"Successfully parsed {len(rules)} rules\n")
        
        # Export intermediate representation to JSON
        parser.export_to_json(rules, 'snort_rules_ir.json')
        print("Exported intermediate representation to: snort_rules_ir.json")
        
        # Export eBPF configurations to JSON
        parser.export_to_ebpf_configs(rules, 'snort_rules_ebpf.json')
        print("Exported eBPF configurations to: snort_rules_ebpf.json")
        
        # Display first 3 rules as examples
        print("\n=== Sample Rules (first 3) ===")
        for i, rule in enumerate(rules[:3]):
            print(f"\n--- Rule {i+1} ---")
            print("Intermediate Representation:")
            print(json.dumps(rule, indent=2))
            print("\neBPF Configuration:")
            print(json.dumps(parser.to_ebpf_config(rule), indent=2))
    else:
        # Demo with test rules
        test_rules = [
            'alert tcp any any -> $HOME_NET 22 (msg:"SSH SYN detected"; flags:S; sid:1000001; rev:1;)',
            'alert udp any any -> $HOME_NET 53 (msg:"DNS query"; sid:1000002; rev:1;)',
            'alert tcp $EXTERNAL_NET 80 -> $HOME_NET any (msg:"HTTP SYN-ACK"; flow:to_client,established; flags:SA; sid:1000003; rev:1;)'
        ]
        
        print("=== Snort Rule Parser Demo ===\n")
        print("Usage: python parser.py <snort3-community.rules>\n")
        print("Running with test rules:\n")
        
        for rule in test_rules:
            print(f"Original: {rule}")
            
            # Parse to intermediate representation
            ir = parser.parse_rule(rule)
            if ir:
                print("Intermediate Representation:")
                print(json.dumps(ir, indent=2))
                
                # Convert to eBPF config
                config = parser.to_ebpf_config(ir)
                print("eBPF Configuration:")
                print(json.dumps(config, indent=2))
                
            print("-" * 60)
