#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF IDS Testing Script
Comprehensive testing and verification for the OOP-based IDS system

Usage:
    python3 test_ids_system.py --batch 0
    python3 test_ids_system.py --export
    python3 test_ids_system.py --summary
    python3 test_ids_system.py --nmap 0
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


class IDSSystemTester:
    """Comprehensive IDS system tester"""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.results = {}
        
    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamps"""
        if self.verbose:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            prefix = f"[{timestamp}] [{level}]"
            print(f"{prefix} {message}")
    
    def test_imports(self) -> bool:
        """Test that all required modules can be imported"""
        self.log("Testing imports...", "TEST")
        try:
            from ebpf_oop_generator import (
                IPConfig, RulePatternFactory, RuleBatcher,
                TCPRuleEBPFGenerator, UDPRuleEBPFGenerator,
                DeploymentManager
            )
            self.log("✓ All core modules imported successfully", "PASS")
            self.results['imports'] = True
            return True
        except ImportError as e:
            self.log(f"✗ Import failed: {e}", "FAIL")
            self.results['imports'] = False
            return False
    
    def test_json_loading(self, json_path: str = "snort_rules_ebpf.json") -> bool:
        """Test loading and parsing JSON rules"""
        self.log(f"Testing JSON loading from {json_path}...", "TEST")
        
        try:
            json_file = Path(json_path)
            if not json_file.exists():
                self.log(f"✗ JSON file not found: {json_path}", "FAIL")
                return False
            
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            rule_count = len(data)
            self.log(f"✓ Loaded {rule_count} rules from JSON", "PASS")
            
            # Analyze rule distribution
            protocols = {}
            for rule in data:
                proto = rule.get('protocol_num', 0)
                protocols[proto] = protocols.get(proto, 0) + 1
            
            self.log(f"  Protocol distribution: {protocols}", "INFO")
            self.results['json_loading'] = True
            self.results['total_rules'] = rule_count
            self.results['protocols'] = protocols
            return True
            
        except Exception as e:
            self.log(f"✗ JSON loading failed: {e}", "FAIL")
            self.results['json_loading'] = False
            return False
    
    def test_rule_factory(self, json_path: str = "snort_rules_ebpf.json") -> bool:
        """Test rule pattern factory"""
        self.log("Testing RulePatternFactory...", "TEST")
        
        try:
            from ebpf_oop_generator import RulePatternFactory, IPConfig
            
            with open(json_path, 'r') as f:
                rules_data = json.load(f)
            
            factory = RulePatternFactory(IPConfig())
            parsed_count = 0
            skipped_count = 0
            
            for rule in rules_data[:100]:  # Test first 100
                pattern = factory.analyze_rule(rule)
                if pattern:
                    parsed_count += 1
                else:
                    skipped_count += 1
            
            self.log(f"✓ Parsed {parsed_count} rules, skipped {skipped_count}", "PASS")
            self.results['rule_factory'] = True
            self.results['parsed_rules'] = parsed_count
            return True
            
        except Exception as e:
            self.log(f"✗ Rule factory test failed: {e}", "FAIL")
            self.results['rule_factory'] = False
            return False
    
    def test_batching(self, json_path: str = "snort_rules_ebpf.json", 
                      batch_size: int = 5) -> bool:
        """Test rule batching"""
        self.log(f"Testing RuleBatcher (batch_size={batch_size})...", "TEST")
        
        try:
            from ebpf_oop_generator import RuleBatcher, IPConfig
            
            batcher = RuleBatcher(batch_size, IPConfig())
            total_rules = batcher.load_rules_from_json(json_path)
            batch_count = batcher.get_batch_count()
            
            self.log(f"✓ Created {batch_count} batches from {total_rules} rules", "PASS")
            
            # Check first batch
            first_batch = batcher.get_batch(0)
            if first_batch:
                self.log(f"  Batch 0: {len(first_batch)} rules", "INFO")
            
            self.results['batching'] = True
            self.results['batch_count'] = batch_count
            return True
            
        except Exception as e:
            self.log(f"✗ Batching test failed: {e}", "FAIL")
            self.results['batching'] = False
            return False
    
    def test_code_generation(self, json_path: str = "snort_rules_ebpf.json",
                            batch_size: int = 5) -> bool:
        """Test eBPF code generation"""
        self.log("Testing eBPF code generation...", "TEST")
        
        try:
            from ebpf_oop_generator import RuleBatcher, IPConfig
            
            batcher = RuleBatcher(batch_size, IPConfig())
            batcher.load_rules_from_json(json_path)
            
            # Generate code for first batch
            code_dict = batcher.generate_batch_code(0)
            
            if not code_dict:
                self.log("✗ No code generated for batch 0", "FAIL")
                return False
            
            tcp_code = code_dict.get('tcp', '')
            udp_code = code_dict.get('udp', '')
            
            self.log(f"✓ Generated eBPF code", "PASS")
            self.log(f"  TCP code: {len(tcp_code)} bytes", "INFO")
            self.log(f"  UDP code: {len(udp_code)} bytes", "INFO")
            
            self.results['code_generation'] = True
            self.results['tcp_code_size'] = len(tcp_code)
            self.results['udp_code_size'] = len(udp_code)
            return True
            
        except Exception as e:
            self.log(f"✗ Code generation failed: {e}", "FAIL")
            self.results['code_generation'] = False
            return False
    
    def test_deployment_manager(self, json_path: str = "snort_rules_ebpf.json") -> bool:
        """Test DeploymentManager"""
        self.log("Testing DeploymentManager...", "TEST")
        
        try:
            from ebpf_oop_generator import DeploymentManager, IPConfig
            
            manager = DeploymentManager(json_path, batch_size=5, ip_config=IPConfig())
            total_rules = manager.load_and_batch_rules()
            batch_count = manager.batcher.get_batch_count()
            
            # Generate code for first batch
            manager.generate_batch_code(0)
            
            # Get batch info
            batch_info = manager.get_batch_info(0)
            
            self.log(f"✓ DeploymentManager working", "PASS")
            self.log(f"  Total rules: {total_rules}", "INFO")
            self.log(f"  Batches: {batch_count}", "INFO")
            self.log(f"  Batch 0 info: {batch_info}", "INFO")
            
            self.results['deployment_manager'] = True
            return True
            
        except Exception as e:
            self.log(f"✗ DeploymentManager test failed: {e}", "FAIL")
            self.results['deployment_manager'] = False
            return False
    
    def test_ids_manager(self) -> bool:
        """Test IDSManager integration"""
        self.log("Testing IDSManager integration...", "TEST")
        
        try:
            from ids_manager_new import IDSManager
            
            manager = IDSManager()
            if not manager.start():
                self.log("✗ Failed to start IDSManager", "FAIL")
                return False
            
            status = manager.get_status()
            
            self.log(f"✓ IDSManager initialized", "PASS")
            self.log(f"  Status: {json.dumps(status, indent=2)}", "INFO")
            
            self.results['ids_manager'] = True
            self.results['ids_status'] = status
            return True
            
        except Exception as e:
            self.log(f"✗ IDSManager test failed: {e}", "FAIL")
            self.results['ids_manager'] = False
            return False
    
    def test_nmap_command_generation(self, batch_num: int = 0) -> bool:
        """Test nmap command generation"""
        self.log(f"Testing nmap command generation for batch {batch_num}...", "TEST")
        
        try:
            from ids_manager_new import IDSManager
            
            manager = IDSManager()
            manager.start()
            
            test_cmd = manager.controller.rule_manager.get_test_command(batch_num)
            
            if test_cmd:
                self.log(f"✓ Generated test command: {test_cmd}", "PASS")
                self.results['nmap_generation'] = True
                self.results['nmap_command'] = test_cmd
                return True
            else:
                self.log("⚠ No nmap command for batch (may be normal)", "WARN")
                self.results['nmap_generation'] = False
                return False
            
        except Exception as e:
            self.log(f"✗ nmap command generation failed: {e}", "FAIL")
            self.results['nmap_generation'] = False
            return False
    
    def test_code_export(self, batch_num: int = 0, output_dir: str = "test_output") -> bool:
        """Test code export functionality"""
        self.log(f"Testing code export for batch {batch_num}...", "TEST")
        
        try:
            from ids_manager_new import IDSManager, IDSConfig
            
            config = IDSConfig()
            config.output_dir = Path(output_dir)
            
            manager = IDSManager(config)
            manager.start()
            
            if manager.controller.rule_manager.generate_batch_code(batch_num):
                if manager.controller.rule_manager.deployment_manager.export_batch_code(
                    batch_num, str(config.output_dir)
                ):
                    self.log(f"✓ Code exported to {output_dir}", "PASS")
                    self.results['code_export'] = True
                    return True
            
            self.log("✗ Export failed", "FAIL")
            return False
            
        except Exception as e:
            self.log(f"✗ Code export test failed: {e}", "FAIL")
            self.results['code_export'] = False
            return False
    
    def run_all_tests(self, json_path: str = "snort_rules_ebpf.json") -> Dict:
        """Run all tests"""
        self.log("=" * 80, "INFO")
        self.log("Starting comprehensive eBPF IDS system tests", "INFO")
        self.log("=" * 80, "INFO")
        
        tests = [
            ("Imports", self.test_imports),
            ("JSON Loading", lambda: self.test_json_loading(json_path)),
            ("Rule Factory", lambda: self.test_rule_factory(json_path)),
            ("Batching", lambda: self.test_batching(json_path, 5)),
            ("Code Generation", lambda: self.test_code_generation(json_path, 5)),
            ("DeploymentManager", lambda: self.test_deployment_manager(json_path)),
            ("IDSManager", self.test_ids_manager),
            ("nmap Commands", self.test_nmap_command_generation),
            ("Code Export", self.test_code_export),
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            try:
                if test_func():
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                self.log(f"✗ Exception in {test_name}: {e}", "ERROR")
                failed += 1
        
        self.log("=" * 80, "INFO")
        self.log(f"Tests completed: {passed} passed, {failed} failed", "INFO")
        self.log("=" * 80, "INFO")
        
        return {
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "results": self.results
        }
    
    def print_summary(self):
        """Print test results summary"""
        print("\n" + "=" * 80)
        print("TEST RESULTS SUMMARY")
        print("=" * 80)
        
        for key, value in self.results.items():
            if isinstance(value, bool):
                status = "✓ PASS" if value else "✗ FAIL"
                print(f"{key}: {status}")
            elif isinstance(value, (int, str)):
                print(f"{key}: {value}")
            elif isinstance(value, dict):
                print(f"{key}:")
                for k, v in value.items():
                    print(f"  {k}: {v}")
        
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="eBPF IDS System Tester")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--batch", type=int, help="Test specific batch number")
    parser.add_argument("--export", action="store_true", help="Test code export")
    parser.add_argument("--nmap", type=int, help="Test nmap command generation")
    parser.add_argument("--summary", action="store_true", help="Run all and print summary")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--json", default="snort_rules_ebpf.json", help="Path to rules JSON")
    
    args = parser.parse_args()
    
    tester = IDSSystemTester(verbose=args.verbose)
    
    if args.summary or args.all:
        tester.run_all_tests(args.json)
        tester.print_summary()
    elif args.batch is not None:
        print(f"Testing batch {args.batch}...")
        from ids_manager_new import IDSManager
        manager = IDSManager()
        manager.deploy_test_batch(args.batch, test_nmap=True)
    elif args.export:
        print("Testing code export...")
        tester.test_code_export()
    elif args.nmap is not None:
        print(f"Testing nmap command for batch {args.nmap}...")
        tester.test_nmap_command_generation(args.nmap)
    else:
        tester.run_all_tests(args.json)
        tester.print_summary()


if __name__ == "__main__":
    main()
