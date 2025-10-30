#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
规则加载和解析模块
"""

import os
import json

try:
    import yaml
except ImportError:
    yaml = None


class RuleLoader:
    """规则加载器"""
    
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        
    def load_from_json(self, filepath):
        """从 JSON 文件加载规则"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except (IOError, json.JSONDecodeError) as e:
            print(f"加载 JSON 规则失败: {filepath}, 错误: {e}")
            return None
    
    def load_from_yaml(self, filepath):
        """从 YAML 文件加载规则"""
        if yaml is None:
            print("PyYAML 未安装，无法加载 YAML 规则")
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            return data
        except (IOError, yaml.YAMLError) as e:
            print(f"加载 YAML 规则失败: {filepath}, 错误: {e}")
            return None
    
    def load_all_rules(self):
        """加载规则目录下的所有规则文件"""
        rules = []
        
        if not os.path.exists(self.rules_dir):
            print(f"规则目录不存在: {self.rules_dir}")
            return rules
        
        for filename in os.listdir(self.rules_dir):
            filepath = os.path.join(self.rules_dir, filename)
            
            if not os.path.isfile(filepath):
                continue
            
            if filename.endswith('.json'):
                rule_data = self.load_from_json(filepath)
                if rule_data:
                    rules.append(rule_data)
            elif filename.endswith(('.yaml', '.yml')):
                rule_data = self.load_from_yaml(filepath)
                if rule_data:
                    rules.append(rule_data)
        
        return rules


class RuleParser:
    """规则解析器"""
    
    @staticmethod
    def parse_signature_rule(rule_data):
        """解析签名规则"""
        return rule_data
    
    @staticmethod
    def parse_anomaly_rule(rule_data):
        """解析异常检测规则"""
        return rule_data
    
    @staticmethod
    def parse_protocol_rule(rule_data):
        """解析协议分析规则"""
        return rule_data
    
    @staticmethod
    def compile_rule(rule):
        """编译规则为可执行格式"""
        return rule
