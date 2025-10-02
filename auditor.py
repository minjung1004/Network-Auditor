#!/usr/bin/env python3
"""
Network Security Auditor
Performs security compliance auditing on network devices
"""

import paramiko
import yaml
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
import re


class NetworkAuditor:
    def __init__(self, base_dir: str = "~/network-auditor"):
        self.base_dir = Path(base_dir).expanduser()
        self.baselines_dir = self.base_dir / "baselines"
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.devices = []
        self.ssh_baseline = {}
        self.users_baseline = {}
        self.firewall_baseline = {}
        self.audit_results = []
    
    # 1. Load device inventory from YAML file
    def load_device_inventory(self):
        inventory_path = self.base_dir / "device_inventory.yaml"
        try:
            with open(inventory_path, 'r') as f:
                data = yaml.safe_load(f)
                self.devices = data.get('devices', [])
                print(f"[+] Loaded {len(self.devices)} devices from inventory")
        except FileNotFoundError:
            print(f"[!] Error: {inventory_path} not found")
            raise
        except yaml.YAMLError as e:
            print(f"[!] Error parsing device inventory: {e}")
            raise
        return None
    
    # Establish SSH connection
    def ssh_connect(self, device: Dict):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                hostname=device['ip'],
                username=device['username'],
                password=device['password'],
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            print(f"[+] Connected to {device['hostname']} ({device['ip']})")
            return client
        except paramiko.AuthenticationException:
            print(f"[!] Authentication failed for {device['hostname']}")
            raise
        except paramiko.SSHException as e:
            print(f"[!] SSH error for {device['hostname']}: {e}")
            raise
        except Exception as e:
            print(f"[!] Connection error for {device['hostname']}: {e}")
            raise
        return client
        
    # Configuration Extractions
    # Extract SSH configuration from /etc/ssh/sshd_config
    def extract_ssh_config(self, client: paramiko.SSHClient):
        config = {}
        try:
            stdin, stdout, stderr = client.exec_command("cat /etc/ssh/sshd_config")
            output = stdout.read().decode('utf-8')
            
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        config[key] = value
            
            print(f"  [+] Extracted {len(config)} SSH configuration parameters")
            return config
        except Exception as e:
            print(f"  [!] Error extracting SSH config: {e}")
            return {}
            
    # Extract user accounts from /etc/passwd
    def extract_user_accounts(self, client: paramiko.SSHClient):
        users = []
        try:
            stdin, stdout, stderr = client.exec_command("cat /etc/passwd")
            output = stdout.read().decode('utf-8')
            
            for line in output.split('\n'):
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 7:
                        users.append({
                            'username': parts[0],
                            'uid': parts[2],
                            'gid': parts[3],
                            'home': parts[5],
                            'shell': parts[6]
                        })
            
            print(f"  [+] Extracted {len(users)} user accounts")
            return users
        except Exception as e:
            print(f"  [!] Error extracting users: {e}")
            return []
            
    # Extract firewall rules using sudo ufw status numbered
    def extract_firewall_rules(self, client: paramiko.SSHClient):
        firewall_data = {
            'status': 'unknown',
            'rules': [],
            'raw_output': ''
        }
        
        try:
            stdin, stdout, stderr = client.exec_command("sudo ufw status numbered")
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            firewall_data['raw_output'] = output
            
            # Check if UFW is active
            if "Status: active" in output:
                firewall_data['status'] = 'active'
            elif "Status: inactive" in output:
                firewall_data['status'] = 'inactive'
            
            # Parse rules
            for line in output.split('\n'):
                # Match pattern: [ 1] 22/tcp ALLOW IN Anywhere
                match = re.search(r'\[\s*\d+\]\s+(\d+)/(tcp|udp)\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)', line)
                if match:
                    firewall_data['rules'].append({
                        'port': int(match.group(1)),
                        'protocol': match.group(2),
                        'action': match.group(3),
                        'direction': match.group(4)
                    })
            
            print(f"  [+] Extracted {len(firewall_data['rules'])} firewall rules")
            return firewall_data
        except Exception as e:
            print(f"  [!] Error extracting firewall rules: {e}")
            return firewall_data
            
    # Baseline Comparison
    # Load all baseline configuration files
    def load_baselines(self):
        """Load all baseline configuration files"""
        try:
            # Load SSH baseline
            with open(self.baselines_dir / "ssh_baseline.yaml", 'r') as f:
                self.ssh_baseline = yaml.safe_load(f)
                print("[+] Loaded SSH baseline configuration")
            
            # Load users baseline
            with open(self.baselines_dir / "users_baseline.yaml", 'r') as f:
                self.users_baseline = yaml.safe_load(f)
                print("[+] Loaded users baseline configuration")
            
            # Load firewall baseline
            with open(self.baselines_dir / "firewall_baseline.yaml", 'r') as f:
                self.firewall_baseline = yaml.safe_load(f)
                print("[+] Loaded firewall baseline configuration")
        except FileNotFoundError as e:
            print(f"[!] Error: Baseline file not found - {e}")
            raise
        except yaml.YAMLError as e:
            print(f"[!] Error parsing baseline file: {e}")
            raise
        return None

    # Compare SSH configuration against baseline
    def compare_ssh_config(self, device_name: str, actual_config: Dict):
        violations = []
        
        for rule in self.ssh_baseline.get('compliance_rules', []):
            param = rule['parameter']
            expected = str(rule['expected'])
            actual = actual_config.get(param, 'NOT_SET')
            
            if str(actual) != expected:
                violations.append({
                    'device': device_name,
                    'category': 'SSH Configuration',
                    'rule': rule['rule'],
                    'parameter': param,
                    'expected': expected,
                    'actual': str(actual),
                    'severity': rule['severity'],
                    'remediation': f"Set {param} to {expected} in /etc/ssh/sshd_config"
                })
        
        return violations

    # Compare user accounts against baseline
    def compare_users(self, device_name: str, actual_users: List[Dict]):
        violations = []
        usernames = [u['username'] for u in actual_users]
        
        # Check required users
        for required in self.users_baseline.get('required_users', []):
            if required['username'] not in usernames:
                violations.append({
                    'device': device_name,
                    'category': 'User Accounts',
                    'rule': required['description'],
                    'parameter': 'required_user',
                    'expected': f"User '{required['username']}' must exist",
                    'actual': 'User not found',
                    'severity': required['severity'],
                    'remediation': f"Create user account: sudo useradd {required['username']}"
                })
        
        # Check prohibited users
        for prohibited in self.users_baseline.get('prohibited_users', []):
            if prohibited['username'] in usernames:
                violations.append({
                    'device': device_name,
                    'category': 'User Accounts',
                    'rule': prohibited['description'],
                    'parameter': 'prohibited_user',
                    'expected': f"User '{prohibited['username']}' should not exist",
                    'actual': 'User exists',
                    'severity': prohibited['severity'],
                    'remediation': f"Remove user account: sudo userdel {prohibited['username']}"
                })
        
        return violations

    # Compare firewall rules against baseline
    def compare_firewall(self, device_name: str, firewall_data: Dict):
        violations = []
        actual_rules = firewall_data.get('rules', [])
        
        # Check if firewall is active
        if firewall_data['status'] != 'active':
            violations.append({
                'device': device_name,
                'category': 'Firewall',
                'rule': 'Firewall must be active',
                'parameter': 'firewall_status',
                'expected': 'active',
                'actual': firewall_data['status'],
                'severity': 'critical',
                'remediation': 'Enable firewall: sudo ufw enable'
            })
        
        # Check required rules
        for required in self.firewall_baseline.get('required_rules', []):
            rule_found = any(
                r['port'] == required['port'] and 
                r['protocol'] == required['protocol'] and
                r['action'] == required['action']
                for r in actual_rules
            )
            
            if not rule_found:
                violations.append({
                    'device': device_name,
                    'category': 'Firewall',
                    'rule': required['description'],
                    'parameter': f"port_{required['port']}",
                    'expected': f"{required['action']} {required['port']}/{required['protocol']}",
                    'actual': 'Rule not found',
                    'severity': required['severity'],
                    'remediation': f"sudo ufw allow {required['port']}/{required['protocol']}"
                })
        
        # Check blocked rules
        for blocked in self.firewall_baseline.get('blocked_rules', []):
            rule_found = any(
                r['port'] == blocked['port'] and 
                r['protocol'] == blocked['protocol'] and
                r['action'] != 'DENY' and r['action'] != 'REJECT'
                for r in actual_rules
            )
            
            if rule_found:
                violations.append({
                    'device': device_name,
                    'category': 'Firewall',
                    'rule': blocked['description'],
                    'parameter': f"port_{blocked['port']}",
                    'expected': f"{blocked['action']} {blocked['port']}/{blocked['protocol']}",
                    'actual': 'Port is allowed',
                    'severity': blocked.get('severity', 'warning'),  # Handle typo in baseline
                    'remediation': f"sudo ufw deny {blocked['port']}/{blocked['protocol']}"
                })
        
        return violations
    
    # Security Score Calculations
    def calculate_security_score(self, violations: List[Dict]):
        score = 100
        stats = {
            'critical': 0,
            'warning': 0,
            'total': len(violations)
        }
        
        for violation in violations:
            severity = violation['severity']
            if severity == 'critical':
                score -= 15
                stats['critical'] += 1
            elif severity == 'warning':
                score -= 5
                stats['warning'] += 1
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return score, stats

    # Report Generation
    def audit_device(self, device: Dict):
        """Perform complete audit on a single device"""
        print(f"\n{'='*80}")
        print(f"Auditing: {device['hostname']} ({device['ip']})")
        print(f"{'='*80}")
        
        result = {
            'device': device['hostname'],
            'ip': device['ip'],
            'timestamp': datetime.now().isoformat(),
            'violations': [],
            'score': 0,
            'status': 'unknown'
        }
        
        try:
            # Connect to device
            client = self.ssh_connect(device)
            
            # Extract configurations
            print("\n[*] Extracting configurations...")
            ssh_config = self.extract_ssh_config(client)
            users = self.extract_user_accounts(client)
            firewall = self.extract_firewall_rules(client)
            
            # Compare against baselines
            print("\n[*] Comparing against baselines...")
            violations = []
            violations.extend(self.compare_ssh_config(device['hostname'], ssh_config))
            violations.extend(self.compare_users(device['hostname'], users))
            violations.extend(self.compare_firewall(device['hostname'], firewall))
            
            # Calculate security score
            score, stats = self.calculate_security_score(violations)
            
            result['violations'] = violations
            result['score'] = score
            result['stats'] = stats
            result['status'] = 'COMPLETED'
            
            print(f"\n[*] Audit completed: {len(violations)} violations found")
            print(f"[*] Security Score: {score}/100")
            print(f"    - Critical: {stats['critical']}")
            print(f"    - Warning: {stats['warning']}")
            
            client.close()
            
        except Exception as e:
            print(f"[!] Audit failed: {e}")
            result['status'] = 'failed'
            result['error'] = str(e)
        
        return result
    
    # Display violations grouped by severity
    def display_violations(self, results: List[Dict]):
        print("\n" + "="*80)
        print("AUDIT REPORT SUMMARY")
        print("="*80)
        
        for result in results:
            print(f"\nDevice: {result['device']} ({result['ip']})")
            print(f"Security Score: {result['score']}/100")
            print(f"Status: {result['status']}")
            
            if result['status'] == 'failed':
                print(f"[ERROR] {result.get('error', 'Unknown error')}")
                continue
            
            violations = result['violations']
            
            if not violations:
                print("✓ No violations found - Device is compliant!")
                continue
            
            # Group by severity
            critical = [v for v in violations if v['severity'] == 'critical']
            warnings = [v for v in violations if v['severity'] == 'warning']
            
            if critical:
                print(f"\n  CRITICAL VIOLATIONS ({len(critical)}):")
                for i, v in enumerate(critical, 1):
                    print(f"    {i}. {v['rule']}")
                    print(f"       Category: {v['category']}")
                    print(f"       Expected: {v['expected']}")
                    print(f"       Actual: {v['actual']}")
                    print(f"       Remediation: {v['remediation']}")
            
            if warnings:
                print(f"\n  WARNINGS ({len(warnings)}):")
                for i, v in enumerate(warnings, 1):
                    print(f"    {i}. {v['rule']}")
                    print(f"       Category: {v['category']}")
                    print(f"       Expected: {v['expected']}")
                    print(f"       Actual: {v['actual']}")
                    print(f"       Remediation: {v['remediation']}")
            

    # Save detailed JSON report
    def save_report(self, results: List[Dict]):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"audit_report_{timestamp}.json"
        
        report = {
            'audit_timestamp': datetime.now().isoformat(),
            'total_devices': len(results),
            'results': results,
            'summary': {
                'completed': sum(1 for r in results if r['status'] == 'completed'),
                'failed': sum(1 for r in results if r['status'] == 'failed'),
                'average_score': sum(r.get('score', 0) for r in results) / len(results) if results else 0
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        return str(report_file)

    # Main Audit Execution 
    def run_audit(self):
        print("\n" + "="*80)
        print("NETWORK SECURITY AUDITOR")
        print("="*80)
        
        # Load configuration
        print("\n[*] Loading configuration files...")
        self.load_device_inventory()
        self.load_baselines()
        
        # Audit each device
        results = []
        for device in self.devices:
            result = self.audit_device(device)
            results.append(result)
        
        # Display and save results
        self.display_violations(results)
        self.save_report(results)
        
        print("\n" + "="*80)
        print("AUDIT COMPLETED")
        print("="*80)
        return None

def main():
    auditor = NetworkAuditor()
    
    try:
        auditor.run_audit()
    except KeyboardInterrupt:
        print("\n\n[!] Audit interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
