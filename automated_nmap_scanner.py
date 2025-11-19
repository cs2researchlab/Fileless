#!/usr/bin/env python3
"""
Automated Nmap Scanner for Fileless Malware Research
Author: Hunter
Course: Cybersecurity Research
Purpose: Automated vulnerability scanning and report generation
"""

import nmap
import json
import datetime
from typing import Dict, List
import sys

class FilelessMalwareScanner:
    """Automated scanner for identifying vulnerable services"""
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.scanner = nmap.PortScanner()
        self.scan_results = {}
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
    def run_comprehensive_scan(self):
        """Execute comprehensive Nmap scan"""
        print(f"[*] Starting comprehensive scan of {self.target_ip}")
        print(f"[*] Timestamp: {self.timestamp}")
        print("-" * 60)
        
        try:
            # Comprehensive scan: SYN scan, version detection, OS detection, scripts
            print("[*] Running SYN scan with version and OS detection...")
            self.scanner.scan(
                hosts=self.target_ip,
                arguments='-sS -sV -O -A -T4 --script=default,vuln'
            )
            
            self.scan_results = self.scanner[self.target_ip]
            print("[+] Scan completed successfully!")
            return True
            
        except Exception as e:
            print(f"[-] Scan failed: {str(e)}")
            return False
    
    def identify_vulnerable_ports(self) -> List[Dict]:
        """Identify potentially vulnerable ports for fileless attacks"""
        vulnerable_ports = []
        
        # Ports commonly exploited for fileless malware
        fileless_target_ports = {
            135: "RPC - Remote code execution",
            139: "NetBIOS - SMB attacks, fileless lateral movement",
            445: "SMB - PowerShell remoting, WMI attacks",
            3389: "RDP - Remote desktop exploitation",
            5985: "WinRM - PowerShell remoting",
            5986: "WinRM HTTPS - Secure PowerShell remoting"
        }
        
        if 'tcp' in self.scan_results:
            for port in self.scan_results['tcp']:
                port_info = self.scan_results['tcp'][port]
                
                vulnerability_level = "Low"
                if port in fileless_target_ports:
                    vulnerability_level = "High"
                elif port_info['state'] == 'open':
                    vulnerability_level = "Medium"
                
                vulnerable_ports.append({
                    'port': port,
                    'service': port_info.get('name', 'unknown'),
                    'state': port_info['state'],
                    'version': port_info.get('product', '') + ' ' + port_info.get('version', ''),
                    'vulnerability_level': vulnerability_level,
                    'attack_vector': fileless_target_ports.get(port, 'General reconnaissance')
                })
        
        return vulnerable_ports
    
    def get_system_info(self) -> Dict:
        """Extract system information from scan"""
        info = {
            'hostname': self.scan_results.get('hostnames', [{}])[0].get('name', 'Unknown'),
            'os_matches': [],
            'open_ports_count': 0,
            'vulnerable_ports_count': 0
        }
        
        # OS Detection
        if 'osmatch' in self.scan_results:
            for os in self.scan_results['osmatch']:
                info['os_matches'].append({
                    'name': os['name'],
                    'accuracy': os['accuracy']
                })
        
        # Port statistics
        if 'tcp' in self.scan_results:
            info['open_ports_count'] = len([p for p in self.scan_results['tcp'] 
                                           if self.scan_results['tcp'][p]['state'] == 'open'])
        
        return info
    
    def generate_text_report(self, filename: str = None):
        """Generate human-readable text report"""
        if filename is None:
            filename = f"scan_report_{self.target_ip}_{self.timestamp}.txt"
        
        vulnerable_ports = self.identify_vulnerable_ports()
        system_info = self.get_system_info()
        
        report = []
        report.append("=" * 80)
        report.append("FILELESS MALWARE VULNERABILITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Target: {self.target_ip}")
        report.append(f"Scan Date: {self.timestamp}")
        report.append(f"Hostname: {system_info['hostname']}")
        report.append("=" * 80)
        report.append("")
        
        # System Information
        report.append("SYSTEM INFORMATION")
        report.append("-" * 80)
        if system_info['os_matches']:
            report.append("Operating System Detection:")
            for os in system_info['os_matches'][:3]:
                report.append(f"  - {os['name']} (Accuracy: {os['accuracy']}%)")
        report.append(f"Total Open Ports: {system_info['open_ports_count']}")
        report.append("")
        
        # Vulnerable Ports Analysis
        report.append("VULNERABLE PORTS ANALYSIS")
        report.append("-" * 80)
        report.append(f"{'Port':<10} {'Service':<20} {'State':<10} {'Risk':<10} {'Attack Vector'}")
        report.append("-" * 80)
        
        for port_info in sorted(vulnerable_ports, key=lambda x: x['port']):
            report.append(
                f"{port_info['port']:<10} "
                f"{port_info['service']:<20} "
                f"{port_info['state']:<10} "
                f"{port_info['vulnerability_level']:<10} "
                f"{port_info['attack_vector']}"
            )
        report.append("")
        
        # High-Risk Ports Summary
        high_risk = [p for p in vulnerable_ports if p['vulnerability_level'] == 'High']
        if high_risk:
            report.append("HIGH-RISK PORTS FOR FILELESS ATTACKS")
            report.append("-" * 80)
            for port in high_risk:
                report.append(f"Port {port['port']} ({port['service']}): {port['attack_vector']}")
            report.append("")
        
        # Recommendations
        report.append("SECURITY RECOMMENDATIONS")
        report.append("-" * 80)
        if any(p['port'] in [139, 445] for p in vulnerable_ports):
            report.append("• SMB ports (139, 445) are open - vulnerable to PowerShell fileless attacks")
            report.append("  Recommendation: Implement SMB signing, restrict PowerShell execution policy")
        if any(p['port'] == 135 for p in vulnerable_ports):
            report.append("• RPC port (135) is open - potential for remote code execution")
            report.append("  Recommendation: Restrict RPC access, enable Windows Firewall")
        if any(p['port'] in [5985, 5986] for p in vulnerable_ports):
            report.append("• WinRM ports are open - PowerShell remoting enabled")
            report.append("  Recommendation: Disable WinRM if not needed, use certificate authentication")
        
        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filename, 'w') as f:
            f.write('\n'.join(report))
        
        print(f"[+] Text report saved to: {filename}")
        return '\n'.join(report)
    
    def generate_json_report(self, filename: str = None):
        """Generate machine-readable JSON report"""
        if filename is None:
            filename = f"scan_report_{self.target_ip}_{self.timestamp}.json"
        
        report_data = {
            'scan_info': {
                'target': self.target_ip,
                'timestamp': self.timestamp,
                'scanner': 'Nmap'
            },
            'system_info': self.get_system_info(),
            'vulnerable_ports': self.identify_vulnerable_ports(),
            'raw_results': dict(self.scan_results)
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[+] JSON report saved to: {filename}")
        return report_data

def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage: python3 automated_nmap_scanner.py <target_ip>")
        print("Example: python3 automated_nmap_scanner.py 192.168.1.5")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║   AUTOMATED FILELESS MALWARE VULNERABILITY SCANNER        ║
║   Research Project: Offensive Security Tools              ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    scanner = FilelessMalwareScanner(target)
    
    # Run scan
    if scanner.run_comprehensive_scan():
        # Generate reports
        print("\n[*] Generating reports...")
        scanner.generate_text_report()
        scanner.generate_json_report()
        
        # Display summary
        print("\n[*] Scan Summary:")
        vulnerable_ports = scanner.identify_vulnerable_ports()
        high_risk = [p for p in vulnerable_ports if p['vulnerability_level'] == 'High']
        
        print(f"    Total open ports: {len(vulnerable_ports)}")
        print(f"    High-risk ports: {len(high_risk)}")
        
        if high_risk:
            print("\n[!] HIGH-RISK PORTS DETECTED:")
            for port in high_risk:
                print(f"    Port {port['port']} - {port['attack_vector']}")
        
        print("\n[+] Scanning complete!")
    else:
        print("[-] Scanning failed. Check network connectivity and permissions.")
        sys.exit(1)

if __name__ == "__main__":
    main()
