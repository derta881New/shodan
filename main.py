#!/usr/bin/env python3
"""
D-Link Device Scanner
Простой сканер D-Link устройств

Автор: Security Research
Версия: 2.0 Simple
"""

import argparse
import requests
import signal
import sys
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ipaddress
import socket
import queue

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Statistics:
    """Thread-safe statistics tracker"""
    def __init__(self):
        self.processed_count = 0
        self.vulnerable_found = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.dlink_hosts = []

    def increment_processed(self):
        with self.lock:
            self.processed_count += 1

    def increment_vulnerable(self, host):
        with self.lock:
            self.vulnerable_found += 1
            self.dlink_hosts.append(host)

    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.processed_count / elapsed if elapsed > 0 else 0
            return {
                'processed_count': self.processed_count,
                'vulnerable': self.vulnerable_found,
                'rate': rate,
                'elapsed': elapsed,
                'hosts': self.dlink_hosts.copy()
            }

class DLinkScanner:
    """Simple D-Link device scanner"""

    def __init__(self, stats, timeout=5):
        self.stats = stats
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Connection': 'close'
        })

    def detect_dlink(self, host):
        """Detect if host is D-Link device"""
        try:
            # Multiple detection methods
            checks = [
                # HNAP check
                {
                    'url': f"http://{host}/HNAP1/",
                    'method': 'GET',
                    'headers': {'SOAPAction': '"http://purenetworks.com/HNAP1/GetDeviceSettings"'},
                    'indicators': ['HNAP', 'D-Link', 'purenetworks.com', 'DeviceType']
                },
                # Web interface check
                {
                    'url': f"http://{host}/",
                    'method': 'GET',
                    'headers': {},
                    'indicators': ['D-Link', 'DIR-', 'DAP-', 'DCS-', 'DWR-', 'DGS-']
                },
                # Login page check
                {
                    'url': f"http://{host}/login.php",
                    'method': 'GET',
                    'headers': {},
                    'indicators': ['D-Link', 'Router']
                }
            ]

            for check in checks:
                try:
                    if check['method'] == 'POST':
                        response = self.session.post(check['url'], headers=check['headers'], timeout=self.timeout)
                    else:
                        response = self.session.get(check['url'], headers=check['headers'], timeout=self.timeout)
                    
                    # Check response
                    response_text = response.text.lower()
                    headers_text = ' '.join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
                    full_text = response_text + ' ' + headers_text
                    
                    for indicator in check['indicators']:
                        if indicator.lower() in full_text:
                            return True
                            
                except Exception:
                    continue

        except Exception:
            pass

        return False

    def scan_single_host(self, host):
        """Simple D-Link device scan"""
        self.stats.increment_processed()

        # Clean host format
        if host.startswith(('http://', 'https://')):
            host = urlparse(host).netloc

        # Extract IP/hostname without port
        if ':' in host and not host.count(':') > 1:  # IPv4 with port
            host = host.split(':')[0]

        try:
            # Detect if it's a D-Link device
            if self.detect_dlink(host):
                self.stats.increment_vulnerable(host)
                return host

        except Exception:
            pass

        return None

def is_valid_target(target):
    """Quick validation for single target"""
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

def validate_and_filter_targets(targets):
    """Validate and filter target list, removing invalid IPs and duplicates"""
    valid_targets = []

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
                continue

    return valid_targets

def save_to_file(host):
    """Save D-Link IP to ip.txt file"""
    try:
        with open('ip.txt', 'a') as f:
            f.write(f"{host}\n")
    except Exception as e:
        print(f"Error saving to file: {e}")

def main():
    parser = argparse.ArgumentParser(description='Simple D-Link Device Scanner')
    parser.add_argument('-t', '--threads', type=int, default=500, 
                       help='Number of threads (default: 500)')
    parser.add_argument('-f', '--file', 
                       help='File with target IPs')
    parser.add_argument('--timeout', type=int, default=5, 
                       help='Request timeout in seconds (default: 5)')

    args = parser.parse_args()

    # Signal handling
    def signal_handler(sig, frame):
        print('\n[!] Interrupted by user')
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)

    stats = Statistics()
    scanner = DLinkScanner(stats, timeout=args.timeout)
    
    # Clear ip.txt file at start
    try:
        open('ip.txt', 'w').close()
    except Exception:
        pass

    # Get targets
    targets = []

    if args.file:
        # File mode
        try:
            with open(args.file, 'r') as f:
                raw_targets = [line.strip() for line in f if line.strip()]
                targets = validate_and_filter_targets(raw_targets)
        except FileNotFoundError:
            print(f"[!] File '{args.file}' not found")
            sys.exit(1)

        if not targets:
            print("[!] No valid targets found")
            sys.exit(1)
            
        print(f"[+] Starting D-Link scanner with {len(targets)} targets")
        print(f"[+] Using {args.threads} threads, timeout: {args.timeout}s")
        
        # Start scanning
        start_time = time.time()
        dlink_results = []
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Submit all scan tasks
            futures = [executor.submit(scanner.scan_single_host, target.strip()) 
                      for target in targets]

            # Process results with progress display
            last_update = time.time()
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:  # If D-Link device found
                        dlink_results.append(result)
                        save_to_file(result)
                        
                except Exception:
                    pass

                # Show progress every second
                current_time = time.time()
                if current_time - last_update >= 1.0:
                    last_update = current_time
                    data = stats.get_stats()
                    print(f"\r📊 Progress: {data['processed_count']} scanned | {data['vulnerable']} vulnerable | Rate: {data['rate']:.1f}/sec", end="", flush=True)
                    
        # Final results
        final_stats = stats.get_stats()
        print(f"\n[+] Scan completed!")
        print(f"[+] Total scanned: {final_stats['processed_count']}")
        print(f"[+] D-Link devices found: {final_stats['vulnerable']}")
        print(f"[+] Scan time: {final_stats['elapsed']:.1f} seconds")
        print(f"[+] Results saved to: ip.txt")
        
        if dlink_results:
            print("\n[+] Found D-Link devices:")
            for ip in dlink_results[:10]:  # Show first 10
                print(f"  - {ip}")
            if len(dlink_results) > 10:
                print(f"  ... and {len(dlink_results) - 10} more")
    else:
        # stdin mode - REAL-TIME STREAMING
        print("[+] D-Link Real-Time Scanner - Reading from stdin")
        print("[+] Press Ctrl+C to stop")
        
        # Real-time scanning from stdin
        dlink_results = []
        start_time = time.time()
        last_update = time.time()
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            active_futures = []
            
            try:
                for line in sys.stdin:
                    target = line.strip()
                    if target and is_valid_target(target):
                        # Submit scan task
                        future = executor.submit(scanner.scan_single_host, target)
                        active_futures.append(future)
                        
                        # Clean completed futures
                        completed = [f for f in active_futures if f.done()]
                        for f in completed:
                            try:
                                result = f.result()
                                if result:  # D-Link device found
                                    dlink_results.append(result)
                                    save_to_file(result)
                            except:
                                pass
                        
                        # Keep only active futures
                        active_futures = [f for f in active_futures if not f.done()]
                        
                        # Show progress every second
                        current_time = time.time()
                        if current_time - last_update >= 1.0:
                            last_update = current_time
                            data = stats.get_stats()
                            print(f"\r📊 Progress: {data['processed_count']} scanned | {data['vulnerable']} vulnerable | Rate: {data['rate']:.1f}/sec | Queue: 0 | Active: {len(active_futures)}", end="", flush=True)
                            
            except KeyboardInterrupt:
                print("\n[!] Stopping scanner...")
                
            # Wait for remaining tasks
            for f in active_futures:
                try:
                    result = f.result(timeout=1)
                    if result:
                        dlink_results.append(result)
                        save_to_file(result)
                except:
                    pass

        # Final summary for stdin mode
        elapsed_total = time.time() - start_time
        print(f"\n[+] Streaming completed!")
        print(f"[+] Total scanned: {stats.get_stats()['processed_count']}")
        print(f"[+] D-Link devices found: {len(dlink_results)}")
        print(f"[+] Scan time: {elapsed_total:.1f}s")
        print(f"[+] Results saved to: ip.txt")
        
        if dlink_results:
            print("\n[+] Found D-Link devices:")
            for ip in dlink_results[:10]:  # Show first 10
                print(f"  - {ip}")
            if len(dlink_results) > 10:
                print(f"  ... and {len(dlink_results) - 10} more")

if __name__ == "__main__":
    main()
