#!/usr/bin/env python3
"""
TLS/SNI Security Scanner
Author: Your Name
License: MIT
"""

import socket
import ssl
import argparse
import json
import sys
import time
from typing import Dict, List, Any
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class TLSSNIScanner:
    def __init__(self, target: str, port: int = 443):
        self.target = target
        self.port = port
        self.results = {}
    
    def banner(self):
        print(f"{Fore.CYAN}")
        print("╔══════════════════════════════════════╗")
        print("║       TLS/SNI Security Scanner       ║")
        print("║          For Educational Use         ║")
        print("╚══════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
    
    def scan_basic_info(self):
        """Scan basic TLS information"""
        print(f"\n{Fore.YELLOW}[*] Scanning basic TLS info for {self.target}:{self.port}")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    self.results['basic_info'] = {
                        'target': self.target,
                        'port': self.port,
                        'certificate': cert,
                        'cipher_suite': cipher,
                        'tls_version': ssock.version()
                    }
                    
                    print(f"{Fore.GREEN}[+] TLS Version: {ssock.version()}")
                    print(f"{Fore.GREEN}[+] Cipher Suite: {cipher}")
                    if cert and 'subject' in cert:
                        subject = dict(x[0] for x in cert['subject'])
                        print(f"{Fore.GREEN}[+] Certificate Subject: {subject}")
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Basic connection failed: {e}")
            self.results['basic_info'] = {'error': str(e)}
    
    def test_sni_handling(self, sni_list: List[str] = None):
        """Test SNI handling with various hostnames"""
        print(f"\n{Fore.YELLOW}[*] Testing SNI handling")
        
        if not sni_list:
            sni_list = [
                self.target,
                f"www.{self.target}",
                "localhost",
                "invalid-hostname-test",
                "a" * 50,
                "127.0.0.1",
                "example.com"
            ]
        
        self.results['sni_tests'] = {}
        
        for sni in sni_list:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=sni) as ssock:
                        cert = ssock.getpeercert()
                        self.results['sni_tests'][sni] = {
                            'status': 'success',
                            'certificate_received': cert is not None
                        }
                        print(f"{Fore.GREEN}[+] SNI '{sni[:30]}...' - Success")
                        
            except Exception as e:
                self.results['sni_tests'][sni] = {
                    'status': 'error',
                    'error': str(e)
                }
                print(f"{Fore.RED}[-] SNI '{sni[:30]}...' - Error: {e}")
            
            time.sleep(0.2)  # Rate limiting
    
    def check_vulnerabilities(self):
        """Check for common TLS vulnerabilities"""
        print(f"\n{Fore.YELLOW}[*] Checking for common vulnerabilities")
        
        vuln_checks = {}
        
        # Check TLS versions
        vuln_checks['tls_versions'] = self.check_tls_versions()
        
        # Check certificate validation
        vuln_checks['cert_validation'] = self.test_certificate_validation()
        
        self.results['vulnerabilities'] = vuln_checks
        
        # Print results
        for check_name, result in vuln_checks.items():
            if result.get('vulnerable', False):
                print(f"{Fore.RED}[-] {check_name}: VULNERABLE - {result.get('details', '')}")
            else:
                print(f"{Fore.GREEN}[+] {check_name}: OK")
    
    def check_tls_versions(self) -> Dict[str, Any]:
        """Check supported TLS versions"""
        tls_versions = {
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1': ssl.PROTOCOL_TLSv1,
        }
        
        results = {}
        vulnerable = False
        
        for version_name, version_protocol in tls_versions.items():
            try:
                context = ssl.SSLContext(version_protocol)
                with socket.create_connection((self.target, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        results[version_name] = {
                            'supported': True,
                            'cipher': ssock.cipher()
                        }
                        if version_name in ['TLSv1', 'TLSv1.1']:
                            vulnerable = True
            except Exception:
                results[version_name] = {'supported': False}
        
        return {
            'vulnerable': vulnerable,
            'details': 'Older TLS versions (v1.0, v1.1) detected' if vulnerable else 'Only modern TLS versions',
            'version_support': results
        }
    
    def test_certificate_validation(self) -> Dict[str, Any]:
        """Test if certificate validation can be bypassed"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((self.target, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname="invalid-hostname-that-should-not-exist.com") as ssock:
                    return {
                        'vulnerable': True,
                        'details': 'Certificate validation bypass possible'
                    }
        except ssl.CertificateError:
            return {
                'vulnerable': False,
                'details': 'Certificate validation working correctly'
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'details': f'Validation test inconclusive: {e}'
            }
    
    def comprehensive_scan(self, enable_fuzzing: bool = False):
        """Run comprehensive scan"""
        self.banner()
        
        print(f"{Fore.WHITE}Target: {self.target}:{self.port}")
        print(f"{Fore.WHITE}Started at: {time.ctime()}\n")
        
        # Run all scans
        self.scan_basic_info()
        self.test_sni_handling()
        self.check_vulnerabilities()
        
        if enable_fuzzing:
            print(f"\n{Fore.YELLOW}[*] Starting SNI fuzzing")
            from fuzzer import SNIFuzzer
            fuzzer = SNIFuzzer(self.target, self.port)
            fuzz_results = fuzzer.run_fuzz_tests()
            self.results['fuzzing'] = fuzz_results
        
        print(f"\n{Fore.CYAN}[*] Scan completed at: {time.ctime()}")
        return self.results

def main():
    parser = argparse.ArgumentParser(description='TLS/SNI Security Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-f', '--fuzz', action='store_true', help='Enable fuzzing tests')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        scanner = TLSSNIScanner(args.target, args.port)
        results = scanner.comprehensive_scan(enable_fuzzing=args.fuzz)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to: {args.output}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
