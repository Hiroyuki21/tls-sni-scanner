#!/usr/bin/env python3
"""
Example usage of TLS/SNI scanner
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import TLSSNIScanner

def main():
    print("=== TLS/SNI Scanner Example ===")
    
    # Basic scan
    scanner = TLSSNIScanner("example.com", 443)
    results = scanner.comprehensive_scan(enable_fuzzing=False)
    
    print("\n=== Scan Results ===")
    print(f"Target: {results['basic_info']['target']}")
    print(f"TLS Version: {results['basic_info']['tls_version']}")
    print(f"Cipher Suite: {results['basic_info']['cipher_suite']}")
    
    # Show SNI test results
    print(f"\nSNI Tests: {len(results['sni_tests'])} performed")
    
    # Show vulnerability results
    vulns = results['vulnerabilities']
    for vuln_name, vuln_info in vulns.items():
        status = "VULNERABLE" if vuln_info.get('vulnerable') else "SECURE"
        print(f"{vuln_name}: {status}")

if __name__ == "__main__":
    main()
