#!/usr/bin/env python3
"""
SNI Fuzzer for TLS implementations
"""

import socket
import ssl
import time
from typing import List, Dict, Any
from colorama import Fore, Style

class SNIFuzzer:
    def __init__(self, target: str, port: int = 443):
        self.target = target
        self.port = port
        self.timeout = 5
    
    def generate_fuzz_payloads(self) -> List[str]:
        """Generate various fuzzing payloads for SNI"""
        payloads = []
        
        # Length-based fuzzing
        for length in [10, 50, 100, 500, 1000]:
            payloads.append('A' * length)
            payloads.append('\x00' * length)
        
        # Special characters
        special_chars = [
            "../../etc/passwd",
            "%s" * 20,
            "%x" * 20,
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "NULL\x00BYTE",
            "..\\..\\windows\\system32\\config",
        ]
        payloads.extend(special_chars)
        
        # Format string attacks
        format_strings = [
            "%s" * 10,
            "%n" * 10,
            "%p" * 10,
            "%x" * 10,
        ]
        payloads.extend(format_strings)
        
        # Buffer overflow patterns
        payloads.extend([
            "A" * 5000,
            "\x41" * 3000,
        ])
        
        return payloads
    
    def test_sni_payload(self, sni_payload: str) -> Dict[str, Any]:
        """Test a single SNI payload"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=sni_payload) as ssock:
                    return {
                        'payload': sni_payload[:100],
                        'status': 'success',
                        'certificate_received': True,
                        'error': None
                    }
                    
        except ssl.SSLError as e:
            return {
                'payload': sni_payload[:100],
                'status': 'ssl_error',
                'certificate_received': False,
                'error': str(e)
            }
        except socket.timeout:
            return {
                'payload': sni_payload[:100],
                'status': 'timeout',
                'certificate_received': False,
                'error': 'Connection timeout'
            }
        except Exception as e:
            return {
                'payload': sni_payload[:100],
                'status': 'error',
                'certificate_received': False,
                'error': str(e)
            }
    
    def run_fuzz_tests(self) -> Dict[str, Any]:
        """Run all fuzzing tests"""
        print(f"{Fore.YELLOW}[*] Generating fuzzing payloads...")
        payloads = self.generate_fuzz_payloads()
        
        print(f"{Fore.YELLOW}[*] Testing {len(payloads)} SNI payloads...")
        
        results = {
            'total_tests': len(payloads),
            'successful': 0,
            'errors': 0,
            'timeouts': 0,
            'ssl_errors': 0,
            'detailed_results': []
        }
        
        for i, payload in enumerate(payloads, 1):
            print(f"{Fore.WHITE}[{i}/{len(payloads)}] Testing: {payload[:50]}...", end=' ')
            
            result = self.test_sni_payload(payload)
            results['detailed_results'].append(result)
            
            if result['status'] == 'success':
                results['successful'] += 1
                print(f"{Fore.GREEN}SUCCESS")
            elif result['status'] == 'timeout':
                results['timeouts'] += 1
                print(f"{Fore.YELLOW}TIMEOUT")
            elif result['status'] == 'ssl_error':
                results['ssl_errors'] += 1
                print(f"{Fore.BLUE}SSL_ERROR")
            else:
                results['errors'] += 1
                print(f"{Fore.RED}ERROR")
            
            time.sleep(0.2)
        
        print(f"\n{Fore.CYAN}[*] Fuzzing completed:")
        print(f"    Successful: {results['successful']}")
        print(f"    SSL Errors: {results['ssl_errors']}")
        print(f"    Timeouts: {results['timeouts']}")
        print(f"    Other Errors: {results['errors']}")
        
        return results

if __name__ == "__main__":
    fuzzer = SNIFuzzer("example.com", 443)
    fuzzer.run_fuzz_tests()
