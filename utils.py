#!/usr/bin/env python3
"""
Utility functions for TLS/SNI scanning
"""

import socket
import ssl
import datetime
from typing import List, Dict, Any

class SSLUtils:
    @staticmethod
    def get_timestamp() -> str:
        return datetime.datetime.now().isoformat()
    
    def check_tls_versions(self, host: str, port: int) -> Dict[str, Any]:
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
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
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
    
    def test_certificate_validation(self, host: str, port: int) -> Dict[str, Any]:
        """Test if certificate validation can be bypassed"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname="invalid-hostname.com") as ssock:
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
    
    def check_weak_ciphers(self, host: str, port: int) -> Dict[str, Any]:
        """Check for weak cipher suites"""
        weak_ciphers = [
            'RC4', 'MD5', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON'
        ]
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else ''
                    
                    vulnerable = any(weak_cipher in cipher_name for weak_cipher in weak_ciphers)
                    
                    return {
                        'vulnerable': vulnerable,
                        'details': f'Weak cipher detected: {cipher_name}' if vulnerable else 'Strong cipher in use',
                        'current_cipher': cipher_name
                    }
        except Exception as e:
            return {
                'vulnerable': False,
                'details': f'Cipher check failed: {e}',
                'current_cipher': None
            }

class NetworkUtils:
    @staticmethod
    def resolve_hostname(hostname: str) -> List[str]:
        """Resolve hostname to IP addresses"""
        try:
            return socket.gethostbyname_ex(hostname)[2]
        except socket.gaierror:
            return []
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: int = 5) -> bool:
        """Check if port is open"""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

if __name__ == "__main__":
    utils = SSLUtils()
    print(utils.get_timestamp())
