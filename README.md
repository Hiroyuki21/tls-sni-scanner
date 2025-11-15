# TLS/SNI Security Scanner

Toolkit lengkap untuk scanning dan fuzzing implementasi TLS/SNI.

## Fitur
- SNI Enumeration
- TLS Configuration Testing  
- Certificate Validation Testing
- Fuzzing SNI Fields
- Vulnerability Detection

## Install di Termux
```bash
pkg update && pkg upgrade
pkg install python git openssl
git clone https://github.com/username/tls-sni-scanner.git
cd tls-sni-scanner
pip install -r requirements.txt

# Basic scan
python scanner.py -t example.com

# Full scan dengan fuzzing
python scanner.py -t example.com -f --output results.json

from scanner import TLSSNIScanner

scanner = TLSSNIScanner("example.com", 443)
results = scanner.comprehensive_scan()
