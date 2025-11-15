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
