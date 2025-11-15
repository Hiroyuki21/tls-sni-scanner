#!/usr/bin/env python3
"""
Configuration settings for TLS/SNI scanner
"""

# Default settings
DEFAULT_TIMEOUT = 10
DEFAULT_PORT = 443
MAX_THREADS = 10

# Common SNI hostnames for testing
COMMON_SNI_HOSTNAMES = [
    "localhost",
    "127.0.0.1", 
    "example.com",
    "test.com",
    "admin",
    "api",
    "secure",
    "mail",
    "webmail",
    "cpanel",
    "whm",
    "webdisk",
    "ftp",
    "ssh",
    "mysql",
    "mongo",
    "redis",
    "elasticsearch",
]

# User agents for HTTP testing
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", 
    "TLS-SNI-Scanner/1.0",
]

# Fuzzing parameters
MAX_FUZZ_PAYLOAD_LENGTH = 10000
FUZZ_DELAY = 0.2
