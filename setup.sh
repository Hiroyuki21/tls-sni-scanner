#!/bin/bash
echo "Setting up TLS/SNI Scanner on Termux..."
echo "======================================"

# Update system
echo "[1] Updating system packages..."
pkg update && pkg upgrade -y

# Install dependencies
echo "[2] Installing dependencies..."
pkg install -y python git openssl

# Install Python packages
echo "[3] Installing Python packages..."
pip install requests cryptography pyopenssl colorama aiohttp

echo ""
echo "Setup complete! 🎉"
echo ""
echo "Usage examples:"
echo "  python scanner.py -t example.com"
echo "  python scanner.py -t google.com -f -o results.json"
echo ""
echo "Legal reminder: Only use for authorized testing!"
