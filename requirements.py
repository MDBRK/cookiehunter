#!/usr/bin/env python3

# ==========================================
# Script Name: install_requirements.py
# Purpose:    Automatically install required Python packages
# Usage:      python3 install_requirements.py
# ==========================================

import subprocess
import sys

required = ["requests", "pyjwt"]

def install(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", package])
    except subprocess.CalledProcessError:
        print(f"[!] Failed to install {package}")

def main():
    print("[*] Checking and installing required packages...\n")
    for package in required:
        try:
            __import__(package)
            print(f"[✓] {package} is already installed.")
        except ImportError:
            print(f"[+] Installing {package}...")
            install(package)

if __name__ == "__main__":
    main()
