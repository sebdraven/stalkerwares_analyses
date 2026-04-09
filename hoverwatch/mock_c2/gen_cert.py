#!/usr/bin/env python3
"""Generate self-signed SSL certificate for the mock C2 server."""

import subprocess
import sys

def main():
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", "key.pem", "-out", "cert.pem",
        "-days", "365", "-nodes",
        "-subj", "/CN=hoverwatch-mock-c2/O=ASTRA-Research",
    ]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ Generated key.pem + cert.pem")
    else:
        print(f"❌ Error: {result.stderr}")
        sys.exit(1)

if __name__ == "__main__":
    main()
