#!/usr/bin/env python3
"""Generate self-signed SSL certificate for the iKeyMonitor mock C2 server."""
import subprocess, sys

def main():
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", "key.pem", "-out", "cert.pem",
        "-days", "365", "-nodes",
        "-subj", "/CN=ikmws.awsapi.io/O=ASTRA-Research",
        "-addext", "subjectAltName=DNS:ikmws.awsapi.io,DNS:ikmws-mirror.awsapi.io,"
                   "DNS:ikm-sv2.awsapi.io,DNS:ikm-sv3.awsapi.io,DNS:ikm-sv4.awsapi.io,"
                   "DNS:localhost,IP:127.0.0.1",
    ]
    print(f"Running: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        print("✅ Generated key.pem + cert.pem (SAN: ikmws*.awsapi.io)")
    else:
        print(f"❌ Error: {r.stderr}")
        sys.exit(1)

if __name__ == "__main__":
    main()
