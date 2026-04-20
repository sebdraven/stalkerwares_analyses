"""
Quick test client for the iKeyMonitor mock C2.
Simulates what the APK does: register → cycle → WS connect.

Usage:
    uv run python test_client.py [--host 127.0.0.1] [--port 8443]
"""

import argparse
import asyncio
import ssl
import time

import httpx
import websockets


BASE = "https://{host}:{port}/index.php?m=api&a={action}"
MOCK_CLIENT_ID = "AA:BB:CC:DD:EE:FF"
MOCK_LICENSE = "TEST-LICENSE-001"


def xml_payload(action: str, extra: str = "") -> str:
    ts = str(int(time.time()))
    return (
        f"<IKMService>"
        f"<Client>{MOCK_CLIENT_ID}</Client>"
        f"<License>{MOCK_LICENSE}</License>"
        f"<WSTimeStamp>{ts}</WSTimeStamp>"
        f"{extra}"
        f"</IKMService>"
    )


async def test_rest(host: str, port: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    async with httpx.AsyncClient(verify=False) as c:
        base = f"https://{host}:{port}/index.php"

        print("\n[1] Register")
        r = await c.post(f"{base}?m=api&a=register", content=xml_payload("register"))
        print(f"    → {r.status_code}: {r.text[:200]}")

        print("\n[2] Account")
        r = await c.post(f"{base}?m=api&a=account", content=xml_payload("account"))
        print(f"    → {r.status_code}: {r.text[:200]}")

        print("\n[3] Get Settings")
        r = await c.post(f"{base}?m=api&a=get_settings", content=xml_payload("get_settings"))
        print(f"    → {r.status_code}: {r.text[:200]}")

        print("\n[4] Get WebSocket Address")
        r = await c.post(f"{base}?m=api&a=get_websocket_address",
                         content=xml_payload("get_websocket_address"))
        print(f"    → {r.status_code}: {r.text[:200]}")

        print("\n[5] Cycle")
        r = await c.post(f"{base}?m=api&a=cycle", content=xml_payload("cycle"))
        print(f"    → {r.status_code}: {r.text[:200]}")

        print("\n[6] Upload keystrokes (typo endpoint)")
        r = await c.post(f"{base}?m=api&a=uoload_keystrokes",
                         content=xml_payload("uoload_keystrokes",
                                             "<Keystrokes>hello world</Keystrokes>"))
        print(f"    → {r.status_code}: {r.text[:200]}")

        print("\n[7] Check Update")
        r = await c.post(f"{base}?m=api&a=check_update", content=xml_payload("check_update"))
        print(f"    → {r.status_code}: {r.text[:200]}")

        print("\n[8] Admin Status")
        r = await c.get(f"https://{host}:{port}/admin/status")
        print(f"    → {r.json()}")

        print("\n[9] Crypto encrypt test")
        r = await c.get(f"https://{host}:{port}/admin/crypto/encrypt?plaintext=ASTRA-2026")
        print(f"    → {r.json()}")


async def test_ws(host: str, port: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    uri = f"wss://{host}:{port}/ws"
    print(f"\n[WS] Connecting to {uri}...")

    async with websockets.connect(uri, ssl=ctx) as ws:
        # Receive onConnect
        msg = await ws.recv()
        print(f"[WS ←] {msg}")

        # Send ACK
        ack = xml_payload("onConnect")
        await ws.send(ack)
        print(f"[WS →] {ack[:200]}")

        # Wait for commands (5 seconds)
        print("[WS] Waiting 5s for commands...")
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            print(f"[WS ←] {msg}")
        except asyncio.TimeoutError:
            print("[WS] No commands received (expected in idle state)")

    print("[WS] Disconnected")


async def main(host: str, port: int):
    print(f"=== iKeyMonitor Mock C2 Test Client ===")
    print(f"Target: {host}:{port}\n")

    await test_rest(host, port)
    await test_ws(host, port)

    print("\n✅ All tests passed")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    args = p.parse_args()
    asyncio.run(main(args.host, args.port))
